"""
SQL-TRUST Case Audit Service
Module 6: Cyber Investigation & Incident Response Orchestration
Provides cryptographically chained, append-only audit logging for investigation cases.
Every state mutation, note addition, and evidence link is sealed in an unbroken hash chain.
"""
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from backend.models.investigation import CaseAuditLog


class CaseAuditService:
    """Manages append-only, tamper-evident audit logging with SHA-256 chain verification."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    @classmethod
    def compute_entry_hash(
        cls,
        previous_hash: str,
        case_id: str,
        sequence_number: int,
        action: str,
        actor: str,
        logged_at: datetime,
        details: Optional[str] = None
    ) -> str:
        """
        Computes a deterministic SHA-256 digest for an audit entry chained to previous_hash.
        Uses second-level precision to ensure deterministic recalculation across SQL Server storage engines.
        """
        iso_time = logged_at.strftime("%Y-%m-%d %H:%M:%S")
        payload = f"{previous_hash}|{case_id}|{sequence_number}|{action}|{actor}|{iso_time}|{details or ''}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def log_action(
        cls,
        db: Session,
        case_id: str,
        action: str,
        actor: str,
        client_ip: Optional[str] = None,
        details: Optional[str] = None
    ) -> CaseAuditLog:
        """
        Appends an immutable audit log record chained to the case's latest audit entry.
        """
        # Determine the latest sequence number and previous hash for this case
        latest_entry = (
            db.query(CaseAuditLog)
            .filter(CaseAuditLog.case_id == case_id)
            .order_by(CaseAuditLog.sequence_number.desc())
            .first()
        )

        sequence_number = (latest_entry.sequence_number + 1) if latest_entry else 1
        previous_hash = latest_entry.current_hash if latest_entry else cls.GENESIS_HASH
        logged_at = datetime.now(timezone.utc).replace(microsecond=0)

        current_hash = cls.compute_entry_hash(
            previous_hash=previous_hash,
            case_id=case_id,
            sequence_number=sequence_number,
            action=action,
            actor=actor,
            logged_at=logged_at,
            details=details
        )

        audit_entry = CaseAuditLog(
            case_id=case_id,
            sequence_number=sequence_number,
            action=action,
            actor=actor,
            client_ip=client_ip,
            details=details,
            previous_hash=previous_hash,
            current_hash=current_hash,
            logged_at=logged_at
        )

        db.add(audit_entry)
        db.flush()
        return audit_entry

    @classmethod
    def verify_audit_chain(cls, db: Session, case_id: str) -> Dict[str, Any]:
        """
        Verifies the cryptographic integrity of the entire audit chain for a case.
        Returns validation status, total count, and any detected discrepancies.
        """
        entries: List[CaseAuditLog] = (
            db.query(CaseAuditLog)
            .filter(CaseAuditLog.case_id == case_id)
            .order_by(CaseAuditLog.sequence_number.asc())
            .all()
        )

        if not entries:
            return {
                "valid": True,
                "case_id": case_id,
                "total_entries": 0,
                "discrepancies": []
            }

        discrepancies = []
        expected_prev_hash = cls.GENESIS_HASH

        for idx, entry in enumerate(entries):
            expected_seq = idx + 1
            if entry.sequence_number != expected_seq:
                discrepancies.append({
                    "entry_id": entry.id,
                    "sequence_number": entry.sequence_number,
                    "error": f"Sequence gap: expected {expected_seq}, found {entry.sequence_number}"
                })

            if entry.previous_hash != expected_prev_hash:
                discrepancies.append({
                    "entry_id": entry.id,
                    "sequence_number": entry.sequence_number,
                    "error": f"Broken chain pointer: expected {expected_prev_hash}, found {entry.previous_hash}"
                })

            recalculated_hash = cls.compute_entry_hash(
                previous_hash=entry.previous_hash or cls.GENESIS_HASH,
                case_id=case_id,
                sequence_number=entry.sequence_number,
                action=entry.action,
                actor=entry.actor,
                logged_at=entry.logged_at,
                details=entry.details
            )

            if recalculated_hash != entry.current_hash:
                discrepancies.append({
                    "entry_id": entry.id,
                    "sequence_number": entry.sequence_number,
                    "error": f"Hash mismatch: recalculated {recalculated_hash}, stored {entry.current_hash}"
                })

            expected_prev_hash = entry.current_hash

        return {
            "valid": len(discrepancies) == 0,
            "case_id": case_id,
            "total_entries": len(entries),
            "discrepancies": discrepancies
        }
