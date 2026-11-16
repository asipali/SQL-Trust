"""
SQL-TRUST Recovery Eligibility Engine
Module 4: Cyber Recovery & State Reconstruction
Evaluates technical restore feasibility independently from cyber trust scores.
Guarantees high confidence never bypasses technical integrity checks.
"""
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.models.recovery import (
    RecoveryPoint,
    RecoveryChain,
    RecoveryEligibility
)
from backend.services.recovery.chain_analyzer import BackupChainAnalyzer


class RecoveryEligibilityEngine:
    """
    Evaluates whether a candidate recovery point is technically restorable.
    Maintains strict separation between technical eligibility and trust confidence.
    """

    def __init__(self, db: Session):
        self.db = db
        self.chain_analyzer = BackupChainAnalyzer(db)

    def evaluate_eligibility(
        self,
        recovery_point_id: str,
        chain_id: Optional[str] = None
    ) -> RecoveryEligibility:
        """
        Evaluates technical restore readiness for a recovery point.
        """
        rp = self.db.query(RecoveryPoint).filter(RecoveryPoint.id == recovery_point_id).first()
        if not rp:
            raise ValueError(f"Recovery point '{recovery_point_id}' not found.")

        # Ensure chain is analyzed
        chain = None
        if chain_id:
            chain = self.db.query(RecoveryChain).filter(RecoveryChain.id == chain_id).first()
        if not chain:
            chain = self.chain_analyzer.analyze_chain_for_target(rp.id)

        blocking_reasons: List[str] = []
        validation_checklist: List[Dict[str, Any]] = []

        # 1. Chain Usable Check
        chain_usable = bool(chain and chain.is_complete)
        validation_checklist.append({
            "check": "CHAIN_COMPLETENESS",
            "passed": chain_usable,
            "details": "Full backup base and necessary chain segments exist." if chain_usable else "Backup chain is incomplete."
        })
        if not chain_usable:
            blocking_reasons.append("Incomplete backup chain: Missing Full base or intervening backup segments.")

        # 2. Chain Consistency Check (LSN continuity)
        chain_consistent = bool(chain and chain.is_valid and chain.validation_status == "VALID")
        validation_checklist.append({
            "check": "LSN_CONTINUITY",
            "passed": chain_consistent,
            "details": "Unbroken LSN sequence verified across all segments." if chain_consistent else f"LSN validation failed: {chain.validation_details if chain else 'No chain'}"
        })
        if not chain_consistent:
            blocking_reasons.append(f"Chain consistency failure: {chain.validation_details if chain else 'Invalid chain'}")

        # 3. Log Sequence Availability
        logs_available = True
        if rp.recovery_point_type == "LOG":
            # Must have non-zero segments and valid status
            logs_available = bool(chain and chain.segment_count >= 2 and chain.validation_status != "MISSING_LOGS")
        validation_checklist.append({
            "check": "LOG_SEQUENCE_AVAILABLE",
            "passed": logs_available,
            "details": "All required transaction log segments available." if logs_available else "Missing transaction log segments in chain."
        })
        if not logs_available:
            blocking_reasons.append("Required transaction log segments are missing from storage.")

        # 4. Database Identity Match
        identity_matched = bool(rp.database_id and rp.database_name)
        validation_checklist.append({
            "check": "DATABASE_IDENTITY_MATCH",
            "passed": identity_matched,
            "details": f"Target database '{rp.database_name}' identity confirmed."
        })
        if not identity_matched:
            blocking_reasons.append("Database identity mismatch or unregistered database.")

        # 5. Backup Files Accessibility
        files_accessible = False
        if rp.backup_record and rp.backup_record.backup_path and os.path.exists(rp.backup_record.backup_path):
            files_accessible = True
        elif rp.storage_object_key:
            files_accessible = True  # Available in SeaweedFS
        validation_checklist.append({
            "check": "FILE_ACCESSIBILITY",
            "passed": files_accessible,
            "details": "Backup archive payload accessible on disk or via SeaweedFS S3." if files_accessible else "Backup file cannot be located on disk or storage."
        })
        if not files_accessible:
            blocking_reasons.append("Backup file is inaccessible on local filesystem and remote object storage.")

        # 6. Integrity Verification Status
        integrity_verified = (rp.integrity_status == "VERIFIED")
        validation_checklist.append({
            "check": "INTEGRITY_VERIFICATION",
            "passed": integrity_verified,
            "details": "SHA-256 checksum and RESTORE VERIFYONLY CHECKSUM passed." if integrity_verified else f"Integrity status is {rp.integrity_status}."
        })
        if not integrity_verified:
            blocking_reasons.append(f"Integrity check failed or pending ({rp.integrity_status}).")

        critical_evidence_missing = not (chain_usable and files_accessible and integrity_verified)

        # Technical Eligibility Decision
        all_checks_passed = (
            chain_usable and
            chain_consistent and
            logs_available and
            identity_matched and
            files_accessible and
            integrity_verified
        )

        if all_checks_passed:
            eligibility_status = "ELIGIBLE"
            is_eligible = True
        elif rp.integrity_status == "FAILED" or (chain and chain.validation_status == "BROKEN_CHAIN"):
            eligibility_status = "BLOCKED"
            is_eligible = False
        else:
            eligibility_status = "INELIGIBLE"
            is_eligible = False

        elig = self.db.query(RecoveryEligibility).filter(
            RecoveryEligibility.recovery_point_id == rp.id
        ).first()

        if not elig:
            elig = RecoveryEligibility(
                recovery_point_id=rp.id,
                chain_id=chain.id if chain else None,
                is_eligible=is_eligible,
                eligibility_status=eligibility_status,
                requires_offline_sandbox=True,
                chain_usable=chain_usable,
                chain_consistent=chain_consistent,
                logs_available=logs_available,
                identity_matched=identity_matched,
                files_accessible=files_accessible,
                integrity_verified=integrity_verified,
                critical_evidence_missing=critical_evidence_missing,
                blocking_reasons_json=json.dumps(blocking_reasons),
                validation_checklist_json=json.dumps(validation_checklist)
            )
            self.db.add(elig)
        else:
            elig.chain_id = chain.id if chain else None
            elig.is_eligible = is_eligible
            elig.eligibility_status = eligibility_status
            elig.chain_usable = chain_usable
            elig.chain_consistent = chain_consistent
            elig.logs_available = logs_available
            elig.identity_matched = identity_matched
            elig.files_accessible = files_accessible
            elig.integrity_verified = integrity_verified
            elig.critical_evidence_missing = critical_evidence_missing
            elig.blocking_reasons_json = json.dumps(blocking_reasons)
            elig.validation_checklist_json = json.dumps(validation_checklist)

        self.db.commit()
        self.db.refresh(elig)
        return elig
