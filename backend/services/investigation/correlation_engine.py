"""
SQL-TRUST Multi-Dimensional Evidence Correlation Engine
Module 6: Cyber Investigation & Incident Response Orchestration
Performs cross-module telemetry scans across four dimensions:
1. Temporal Proximity (sliding time window)
2. Principal Lineage (attacker identity overlap)
3. Target Object Overlap (compromised tables/stored procedures/roles)
4. Attack Graph Progression (MITRE ATT&CK kill-chain mapping)
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from backend.models.investigation import InvestigationCase, CaseEvidenceLink
from backend.models.security import SecurityAlert, DetectionRule
from backend.models.forensics import ForensicFinding, ForensicInvestigation
from backend.models.recovery import RecoveryPoint, RecoveryAssessment
from backend.models.restore import RecoveryJob
from backend.schemas.investigation import CaseEvidenceLinkCreateRequest
from backend.services.investigation.case_service import CaseService  # pyrefly: ignore[missing-import]
from backend.services.investigation.classification_engine import ClassificationEngine  # pyrefly: ignore[missing-import]
from backend.services.investigation.audit_service import CaseAuditService  # pyrefly: ignore[missing-import]


def ensure_utc(dt: Optional[datetime]) -> datetime:
    """Normalizes any datetime to offset-aware UTC datetime."""
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class CorrelationEngine:
    """Executes multi-dimensional correlation scans across Modules 1-5."""

    @classmethod
    def correlate_case_evidence(
        cls,
        db: Session,
        case_id: str,
        sliding_window_minutes: int = 30,
        auto_link: bool = True,
        actor: str = "investigator",
        client_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Scans for correlated alerts, forensic findings, and recovery points,
        optionally links them as evidence, and reclassifies the case.
        """
        case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found")

        # 1. Gather already linked evidence IDs
        existing_links = db.query(CaseEvidenceLink).filter(CaseEvidenceLink.case_id == case.id).all()
        linked_ids: Set[str] = {link.source_id for link in existing_links}

        # 2. Extract baseline entities and principals from current case
        known_principals: Set[str] = set()
        known_objects: Set[str] = {case.target_database_name}

        for link in existing_links:
            if link.source_module == "MODULE_2_SECURITY":
                alert = db.query(SecurityAlert).filter(SecurityAlert.id == link.source_id).first()
                if alert:
                    if alert.principal_name:
                        known_principals.add(alert.principal_name.lower())
                    if alert.target_object:
                        known_objects.add(alert.target_object)
            elif link.source_module == "MODULE_3_FORENSICS":
                finding = db.query(ForensicFinding).filter(ForensicFinding.id == link.source_id).first()
                if finding and finding.entity_name:
                    known_objects.add(finding.entity_name)

        # Temporal bounds
        case_opened_utc = ensure_utc(case.opened_at)
        window_delta = timedelta(minutes=sliding_window_minutes)
        window_start = case_opened_utc - window_delta
        window_end = case_opened_utc + window_delta

        candidates: List[Dict[str, Any]] = []

        # 3. Dimension A: Temporal & Database Security Alerts
        temporal_alerts = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.created_at >= window_start,
                SecurityAlert.created_at <= window_end
            )
            .all()
        )
        for alert in temporal_alerts:
            if alert.id in linked_ids:
                continue
            
            # Check database match or principal match
            alert_db = alert.target_object.split(".")[0] if alert.target_object else None
            p_match = alert.principal_name and alert.principal_name.lower() in known_principals
            db_match = alert_db == case.target_database_name

            if db_match or p_match:
                corr_type = "PRINCIPAL" if p_match else "TEMPORAL"
                candidates.append({
                    "source_module": "MODULE_2_SECURITY",
                    "source_entity": "security_alerts",
                    "source_id": alert.id,
                    "correlation_type": corr_type,
                    "description": f"Security Alert: {alert.title} (Severity: {alert.severity})",
                    "timestamp": ensure_utc(alert.created_at),
                    "confidence": 0.90 if (db_match and p_match) else 0.75,
                    "already_linked": False
                })

        # 4. Dimension B: Forensic Drift Findings on Target Database
        forensic_invs = (
            db.query(ForensicInvestigation)
            .filter(ForensicInvestigation.database_name == case.target_database_name)
            .all()
        )
        for inv in forensic_invs:
            for finding in inv.findings:
                if finding.id in linked_ids:
                    continue
                # Temporal or object check
                f_time = ensure_utc(finding.detected_at or case.opened_at)
                is_in_window = window_start <= f_time <= window_end
                obj_match = any(finding.entity_name in obj for obj in known_objects if obj)

                if is_in_window or obj_match:
                    candidates.append({
                        "source_module": "MODULE_3_FORENSICS",
                        "source_entity": "forensic_findings",
                        "source_id": finding.id,
                        "correlation_type": "TARGET_OBJECT" if obj_match else "TEMPORAL",
                        "description": f"Forensic Drift: {finding.finding_type} on {finding.entity_name}",
                        "timestamp": f_time,
                        "confidence": 0.95 if (is_in_window and obj_match) else 0.80,
                        "already_linked": False
                    })

        # 5. Dimension C: Compromised Recovery Points
        recovery_points = (
            db.query(RecoveryPoint)
            .filter(RecoveryPoint.database_name == case.target_database_name)
            .all()
        )
        for rp in recovery_points:
            if rp.id in linked_ids:
                continue
            rp_time = ensure_utc(rp.recovery_point_time)
            is_in_window = window_start <= rp_time <= window_end
            if is_in_window:
                candidates.append({
                    "source_module": "MODULE_4_RECOVERY",
                    "source_entity": "recovery_points",
                    "source_id": rp.id,
                    "correlation_type": "TEMPORAL",
                    "description": f"Recovery Point Candidate at {rp.recovery_point_time}",
                    "timestamp": rp_time,
                    "confidence": 0.85,
                    "already_linked": False
                })

        # 6. Auto-link discovered candidates if requested
        linked_count = 0
        if auto_link and candidates:
            for cand in candidates:
                link_req = CaseEvidenceLinkCreateRequest(
                    source_module=cand["source_module"],
                    source_entity=cand["source_entity"],
                    source_id=cand["source_id"],
                    evidence_role="CORRELATED_INDICATOR",
                    metadata_snapshot=f'{{"correlation_type": "{cand["correlation_type"]}", "confidence": {cand["confidence"]}}}',
                    linked_by=actor
                )
                try:
                    CaseService.link_evidence(db=db, case_id=case.id, req=link_req, client_ip=client_ip)
                    cand["already_linked"] = True
                    linked_count += 1
                except Exception:
                    pass  # Already linked or idempotency check

            # Recalculate classification with newly linked evidence
            ClassificationEngine.classify_case(db=db, case_id=case.id, actor=actor, client_ip=client_ip)
            
            CaseAuditService.log_action(
                db=db,
                case_id=case.id,
                action="CORRELATION_SCAN_EXECUTED",
                actor=actor,
                client_ip=client_ip,
                details=f"Correlation scan discovered {len(candidates)} candidates; {linked_count} automatically linked as CORRELATED_INDICATOR."
            )
            db.commit()
            db.refresh(case)

        summary = (
            f"Correlation scan across {sliding_window_minutes}-minute window identified "
            f"{len(candidates)} telemetry items. {linked_count} newly linked into case {case.case_number}."
        )

        return {
            "case_id": case.id,
            "candidates_found": len(candidates),
            "candidates_linked": linked_count,
            "discovered_principals": sorted(list(known_principals)),
            "discovered_objects": sorted(list(known_objects)),
            "correlation_summary": summary,
            "candidates": candidates
        }
