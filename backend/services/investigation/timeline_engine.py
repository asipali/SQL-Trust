"""
SQL-TRUST Investigation Timeline Reconstruction Engine
Module 6: Cyber Investigation & Incident Response Orchestration
Integrates telemetry across Modules 1-6 (Alerts, Forensic Drift Findings,
Recovery Points, Restore Validation Jobs, Status Transitions, and Analyst Notes)
into a unified, chronologically sorted, microsecond-normalized investigation timeline.
"""
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc

from backend.models.investigation import (
    InvestigationCase,
    CaseEvidenceLink,
    CaseStatusHistory,
    CaseNote,
    CaseContainmentAction,
    CaseMitreTechnique
)
from backend.models.security import SecurityAlert, DetectionRule
from backend.models.forensics import ForensicFinding, ForensicInvestigation
from backend.models.recovery import RecoveryPoint, RecoveryAssessment
from backend.models.restore import RecoveryJob, RecoveryValidation
from backend.services.investigation.classification_engine import ClassificationEngine  # pyrefly: ignore[missing-import]


def ensure_utc(dt: Optional[datetime]) -> datetime:
    """Normalizes any datetime (naive or aware) to offset-aware UTC datetime."""
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class TimelineEngine:
    """Reconstructs unified chronological investigation timelines with milestone tagging."""

    @classmethod
    def build_case_timeline(cls, db: Session, case_id: str) -> List[Dict[str, Any]]:
        """
        Collates and normalizes all evidence, telemetry, status transitions, notes,
        and containment actions for a case into an ordered chronological timeline.
        """
        case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found")

        events: List[Dict[str, Any]] = []

        # 1. Root Case Opening Event
        events.append({
            "event_id": f"evt-case-{case.id}",
            "timestamp": ensure_utc(case.opened_at),
            "source_module": "MODULE_6_INVESTIGATION",
            "source_entity": "investigation_cases",
            "source_id": case.id,
            "event_type": "CASE_OPENED",
            "severity": case.priority.replace("P1_", "").replace("P2_", "").replace("P3_", "").replace("P4_", ""),
            "summary": f"Investigation Case {case.case_number} Opened",
            "details": case.description or f"Case opened with initial priority {case.priority} in category {case.incident_category}.",
            "actor": case.created_by,
            "target_object": case.target_database_name,
            "mitre_technique": None,
            "is_milestone": True
        })

        # 2. Linked Evidence Items
        evidence_links = db.query(CaseEvidenceLink).filter(CaseEvidenceLink.case_id == case.id).all()
        for link in evidence_links:
            # 2.1 Module 2 Security Alert
            if link.source_module == "MODULE_2_SECURITY" and link.source_entity == "security_alerts":
                alert = db.query(SecurityAlert).filter(SecurityAlert.id == link.source_id).first()
                if alert:
                    ts = alert.detection_timestamp or alert.created_at or case.opened_at
                    rule = db.query(DetectionRule).filter(DetectionRule.id == alert.rule_id).first()
                    rule_code = rule.rule_id if rule and hasattr(rule, "rule_id") else (rule.rule_code if rule and hasattr(rule, "rule_code") else "RULE-001")
                    norm_code = rule_code.replace("_", "-")[:8].upper()
                    techs = ClassificationEngine.RULE_TECHNIQUE_MAP.get(norm_code, [])
                    primary_tech = techs[0][0] if techs else None

                    is_ms = (link.evidence_role == "ROOT_CAUSE" or alert.severity in ("CRITICAL", "HIGH"))
                    events.append({
                        "event_id": f"evt-alert-{alert.id}",
                        "timestamp": ensure_utc(ts),
                        "source_module": "MODULE_2_SECURITY",
                        "source_entity": "security_alerts",
                        "source_id": alert.id,
                        "event_type": "SECURITY_ALERT_TRIGGERED",
                        "severity": alert.severity,
                        "summary": alert.title,
                        "details": alert.description or alert.explanation,
                        "actor": alert.principal_name,
                        "target_object": alert.target_object or case.target_database_name,
                        "mitre_technique": primary_tech,
                        "is_milestone": is_ms
                    })

            # 2.2 Module 3 Forensic Finding
            elif link.source_module == "MODULE_3_FORENSICS" and link.source_entity == "forensic_findings":
                finding = db.query(ForensicFinding).filter(ForensicFinding.id == link.source_id).first()
                if finding:
                    ts = finding.detected_at or case.opened_at
                    f_cat = (finding.category or "").upper()
                    f_type = (finding.finding_type or "").upper()

                    if f_cat == "SCHEMA" or "OBJECT" in f_type:
                        tech = "T1505.001"
                    elif f_cat in ("PRINCIPAL", "ROLE_MEMBERSHIP") or "USER" in f_type or "ROLE" in f_type:
                        tech = "T1068"
                    elif f_cat == "CONFIGURATION" or "CONFIG" in f_type:
                        tech = "T1562.001"
                    else:
                        tech = None

                    is_ms = finding.severity in ("CRITICAL", "HIGH")
                    events.append({
                        "event_id": f"evt-finding-{finding.id}",
                        "timestamp": ensure_utc(ts),
                        "source_module": "MODULE_3_FORENSICS",
                        "source_entity": "forensic_findings",
                        "source_id": finding.id,
                        "event_type": f"FORENSIC_{finding.finding_type}",
                        "severity": finding.severity,
                        "summary": f"Forensic Drift: {finding.finding_type} on {finding.entity_name}",
                        "details": finding.explanation,
                        "actor": None,
                        "target_object": f"{finding.schema_name or 'dbo'}.{finding.entity_name}",
                        "mitre_technique": tech,
                        "is_milestone": is_ms
                    })

            # 2.3 Module 4 Recovery Point
            elif link.source_module == "MODULE_4_RECOVERY" and link.source_entity == "recovery_points":
                point = db.query(RecoveryPoint).filter(RecoveryPoint.id == link.source_id).first()
                if point:
                    assessment = db.query(RecoveryAssessment).filter(RecoveryAssessment.recovery_point_id == point.id).first()
                    ts = assessment.assessed_at if assessment else point.recovery_point_time
                    trust_class = assessment.trust_classification if assessment else "UNASSESSED"
                    is_threat = trust_class in ("LOW_CONFIDENCE", "COMPROMISED")

                    events.append({
                        "event_id": f"evt-recpoint-{point.id}",
                        "timestamp": ensure_utc(ts),
                        "source_module": "MODULE_4_RECOVERY",
                        "source_entity": "recovery_points",
                        "source_id": point.id,
                        "event_type": "RECOVERY_POINT_ASSESSED",
                        "severity": "CRITICAL" if is_threat else "INFO",
                        "summary": f"Recovery Point Evaluated: {point.recovery_point_time.strftime('%Y-%m-%d %H:%M:%S')} ({trust_class})",
                        "details": assessment.confidence_rationale if assessment else "Recovery candidate assessed for restore eligibility.",
                        "actor": "recovery_engine",
                        "target_object": point.database_name,
                        "mitre_technique": "T1485" if is_threat else None,
                        "is_milestone": is_threat
                    })

            # 2.4 Module 5 Restore Job / Validation
            elif link.source_module == "MODULE_5_RESTORE" and link.source_entity == "recovery_jobs":
                job = db.query(RecoveryJob).filter(RecoveryJob.id == link.source_id).first()
                if job:
                    validation = db.query(RecoveryValidation).filter(RecoveryValidation.job_id == job.id).first()
                    ts = validation.validated_at if validation else (job.created_at or case.opened_at)
                    outcome = validation.overall_assessment if validation else job.status
                    is_fail = (outcome == "FAILED" or job.status in ("FAILED", "TERMINATED"))

                    events.append({
                        "event_id": f"evt-recjob-{job.id}",
                        "timestamp": ensure_utc(ts),
                        "source_module": "MODULE_5_RESTORE",
                        "source_entity": "recovery_jobs",
                        "source_id": job.id,
                        "event_type": "RESTORE_VALIDATION_COMPLETED",
                        "severity": "CRITICAL" if is_fail else "INFO",
                        "summary": f"Sandbox Recovery Validation: {job.job_reference} ({outcome})",
                        "details": validation.assessment_rationale if validation else f"Isolated restore job status {job.status}.",
                        "actor": "restore_orchestrator",
                        "target_object": job.target_database_name,
                        "mitre_technique": "T1485" if is_fail else None,
                        "is_milestone": True
                    })

        # 3. Status Transition History
        status_transitions = db.query(CaseStatusHistory).filter(CaseStatusHistory.case_id == case.id).all()
        for hist in status_transitions:
            is_key_state = hist.to_status in ("CONTAINMENT_REVIEW", "RECOVERY_COORDINATION", "RESOLVED", "CLOSED")
            events.append({
                "event_id": f"evt-status-{hist.id}",
                "timestamp": ensure_utc(hist.transitioned_at),
                "source_module": "MODULE_6_INVESTIGATION",
                "source_entity": "case_status_history",
                "source_id": hist.id,
                "event_type": "STATUS_TRANSITION",
                "severity": "INFO",
                "summary": f"Case Status Changed: {hist.from_status} -> {hist.to_status}",
                "details": hist.transition_reason or f"Investigator transitioned status to {hist.to_status}.",
                "actor": hist.changed_by,
                "target_object": case.target_database_name,
                "mitre_technique": None,
                "is_milestone": is_key_state
            })

        # 4. Containment Actions
        containment_actions = db.query(CaseContainmentAction).filter(CaseContainmentAction.case_id == case.id).all()
        for act in containment_actions:
            events.append({
                "event_id": f"evt-containment-{act.id}",
                "timestamp": ensure_utc(act.created_at),
                "source_module": "MODULE_6_INVESTIGATION",
                "source_entity": "case_containment_actions",
                "source_id": act.id,
                "event_type": f"CONTAINMENT_{act.action_type}",
                "severity": "HIGH",
                "summary": f"Containment Action Proposed: {act.action_type} ({act.status})",
                "details": f"Target: {act.target_principal or act.target_object}. Script: {act.recommended_script}",
                "actor": act.reviewed_by or "system",
                "target_object": act.target_object or case.target_database_name,
                "mitre_technique": None,
                "is_milestone": True
            })

        # 5. Analyst Notes
        notes = db.query(CaseNote).filter(CaseNote.case_id == case.id).all()
        for note in notes:
            events.append({
                "event_id": f"evt-note-{note.id}",
                "timestamp": ensure_utc(note.created_at),
                "source_module": "MODULE_6_INVESTIGATION",
                "source_entity": "case_notes",
                "source_id": note.id,
                "event_type": f"ANALYST_NOTE_{note.note_type}",
                "severity": "INFO",
                "summary": f"Analyst Note ({note.note_type})",
                "details": note.content,
                "actor": note.author,
                "target_object": case.target_database_name,
                "mitre_technique": None,
                "is_milestone": note.is_pinned
            })

        # Sort strictly chronologically: oldest first
        events.sort(key=lambda x: x["timestamp"])
        return events

    @classmethod
    def get_milestones(cls, timeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filters the timeline to only return critical milestone events."""
        return [evt for evt in timeline if evt.get("is_milestone", False)]
