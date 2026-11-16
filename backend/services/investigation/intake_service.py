"""
SQL-TRUST Incident Intake and Ingestion Service
Module 6: Cyber Investigation & Incident Response Orchestration
Provides automated and manual ingestion pipelines across Modules 2-5,
enforcing temporal clustering, deduplication, evidence linkages, and classification.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from backend.models.investigation import InvestigationCase, CaseEvidenceLink
from backend.models.security import SecurityAlert, DetectionRule
from backend.models.forensics import ForensicFinding, ForensicInvestigation
from backend.models.recovery import RecoveryPoint, RecoveryAssessment
from backend.models.restore import RecoveryJob, RecoveryValidation
from backend.schemas.investigation import CaseCreateRequest, CaseEvidenceLinkCreateRequest
from backend.services.investigation.case_service import CaseService  # pyrefly: ignore[missing-import]
from backend.services.investigation.audit_service import CaseAuditService  # pyrefly: ignore[missing-import]
from backend.services.investigation.classification_engine import ClassificationEngine  # pyrefly: ignore[missing-import]


class IncidentIntakeService:
    """Orchestrates multi-source incident ingestion, temporal clustering, and deduplication."""

    CLUSTERING_WINDOW_MINUTES = 30

    @classmethod
    def find_active_case_for_clustering(
        cls,
        db: Session,
        database_name: str,
        event_time: datetime
    ) -> Optional[InvestigationCase]:
        """
        Finds an open (NEW, TRIAGED, or ACTIVE) investigation case for the database
        within the clustering window (default 30 minutes).
        """
        window_start = event_time - timedelta(minutes=cls.CLUSTERING_WINDOW_MINUTES)
        return (
            db.query(InvestigationCase)
            .filter(
                InvestigationCase.target_database_name == database_name,
                InvestigationCase.status.in_(["NEW", "TRIAGED", "ACTIVE"]),
                InvestigationCase.opened_at >= window_start
            )
            .order_by(desc(InvestigationCase.opened_at))
            .first()
        )

    @classmethod
    def intake_from_security_alert(
        cls,
        db: Session,
        alert_id: str,
        actor: str = "automated_collector",
        client_ip: Optional[str] = None
    ) -> InvestigationCase:
        """
        Ingests a Module 2 SecurityAlert into an existing case or spawns a new one.
        """
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            raise ValueError(f"SecurityAlert '{alert_id}' not found")

        # Resolve database name
        database_name = "master"
        if hasattr(alert, "database_name") and alert.database_name:
            database_name = alert.database_name
        elif alert.related_events and len(alert.related_events) > 0 and alert.related_events[0].database_name:
            database_name = alert.related_events[0].database_name
        elif alert.target_object:
            database_name = alert.target_object.split(".")[0]

        event_time = alert.created_at if hasattr(alert, "created_at") and alert.created_at else datetime.now(timezone.utc)

        # Check for clustering into active case on this database
        existing_case = cls.find_active_case_for_clustering(
            db=db,
            database_name=database_name,
            event_time=event_time
        )

        if existing_case:
            # Correlate into existing case
            link_req = CaseEvidenceLinkCreateRequest(
                source_module="MODULE_2_SECURITY",
                source_entity="security_alerts",
                source_id=alert.id,
                evidence_role="INDICATOR_OF_COMPROMISE",
                metadata_snapshot=f'{{"severity": "{alert.severity}", "title": "{alert.title}"}}',
                linked_by=actor
            )
            CaseService.link_evidence(db=db, case_id=existing_case.id, req=link_req, client_ip=client_ip)
            ClassificationEngine.classify_case(db=db, case_id=existing_case.id, actor=actor, client_ip=client_ip)

            CaseAuditService.log_action(
                db=db,
                case_id=existing_case.id,
                action="ALERT_CORRELATED",
                actor=actor,
                client_ip=client_ip,
                details=f"Correlated security alert ({alert.severity}) into active case {existing_case.case_number}"
            )
            db.commit()
            db.refresh(existing_case)
            return existing_case

        # Spawn new case
        rule = db.query(DetectionRule).filter(DetectionRule.id == alert.rule_id).first()
        rule_code = rule.rule_id if rule and hasattr(rule, "rule_id") else (rule.rule_code if rule and hasattr(rule, "rule_code") else "RULE-001")
        normalized_code = rule_code.replace("_", "-")[:8].upper()
        category = ClassificationEngine.RULE_CATEGORY_MAP.get(normalized_code, "SUSPICIOUS_ACTIVITY")

        priority_map = {
            "CRITICAL": "P1_CRITICAL",
            "HIGH": "P2_HIGH",
            "MEDIUM": "P3_MEDIUM",
            "LOW": "P4_LOW"
        }
        initial_priority = priority_map.get(alert.severity.upper(), "P3_MEDIUM")

        create_req = CaseCreateRequest(
            title=f"Security Alert: {alert.title}",
            description=alert.description or f"Triggered by {rule_code} on {database_name}",
            target_database_name=database_name,
            priority=initial_priority,
            incident_category=category,
            created_by=actor,
            idempotency_key=f"alert-{alert.id}"
        )

        case = CaseService.create_case(db=db, req=create_req, client_ip=client_ip)

        # Link alert as ROOT_CAUSE
        link_req = CaseEvidenceLinkCreateRequest(
            source_module="MODULE_2_SECURITY",
            source_entity="security_alerts",
            source_id=alert.id,
            evidence_role="ROOT_CAUSE",
            metadata_snapshot=f'{{"severity": "{alert.severity}", "title": "{alert.title}"}}',
            linked_by=actor
        )
        CaseService.link_evidence(db=db, case_id=case.id, req=link_req, client_ip=client_ip)

        # Classify case
        ClassificationEngine.classify_case(db=db, case_id=case.id, actor=actor, client_ip=client_ip)
        db.refresh(case)
        return case

    @classmethod
    def intake_from_forensic_finding(
        cls,
        db: Session,
        finding_id: str,
        actor: str = "forensic_collector",
        client_ip: Optional[str] = None
    ) -> InvestigationCase:
        """
        Ingests a Module 3 ForensicFinding (schema/principal/config drift) into a case.
        """
        finding = db.query(ForensicFinding).filter(ForensicFinding.id == finding_id).first()
        if not finding:
            raise ValueError(f"ForensicFinding '{finding_id}' not found")

        # Resolve database name via investigation
        investigation = (
            db.query(ForensicInvestigation)
            .filter(ForensicInvestigation.id == finding.investigation_id)
            .first()
        )
        database_name = investigation.database_name if investigation else "UNKNOWN"
        finding_time = finding.detected_at if hasattr(finding, "detected_at") and finding.detected_at else datetime.now(timezone.utc)

        existing_case = cls.find_active_case_for_clustering(
            db=db,
            database_name=database_name,
            event_time=finding_time
        )

        entity = finding.entity_name or database_name

        if existing_case:
            link_req = CaseEvidenceLinkCreateRequest(
                source_module="MODULE_3_FORENSICS",
                source_entity="forensic_findings",
                source_id=finding.id,
                evidence_role="INDICATOR_OF_COMPROMISE",
                metadata_snapshot=f'{{"category": "{finding.category}", "finding_type": "{finding.finding_type}", "entity_name": "{entity}"}}',
                linked_by=actor
            )
            CaseService.link_evidence(db=db, case_id=existing_case.id, req=link_req, client_ip=client_ip)
            ClassificationEngine.classify_case(db=db, case_id=existing_case.id, actor=actor, client_ip=client_ip)
            return existing_case

        cat = (finding.category or "").upper()
        if cat == "SCHEMA" or "OBJECT" in (finding.finding_type or ""):
            category = "SCHEMA_TAMPERING"
        elif cat in ("PRINCIPAL", "ROLE_MEMBERSHIP") or "USER" in (finding.finding_type or "") or "ROLE" in (finding.finding_type or ""):
            category = "PRIVILEGE_ESCALATION"
        elif cat == "CONFIGURATION" or "CONFIG" in (finding.finding_type or ""):
            category = "DEFENSE_EVASION"
        else:
            category = "SUSPICIOUS_ACTIVITY"

        create_req = CaseCreateRequest(
            title=f"Forensic Anomaly: {finding.finding_type} on {entity}",
            description=finding.explanation or f"Baseline drift detected in {finding.category or 'object'}",
            target_database_name=database_name,
            priority="P2_HIGH" if finding.severity in ("HIGH", "CRITICAL") else "P3_MEDIUM",
            incident_category=category,
            created_by=actor,
            idempotency_key=f"finding-{finding.id}"
        )
        case = CaseService.create_case(db=db, req=create_req, client_ip=client_ip)

        link_req = CaseEvidenceLinkCreateRequest(
            source_module="MODULE_3_FORENSICS",
            source_entity="forensic_findings",
            source_id=finding.id,
            evidence_role="ROOT_CAUSE",
            metadata_snapshot=f'{{"category": "{finding.category}", "finding_type": "{finding.finding_type}", "entity_name": "{entity}"}}',
            linked_by=actor
        )
        CaseService.link_evidence(db=db, case_id=case.id, req=link_req, client_ip=client_ip)
        ClassificationEngine.classify_case(db=db, case_id=case.id, actor=actor, client_ip=client_ip)
        db.refresh(case)
        return case

    @classmethod
    def intake_from_recovery_risk(
        cls,
        db: Session,
        recovery_point_id: str,
        actor: str = "recovery_engine",
        client_ip: Optional[str] = None
    ) -> InvestigationCase:
        """
        Ingests a high-risk or compromised Module 4 RecoveryPoint into an investigation case.
        """
        point = db.query(RecoveryPoint).filter(RecoveryPoint.id == recovery_point_id).first()
        if not point:
            raise ValueError(f"RecoveryPoint '{recovery_point_id}' not found")

        assessment = (
            db.query(RecoveryAssessment)
            .filter(RecoveryAssessment.recovery_point_id == point.id)
            .first()
        )
        trust_class = assessment.trust_classification if assessment else "UNASSESSED"
        trust_score = assessment.trust_score if assessment else 0.0

        is_critical = trust_class in ("LOW_CONFIDENCE", "COMPROMISED") or (trust_score is not None and trust_score < 40.0)

        create_req = CaseCreateRequest(
            title=f"Recovery Risk: {point.database_name} (Trust: {trust_class})",
            description=f"Recovery point candidate at {point.recovery_point_time} flagged as {trust_class} with trust score {trust_score}",
            target_database_name=point.database_name,
            priority="P1_CRITICAL" if is_critical else "P2_HIGH",
            incident_category="RANSOMWARE" if is_critical else "SUSPICIOUS_ACTIVITY",
            created_by=actor,
            idempotency_key=f"recovery-risk-{point.id}"
        )
        case = CaseService.create_case(db=db, req=create_req, client_ip=client_ip)

        link_req = CaseEvidenceLinkCreateRequest(
            source_module="MODULE_4_RECOVERY",
            source_entity="recovery_points",
            source_id=point.id,
            evidence_role="RECOVERY_VERIFICATION",
            metadata_snapshot=f'{{"trust_score": {trust_score}, "trust_classification": "{trust_class}"}}',
            linked_by=actor
        )
        CaseService.link_evidence(db=db, case_id=case.id, req=link_req, client_ip=client_ip)
        ClassificationEngine.classify_case(db=db, case_id=case.id, actor=actor, client_ip=client_ip)
        db.refresh(case)
        return case

    @classmethod
    def intake_from_validation_failure(
        cls,
        db: Session,
        job_id: str,
        actor: str = "restore_validator",
        client_ip: Optional[str] = None
    ) -> InvestigationCase:
        """
        Ingests a failed Module 5 RecoveryValidation job into an investigation case.
        """
        job = db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
        if not job:
            raise ValueError(f"RecoveryJob '{job_id}' not found")

        validation = db.query(RecoveryValidation).filter(RecoveryValidation.job_id == job.id).first()
        outcome = validation.overall_assessment if validation and validation.overall_assessment else ("FAILED" if job.status in ("FAILED", "TERMINATED") else "SUSPICIOUS")

        create_req = CaseCreateRequest(
            title=f"Recovery Validation Failure: {job.job_reference} on {job.target_database_name}",
            description=f"Isolated restore validation produced outcome '{outcome}'. DBCC: {validation.dbcc_status if validation else 'UNKNOWN'}",
            target_database_name=job.target_database_name,
            priority="P1_CRITICAL" if outcome == "FAILED" else "P2_HIGH",
            incident_category="DATA_DESTRUCTION",
            created_by=actor,
            idempotency_key=f"validation-failure-{job.id}"
        )
        case = CaseService.create_case(db=db, req=create_req, client_ip=client_ip)

        link_req = CaseEvidenceLinkCreateRequest(
            source_module="MODULE_5_RESTORE",
            source_entity="recovery_jobs",
            source_id=job.id,
            evidence_role="RECOVERY_VERIFICATION",
            metadata_snapshot=f'{{"outcome": "{outcome}", "reference": "{job.job_reference}"}}',
            linked_by=actor
        )
        CaseService.link_evidence(db=db, case_id=case.id, req=link_req, client_ip=client_ip)
        ClassificationEngine.classify_case(db=db, case_id=case.id, actor=actor, client_ip=client_ip)
        db.refresh(case)
        return case
