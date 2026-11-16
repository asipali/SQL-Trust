"""
SQL-TRUST Forensic Investigation Coordinator
Module 3: Database Forensics Engine
Coordinates baseline diffing, schema forensics, principal analysis,
configuration drift, telemetry correlation, and WORM evidence archival.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.models.forensics import (
    ForensicBaseline,
    ForensicBaselineItem,
    ForensicInvestigation,
    ForensicFinding
)
from backend.services.forensics.schema_engine import SchemaForensicsEngine
from backend.services.forensics.principal_analyzer import PrincipalAnalyzer
from backend.services.forensics.config_analyzer import ConfigurationAnalyzer
from backend.services.forensics.timeline_engine import TimelineCorrelator
from backend.services.forensics.evidence_service import ForensicEvidenceService


class ForensicService:
    """
    Coordinates end-to-end forensic comparison investigations.
    """

    def __init__(self, db: Session):
        self.db = db

    def execute_investigation(
        self,
        ref_baseline_id: str,
        target_baseline_id: str,
        investigation_name: Optional[str] = None,
        summary_notes: Optional[str] = None
    ) -> ForensicInvestigation:
        """
        Executes an exhaustive forensic investigation between two baseline states.
        """
        ref_b = self.db.query(ForensicBaseline).filter(ForensicBaseline.id == ref_baseline_id).first()
        if not ref_b:
            raise ValueError(f"Reference baseline '{ref_baseline_id}' not found.")

        tgt_b = self.db.query(ForensicBaseline).filter(ForensicBaseline.id == target_baseline_id).first()
        if not tgt_b:
            raise ValueError(f"Target baseline '{target_baseline_id}' not found.")

        name = investigation_name or f"Investigation_{ref_b.database_name}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        # Create investigation record
        investigation = ForensicInvestigation(
            investigation_name=name,
            server_name=ref_b.server_name,
            database_name=ref_b.database_name,
            ref_baseline_id=ref_b.id,
            target_baseline_id=tgt_b.id,
            status="IN_PROGRESS",
            summary_notes=summary_notes,
            started_at=datetime.now(timezone.utc)
        )
        self.db.add(investigation)
        self.db.commit()
        self.db.refresh(investigation)

        ref_items = ref_b.items
        tgt_items = tgt_b.items

        # 1. Run Schema Forensics
        raw_findings: List[Dict[str, Any]] = []
        raw_findings.extend(SchemaForensicsEngine.compare_schema_items(ref_items, tgt_items))

        # 2. Run Security Principal & Privilege Analysis
        raw_findings.extend(PrincipalAnalyzer.compare_principals(ref_items, tgt_items))

        # 3. Run Configuration Drift Analysis
        raw_findings.extend(ConfigurationAnalyzer.compare_configurations(ref_items, tgt_items))

        # Persist ForensicFindings
        findings_objects: List[ForensicFinding] = []
        critical_count = 0
        high_count = 0

        for rf in raw_findings:
            sev = rf.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                critical_count += 1
            elif sev == "HIGH":
                high_count += 1

            finding = ForensicFinding(
                investigation_id=investigation.id,
                category=rf["category"],
                finding_type=rf["finding_type"],
                severity=sev,
                entity_name=rf["entity_name"],
                schema_name=rf.get("schema_name"),
                before_state_json=rf.get("before_state_json"),
                after_state_json=rf.get("after_state_json"),
                explanation=rf["explanation"],
                confidence_score=rf.get("confidence_score", 1.0)
            )
            findings_objects.append(finding)

        self.db.add_all(findings_objects)
        self.db.commit()

        # 4. Correlate with Module 2 Security Telemetry Events
        correlator = TimelineCorrelator(self.db)
        correlator.correlate_investigation_findings(investigation, findings_objects)

        # Update Investigation Summary
        investigation.findings_count = len(findings_objects)
        investigation.critical_findings_count = critical_count
        investigation.high_findings_count = high_count
        investigation.status = "COMPLETED"
        investigation.completed_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(investigation)

        # 5. Automatically Archive and Sign Investigation Report in SeaweedFS Object Lock WORM
        try:
            evidence_svc = ForensicEvidenceService(self.db)
            evidence_svc.archive_investigation_report(investigation)
        except Exception as e:
            # Non-fatal to investigation status
            investigation.summary_notes = (investigation.summary_notes or "") + f" [WORM Archive Note: {str(e)}]"
            self.db.commit()

        return investigation
