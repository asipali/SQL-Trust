"""
SQL-TRUST Forensic Timeline & Telemetry Correlator
Module 3: Database Forensics Engine
Correlates Module 3 state drift findings with Module 2 security telemetry events.
Maintains epistemological rigor: temporal proximity provides context but does not prove causation.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.models.security import SecurityEvent
from backend.models.forensics import (
    ForensicInvestigation,
    ForensicFinding,
    ForensicCorrelation
)


class TimelineCorrelator:
    """
    Constructs unified investigative timelines and correlates state drift with audited actions.
    """

    def __init__(self, db: Session):
        self.db = db

    def correlate_investigation_findings(
        self,
        investigation: ForensicInvestigation,
        findings: List[ForensicFinding]
    ) -> List[ForensicCorrelation]:
        """
        Scans security events between reference baseline and target baseline,
        associating relevant audited actor events with forensic drift findings.
        """
        ref_ts = investigation.ref_baseline.captured_at
        tgt_ts = investigation.target_baseline.captured_at if investigation.target_baseline else datetime.now(timezone.utc)

        # Query events occurring between reference baseline and target baseline
        # Include events in target database AND master (for server-level role/login grants)
        events = self.db.query(SecurityEvent).filter(
            SecurityEvent.server_name == investigation.server_name,
            SecurityEvent.event_timestamp >= ref_ts,
            SecurityEvent.event_timestamp <= tgt_ts,
            (SecurityEvent.database_name == investigation.database_name) | (SecurityEvent.database_name == "master") | (SecurityEvent.database_name.is_(None))
        ).order_by(SecurityEvent.event_timestamp.asc()).all()

        correlations: List[ForensicCorrelation] = []

        for finding in findings:
            entity_lower = finding.entity_name.lower()
            matched_events = []

            for ev in events:
                raw_upper = (ev.raw_payload or "").upper()
                target_upper = (ev.target_object or "").upper()
                statement_upper = (ev.statement or "").upper() if hasattr(ev, 'statement') else ""

                # Correlation logic by category
                if finding.category == "SCHEMA":
                    # Object name match in target_object or statement
                    if entity_lower in target_upper.lower() or entity_lower in raw_upper.lower():
                        score = 0.95 if entity_lower == target_upper.lower() else 0.85
                        corr_type = "EXACT_OBJECT_MATCH" if entity_lower == target_upper.lower() else "ACTION_PATTERN_MATCH"
                        matched_events.append((ev, corr_type, score))

                elif finding.category == "PRINCIPAL":
                    # User name match in target_object or statement
                    if entity_lower in target_upper.lower() or entity_lower in raw_upper.lower():
                        score = 0.95 if entity_lower == target_upper.lower() else 0.85
                        corr_type = "EXACT_PRINCIPAL_MATCH"
                        matched_events.append((ev, corr_type, score))

                elif finding.category == "ROLE_MEMBERSHIP":
                    # Check for role keywords
                    if "ALTER SERVER ROLE" in raw_upper or "ALTER ROLE" in raw_upper or "SP_ADDSRVROLEMEMBER" in raw_upper:
                        score = 0.90 if entity_lower in raw_upper.lower() else 0.70
                        corr_type = "ROLE_MUTATION_MATCH"
                        matched_events.append((ev, corr_type, score))

                elif finding.category == "CONFIGURATION":
                    # Check for ALTER DATABASE
                    if "ALTER DATABASE" in raw_upper:
                        score = 0.85
                        corr_type = "DATABASE_CONFIGURATION_MATCH"
                        matched_events.append((ev, corr_type, score))

            # Record top correlations for this finding
            for ev, corr_type, score in matched_events:
                time_delta = int(abs((tgt_ts - ev.event_timestamp).total_seconds()))
                corr = ForensicCorrelation(
                    finding_id=finding.id,
                    event_id=ev.id,
                    correlation_type=corr_type,
                    time_delta_seconds=time_delta,
                    confidence_score=score,
                    correlation_notes=(
                        f"Principal '{ev.principal_name}' executed action '{ev.action}' from IP '{ev.client_ip or 'local'}'. "
                        f"Temporal proximity indicates probable cause, but does not constitute mathematically absolute proof."
                    )
                )
                correlations.append(corr)

        if correlations:
            self.db.add_all(correlations)
            self.db.commit()

        return correlations

    def get_unified_timeline(self, investigation_id: str) -> List[Dict[str, Any]]:
        """
        Builds a chronological merged timeline containing baselines, findings,
        and correlated Module 2 security telemetry events.
        """
        inv = self.db.query(ForensicInvestigation).filter(ForensicInvestigation.id == investigation_id).first()
        if not inv:
            return []

        timeline_entries: List[Dict[str, Any]] = []

        # 1. Reference Baseline Marker
        timeline_entries.append({
            "timestamp": inv.ref_baseline.captured_at.isoformat(),
            "timeline_type": "BASELINE_REFERENCE",
            "title": f"Reference Baseline Captured: '{inv.ref_baseline.baseline_name}'",
            "description": f"Initial state established with {inv.ref_baseline.total_objects} objects and {inv.ref_baseline.total_principals} principals.",
            "severity": "INFO",
            "metadata": {
                "baseline_id": inv.ref_baseline.id,
                "sha256": inv.ref_baseline.sha256_manifest
            }
        })

        # 2. Correlated Telemetry Events
        correlations = self.db.query(ForensicCorrelation).join(
            ForensicFinding, ForensicCorrelation.finding_id == ForensicFinding.id
        ).filter(ForensicFinding.investigation_id == investigation_id).all()

        seen_event_ids = set()
        for corr in correlations:
            ev = corr.event
            if ev.id in seen_event_ids:
                continue
            seen_event_ids.add(ev.id)

            timeline_entries.append({
                "timestamp": ev.event_timestamp.isoformat(),
                "timeline_type": "SECURITY_TELEMETRY",
                "title": f"Audited Action: {ev.action} by '{ev.principal_name}'",
                "description": f"Executed statement: {ev.raw_payload[:180]}...",
                "severity": ev.severity,
                "metadata": {
                    "event_id": ev.id,
                    "event_source": ev.event_source,
                    "client_ip": ev.client_ip,
                    "client_app": ev.client_app,
                    "confidence_score": corr.confidence_score,
                    "correlation_type": corr.correlation_type
                }
            })

        # 3. Target Baseline / Investigation Findings Marker
        tgt_time = inv.target_baseline.captured_at if inv.target_baseline else (inv.completed_at or datetime.now(timezone.utc))
        timeline_entries.append({
            "timestamp": tgt_time.isoformat(),
            "timeline_type": "INVESTIGATION_COMPLETED",
            "title": f"Investigation Completed: '{inv.investigation_name}'",
            "description": f"Detected {inv.findings_count} total state drift findings ({inv.critical_findings_count} CRITICAL, {inv.high_findings_count} HIGH).",
            "severity": "CRITICAL" if inv.critical_findings_count > 0 else ("HIGH" if inv.high_findings_count > 0 else "INFO"),
            "metadata": {
                "investigation_id": inv.id,
                "findings_count": inv.findings_count
            }
        })

        # Sort all entries chronologically
        timeline_entries.sort(key=lambda x: x["timestamp"])
        return timeline_entries
