"""
SQL-TRUST Incident & Forensic Recovery Correlator
Module 4: Cyber Recovery & State Reconstruction
Integrates Module 2 security telemetry (events/alerts) and Module 3 forensic baselines
with candidate recovery points. Categorizes evidence by causal confidence and impact.
"""
import json
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.models.recovery import RecoveryPoint
from backend.models.security import SecuritySource, SecurityEvent, SecurityAlert, MonitoringHealth
from backend.models.forensics import ForensicBaseline, ForensicFinding, ForensicInvestigation


def to_utc(dt: Optional[datetime]) -> datetime:
    if not dt:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class RecoveryCorrelator:
    """
    Correlates multi-source telemetry and forensic baselines with recovery points.
    Applies epistemological caution: proximity does not equal causation.
    """

    def __init__(self, db: Session):
        self.db = db

    def correlate_evidence_for_point(self, recovery_point: RecoveryPoint) -> Dict[str, Any]:
        """
        Scans security events, detection alerts, and forensic baselines around the recovery point.
        Returns categorized evidence packages: positive, negative, missing telemetry, uncertainty.
        """
        rp_time = recovery_point.recovery_point_time
        if rp_time.tzinfo is None:
            rp_time = rp_time.replace(tzinfo=timezone.utc)

        db_name = recovery_point.database_name
        server_name = recovery_point.server_name

        positive_indicators: List[Dict[str, Any]] = []
        negative_indicators: List[Dict[str, Any]] = []
        missing_telemetry: List[Dict[str, Any]] = []
        uncertainty_factors: List[Dict[str, Any]] = []
        evidence_records: List[Dict[str, Any]] = []

        # ---------------------------------------------------------------------
        # 1. Module 1: Backup Integrity & WORM Immutability Verification
        # ---------------------------------------------------------------------
        if recovery_point.integrity_status == "VERIFIED" and recovery_point.sha256:
            pos_item = {
                "evidence_source": "MODULE_1_BACKUP",
                "source_record_id": str(recovery_point.backup_id or recovery_point.id),
                "relationship_type": "CONFIRMED",
                "time_delta_seconds": 0,
                "impact_direction": "POSITIVE",
                "weight_applied": 20.0,
                "description": f"Backup payload verified with SHA-256 ({recovery_point.sha256[:16]}...) and RESTORE VERIFYONLY CHECKSUM.",
                "metadata": {"sha256": recovery_point.sha256}
            }
            positive_indicators.append(pos_item)
            evidence_records.append(pos_item)
        elif recovery_point.integrity_status == "FAILED":
            neg_item = {
                "evidence_source": "MODULE_1_BACKUP",
                "source_record_id": str(recovery_point.backup_id or recovery_point.id),
                "relationship_type": "CONFIRMED",
                "time_delta_seconds": 0,
                "impact_direction": "NEGATIVE",
                "weight_applied": -50.0,
                "description": "Backup failed cryptographic or SQL Server page checksum verification.",
                "metadata": {"integrity_status": "FAILED"}
            }
            negative_indicators.append(neg_item)
            evidence_records.append(neg_item)

        if recovery_point.retention_mode in ("COMPLIANCE", "GOVERNANCE"):
            worm_item = {
                "evidence_source": "MODULE_1_BACKUP",
                "source_record_id": str(recovery_point.backup_id or recovery_point.id),
                "relationship_type": "CONFIRMED",
                "time_delta_seconds": 0,
                "impact_direction": "POSITIVE",
                "weight_applied": 15.0,
                "description": f"Immutable S3 Object Lock active in {recovery_point.retention_mode} mode until {recovery_point.retention_until}.",
                "metadata": {"version_id": recovery_point.storage_version_id, "mode": recovery_point.retention_mode}
            }
            positive_indicators.append(worm_item)
            evidence_records.append(worm_item)

        # ---------------------------------------------------------------------
        # 2. Module 2: Security Events & Incidents Proximity
        # ---------------------------------------------------------------------
        # Scan events up to 72 hours before the recovery point, or 24 hours after
        window_start = rp_time - timedelta(hours=72)
        window_end = rp_time + timedelta(hours=24)

        events = self.db.query(SecurityEvent).filter(
            SecurityEvent.server_name == server_name,
            SecurityEvent.event_timestamp >= window_start,
            SecurityEvent.event_timestamp <= window_end,
            (SecurityEvent.database_name == db_name) | (SecurityEvent.database_name == "master") | (SecurityEvent.database_name.is_(None))
        ).order_by(SecurityEvent.event_timestamp.asc()).all()

        for ev in events:
            ev_time = ev.event_timestamp
            if ev_time.tzinfo is None:
                ev_time = ev_time.replace(tzinfo=timezone.utc)
            delta_sec = int((ev_time - rp_time).total_seconds())

            # Events occurring BEFORE or AT the recovery point directly affect the backup's internal state
            if delta_sec <= 0:
                if ev.event_type == "ROLE_MEMBER_CHANGE" and ev.severity in ("CRITICAL", "HIGH"):
                    item = {
                        "evidence_source": "MODULE_2_EVENT",
                        "source_record_id": str(ev.id),
                        "relationship_type": "CONFIRMED",
                        "time_delta_seconds": delta_sec,
                        "impact_direction": "NEGATIVE",
                        "weight_applied": -40.0,
                        "description": f"Role membership escalation '{ev.action}' by '{ev.principal_name}' occurred {abs(delta_sec)}s before recovery point.",
                        "metadata": {"event_type": ev.event_type, "severity": ev.severity}
                    }
                    negative_indicators.append(item)
                    evidence_records.append(item)

                elif ev.event_type == "AUDIT_TAMPERING":
                    item = {
                        "evidence_source": "MODULE_2_EVENT",
                        "source_record_id": str(ev.id),
                        "relationship_type": "CONFIRMED",
                        "time_delta_seconds": delta_sec,
                        "impact_direction": "NEGATIVE",
                        "weight_applied": -40.0,
                        "description": f"Audit tampering / disablement attempt by '{ev.principal_name}' occurred prior to recovery point.",
                        "metadata": {"event_type": ev.event_type}
                    }
                    negative_indicators.append(item)
                    evidence_records.append(item)

                elif ev.event_type == "SCHEMA_MUTATION" and ev.severity in ("HIGH", "CRITICAL"):
                    item = {
                        "evidence_source": "MODULE_2_EVENT",
                        "source_record_id": str(ev.id),
                        "relationship_type": "CONFIRMED",
                        "time_delta_seconds": delta_sec,
                        "impact_direction": "NEGATIVE",
                        "weight_applied": -30.0,
                        "description": f"High-severity DDL mutation on '{ev.target_object}' by '{ev.principal_name}' preceded recovery point.",
                        "metadata": {"target": ev.target_object}
                    }
                    negative_indicators.append(item)
                    evidence_records.append(item)

            else:
                # Events occurring AFTER the recovery point:
                # CRITICAL AUDIT FIX: A security event occurring after a backup must NOT automatically increase trust.
                # In modern multi-stage intrusions, attackers frequently establish persistence, dormant backdoors,
                # or rogue accounts days or weeks before detection or destructive payloads.
                # Proximity to an intrusion represents an INCIDENT HAZARD WINDOW, NOT safety.
                if ev.event_type in ("ROLE_MEMBER_CHANGE", "AUDIT_TAMPERING", "SCHEMA_MUTATION") and ev.severity in ("CRITICAL", "HIGH"):
                    item = {
                        "evidence_source": "MODULE_2_EVENT",
                        "source_record_id": str(ev.id),
                        "relationship_type": "TEMPORAL_PROXIMITY",
                        "time_delta_seconds": delta_sec,
                        "impact_direction": "UNCERTAINTY",
                        "weight_applied": -10.0,
                        "description": (
                            f"Incident proximity hazard: High-severity event '{ev.event_type}' on '{ev.target_object or ev.principal_name}' "
                            f"occurred {delta_sec}s after this recovery point. Initial intrusion start time remains unverified; "
                            f"detection lag may mask pre-backup persistence. Sandbox forensic validation required."
                        ),
                        "metadata": {"event_id": str(ev.id), "event_type": ev.event_type, "severity": ev.severity}
                    }
                    uncertainty_factors.append(item)
                    evidence_records.append(item)

        # ---------------------------------------------------------------------
        # 3. Module 2: Monitoring Health Gaps
        # ---------------------------------------------------------------------
        # Check for telemetry collection gaps directly impacting the recovery window (within 2 hours)
        gap_alerts = self.db.query(SecurityAlert).join(SecuritySource).filter(
            SecuritySource.server_name == server_name,
            SecurityAlert.rule.has(rule_id="RULE_010_COLLECTION_GAP"),
            SecurityAlert.detection_timestamp >= rp_time - timedelta(hours=2),
            SecurityAlert.detection_timestamp <= rp_time + timedelta(hours=1)
        ).all()

        for ga in gap_alerts:
            is_blindness = (ga.severity in ("CRITICAL", "HIGH"))
            blindness_suffix = " Telemetry blindness present." if is_blindness else ""
            gap_item = {
                "evidence_source": "MONITORING_HEALTH",
                "source_record_id": str(ga.id),
                "relationship_type": "PROBABLE",
                "time_delta_seconds": int((to_utc(ga.detection_timestamp) - rp_time).total_seconds()),
                "impact_direction": "UNCERTAINTY",
                "weight_applied": -25.0,
                "description": f"Monitoring telemetry gap detected around recovery window: '{ga.title}'.{blindness_suffix}",
                "metadata": {"alert_id": str(ga.id), "severity": ga.severity}
            }
            missing_telemetry.append(gap_item)
            uncertainty_factors.append(gap_item)
            evidence_records.append(gap_item)

        # ---------------------------------------------------------------------
        # 4. Module 3: Forensic Baselines and Findings
        # ---------------------------------------------------------------------
        # Find closest baseline prior to or at recovery point
        closest_baseline = self.db.query(ForensicBaseline).filter(
            ForensicBaseline.database_name == db_name,
            ForensicBaseline.captured_at <= rp_time
        ).order_by(ForensicBaseline.captured_at.desc()).first()

        if closest_baseline:
            # Check investigations involving this baseline
            findings = self.db.query(ForensicFinding).join(ForensicInvestigation).filter(
                (ForensicInvestigation.target_baseline_id == closest_baseline.id) |
                (ForensicInvestigation.ref_baseline_id == closest_baseline.id)
            ).all()

            critical_findings = [f for f in findings if f.severity == "CRITICAL"]
            encrypted_findings = [f for f in findings if f.finding_type == "UNOBSERVABLE_ENCRYPTED"]

            if critical_findings:
                for cf in critical_findings:
                    item = {
                        "evidence_source": "MODULE_3_FINDING",
                        "source_record_id": str(cf.id),
                        "relationship_type": "CONFIRMED",
                        "time_delta_seconds": int((to_utc(closest_baseline.captured_at) - rp_time).total_seconds()),
                        "impact_direction": "NEGATIVE",
                        "weight_applied": -45.0,
                        "description": f"Forensic investigation confirmed critical privilege drift: {cf.explanation}",
                        "metadata": {"finding_type": cf.finding_type, "entity": cf.entity_name}
                    }
                    negative_indicators.append(item)
                    evidence_records.append(item)

            if encrypted_findings:
                for ef in encrypted_findings:
                    item = {
                        "evidence_source": "MODULE_3_FINDING",
                        "source_record_id": str(ef.id),
                        "relationship_type": "CONFIRMED",
                        "time_delta_seconds": 0,
                        "impact_direction": "UNCERTAINTY",
                        "weight_applied": -30.0,
                        "description": f"Unobservable encrypted module planted: {ef.explanation}",
                        "metadata": {"entity": ef.entity_name}
                    }
                    uncertainty_factors.append(item)
                    evidence_records.append(item)

            if not critical_findings and not encrypted_findings and len(findings) == 0:
                pos_base = {
                    "evidence_source": "MODULE_3_BASELINE",
                    "source_record_id": str(closest_baseline.id),
                    "relationship_type": "CONFIRMED",
                    "time_delta_seconds": int((to_utc(closest_baseline.captured_at) - rp_time).total_seconds()),
                    "impact_direction": "POSITIVE",
                    "weight_applied": 25.0,
                    "description": f"Clean Module 3 forensic baseline '{closest_baseline.baseline_name}' matches state at recovery point.",
                    "metadata": {"baseline_id": str(closest_baseline.id)}
                }
                positive_indicators.append(pos_base)
                evidence_records.append(pos_base)
        else:
            uncert_item = {
                "evidence_source": "MODULE_3_BASELINE",
                "source_record_id": "NONE",
                "relationship_type": "UNKNOWN",
                "time_delta_seconds": 0,
                "impact_direction": "UNCERTAINTY",
                "weight_applied": -15.0,
                "description": "No Module 3 forensic baseline snapshot available prior to recovery point. Schema state unverified.",
                "metadata": {}
            }
            uncertainty_factors.append(uncert_item)

        return {
            "positive_indicators": positive_indicators,
            "negative_indicators": negative_indicators,
            "missing_telemetry": missing_telemetry,
            "uncertainty_factors": uncertainty_factors,
            "evidence_records": evidence_records
        }
