"""
SQL-TRUST Security Detection Rule Engine
Module 2: Security Monitoring Engine
Implements 10 explainable, rule-based detection routines with configurable thresholds and alert deduplication.
"""
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select, func, and_

from backend.models.security import (
    DetectionRule,
    SecurityEvent,
    SecurityAlert,
    AlertStatusHistory,
    alert_event_associations
)

DEFAULT_RULES = [
    {
        "rule_id": "RULE_001_FAILED_LOGINS",
        "rule_name": "Multiple Failed Logins (Brute-Force Detection)",
        "description": "Detects repeated authentication failures from the same principal or client within a time window.",
        "condition_type": "THRESHOLD",
        "threshold_value": 3,
        "time_window_seconds": 300,
        "severity": "HIGH",
        "is_enabled": True
    },
    {
        "rule_id": "RULE_002_NEW_PRIVILEGED_LOGIN",
        "rule_name": "New Privileged Login Creation",
        "description": "Detects creation of a new login followed by assignment of administrative privileges.",
        "condition_type": "SEQUENCE",
        "threshold_value": 1,
        "time_window_seconds": 3600,
        "severity": "CRITICAL",
        "is_enabled": True
    },
    {
        "rule_id": "RULE_003_SYSADMIN_CHANGE",
        "rule_name": "Sysadmin Role Membership Mutation",
        "description": "Detects addition or removal of a principal from the high-privilege sysadmin fixed server role.",
        "condition_type": "STATE_CHANGE",
        "threshold_value": 1,
        "time_window_seconds": 60,
        "severity": "CRITICAL",
        "is_enabled": True
    },
    {
        "rule_id": "RULE_004_DATABASE_ROLE_ESCALATION",
        "rule_name": "Database Role Privilege Escalation",
        "description": "Detects assignment of administrative database roles such as db_owner or db_securityadmin.",
        "condition_type": "STATE_CHANGE",
        "threshold_value": 1,
        "time_window_seconds": 60,
        "severity": "HIGH",
        "is_enabled": True
    },
    {
        "rule_id": "RULE_005_PERMISSION_CHANGE",
        "rule_name": "Sensitive Permission Grant/Revoke",
        "description": "Detects sensitive GRANT, DENY or REVOKE statements granting control or schema modification rights.",
        "condition_type": "STATE_CHANGE",
        "threshold_value": 1,
        "time_window_seconds": 60,
        "severity": "MEDIUM",
        "is_enabled": True
    },
    {
        "rule_id": "RULE_006_PRINCIPAL_DELETION",
        "rule_name": "Security Principal Deletion",
        "description": "Detects DROP LOGIN or DROP USER commands which may indicate defense evasion or cover-up.",
        "condition_type": "STATE_CHANGE",
        "threshold_value": 1,
        "time_window_seconds": 60,
        "severity": "HIGH",
        "is_enabled": True
    },
    {
        "rule_id": "RULE_007_SCHEMA_MUTATION",
        "rule_name": "Suspicious Schema Object Deletion or Mutation",
        "description": "Detects DROP or destructive ALTER commands executed on database tables, views or procedures.",
        "condition_type": "STATE_CHANGE",
        "threshold_value": 1,
        "time_window_seconds": 60,
        "severity": "HIGH",
        "is_enabled": True
    },
    {
        "rule_id": "RULE_008_AUDIT_TAMPERING",
        "rule_name": "Audit Configuration Tampering",
        "description": "Detects attempts to disable, alter or drop SQL Server Audit or Audit Specifications.",
        "condition_type": "STATE_CHANGE",
        "threshold_value": 1,
        "time_window_seconds": 60,
        "severity": "CRITICAL",
        "is_enabled": True
    },
    {
        "rule_id": "RULE_009_XE_INTERRUPTION",
        "rule_name": "Extended Events Interruption",
        "description": "Detects unauthorized stopping, modification or deletion of the Extended Events telemetry session.",
        "condition_type": "STATE_CHANGE",
        "threshold_value": 1,
        "time_window_seconds": 60,
        "severity": "CRITICAL",
        "is_enabled": True
    },
    {
        "rule_id": "RULE_010_COLLECTION_GAP",
        "rule_name": "Audit Collection Lag or Telemetry Gap",
        "description": "Detects significant gaps in telemetry collection indicating collector disruption or logging failure.",
        "condition_type": "GAP",
        "threshold_value": 180,  # 180 seconds threshold
        "time_window_seconds": 300,
        "severity": "HIGH",
        "is_enabled": True
    }
]


def ensure_default_rules(db: Session) -> Dict[str, DetectionRule]:
    """Ensures all 10 default detection rules exist in the control database."""
    rules_by_id = {}
    for r_def in DEFAULT_RULES:
        rule = db.query(DetectionRule).filter_by(rule_id=r_def["rule_id"]).first()
        if not rule:
            rule = DetectionRule(**r_def)
            db.add(rule)
            db.commit()
            db.refresh(rule)
        rules_by_id[rule.rule_id] = rule
    return rules_by_id


class RuleEngine:
    """
    Evaluates new normalized security events against active detection rules.
    Emits deduplicated alerts with complete diagnostic explanation and event linking.
    """

    def __init__(self, db: Session):
        self.db = db
        self.rules = ensure_default_rules(db)

    def evaluate_events(self, events: List[SecurityEvent], source_id: str) -> List[SecurityAlert]:
        """Evaluates a batch of newly ingested security events."""
        generated_alerts = []
        if not events:
            return generated_alerts

        # Evaluate rules sequentially
        self._evaluate_failed_logins(events, source_id, generated_alerts)
        self._evaluate_sysadmin_changes(events, source_id, generated_alerts)
        self._evaluate_privileged_login_creation(events, source_id, generated_alerts)
        self._evaluate_role_escalations(events, source_id, generated_alerts)
        self._evaluate_permission_changes(events, source_id, generated_alerts)
        self._evaluate_principal_deletions(events, source_id, generated_alerts)
        self._evaluate_schema_mutations(events, source_id, generated_alerts)
        self._evaluate_audit_tampering(events, source_id, generated_alerts)
        self._evaluate_xe_interruptions(events, source_id, generated_alerts)

        return generated_alerts

    def _create_or_deduplicate_alert(
        self,
        source_id: str,
        rule: DetectionRule,
        title: str,
        description: str,
        severity: str,
        explanation: str,
        principal_name: Optional[str],
        target_object: Optional[str],
        related_events: List[SecurityEvent],
        confidence_score: float = 1.0
    ) -> SecurityAlert:
        """
        Deduplicates against active alerts for the same rule and principal in NEW/ACKNOWLEDGED status.
        If an active alert exists, appends events; otherwise creates a new alert.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=rule.time_window_seconds)

        existing_alert = self.db.query(SecurityAlert).filter(
            SecurityAlert.source_id == source_id,
            SecurityAlert.rule_id == rule.id,
            SecurityAlert.principal_name == principal_name,
            SecurityAlert.status.in_(["NEW", "ACKNOWLEDGED", "INVESTIGATING"]),
            SecurityAlert.updated_at >= cutoff
        ).first()

        if existing_alert:
            # Append new events
            existing_event_ids = {e.id for e in existing_alert.related_events}
            for ev in related_events:
                if ev.id not in existing_event_ids:
                    existing_alert.related_events.append(ev)
            existing_alert.related_event_count = len(existing_alert.related_events)
            existing_alert.updated_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(existing_alert)
            return existing_alert

        # Create fresh alert
        new_alert = SecurityAlert(
            source_id=source_id,
            rule_id=rule.id,
            title=title,
            description=description,
            severity=severity or rule.severity,
            status="NEW",
            detection_timestamp=datetime.now(timezone.utc),
            principal_name=principal_name,
            target_object=target_object,
            explanation=explanation,
            confidence_score=confidence_score,
            related_event_count=len(related_events)
        )
        new_alert.related_events.extend(related_events)
        self.db.add(new_alert)
        self.db.commit()
        self.db.refresh(new_alert)

        # Record initial status history
        history = AlertStatusHistory(
            alert_id=new_alert.id,
            previous_status="NONE",
            new_status="NEW",
            changed_by="RuleEngine",
            comment="Alert created by automated detection rule."
        )
        self.db.add(history)
        self.db.commit()

        return new_alert

    def _evaluate_failed_logins(self, events: List[SecurityEvent], source_id: str, out_alerts: List[SecurityAlert]):
        rule = self.rules.get("RULE_001_FAILED_LOGINS")
        if not rule or not rule.is_enabled:
            return

        failed_events = [e for e in events if e.event_type == "LOGIN_FAILED" or (e.action == "LGFL" and not e.success)]
        if not failed_events:
            return

        # Group by principal
        by_principal = {}
        for ev in failed_events:
            p = ev.principal_name or ev.client_ip or "UNKNOWN"
            by_principal.setdefault(p, []).append(ev)

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=rule.time_window_seconds)

        for principal, evs in by_principal.items():
            # Query recent historical failed logins within the sliding time window
            recent_db_events = self.db.query(SecurityEvent).filter(
                SecurityEvent.source_id == source_id,
                (SecurityEvent.principal_name == principal) | (SecurityEvent.client_ip == principal),
                (SecurityEvent.event_type == "LOGIN_FAILED") | ((SecurityEvent.action == "LGFL") & (SecurityEvent.success == False)),
                SecurityEvent.event_timestamp >= cutoff
            ).all()

            # Merge unique events
            combined = {e.id: e for e in recent_db_events}
            for e in evs:
                combined[e.id] = e

            all_evs = list(combined.values())
            if len(all_evs) >= rule.threshold_value:
                alert = self._create_or_deduplicate_alert(
                    source_id=source_id,
                    rule=rule,
                    title=f"Multiple Authentication Failures for '{principal}'",
                    description=f"Detected {len(all_evs)} failed login attempts within monitoring window.",
                    severity=rule.severity,
                    explanation=f"Threshold of {rule.threshold_value} failed attempts exceeded. Possible password brute-force or credential spraying attempt.",
                    principal_name=principal,
                    target_object=None,
                    related_events=all_evs,
                    confidence_score=0.95
                )
                out_alerts.append(alert)

    def _evaluate_sysadmin_changes(self, events: List[SecurityEvent], source_id: str, out_alerts: List[SecurityAlert]):
        rule = self.rules.get("RULE_003_SYSADMIN_CHANGE")
        if not rule or not rule.is_enabled:
            return

        for ev in events:
            raw = (ev.raw_payload or "").upper()
            if ev.event_type == "SYSADMIN_MEMBERSHIP_CHANGE" or ("SYSADMIN" in raw and ("ADD" in raw or "DROP" in raw or "ALTER" in raw)):
                alert = self._create_or_deduplicate_alert(
                    source_id=source_id,
                    rule=rule,
                    title="Sysadmin Server Role Membership Mutated",
                    description=f"Principal '{ev.principal_name}' modified sysadmin role membership.",
                    severity=rule.severity,
                    explanation="Direct modification of the sysadmin fixed server role detected. Grants total control over the SQL Server instance.",
                    principal_name=ev.principal_name,
                    target_object="sysadmin",
                    related_events=[ev],
                    confidence_score=1.0
                )
                out_alerts.append(alert)

    def _evaluate_privileged_login_creation(self, events: List[SecurityEvent], source_id: str, out_alerts: List[SecurityAlert]):
        rule = self.rules.get("RULE_002_NEW_PRIVILEGED_LOGIN")
        if not rule or not rule.is_enabled:
            return

        for ev in events:
            raw = (ev.raw_payload or "").upper()
            # Pattern A: Combined CREATE LOGIN with server admin role specification
            if "CREATE LOGIN" in raw and ("SYSADMIN" in raw or "SECURITYADMIN" in raw or "SERVERADMIN" in raw):
                alert = self._create_or_deduplicate_alert(
                    source_id=source_id,
                    rule=rule,
                    title=f"New High-Privilege Login Created: '{ev.target_object or 'Unknown'}'",
                    description=f"Principal '{ev.principal_name}' created a privileged login.",
                    severity=rule.severity,
                    explanation="A new login was created with administrative server roles. Requires immediate authorization review.",
                    principal_name=ev.principal_name,
                    target_object=ev.target_object,
                    related_events=[ev],
                    confidence_score=0.9
                )
                out_alerts.append(alert)
                continue

            # Pattern B: Role grant to recently created login (sequence correlation)
            if ("ALTER SERVER ROLE" in raw or "SP_ADDSRVROLEMEMBER" in raw) and ("ADD MEMBER" in raw or "SP_ADDSRVROLEMEMBER" in raw):
                if "SYSADMIN" in raw or "SECURITYADMIN" in raw or "SERVERADMIN" in raw:
                    member_name = ev.target_object
                    if member_name:
                        cutoff = datetime.now(timezone.utc) - timedelta(seconds=rule.time_window_seconds)
                        recent_creation = self.db.query(SecurityEvent).filter(
                            SecurityEvent.source_id == source_id,
                            SecurityEvent.target_object == member_name,
                            SecurityEvent.event_timestamp >= cutoff,
                            (SecurityEvent.action == "CR") | (SecurityEvent.raw_payload.like("%CREATE LOGIN%"))
                        ).first()
                        if recent_creation:
                            alert = self._create_or_deduplicate_alert(
                                source_id=source_id,
                                rule=rule,
                                title=f"New High-Privilege Login Created: '{member_name}'",
                                description=f"Principal '{ev.principal_name}' granted server admin role to newly created login '{member_name}'.",
                                severity=rule.severity,
                                explanation="A newly created login was immediately promoted to an administrative server role.",
                                principal_name=ev.principal_name,
                                target_object=member_name,
                                related_events=[recent_creation, ev],
                                confidence_score=0.95
                            )
                            out_alerts.append(alert)

    def _evaluate_role_escalations(self, events: List[SecurityEvent], source_id: str, out_alerts: List[SecurityAlert]):
        rule = self.rules.get("RULE_004_DATABASE_ROLE_ESCALATION")
        if not rule or not rule.is_enabled:
            return

        for ev in events:
            raw = (ev.raw_payload or "").upper()
            if "DB_OWNER" in raw or "DB_SECURITYADMIN" in raw:
                alert = self._create_or_deduplicate_alert(
                    source_id=source_id,
                    rule=rule,
                    title="Database Role Escalation to db_owner",
                    description=f"Principal '{ev.principal_name}' granted high database privileges in '{ev.database_name}'.",
                    severity=rule.severity,
                    explanation="Assignment of db_owner or db_securityadmin grants unconstrained database object access and bypass capabilities.",
                    principal_name=ev.principal_name,
                    target_object=ev.target_object or ev.database_name,
                    related_events=[ev],
                    confidence_score=0.85
                )
                out_alerts.append(alert)

    def _evaluate_permission_changes(self, events: List[SecurityEvent], source_id: str, out_alerts: List[SecurityAlert]):
        rule = self.rules.get("RULE_005_PERMISSION_CHANGE")
        if not rule or not rule.is_enabled:
            return

        for ev in events:
            if ev.action in ("G", "D", "R") or "PERMISSION" in ev.event_type:
                raw = (ev.raw_payload or "").upper()
                if "CONTROL" in raw or "ALTER" in raw or "TAKE OWNERSHIP" in raw:
                    alert = self._create_or_deduplicate_alert(
                        source_id=source_id,
                        rule=rule,
                        title=f"High-Impact Permission Mutation: {ev.action}",
                        description=f"Sensitive permission grant/revoke executed by '{ev.principal_name}'.",
                        severity=rule.severity,
                        explanation=f"Explicit permission statement executed: {ev.target_object or ''}",
                        principal_name=ev.principal_name,
                        target_object=ev.target_object,
                        related_events=[ev],
                        confidence_score=0.80
                    )
                    out_alerts.append(alert)

    def _evaluate_principal_deletions(self, events: List[SecurityEvent], source_id: str, out_alerts: List[SecurityAlert]):
        rule = self.rules.get("RULE_006_PRINCIPAL_DELETION")
        if not rule or not rule.is_enabled:
            return

        for ev in events:
            raw = (ev.raw_payload or "").upper()
            if "DROP LOGIN" in raw or "DROP USER" in raw:
                alert = self._create_or_deduplicate_alert(
                    source_id=source_id,
                    rule=rule,
                    title=f"Security Principal Deletion: '{ev.target_object or 'Unknown'}'",
                    description=f"Principal deletion executed by '{ev.principal_name}'.",
                    severity=rule.severity,
                    explanation="Removal of security principals can indicate account deletion to conceal unauthorized actions or disrupt administrative access.",
                    principal_name=ev.principal_name,
                    target_object=ev.target_object,
                    related_events=[ev],
                    confidence_score=0.85
                )
                out_alerts.append(alert)

    def _evaluate_schema_mutations(self, events: List[SecurityEvent], source_id: str, out_alerts: List[SecurityAlert]):
        rule = self.rules.get("RULE_007_SCHEMA_MUTATION")
        if not rule or not rule.is_enabled:
            return

        for ev in events:
            if ev.action == "DR" or "DROPPED" in ev.event_type or "ALTERED" in ev.event_type:
                raw = (ev.raw_payload or "").upper()
                if "DROP TABLE" in raw or "DROP PROCEDURE" in raw or "DROP DATABASE" in raw:
                    alert = self._create_or_deduplicate_alert(
                        source_id=source_id,
                        rule=rule,
                        title=f"Destructive DDL Command Executed: '{ev.target_object or 'Object'}'",
                        description=f"Destructive schema alteration by '{ev.principal_name}' in '{ev.database_name}'.",
                        severity=rule.severity,
                        explanation="Drop table or database DDL statement detected. May indicate data destruction or ransomware sabotage.",
                        principal_name=ev.principal_name,
                        target_object=ev.target_object,
                        related_events=[ev],
                        confidence_score=0.9
                    )
                    out_alerts.append(alert)

    def _evaluate_audit_tampering(self, events: List[SecurityEvent], source_id: str, out_alerts: List[SecurityAlert]):
        rule = self.rules.get("RULE_008_AUDIT_TAMPERING")
        if not rule or not rule.is_enabled:
            return

        for ev in events:
            raw = (ev.raw_payload or "").upper()
            if ev.event_type == "AUDIT_CONFIGURATION_CHANGE" or ("SERVER AUDIT" in raw and ("STATE = OFF" in raw or "DROP" in raw)):
                alert = self._create_or_deduplicate_alert(
                    source_id=source_id,
                    rule=rule,
                    title="SQL Server Audit Tampering Detected",
                    description=f"Principal '{ev.principal_name}' disabled or altered the Server Audit configuration.",
                    severity=rule.severity,
                    explanation="SQL Server Audit state was disabled or modified. Disabling audit telemetry is a common adversary technique prior to lateral movement or data exfiltration.",
                    principal_name=ev.principal_name,
                    target_object="SQLTrust_ServerAudit",
                    related_events=[ev],
                    confidence_score=1.0
                )
                out_alerts.append(alert)

    def _evaluate_xe_interruptions(self, events: List[SecurityEvent], source_id: str, out_alerts: List[SecurityAlert]):
        rule = self.rules.get("RULE_009_XE_INTERRUPTION")
        if not rule or not rule.is_enabled:
            return

        for ev in events:
            raw = (ev.raw_payload or "").upper()
            if ev.event_type == "EXTENDED_EVENTS_INTERRUPTION" or ("EVENT SESSION" in raw and ("STATE = STOP" in raw or "DROP" in raw)):
                alert = self._create_or_deduplicate_alert(
                    source_id=source_id,
                    rule=rule,
                    title="Extended Events Telemetry Session Interrupted",
                    description=f"Principal '{ev.principal_name}' stopped or dropped the security event session.",
                    severity=rule.severity,
                    explanation="Extended Events session stopped. Blind spots in telemetry indicate possible defense evasion or tampering.",
                    principal_name=ev.principal_name,
                    target_object="SQLTrust_Security_XE",
                    related_events=[ev],
                    confidence_score=1.0
                )
                out_alerts.append(alert)

    def evaluate_collection_gap(
        self,
        source_id: str,
        lag_seconds: int,
        error_message: Optional[str] = None
    ) -> Optional[SecurityAlert]:
        """
        Evaluates RULE_010_COLLECTION_GAP based on collector latency or telemetry disruption.
        """
        rule = self.rules.get("RULE_010_COLLECTION_GAP")
        if not rule or not rule.is_enabled:
            return None

        if lag_seconds >= rule.threshold_value or error_message:
            explanation = (
                f"Telemetry collection lag ({lag_seconds}s) exceeded critical threshold ({rule.threshold_value}s). "
                f"Collector health is compromised. Missing telemetry creates forensic blind spots."
            )
            if error_message:
                explanation += f" Error details: {error_message}"

            alert = self._create_or_deduplicate_alert(
                source_id=source_id,
                rule=rule,
                title="Critical Telemetry Collection Gap Detected",
                description=f"Collector lag reached {lag_seconds}s (Threshold: {rule.threshold_value}s).",
                severity=rule.severity,
                explanation=explanation,
                principal_name="TelemetrySubsystem",
                target_object="CollectorPipeline",
                related_events=[],
                confidence_score=0.95
            )
            return alert
        return None
