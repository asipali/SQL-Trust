"""
Unit and integration tests for all 10 SQL-TRUST detection rules.
"""

import uuid
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models.security import (
    SecuritySource,
    SecurityEvent,
    SecurityAlert,
    DetectionRule
)
from backend.services.security.rule_engine import RuleEngine
from backend.services.security.normalizer import compute_event_fingerprint


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def telemetry_source(db_session: Session):
    source = db_session.query(SecuritySource).first()
    if not source:
        source = SecuritySource(
            id=str(uuid.uuid4()),
            source_name="PyTest_AuditSource",
            server_name="localhost\\SQLEXPRESS",
            source_type="HYBRID",
            audit_target_path="D:\\Desktop\\HackShift\\SQL Trust\\data\\audit\\",
            xe_target_path="D:\\Desktop\\HackShift\\SQL Trust\\data\\extended_events\\",
            is_active=True
        )
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)
    return source


def make_event(source_id: str, event_type: str, action: str, principal: str, target: str = None, payload: str = "", success: bool = True):
    now = datetime.now(timezone.utc)
    seq = uuid.uuid4().hex[:8]
    source_ev_id = f"test_sqlaudit:100:{seq}"
    fp = compute_event_fingerprint(
        server_name="localhost\\SQLEXPRESS",
        event_source="SQL_AUDIT",
        source_file="SQLTrust_ServerAudit.sqlaudit",
        event_timestamp=now,
        action=action,
        principal_name=principal,
        session_id=55,
        statement=payload,
        source_event_id=source_ev_id
    )
    return SecurityEvent(
        source_id=source_id,
        event_source="SQL_AUDIT",
        source_file="SQLTrust_ServerAudit.sqlaudit",
        source_event_id=source_ev_id,
        event_fingerprint=fp,
        event_timestamp=now,
        collection_timestamp=now,
        server_name="localhost\\SQLEXPRESS",
        database_name="SQLTrust_Lab",
        principal_name=principal,
        session_id=55,
        client_ip="127.0.0.1",
        client_app="PyTestSuite",
        event_type=event_type,
        action=action,
        success=success,
        target_object=target,
        severity="MEDIUM",
        raw_payload=payload,
        evidence_reference="local://data/audit/SQLTrust_ServerAudit.sqlaudit",
        integrity_status="VERIFIED"
    )


def test_rule_001_failed_logins(db_session, telemetry_source):
    engine = RuleEngine(db_session)
    now = datetime.now(timezone.utc)
    evs = [
        make_event(telemetry_source.id, "LOGIN_FAILED", "LGFL", "test_hacker", payload="Failed login", success=False),
        make_event(telemetry_source.id, "LOGIN_FAILED", "LGFL", "test_hacker", payload="Failed login", success=False),
        make_event(telemetry_source.id, "LOGIN_FAILED", "LGFL", "test_hacker", payload="Failed login", success=False),
    ]
    db_session.add_all(evs)
    db_session.commit()
    alerts = engine.evaluate_events(evs, telemetry_source.id)
    r1 = [a for a in alerts if a.rule.rule_id == "RULE_001_FAILED_LOGINS"]
    assert len(r1) == 1
    assert r1[0].severity == "HIGH"


def test_rule_002_new_privileged_login(db_session, telemetry_source):
    engine = RuleEngine(db_session)
    ev = make_event(telemetry_source.id, "PRINCIPAL_CREATION", "CR", "sa", "new_admin", "CREATE LOGIN new_admin WITH PASSWORD = '***'; ALTER SERVER ROLE sysadmin ADD MEMBER new_admin;")
    db_session.add(ev)
    db_session.commit()
    alerts = engine.evaluate_events([ev], telemetry_source.id)
    r2 = [a for a in alerts if a.rule.rule_id == "RULE_002_NEW_PRIVILEGED_LOGIN"]
    assert len(r2) == 1
    assert r2[0].severity == "CRITICAL"


def test_rule_003_sysadmin_change(db_session, telemetry_source):
    engine = RuleEngine(db_session)
    ev = make_event(telemetry_source.id, "SYSADMIN_MEMBERSHIP_CHANGE", "AP", "sa", "sysadmin", "ALTER SERVER ROLE sysadmin ADD MEMBER rogue_user")
    db_session.add(ev)
    db_session.commit()
    alerts = engine.evaluate_events([ev], telemetry_source.id)
    r3 = [a for a in alerts if a.rule.rule_id == "RULE_003_SYSADMIN_CHANGE"]
    assert len(r3) == 1
    assert r3[0].severity == "CRITICAL"


def test_rule_004_database_role_escalation(db_session, telemetry_source):
    engine = RuleEngine(db_session)
    ev = make_event(telemetry_source.id, "ROLE_MEMBER_CHANGE", "AP", "dbo", "db_owner", "ALTER ROLE db_owner ADD MEMBER contractor")
    db_session.add(ev)
    db_session.commit()
    alerts = engine.evaluate_events([ev], telemetry_source.id)
    r4 = [a for a in alerts if a.rule.rule_id == "RULE_004_DATABASE_ROLE_ESCALATION"]
    assert len(r4) == 1
    assert r4[0].severity == "HIGH"


def test_rule_005_permission_change(db_session, telemetry_source):
    engine = RuleEngine(db_session)
    ev = make_event(telemetry_source.id, "PERMISSION_CHANGE", "G", "dbo", "AuditTable", "GRANT CONTROL ON AuditTable TO suspicious_user")
    db_session.add(ev)
    db_session.commit()
    alerts = engine.evaluate_events([ev], telemetry_source.id)
    r5 = [a for a in alerts if a.rule.rule_id == "RULE_005_PERMISSION_CHANGE"]
    assert len(r5) == 1
    assert r5[0].severity == "MEDIUM"


def test_rule_006_principal_deletion(db_session, telemetry_source):
    engine = RuleEngine(db_session)
    ev = make_event(telemetry_source.id, "PRINCIPAL_DELETION", "DR", "sa", "former_user", "DROP LOGIN former_user")
    db_session.add(ev)
    db_session.commit()
    alerts = engine.evaluate_events([ev], telemetry_source.id)
    r6 = [a for a in alerts if a.rule.rule_id == "RULE_006_PRINCIPAL_DELETION"]
    assert len(r6) == 1
    assert r6[0].severity == "HIGH"


def test_rule_007_schema_mutation(db_session, telemetry_source):
    engine = RuleEngine(db_session)
    ev = make_event(telemetry_source.id, "SCHEMA_CHANGE", "DR", "dbo", "SensitiveData", "DROP TABLE SensitiveData")
    db_session.add(ev)
    db_session.commit()
    alerts = engine.evaluate_events([ev], telemetry_source.id)
    r7 = [a for a in alerts if a.rule.rule_id == "RULE_007_SCHEMA_MUTATION"]
    assert len(r7) == 1
    assert r7[0].severity == "HIGH"


def test_rule_008_audit_tampering(db_session, telemetry_source):
    engine = RuleEngine(db_session)
    ev = make_event(telemetry_source.id, "AUDIT_CONFIGURATION_CHANGE", "AL", "intruder", "SQLTrust_ServerAudit", "ALTER SERVER AUDIT SQLTrust_ServerAudit WITH (STATE = OFF)")
    db_session.add(ev)
    db_session.commit()
    alerts = engine.evaluate_events([ev], telemetry_source.id)
    r8 = [a for a in alerts if a.rule.rule_id == "RULE_008_AUDIT_TAMPERING"]
    assert len(r8) == 1
    assert r8[0].severity == "CRITICAL"


def test_rule_009_xe_interruption(db_session, telemetry_source):
    engine = RuleEngine(db_session)
    ev = make_event(telemetry_source.id, "EXTENDED_EVENTS_INTERRUPTION", "AL", "intruder", "SQLTrust_Security_XE", "ALTER EVENT SESSION SQLTrust_Security_XE ON SERVER STATE = STOP")
    db_session.add(ev)
    db_session.commit()
    alerts = engine.evaluate_events([ev], telemetry_source.id)
    r9 = [a for a in alerts if a.rule.rule_id == "RULE_009_XE_INTERRUPTION"]
    assert len(r9) == 1
    assert r9[0].severity == "CRITICAL"


def test_rule_010_collection_gap(db_session, telemetry_source):
    engine = RuleEngine(db_session)
    alert = engine.evaluate_collection_gap(telemetry_source.id, lag_seconds=200, error_message="Collector timeout")
    assert alert is not None
    assert alert.rule.rule_id == "RULE_010_COLLECTION_GAP"
    assert alert.severity == "HIGH"
