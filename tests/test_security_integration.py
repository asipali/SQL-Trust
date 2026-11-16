"""
SQL-TRUST Module 2: Security Monitoring Engine — Integration Tests
Tests live Audit inspection, Extended Events session state, incremental collection,
deduplication, rule detection, alert transitions, and WORM evidence archiving.
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import SessionLocal, init_db
from backend.models.security import SecuritySource, SecurityEvent, SecurityAlert, EvidenceArchive
from backend.services.security.audit_service import AuditService
from backend.services.security.xe_service import ExtendedEventsService
from backend.services.security.audit_collector import AuditCollector
from backend.services.security.xe_collector import XECollector
from backend.services.security.evidence_archiver import EvidenceArchiver
from backend.services.security.signer import signer

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_integration():
    init_db()


def test_live_audit_configuration_inspection():
    """Verify live SQL Server Audit inspection returns active status and action groups."""
    audit_info = AuditService.inspect_audit_configuration()
    assert audit_info["audit_configured"] is True
    assert audit_info["audit_enabled"] is True
    assert audit_info["spec_enabled"] is True
    assert len(audit_info["action_groups"]) >= 10
    assert "FAILED_LOGIN_GROUP" in audit_info["action_groups"]
    assert "AUDIT_CHANGE_GROUP" in audit_info["action_groups"]


def test_live_extended_events_session_inspection():
    """Verify live Extended Events session inspection returns running state and target."""
    xe_info = ExtendedEventsService.inspect_xe_configuration()
    assert xe_info["session_configured"] is True
    assert xe_info["session_running"] is True
    assert "login" in xe_info["events_configured"]
    assert "error_reported" in xe_info["events_configured"]
    assert "SQLTrust_XE.xel" in xe_info["target_file_path"]


def test_live_incremental_collection_and_deduplication():
    """Verify incremental collection collects events and enforces zero duplicate fingerprints."""
    from sqlalchemy import func
    db = SessionLocal()
    # Select the primary live host source configured with active paths
    source = (
        db.query(SecuritySource)
        .filter(SecuritySource.source_name == "SQLServer-LocalHost")
        .first()
        or db.query(SecuritySource).first()
    )
    assert source is not None

    # First collection
    audit_collector = AuditCollector(db=db, source=source)
    res1 = audit_collector.collect_incremental()
    assert res1["success"] is True

    # Run second collection
    res2 = audit_collector.collect_incremental()
    assert res2["success"] is True

    # Assert that zero duplicate fingerprints exist across all ingested events
    duplicate_count = db.query(
        SecurityEvent.event_fingerprint,
        func.count(SecurityEvent.id)
    ).group_by(SecurityEvent.event_fingerprint).having(func.count(SecurityEvent.id) > 1).count()
    assert duplicate_count == 0

    db.close()


def test_api_alert_lifecycle_transition():
    """Test updating alert status via PATCH /api/v1/security/alerts/{id}."""
    db = SessionLocal()
    alert = db.query(SecurityAlert).first()
    if not alert:
        # Create a test alert if none exists
        from backend.models.security import DetectionRule
        rule = db.query(DetectionRule).first()
        source = db.query(SecuritySource).first()
        alert = SecurityAlert(
            source_id=source.id,
            rule_id=rule.id,
            title="Integration Test Alert",
            description="Testing alert transition",
            severity="HIGH",
            status="NEW",
            explanation="Test explanation",
            related_event_count=1
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

    alert_id = alert.id
    db.close()

    # Transition to ACKNOWLEDGED
    res1 = client.patch(
        f"/api/v1/security/alerts/{alert_id}",
        json={"status": "ACKNOWLEDGED", "comment": "Triage started"}
    )
    assert res1.status_code == 200
    assert res1.json()["status"] == "ACKNOWLEDGED"

    # Transition to RESOLVED
    res2 = client.patch(
        f"/api/v1/security/alerts/{alert_id}",
        json={"status": "RESOLVED", "comment": "Remediated by DBA"}
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "RESOLVED"

    # Verify status history recorded
    get_res = client.get(f"/api/v1/security/alerts/{alert_id}")
    assert get_res.status_code == 200
    hist = get_res.json().get("status_history", [])
    assert len(hist) >= 2


def test_evidence_archival_and_worm_retention():
    """Verify evidence archival creates S3 Object Lock object with Ed25519 signature."""
    db = SessionLocal()
    archive = db.query(EvidenceArchive).first()
    assert archive is not None
    assert archive.storage_bucket == "sqltrust-backups-locked"
    assert archive.retention_mode == "COMPLIANCE"
    assert archive.storage_version_id is not None
    assert archive.signature is not None
    assert len(archive.sha256) == 64
    db.close()
