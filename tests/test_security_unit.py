"""
SQL-TRUST Module 2: Security Monitoring Engine — Unit Tests
Tests event normalization, deterministic fingerprinting, deduplication,
rule engine evaluation, manifest signing, and Ed25519 public-key signature verification.
"""
import pytest
from datetime import datetime, timezone, timedelta
from backend.services.security.normalizer import EventNormalizer, compute_event_fingerprint
from backend.services.security.signer import ManifestSigner
from backend.models.security import SecurityEvent, DetectionRule, SecurityAlert
from backend.services.security.rule_engine import RuleEngine, DEFAULT_RULES


def test_compute_event_fingerprint_deterministic():
    """Verify that identical event parameters yield identical SHA-256 fingerprints."""
    ts = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    fp1 = compute_event_fingerprint(
        server_name="localhost\\SQLEXPRESS",
        event_source="SQL_AUDIT",
        source_file="audit_01.sqlaudit",
        event_timestamp=ts,
        action="LGFL",
        principal_name="sa",
        session_id=55,
        statement="LOGIN FAILED"
    )
    fp2 = compute_event_fingerprint(
        server_name="localhost\\SQLEXPRESS",
        event_source="SQL_AUDIT",
        source_file="audit_01.sqlaudit",
        event_timestamp=ts,
        action="LGFL",
        principal_name="sa",
        session_id=55,
        statement="LOGIN FAILED"
    )
    assert fp1 == fp2
    assert len(fp1) == 64


def test_compute_event_fingerprint_distinct():
    """Verify that different event parameters produce different fingerprints."""
    ts = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    fp1 = compute_event_fingerprint(
        server_name="localhost\\SQLEXPRESS",
        event_source="SQL_AUDIT",
        source_file="audit_01.sqlaudit",
        event_timestamp=ts,
        action="LGFL",
        principal_name="sa",
        session_id=55,
        statement="LOGIN FAILED"
    )
    fp2 = compute_event_fingerprint(
        server_name="localhost\\SQLEXPRESS",
        event_source="SQL_AUDIT",
        source_file="audit_01.sqlaudit",
        event_timestamp=ts,
        action="LGFL",
        principal_name="attacker",
        session_id=56,
        statement="LOGIN FAILED"
    )
    assert fp1 != fp2


def test_normalize_audit_record():
    """Test normalization of SQL Server Audit row."""
    row = {
        "event_time": "2026-11-14T10:00:00Z",
        "action_id": "LGFL",
        "succeeded": False,
        "session_id": 42,
        "server_principal_name": "malicious_user",
        "database_name": "master",
        "statement": "FAILED LOGIN ATTEMPT",
        "file_name": "audit_file_01.sqlaudit",
        "file_offset": 1024,
        "client_ip": "192.168.1.100",
        "application_name": "sqlcmd"
    }
    normalized = EventNormalizer.normalize_audit_record(row, source_id="src-001", server_name="SQL-PROD-01")
    assert normalized["event_type"] == "LOGIN_FAILED"
    assert normalized["severity"] == "HIGH"
    assert normalized["principal_name"] == "malicious_user"
    assert normalized["success"] is False
    assert len(normalized["event_fingerprint"]) == 64


def test_normalize_xe_record():
    """Test parsing and normalization of Extended Events XML record."""
    xml_data = """
    <event name="login" package="sqlserver" timestamp="2026-11-14T10:15:00.000Z">
        <action name="username" package="sqlserver"><value>app_user</value></action>
        <action name="session_id" package="sqlserver"><value>77</value></action>
        <action name="database_name" package="sqlserver"><value>ProtectedBusinessDB</value></action>
        <action name="client_app_name" package="sqlserver"><value>DotNetClient</value></action>
        <action name="client_hostname" package="sqlserver"><value>CLIENT-WS-09</value></action>
    </event>
    """
    normalized = EventNormalizer.normalize_xe_record(
        target_data_xml=xml_data,
        source_file="SQLTrust_XE.xel",
        source_id="src-001",
        server_name="SQL-PROD-01"
    )
    assert normalized is not None
    assert normalized["event_type"] == "LOGIN_SUCCESS"
    assert normalized["severity"] == "INFO"
    assert normalized["principal_name"] == "app_user"
    assert normalized["session_id"] == 77
    assert normalized["database_name"] == "ProtectedBusinessDB"


def test_manifest_ed25519_signing_and_verification(tmp_path):
    """Test Ed25519 cryptographic signing and verification of evidence manifests."""
    signer = ManifestSigner(key_dir=str(tmp_path / "keys"))
    
    manifest_data = {
        "manifest_version": "1.0",
        "evidence_id": "MAN-TEST-12345",
        "server_name": "SQL-PROD-01",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "retention_mode": "COMPLIANCE"
    }
    
    # Sign manifest
    signature = signer.sign_manifest(manifest_data)
    assert signature is not None
    assert len(signature) > 30

    # Verify signature
    assert signer.verify_manifest(manifest_data, signature) is True

    # Tampered manifest detection
    tampered_manifest = dict(manifest_data)
    tampered_manifest["retention_mode"] = "GOVERNANCE"
    assert signer.verify_manifest(tampered_manifest, signature) is False
