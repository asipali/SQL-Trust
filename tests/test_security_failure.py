"""
SQL-TRUST Module 2: Security Monitoring Engine — Failure & Edge Case Tests
Tests error handling, invalid inputs, duplicate prevention, tampered signatures,
and edge case resilience.
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import init_db
from backend.services.security.signer import signer
from backend.services.security.evidence_archiver import EvidenceArchiver

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_failures():
    init_db()


def test_invalid_source_id_404():
    """Verify requesting non-existent source returns 404."""
    res = client.get("/api/v1/security/sources/non-existent-source-uuid/audit")
    assert res.status_code == 404


def test_duplicate_source_registration_409():
    """Verify registering a source with an existing name returns 409 conflict."""
    # First get existing source name
    sources = client.get("/api/v1/security/sources").json()
    assert len(sources) > 0
    dup_name = sources[0]["source_name"]

    res = client.post("/api/v1/security/sources", json={
        "source_name": dup_name,
        "server_name": r"localhost\SQLEXPRESS"
    })
    assert res.status_code == 409


def test_invalid_alert_id_404():
    """Verify querying non-existent alert returns 404."""
    res = client.get("/api/v1/security/alerts/non-existent-alert-uuid")
    assert res.status_code == 404


def test_invalid_alert_status_transition_400():
    """Verify invalid alert status string returns 400 Bad Request."""
    alerts = client.get("/api/v1/security/alerts").json()
    if alerts:
        alert_id = alerts[0]["id"]
        res = client.patch(
            f"/api/v1/security/alerts/{alert_id}",
            json={"status": "INVALID_STATUS_STRING"}
        )
        assert res.status_code == 400


def test_tampered_manifest_signature_rejection():
    """Verify Ed25519 signature verification fails if any manifest field is altered."""
    manifest_data = {
        "manifest_version": "1.0",
        "evidence_id": "MAN-TAMPER-TEST-001",
        "server_name": "localhost\\SQLEXPRESS",
        "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "retention_mode": "COMPLIANCE"
    }
    sig = signer.sign_manifest(manifest_data)
    assert signer.verify_manifest(manifest_data, sig) is True

    # Tamper with SHA-256
    tampered = dict(manifest_data)
    tampered["sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
    assert signer.verify_manifest(tampered, sig) is False

    # Tamper with retention mode
    tampered2 = dict(manifest_data)
    tampered2["retention_mode"] = "GOVERNANCE"
    assert signer.verify_manifest(tampered2, sig) is False


def test_nonexistent_evidence_file_rejection(tmp_path):
    """Verify EvidenceArchiver raises FileNotFoundError for missing local files."""
    from backend.database import SessionLocal
    from backend.models.security import SecuritySource
    db = SessionLocal()
    source = db.query(SecuritySource).first()
    archiver = EvidenceArchiver(db=db, source=source)
    with pytest.raises(FileNotFoundError):
        archiver.archive_file(str(tmp_path / "non_existent_file.sqlaudit"))
    db.close()
