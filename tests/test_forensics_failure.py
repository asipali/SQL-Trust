"""
Failure and boundary tests for SQL-TRUST Module 3: Database Forensics Engine.
Validates 404 rejections, invalid baseline comparisons, non-existent database handling,
and signature verification error reporting.
"""
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_invalid_baseline_id_404():
    resp = client.get("/api/v1/forensics/baselines/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_invalid_baseline_items_empty():
    resp = client.get("/api/v1/forensics/baselines/00000000-0000-0000-0000-000000000000/items")
    assert resp.status_code == 200
    assert resp.json() == []


def test_invalid_investigation_id_404():
    resp = client.get("/api/v1/forensics/investigations/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_investigation_with_nonexistent_baseline_404():
    payload = {
        "ref_baseline_id": "00000000-0000-0000-0000-000000000000",
        "target_baseline_id": "11111111-1111-1111-1111-111111111111"
    }
    resp = client.post("/api/v1/forensics/investigations/compare", json=payload)
    assert resp.status_code == 404


def test_capture_baseline_nonexistent_database_500():
    payload = {
        "database_name": "Ghost_Database_That_Does_Not_Exist",
        "archive_to_worm": False
    }
    resp = client.post("/api/v1/forensics/baselines/capture", json=payload)
    assert resp.status_code == 500
    assert "failed" in resp.json()["detail"].lower()


def test_verify_nonexistent_evidence_archive_400():
    resp = client.get("/api/v1/forensics/evidence/00000000-0000-0000-0000-000000000000/verify")
    assert resp.status_code == 400
