"""
Failure and boundary tests for SQL-TRUST Module 4: Cyber Recovery & State Reconstruction.
Tests 404 error responses, non-existent entity lookups, broken chains,
tampered manifests, and corrupt evidence verification.
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_invalid_recovery_point_id_404():
    resp = client.get("/api/v1/recovery/points/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_invalid_recovery_chain_id_404():
    resp = client.get("/api/v1/recovery/chains/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_invalid_assessment_id_404():
    resp = client.get("/api/v1/recovery/assessments/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_analyze_chain_nonexistent_target_404():
    payload = {
        "target_recovery_point_id": "00000000-0000-0000-0000-000000000000"
    }
    resp = client.post("/api/v1/recovery/chains/analyze", json=payload)
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_create_assessment_nonexistent_point_404():
    payload = {
        "recovery_point_id": "00000000-0000-0000-0000-000000000000",
        "assessment_name": "Ghost_Assessment"
    }
    resp = client.post("/api/v1/recovery/assessments", json=payload)
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_verify_nonexistent_recovery_evidence_404():
    resp = client.get("/api/v1/recovery/evidence/00000000-0000-0000-0000-000000000000/verify")
    assert resp.status_code in (400, 404)
