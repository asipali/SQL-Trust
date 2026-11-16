"""
API integration tests for SQL-TRUST Module 4: Cyber Recovery & State Reconstruction.
Tests HTTP endpoints for recovery points, backup chain analysis, cyber trust assessments,
eligibility evaluations, ranked recommendations, and WORM evidence verification.
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import SessionLocal
from backend.models.recovery import RecoveryPoint, RecoveryChain, RecoveryAssessment

client = TestClient(app)


def test_api_recovery_health():
    resp = client.get("/api/v1/recovery/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "database_connected" in data
    assert "storage_connected" in data
    assert "worm_compliance_active" in data
    assert data["worm_compliance_active"] is True


def test_api_list_recovery_points():
    resp = client.get("/api/v1/recovery/points?discover=true")
    assert resp.status_code == 200
    points = resp.json()
    assert isinstance(points, list)


def test_api_list_recovery_chains():
    resp = client.get("/api/v1/recovery/chains")
    assert resp.status_code == 200
    chains = resp.json()
    assert isinstance(chains, list)


def test_api_list_recovery_assessments():
    resp = client.get("/api/v1/recovery/assessments")
    assert resp.status_code == 200
    assessments = resp.json()
    assert isinstance(assessments, list)


def test_api_list_recovery_recommendations():
    resp = client.get("/api/v1/recovery/recommendations")
    assert resp.status_code == 200
    recs = resp.json()
    assert isinstance(recs, list)


def test_api_list_recovery_eligibility():
    resp = client.get("/api/v1/recovery/eligibility")
    assert resp.status_code == 200
    eligs = resp.json()
    assert isinstance(eligs, list)


def test_api_analyze_chain_and_assess_point():
    # 1. Fetch available recovery points
    pts_resp = client.get("/api/v1/recovery/points?discover=true")
    assert pts_resp.status_code == 200
    points = pts_resp.json()

    if not points:
        pytest.skip("No existing backups in database to analyze")

    target_pt = points[0]
    target_id = target_pt["id"]

    # 2. Analyze backup chain for target point
    chain_resp = client.post("/api/v1/recovery/chains/analyze", json={
        "target_recovery_point_id": target_id
    })
    assert chain_resp.status_code == 200
    chain = chain_resp.json()
    assert "id" in chain
    assert "validation_status" in chain
    assert chain["target_recovery_point_id"] == target_id
    chain_id = chain["id"]

    # 3. Create trust assessment & eligibility
    assess_resp = client.post("/api/v1/recovery/assessments", json={
        "recovery_point_id": target_id,
        "chain_id": chain_id,
        "assessment_name": f"Test_Assessment_{target_pt['database_name']}",
        "archive_to_worm": True
    })
    assert assess_resp.status_code == 200
    assessment = assess_resp.json()
    assert "trust_classification" in assessment
    assert assessment["recovery_point_id"] == target_id
    assessment_id = assessment["id"]

    # 4. Fetch evidence items
    ev_resp = client.get(f"/api/v1/recovery/assessments/{assessment_id}/evidence")
    assert ev_resp.status_code == 200
    assert isinstance(ev_resp.json(), list)

    # 5. Fetch recommendations
    rec_resp = client.get(f"/api/v1/recovery/assessments/{assessment_id}/recommendations")
    assert rec_resp.status_code == 200
    assert isinstance(rec_resp.json(), list)

    # 6. Verify signed evidence in WORM storage
    verify_resp = client.get(f"/api/v1/recovery/evidence/{assessment_id}/verify")
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["valid"] is True
    assert v_data["sha256_match"] is True
    assert v_data["signature_valid"] is True
    assert v_data["worm_mode"] == "COMPLIANCE"
