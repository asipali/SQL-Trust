"""
API integration tests for SQL-TRUST Module 3: Database Forensics Engine.
Validates baseline capture, item listing, investigation comparison, and timeline retrieval.
"""
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_api_baselines_list():
    resp = client.get("/api/v1/forensics/baselines")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_api_investigations_list():
    resp = client.get("/api/v1/forensics/investigations")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_api_capture_baseline_and_query_items():
    # Capture a baseline for SQLTrust_Lab
    payload = {
        "database_name": "SQLTrust_Lab",
        "server_name": "localhost\\SQLEXPRESS",
        "baseline_name": "PyTest_Baseline_Lab",
        "notes": "Automated API integration test",
        "archive_to_worm": False  # Skip WORM upload for rapid unit API check
    }
    resp = client.post("/api/v1/forensics/baselines/capture", json=payload)
    assert resp.status_code == 200
    b_data = resp.json()
    assert b_data["database_name"] == "SQLTrust_Lab"
    assert b_data["status"] == "COMPLETED"
    baseline_id = b_data["id"]

    # Query baseline items
    items_resp = client.get(f"/api/v1/forensics/baselines/{baseline_id}/items")
    assert items_resp.status_code == 200
    items = items_resp.json()
    assert isinstance(items, list)
    assert len(items) > 0

    # Filter items by type
    opt_resp = client.get(f"/api/v1/forensics/baselines/{baseline_id}/items?item_type=DATABASE_OPTION")
    assert opt_resp.status_code == 200
    opts = opt_resp.json()
    assert len(opts) == 1
    assert opts[0]["item_name"] == "DATABASE_CONFIGURATION"


def test_api_investigation_comparison_flow():
    # Capture Baseline 1
    b1_resp = client.post("/api/v1/forensics/baselines/capture", json={
        "database_name": "SQLTrust_Lab",
        "baseline_name": "PyTest_Comp_Base1",
        "archive_to_worm": False
    })
    assert b1_resp.status_code == 200
    b1_id = b1_resp.json()["id"]

    # Capture Baseline 2
    b2_resp = client.post("/api/v1/forensics/baselines/capture", json={
        "database_name": "SQLTrust_Lab",
        "baseline_name": "PyTest_Comp_Base2",
        "archive_to_worm": False
    })
    assert b2_resp.status_code == 200
    b2_id = b2_resp.json()["id"]

    # Compare B1 vs B2
    comp_resp = client.post("/api/v1/forensics/investigations/compare", json={
        "ref_baseline_id": b1_id,
        "target_baseline_id": b2_id,
        "investigation_name": "PyTest_Investigation_SelfCompare",
        "summary_notes": "Comparing identical baselines"
    })
    assert comp_resp.status_code == 200
    inv_data = comp_resp.json()
    assert inv_data["status"] == "COMPLETED"
    assert inv_data["findings_count"] == 0  # Identical states have 0 findings

    # Query Timeline
    inv_id = inv_data["id"]
    timeline_resp = client.get(f"/api/v1/forensics/investigations/{inv_id}/timeline")
    assert timeline_resp.status_code == 200
    timeline = timeline_resp.json()
    assert len(timeline) >= 2  # Baseline reference + Investigation completed
