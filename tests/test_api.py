"""
SQL-TRUST Module 1 — FastAPI Endpoint Integration Tests
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import init_db
from backend.config import settings

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_api_db():
    init_db()


def test_api_database_discovery():
    """Test GET /api/v1/databases."""
    response = client.get("/api/v1/databases")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    names = [d["name"] for d in data]
    assert "master" in names


def test_api_test_connection():
    """Test POST /api/v1/databases/test-connection."""
    response = client.post("/api/v1/databases/test-connection")
    assert response.status_code == 200
    data = response.json()
    assert data["connected"] is True
    assert "version" in data


def test_api_database_registration_and_get():
    """Test POST /api/v1/databases/register and GET /api/v1/databases/{id}."""
    resp = client.post("/api/v1/databases/register", json={
        "database_name": "SQLTrust_TestDB"
    })
    assert resp.status_code == 200
    reg = resp.json()
    assert reg["database_name"] == "SQLTrust_TestDB"
    db_id = reg["id"]

    # Fetch by ID
    get_resp = client.get(f"/api/v1/databases/{db_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == db_id

    # List registered
    list_resp = client.get("/api/v1/databases/registered")
    assert list_resp.status_code == 200
    assert any(d["id"] == db_id for d in list_resp.json())


def test_api_create_backup_and_query():
    """Test backup creation via API, manifest fetch, and verification."""
    # Register DB
    reg_resp = client.post("/api/v1/databases/register", json={"database_name": "SQLTrust_TestDB"})
    db_id = reg_resp.json()["id"]

    # Trigger FULL backup
    backup_resp = client.post("/api/v1/backups/full", json={
        "database_id": db_id,
        "notes": "FastAPI Client Test"
    })
    assert backup_resp.status_code == 201
    backup_data = backup_resp.json()
    assert backup_data["backup_status"] == "COMPLETED"
    backup_id = backup_data["id"]

    # Fetch single backup details
    detail_resp = client.get(f"/api/v1/backups/{backup_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == backup_id

    # Fetch manifest
    manifest_resp = client.get(f"/api/v1/backups/{backup_id}/manifest")
    assert manifest_resp.status_code == 200
    manifest = manifest_resp.json()
    assert manifest["manifest_version"] == "1.0"
    assert "manifest_data" in manifest
    assert manifest["manifest_data"]["database_name"] == "SQLTrust_TestDB"

    # Re-verify
    verify_resp = client.post(f"/api/v1/backups/{backup_id}/verify")
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["sql_verification"] == "PASSED"
    assert v_data["sha256_match"] is True

    # List backups with filter
    history_resp = client.get(f"/api/v1/backups?database_id={db_id}&backup_type=FULL")
    assert history_resp.status_code == 200
    assert len(history_resp.json()) > 0

    # Get stats
    stats_resp = client.get("/api/v1/backups/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_backups"] >= 1
    assert stats["successful_backups"] >= 1


def test_api_storage_endpoints():
    """Test storage health and object listing."""
    health_resp = client.get("/api/v1/storage/health")
    assert health_resp.status_code == 200
    health = health_resp.json()
    assert health["connected"] is True
    assert health["bucket"] == settings.effective_s3_bucket
    assert health.get("object_lock_enabled") is True
    assert health.get("versioning_status") == "Enabled"

    objs_resp = client.get("/api/v1/storage/backups")
    assert objs_resp.status_code == 200
    objs = objs_resp.json()
    assert isinstance(objs, list)
    assert len(objs) > 0
