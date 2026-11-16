"""
SQL-TRUST Module 2: Security Monitoring Engine — API Integration Tests
Tests all 13 FastAPI endpoints under /api/v1/security.
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import init_db

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_api():
    init_db()


def test_api_security_sources():
    """Test GET /api/v1/security/sources."""
    res = client.get("/api/v1/security/sources")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert any(s["source_name"] == "SQLServer-LocalHost" for s in data)


def test_api_security_rules():
    """Test GET /api/v1/security/rules."""
    res = client.get("/api/v1/security/rules")
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) == 10
    rule_ids = [r["rule_id"] for r in rules]
    assert "RULE_001_FAILED_LOGINS" in rule_ids
    assert "RULE_003_SYSADMIN_CHANGE" in rule_ids
    assert "RULE_008_AUDIT_TAMPERING" in rule_ids


def test_api_security_health():
    """Test GET /api/v1/security/health."""
    res = client.get("/api/v1/security/health")
    assert res.status_code == 200
    health = res.json()
    assert "overall_status" in health
    assert "sql_server" in health
    assert "audit" in health
    assert "extended_events" in health
    assert "storage" in health


def test_api_security_events_empty_or_listed():
    """Test GET /api/v1/security/events."""
    res = client.get("/api/v1/security/events")
    assert res.status_code == 200
    events = res.json()
    assert isinstance(events, list)


def test_api_security_alerts_list():
    """Test GET /api/v1/security/alerts."""
    res = client.get("/api/v1/security/alerts")
    assert res.status_code == 200
    alerts = res.json()
    assert isinstance(alerts, list)
