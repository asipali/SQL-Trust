"""
SQL-TRUST Test Suite — Health & Environment Validation
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import test_sql_connection as check_db_conn, build_odbc_connection_string

client = TestClient(app)


def test_root_endpoint():
    """Verify root endpoint availability."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "version" in data


def test_health_endpoint():
    """Verify health endpoint response per specification."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "SQL-TRUST" in data["service"]
    assert "environment" in data


def test_sql_connectivity():
    """Verify non-destructive SQL Server connection using SELECT @@VERSION."""
    result = check_db_conn()
    assert isinstance(result, dict)
    assert result.get("success") is True
    assert "Microsoft SQL Server 2022" in result.get("version", "")


def test_odbc_connection_string_builder():
    """Verify connection string formatting and security options."""
    conn_str = build_odbc_connection_string(
        server="test_server",
        database="master",
        driver="ODBC Driver 18 for SQL Server",
        trusted_connection="yes"
    )
    assert "DRIVER={ODBC Driver 18 for SQL Server}" in conn_str
    assert "SERVER=test_server" in conn_str
    assert "TrustServerCertificate=yes" in conn_str
    assert "Trusted_Connection=yes" in conn_str
