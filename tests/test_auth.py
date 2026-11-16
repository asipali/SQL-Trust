"""
SQL-TRUST Test Suite — Authentication, RBAC & Demo Account Management
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.auth_service import AuthService

client = TestClient(app)


def test_password_hashing():
    """Verify PBKDF2-HMAC-SHA256 password hashing and validation."""
    password = "SuperSecretPassword!2026"
    hashed = AuthService.hash_password(password)
    assert hashed != password
    assert hashed.startswith("pbkdf2:sha256:100000$")
    assert AuthService.verify_password(password, hashed) is True
    assert AuthService.verify_password("WrongPassword!", hashed) is False


def test_token_creation_and_verification():
    """Verify HMAC-SHA256 token encoding, expiration, and payload extraction."""
    user_data = {
        "sub": "demo_admin",
        "username": "demo_admin",
        "role": "Admin",
        "is_demo_account": True
    }
    token = AuthService.create_access_token(user_data, expires_minutes=60)
    assert isinstance(token, str)
    assert len(token) > 20

    payload = AuthService.decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "demo_admin"
    assert payload["username"] == "demo_admin"
    assert payload["role"] == "Admin"
    assert payload["is_demo_account"] is True

    # Tampered token check
    tampered_token = token[:-5] + "XXXXX"
    assert AuthService.decode_access_token(tampered_token) is None


def test_rbac_permissions():
    """Verify RBAC role permission checks."""
    assert AuthService.has_permission("Admin", "databases:write") is True
    assert AuthService.has_permission("Admin", "investigations:close") is True
    assert AuthService.has_permission("Investigator", "investigations:write") is True
    assert AuthService.has_permission("Investigator", "restore:approve") is False
    assert AuthService.has_permission("Reviewer", "restore:approve") is True
    assert AuthService.has_permission("Reviewer", "forensics:capture") is False
    assert AuthService.has_permission("Auditor", "security:read") is True
    assert AuthService.has_permission("Auditor", "investigations:write") is False


def test_get_demo_accounts_endpoint():
    """Verify listing pre-configured demo accounts via API."""
    response = client.get("/api/v1/auth/demo-accounts")
    assert response.status_code == 200
    data = response.json()
    assert "accounts" in data
    assert len(data["accounts"]) == 5
    usernames = [acc["username"] for acc in data["accounts"]]
    assert "demo_admin" in usernames
    assert "demo_investigator" in usernames
    assert "demo_analyst" in usernames
    assert "demo_reviewer" in usernames
    assert "demo_auditor" in usernames


def test_demo_login_success():
    """Verify authenticating as demo_admin returns valid token and user profile."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "demo_admin", "password": "SQLTrustDemo!Admin2026"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["username"] == "demo_admin"
    assert data["role"] == "Admin"
    assert data["is_demo_account"] is True


def test_demo_login_failure():
    """Verify invalid password returns 401 Unauthorized."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "demo_admin", "password": "WrongPassword!"}
    )
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]


def test_get_current_user_with_token():
    """Verify /me endpoint resolves authenticated user from Bearer token."""
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "demo_investigator", "password": "SQLTrustDemo!Investigator2026"}
    )
    token = login_res.json()["access_token"]

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    user_info = response.json()
    assert user_info["username"] == "demo_investigator"
    assert user_info["role"] == "Investigator"


def test_seed_demo_accounts_endpoint():
    """Verify idempotent demo account re-seeding endpoint."""
    response = client.post("/api/v1/auth/seed-demo-accounts")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["details"]["total_demo_accounts"] == 5
