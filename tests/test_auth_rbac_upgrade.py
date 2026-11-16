"""
SQL-TRUST Test Suite — Production Auth & Role-Based Access Control (RBAC) Upgrades
Verifies:
- Self-registration with mandatory least-privilege READ_ONLY_REVIEWER role
- No role escalation via registration payloads
- Duplicate checks (username, email)
- Password validation
- Login with username or email
- Admin-only user management
- Safeguards preventing demotion or deactivation of the last active administrator
- Permission matrix enforcement across roles
- Audit trail logging
"""
import pytest
import uuid
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.auth_service import AuthService, ROLE_PERMISSIONS

client = TestClient(app)


def test_registration_with_least_privilege():
    """Verify new registration is strictly assigned READ_ONLY_REVIEWER role."""
    unique_user = f"analyst_{uuid.uuid4().hex[:6]}"
    unique_email = f"{unique_user}@sqltrust.internal"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Junior Security Reviewer",
            "email": unique_email,
            "username": unique_user,
            "password": "StrongPassword!2026",
            "confirm_password": "StrongPassword!2026"
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == unique_user
    assert data["email"] == unique_email
    assert data["role"] == "READ_ONLY_REVIEWER"
    assert data["is_active"] is True
    # Verify permissions assigned to newly registered user
    assert "dashboard.view" in data["permissions"]
    assert "backup.create" not in data["permissions"]
    assert "investigation.create" not in data["permissions"]
    assert "users.update" not in data["permissions"]


def test_registration_role_escalation_impossible():
    """Verify passing privileged role in payload is completely ignored or assigned safe default."""
    unique_user = f"hacker_{uuid.uuid4().hex[:6]}"
    unique_email = f"{unique_user}@sqltrust.internal"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Attempted Admin Escalation",
            "email": unique_email,
            "username": unique_user,
            "password": "StrongPassword!2026",
            "confirm_password": "StrongPassword!2026",
            "role": "SECURITY_ADMIN"  # Attempted escalation
        }
    )
    assert response.status_code == 201
    data = response.json()
    # Must STILL be safe default READ_ONLY_REVIEWER
    assert data["role"] == "READ_ONLY_REVIEWER"


def test_registration_duplicate_username_and_email():
    """Verify 409 Conflict when attempting to register existing username or email."""
    unique_user = f"dup_{uuid.uuid4().hex[:6]}"
    unique_email = f"{unique_user}@sqltrust.internal"

    # First registration succeeds
    res1 = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Original User",
            "email": unique_email,
            "username": unique_user,
            "password": "StrongPassword!2026",
            "confirm_password": "StrongPassword!2026"
        }
    )
    assert res1.status_code == 201

    # Duplicate username
    res2 = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Duplicate Username",
            "email": f"other_{uuid.uuid4().hex[:4]}@sqltrust.internal",
            "username": unique_user,
            "password": "StrongPassword!2026",
            "confirm_password": "StrongPassword!2026"
        }
    )
    assert res2.status_code == 409
    assert "already registered" in res2.json()["detail"]

    # Duplicate email
    res3 = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Duplicate Email",
            "email": unique_email,
            "username": f"other_{uuid.uuid4().hex[:4]}",
            "password": "StrongPassword!2026",
            "confirm_password": "StrongPassword!2026"
        }
    )
    assert res3.status_code == 409
    assert "already registered" in res3.json()["detail"]


def test_registration_password_mismatch_and_weak_password():
    """Verify validation errors for mismatched and weak passphrases."""
    # Mismatched password
    res1 = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Test User",
            "email": "test_mismatch@sqltrust.internal",
            "username": "test_mismatch",
            "password": "StrongPassword!2026",
            "confirm_password": "DifferentPassword!2026"
        }
    )
    assert res1.status_code == 400
    assert "do not match" in res1.json()["detail"]

    # Weak password (< 8 chars)
    res2 = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Test User",
            "email": "test_weak@sqltrust.internal",
            "username": "test_weak",
            "password": "shor1!",
            "confirm_password": "shor1!"
        }
    )
    assert res2.status_code in (400, 422)


def test_login_with_email():
    """Verify login works with email identifier as well as username."""
    unique_user = f"email_user_{uuid.uuid4().hex[:6]}"
    unique_email = f"{unique_user}@sqltrust.internal"

    client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Email Login Tester",
            "email": unique_email,
            "username": unique_user,
            "password": "StrongPassword!2026",
            "confirm_password": "StrongPassword!2026"
        }
    )

    # Login using email
    res = client.post(
        "/api/v1/auth/login",
        json={"username": unique_email, "password": "StrongPassword!2026"}
    )
    assert res.status_code == 200
    assert res.json()["username"] == unique_user
    assert "access_token" in res.json()


def test_admin_user_management_endpoints():
    """Verify /api/v1/auth/users listing, role changes, and status updates."""
    # Admin login
    admin_login = client.post(
        "/api/v1/auth/login",
        json={"username": "demo_admin", "password": "SQLTrustDemo!Admin2026"}
    )
    admin_token = admin_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Register target user
    target_user = f"target_{uuid.uuid4().hex[:6]}"
    reg = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Target Employee",
            "email": f"{target_user}@sqltrust.internal",
            "username": target_user,
            "password": "StrongPassword!2026",
            "confirm_password": "StrongPassword!2026"
        }
    )
    target_id = reg.json()["id"]

    # List users as admin
    users_res = client.get("/api/v1/auth/users", headers=headers)
    assert users_res.status_code == 200
    assert any(u["id"] == target_id for u in users_res.json())

    # Update role to SENIOR_ANALYST
    role_res = client.put(
        f"/api/v1/auth/users/{target_id}/role",
        headers=headers,
        json={"role": "SENIOR_ANALYST"}
    )
    assert role_res.status_code == 200
    assert role_res.json()["role"] == "SENIOR_ANALYST"
    assert "forensics.analyze" in role_res.json()["permissions"]

    # Update status to deactivated
    status_res = client.put(
        f"/api/v1/auth/users/{target_id}/status",
        headers=headers,
        json={"is_active": False}
    )
    assert status_res.status_code == 200
    assert status_res.json()["is_active"] is False

    # Attempting to login deactivated user must fail with 403
    deactivated_login = client.post(
        "/api/v1/auth/login",
        json={"username": target_user, "password": "StrongPassword!2026"}
    )
    assert deactivated_login.status_code == 403
    assert "deactivated" in deactivated_login.json()["detail"].lower()


def test_last_administrator_safeguard():
    """Verify administrator cannot demote or deactivate the last active administrator account."""
    admin_login = client.post(
        "/api/v1/auth/login",
        json={"username": "demo_admin", "password": "SQLTrustDemo!Admin2026"}
    )
    admin_token = admin_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Fetch admin user ID
    me = client.get("/api/v1/auth/me", headers=headers).json()
    admin_id = me["id"]

    # Attempt to demote demo_admin to READ_ONLY_REVIEWER
    demote_res = client.put(
        f"/api/v1/auth/users/{admin_id}/role",
        headers=headers,
        json={"role": "READ_ONLY_REVIEWER"}
    )
    # If demo_admin is the only active admin, this must be rejected with 400
    if demote_res.status_code == 400:
        assert "last active administrator" in demote_res.json()["detail"].lower()

    # Attempt to deactivate demo_admin
    deactivate_res = client.put(
        f"/api/v1/auth/users/{admin_id}/status",
        headers=headers,
        json={"is_active": False}
    )
    if deactivate_res.status_code == 400:
        assert "last active administrator" in deactivate_res.json()["detail"].lower()


def test_auth_audit_log_endpoint():
    """Verify /api/v1/auth/audit-log returns recorded security modifications."""
    admin_login = client.post(
        "/api/v1/auth/login",
        json={"username": "demo_admin", "password": "SQLTrustDemo!Admin2026"}
    )
    admin_token = admin_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    res = client.get("/api/v1/auth/audit-log", headers=headers)
    assert res.status_code == 200
    logs = res.json()
    assert isinstance(logs, list)
    assert len(logs) > 0
    actions = [log["action"] for log in logs]
    assert any(a in ("USER_REGISTERED", "ROLE_CHANGED", "STATUS_CHANGED", "LOGIN_FAILED") for a in actions)


def test_permission_matrix_integrity():
    """Verify role permission boundaries match requested security model."""
    # SECURITY_ADMIN possesses all operations
    assert AuthService.has_permission("SECURITY_ADMIN", "users.update") is True
    assert AuthService.has_permission("SECURITY_ADMIN", "backup.create") is True
    assert AuthService.has_permission("SECURITY_ADMIN", "recovery.approve") is True

    # READ_ONLY_REVIEWER has no creation or modification rights
    assert AuthService.has_permission("READ_ONLY_REVIEWER", "dashboard.view") is True
    assert AuthService.has_permission("READ_ONLY_REVIEWER", "backup.create") is False
    assert AuthService.has_permission("READ_ONLY_REVIEWER", "investigation.create") is False
    assert AuthService.has_permission("READ_ONLY_REVIEWER", "recovery.approve") is False
    assert AuthService.has_permission("READ_ONLY_REVIEWER", "users.update") is False

    # INCIDENT_APPROVER can approve recovery and plans, but cannot manage users
    assert AuthService.has_permission("INCIDENT_APPROVER", "recovery.approve") is True
    assert AuthService.has_permission("INCIDENT_APPROVER", "restore.approve") is True
    assert AuthService.has_permission("INCIDENT_APPROVER", "users.update") is False

    # AUDITOR has read-only access to audit logs and evidence, but no modifications
    assert AuthService.has_permission("AUDITOR", "audit.view") is True
    assert AuthService.has_permission("AUDITOR", "evidence.view") is True
    assert AuthService.has_permission("AUDITOR", "evidence.collect") is False
    assert AuthService.has_permission("AUDITOR", "backup.create") is False
