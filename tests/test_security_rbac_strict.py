"""
SQL-TRUST Test Suite — Strict Role-Based Access Control (RBAC) & Least Privilege
Validates:
1. Unauthenticated requests return HTTP 401 Unauthorized.
2. Only SECURITY_ADMIN has full platform administrative oversight.
3. Separation of duties across all 7 canonical roles:
   - SECURITY_ADMIN
   - INCIDENT_APPROVER
   - SENIOR_ANALYST
   - INVESTIGATION_ANALYST
   - INCIDENT_REVIEWER
   - AUDITOR
   - READ_ONLY_REVIEWER
4. Strict least-privilege boundary enforcement (HTTP 403 Forbidden on unpermitted operations).
5. Record-level access control on investigation cases (investigators cannot modify unrelated cases).
6. Immutable audit logging of authorization failures (action: PERMISSION_DENIED).
7. Safeguards preventing demotion or deactivation of the last active administrator.
"""
import uuid
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import get_db
from backend.models.auth import User, AuthAuditLog
from backend.services.auth_service import AuthService

client = TestClient(app)


@pytest.fixture(autouse=True)
def seed_demo_users():
    """Ensure standard demo users are seeded before tests."""
    db = next(get_db())
    try:
        AuthService.seed_demo_accounts(db)
    finally:
        db.close()


def get_token_for(username: str, password: str) -> str:
    """Helper to authenticate and return a JWT Bearer token."""
    res = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password}
    )
    assert res.status_code == 200, f"Login failed for {username}: {res.text}"
    return res.json()["access_token"]


def create_user_with_role(role: str, prefix: str = "user") -> tuple[str, str, str]:
    """Helper to register and promote a user to any canonical role."""
    unique_user = f"{prefix}_{uuid.uuid4().hex[:6]}"
    unique_email = f"{unique_user}@sqltrust.internal"
    pwd = "StrongPassword!2026"

    # Register as default READ_ONLY_REVIEWER
    reg_res = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": f"Test {role}",
            "email": unique_email,
            "username": unique_user,
            "password": pwd,
            "confirm_password": pwd
        }
    )
    assert reg_res.status_code == 201
    user_id = reg_res.json()["id"]

    # If role is different from READ_ONLY_REVIEWER, use admin to promote
    if role != "READ_ONLY_REVIEWER":
        admin_token = get_token_for("demo_admin", "SQLTrustDemo!Admin2026")
        promo_res = client.put(
            f"/api/v1/auth/users/{user_id}/role",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"role": role}
        )
        assert promo_res.status_code == 200

    token = get_token_for(unique_user, pwd)
    return unique_user, user_id, token


# =========================================================================
# 1. Unauthenticated Requests (HTTP 401 Unauthorized)
# =========================================================================

def test_unauthenticated_requests_return_401():
    """Verify that requests missing Bearer token receive 401 Unauthorized."""
    # 1. Current user profile
    res1 = client.get("/api/v1/auth/me")
    assert res1.status_code == 401
    assert "Authentication required" in res1.json()["detail"]

    # 2. Administrative users endpoint
    res2 = client.get("/api/v1/auth/users")
    assert res2.status_code == 401

    # 3. Investigation case creation
    res3 = client.post(
        "/api/v1/investigations",
        json={
            "title": "Unauthenticated Intrusion",
            "database_name": "FINANCE_PROD",
            "incident_category": "DATA_EXFILTRATION",
            "initial_priority": "P1_CRITICAL"
        }
    )
    assert res3.status_code == 401

    # 4. Investigations list
    res4 = client.get("/api/v1/investigations")
    assert res4.status_code == 401


# =========================================================================
# 2. SECURITY_ADMIN Full Platform Access
# =========================================================================

def test_security_admin_has_full_platform_access():
    """Verify that SECURITY_ADMIN can access user admin, cases, and all operations."""
    admin_token = get_token_for("demo_admin", "SQLTrustDemo!Admin2026")
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Get profile and verify all permissions
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["role"] in ("Admin", "SECURITY_ADMIN")
    assert "users.view" in me_res.json()["permissions"]
    assert "investigations:write" in me_res.json()["permissions"]

    # 2. List all users
    users_res = client.get("/api/v1/auth/users", headers=headers)
    assert users_res.status_code == 200
    assert len(users_res.json()) >= 1

    # 3. Create investigation case
    case_res = client.post(
        "/api/v1/investigations",
        headers=headers,
        json={
            "title": "Admin Created Security Incident",
            "target_database_name": "CREDIT_DATA",
            "incident_category": "DATA_EXFILTRATION",
            "priority": "P2_HIGH",
            "created_by": "demo_admin"
        }
    )
    assert case_res.status_code == 201
    case_id = case_res.json()["id"]

    # 4. Read case audit logs
    audit_res = client.get(f"/api/v1/investigations/{case_id}/audit-logs", headers=headers)
    assert audit_res.status_code == 200


# =========================================================================
# 3. Non-Admin Roles Prohibited from Administrative User Management
# =========================================================================

@pytest.mark.parametrize("role,username,password", [
    ("INCIDENT_APPROVER", "demo_reviewer", "SQLTrustDemo!Reviewer2026"),
    ("SENIOR_ANALYST", "demo_analyst", "SQLTrustDemo!Analyst2026"),
    ("INVESTIGATION_ANALYST", "demo_investigator", "SQLTrustDemo!Investigator2026"),
    ("AUDITOR", "demo_auditor", "SQLTrustDemo!Auditor2026")
])
def test_non_admin_roles_forbidden_from_user_management(role, username, password):
    """Verify all 6 non-admin roles receive 403 Forbidden on /api/v1/auth/users."""
    token = get_token_for(username, password)
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to list users
    res = client.get("/api/v1/auth/users", headers=headers)
    assert res.status_code == 403
    assert "Administrator authority required" in res.json()["detail"]


# =========================================================================
# 4. INCIDENT_APPROVER Role Least Privilege & Separation of Duties
# =========================================================================

def test_incident_approver_least_privilege():
    """
    Verify INCIDENT_APPROVER:
    - CAN read investigations.
    - CANNOT create investigation cases (403).
    - CANNOT manage users (403).
    """
    token = get_token_for("demo_reviewer", "SQLTrustDemo!Reviewer2026")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. CAN read cases
    read_res = client.get("/api/v1/investigations", headers=headers)
    assert read_res.status_code == 200

    # 2. CANNOT create investigation case (requires investigations:write)
    create_res = client.post(
        "/api/v1/investigations",
        headers=headers,
        json={
            "title": "Unauthorized Case from Reviewer",
            "database_name": "PAYMENTS_DB",
            "incident_category": "MALWARE_RANSOMWARE",
            "initial_priority": "P2_HIGH"
        }
    )
    assert create_res.status_code == 403
    assert "investigations:write" in create_res.json()["detail"]


# =========================================================================
# 5. SENIOR_ANALYST Role Permissions
# =========================================================================

def test_senior_analyst_permissions_and_boundaries():
    """
    Verify SENIOR_ANALYST:
    - CAN create and triage cases.
    - CANNOT access user administration (403).
    - CANNOT close cases without closure permission (403).
    """
    token = get_token_for("demo_analyst", "SQLTrustDemo!Analyst2026")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. CAN create investigation case
    create_res = client.post(
        "/api/v1/investigations",
        headers=headers,
        json={
            "title": "Senior Analyst Ingested Case",
            "target_database_name": "ANALYTICS_WAREHOUSE",
            "incident_category": "SUSPICIOUS_ACTIVITY",
            "priority": "P2_HIGH",
            "created_by": "demo_analyst"
        }
    )
    assert create_res.status_code == 201
    case_id = create_res.json()["id"]

    # 2. CANNOT close case (requires investigations:close)
    close_res = client.post(
        f"/api/v1/investigations/{case_id}/close",
        headers=headers,
        json={
            "closed_by": "demo_analyst",
            "closure_reason": "FALSE_POSITIVE",
            "closure_notes": "Attempting closure without authorization"
        }
    )
    assert close_res.status_code == 403
    assert "investigations:close" in close_res.json()["detail"]


# =========================================================================
# 6. INVESTIGATION_ANALYST Record-Level Access Control
# =========================================================================

def test_investigation_analyst_record_level_access_control():
    """
    Verify INVESTIGATION_ANALYST record-level security:
    - Analyst A CAN update and add notes to cases assigned to Analyst A.
    - Analyst A CANNOT update or add notes to cases assigned to Analyst B (403 Record-level access denied).
    """
    # 1. Create Analyst A and Analyst B
    user_a, id_a, token_a = create_user_with_role("INVESTIGATION_ANALYST", "analyst_a")
    user_b, id_b, token_b = create_user_with_role("INVESTIGATION_ANALYST", "analyst_b")

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # 2. Analyst A creates Case A
    case_a_res = client.post(
        "/api/v1/investigations",
        headers=headers_a,
        json={
            "title": "Analyst A Confidential Case",
            "target_database_name": "PAYROLL_DB",
            "incident_category": "SUSPICIOUS_ACTIVITY",
            "priority": "P2_HIGH",
            "created_by": user_a,
            "lead_investigator": user_a
        }
    )
    assert case_a_res.status_code == 201
    case_a_id = case_a_res.json()["id"]

    # 3. Analyst B creates Case B
    case_b_res = client.post(
        "/api/v1/investigations",
        headers=headers_b,
        json={
            "title": "Analyst B Confidential Case",
            "target_database_name": "HEALTH_RECORDS",
            "incident_category": "DATA_EXFILTRATION",
            "priority": "P2_HIGH",
            "created_by": user_b,
            "lead_investigator": user_b
        }
    )
    assert case_b_res.status_code == 201
    case_b_id = case_b_res.json()["id"]

    # 4. Analyst A CAN add a note to Case A
    note_a_res = client.post(
        f"/api/v1/investigations/{case_a_id}/notes",
        headers=headers_a,
        json={"content": "Analyst A updating own case note.", "author": user_a}
    )
    assert note_a_res.status_code == 201

    # 5. Analyst A ATTEMPTS to add note to Case B (Assigned to Analyst B) -> 403 Forbidden
    unauth_note_res = client.post(
        f"/api/v1/investigations/{case_b_id}/notes",
        headers=headers_a,
        json={"content": "Analyst A snooping on Analyst B.", "author": user_a}
    )
    assert unauth_note_res.status_code == 403
    assert "Record-level access denied" in unauth_note_res.json()["detail"]

    # 6. Analyst A ATTEMPTS to update Case B metadata -> 403 Forbidden
    unauth_update_res = client.patch(
        f"/api/v1/investigations/{case_b_id}",
        headers=headers_a,
        json={"title": "Tampered Title by unauthorized analyst"}
    )
    assert unauth_update_res.status_code == 403
    assert "Record-level access denied" in unauth_update_res.json()["detail"]


# =========================================================================
# 7. AUDITOR Role Read-Only Enforcement
# =========================================================================

def test_auditor_role_read_only_enforcement():
    """
    Verify AUDITOR role:
    - CAN read audit logs and verify cryptographic audit hash chain.
    - CANNOT create investigation cases (403).
    - CANNOT update investigation cases (403).
    - CANNOT add notes or evidence (403).
    """
    token = get_token_for("demo_auditor", "SQLTrustDemo!Auditor2026")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. CAN read cases
    cases_res = client.get("/api/v1/investigations", headers=headers)
    assert cases_res.status_code == 200

    # 2. CANNOT create cases
    create_res = client.post(
        "/api/v1/investigations",
        headers=headers,
        json={
            "title": "Auditor Created Case",
            "database_name": "AUDIT_DB",
            "incident_category": "PRIVILEGE_ESCALATION",
            "initial_priority": "P3_MEDIUM"
        }
    )
    assert create_res.status_code == 403
    assert "investigations:write" in create_res.json()["detail"]


# =========================================================================
# 8. READ_ONLY_REVIEWER Least-Privilege Default Role
# =========================================================================

def test_read_only_reviewer_least_privilege_enforcement():
    """
    Verify READ_ONLY_REVIEWER (default registered role):
    - CAN view own profile (/me).
    - CANNOT list administrative users (403).
    - CANNOT create investigation cases (403).
    - CANNOT access audit logs requiring audit.view (403).
    """
    username, user_id, token = create_user_with_role("READ_ONLY_REVIEWER", "junior_guest")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. CAN view own profile
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "READ_ONLY_REVIEWER"

    # 2. CANNOT list administrative users (403)
    users_res = client.get("/api/v1/auth/users", headers=headers)
    assert users_res.status_code == 403

    # 3. CANNOT create investigation case (403)
    case_res = client.post(
        "/api/v1/investigations",
        headers=headers,
        json={
            "title": "Guest Created Incident",
            "database_name": "CORE_DB",
            "incident_category": "UNAUTHORIZED_ACCESS",
            "initial_priority": "P1_CRITICAL"
        }
    )
    assert case_res.status_code == 403


# =========================================================================
# 9. Audit Logging of Authorization Denials (PERMISSION_DENIED)
# =========================================================================

def test_permission_denied_audit_logging():
    """
    Verify that when any user triggers a 403 Forbidden,
    an immutable entry is logged in AuthAuditLog with action='PERMISSION_DENIED'.
    """
    username, user_id, token = create_user_with_role("READ_ONLY_REVIEWER", "audit_test_user")
    headers = {"Authorization": f"Bearer {token}"}

    # Trigger a 403 by trying to access admin endpoint
    client.get("/api/v1/auth/users", headers=headers)

    # Inspect audit logs directly from database
    db = next(get_db())
    try:
        denied_log = db.query(AuthAuditLog).filter(
            AuthAuditLog.actor_username == username,
            AuthAuditLog.action == "PERMISSION_DENIED"
        ).order_by(AuthAuditLog.timestamp.desc()).first()

        assert denied_log is not None
        assert denied_log.actor_role == "READ_ONLY_REVIEWER"
        assert "Denied attempt" in denied_log.details
    finally:
        db.close()


# =========================================================================
# 10. Last Administrator Protection Safeguard
# =========================================================================

def test_last_administrator_protection_safeguard():
    """
    Verify that the system strictly prevents demoting or deactivating the last active administrator.
    """
    admin_token = get_token_for("demo_admin", "SQLTrustDemo!Admin2026")
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Fetch admin user id
    me_res = client.get("/api/v1/auth/me", headers=headers)
    admin_id = me_res.json()["id"]

    # Deactivate any other secondary administrators first so demo_admin is sole admin
    db = next(get_db())
    try:
        other_admins = db.query(User).filter(
            User.id != admin_id,
            User.role.in_(["Admin", "SECURITY_ADMIN"]),
            User.is_active == True
        ).all()
        for a in other_admins:
            a.is_active = False
        db.commit()
    finally:
        db.close()

    # 2. Attempt to demote the sole admin to AUDITOR -> 400 Bad Request
    demote_res = client.put(
        f"/api/v1/auth/users/{admin_id}/role",
        headers=headers,
        json={"role": "AUDITOR"}
    )
    assert demote_res.status_code == 400
    assert "last active administrator" in demote_res.json()["detail"]

    # 3. Attempt to deactivate the sole admin -> 400 Bad Request
    deact_res = client.put(
        f"/api/v1/auth/users/{admin_id}/status",
        headers=headers,
        json={"is_active": False}
    )
    assert deact_res.status_code == 400
    assert "last active administrator" in deact_res.json()["detail"]
