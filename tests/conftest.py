"""
SQL-TRUST Test Configuration & Dependency Overrides
Ensures that existing functional unit/integration test suites have an authenticated context,
while security and RBAC test suites strictly execute through real token validation and permission gates.
"""
import pytest
from backend.main import app
from backend.api.v1.auth import get_current_user
from backend.models.auth import User


@pytest.fixture(autouse=True)
def default_auth_for_functional_tests(request):
    """
    Automatically authenticates functional tests as SECURITY_ADMIN,
    while leaving security, auth, and RBAC test suites completely un-overridden
    to test real HTTP 401 unauthenticated and HTTP 403 forbidden enforcement.
    """
    module_name = request.module.__name__
    
    # Do NOT override for authentication and security test suites
    if any(keyword in module_name for keyword in ("auth", "security_rbac", "test_rbac")):
        app.dependency_overrides.pop(get_current_user, None)
        yield
        app.dependency_overrides.pop(get_current_user, None)
        return

    # Provide default authenticated admin for existing functional/regression tests
    test_admin = User(
        id="test-fixture-admin-id",
        username="demo_admin",
        full_name="Platform Administrator",
        email="admin@sqltrust.internal",
        hashed_password="pbkdf2:sha256:100000$test$test",
        role="SECURITY_ADMIN",
        is_active=True,
        is_pending_approval=False,
        is_demo_account=True
    )
    app.dependency_overrides[get_current_user] = lambda: test_admin
    yield
    app.dependency_overrides.pop(get_current_user, None)
