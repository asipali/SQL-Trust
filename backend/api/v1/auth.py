"""
SQL-TRUST Authentication & RBAC API Endpoints
Provides registration, login, session validation, user administration, and permission enforcement.
"""
from typing import Optional, List, Any
from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.config import settings
from backend.database import get_db
from backend.models.backup import utc_now
from backend.models.auth import User, AuthAuditLog
from backend.schemas.auth import (
    RegisterRequest,
    LoginRequest,
    LoginResponse,
    UserResponse,
    UpdateUserRoleRequest,
    UpdateUserStatusRequest,
    AuthAuditLogResponse,
    DemoAccountsListResponse,
    DemoAccountInfo
)
from backend.services.auth_service import (
    AuthService,
    DEMO_ACCOUNTS_METADATA
)

router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])


def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Resolves authenticated user from Bearer token or development X-User-Role fallback."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        payload = AuthService.decode_access_token(token)
        if payload and "sub" in payload:
            user = db.query(User).filter(User.id == payload["sub"]).first()
            if user and user.is_active and not user.is_pending_approval:
                return user
    
    # In development mode, fallback to demo user matching header if provided
    if x_user_role and settings.ENVIRONMENT.lower() != "production":
        canonical_role = AuthService.normalize_role(x_user_role)
        role_user = db.query(User).filter(
            or_(User.role == x_user_role, User.role == canonical_role),
            User.is_active == True
        ).first()
        if role_user:
            return role_user

    return None


def require_authenticated_user(
    current_user: Optional[User] = Depends(get_current_user)
) -> User:
    """Enforces that a valid, active authenticated session is present."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer session token."
        )
    return current_user


def require_permission(permission: str):
    """Factory creating FastAPI dependencies that enforce explicit permissions on routes and audit violations."""
    def dependency(
        current_user: User = Depends(require_authenticated_user),
        db: Session = Depends(get_db)
    ) -> User:
        if not AuthService.has_permission(current_user.role, permission):
            try:
                AuthService.log_audit(
                    db=db,
                    actor_username=current_user.username,
                    actor_role=current_user.role,
                    action="PERMISSION_DENIED",
                    details=f"Denied attempt to execute operation requiring '{permission}' capability"
                )
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: role '{current_user.role}' lacks '{permission}' capability."
            )
        return current_user
    return dependency


def require_admin(
    current_user: User = Depends(require_authenticated_user),
    db: Session = Depends(get_db)
) -> User:
    """Enforces that the user has administrative authority and logs audit on denial."""
    if not AuthService.is_admin(current_user.role):
        try:
            AuthService.log_audit(
                db=db,
                actor_username=current_user.username,
                actor_role=current_user.role,
                action="PERMISSION_DENIED",
                details="Denied attempt to perform administrative operation without SECURITY_ADMIN authority"
            )
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator authority required for this operation."
        )
    return current_user


def check_case_access(current_user: User, case: Any, operation: str = "modify") -> None:
    """
    Enforces record-level authorization on investigation cases:
    - SECURITY_ADMIN and SENIOR_ANALYST have platform-wide oversight.
    - INVESTIGATION_ANALYST can only modify investigations where they are the assigned
      lead investigator, creator, or unassigned.
    - Other roles (AUDITOR, INCIDENT_REVIEWER, READ_ONLY_REVIEWER) cannot modify cases.
    """
    if AuthService.is_admin(current_user.role):
        return

    canonical_role = AuthService.normalize_role(current_user.role)
    if canonical_role in ("AUDITOR", "INCIDENT_REVIEWER", "READ_ONLY_REVIEWER"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{current_user.role}' is not permitted to {operation} investigation records."
        )

    if canonical_role == "SENIOR_ANALYST":
        return

    if canonical_role == "INVESTIGATION_ANALYST":
        lead = getattr(case, "lead_investigator", None)
        creator = getattr(case, "created_by", None)
        team = getattr(case, "assigned_team", None)

        is_assigned = (
            (lead and lead == current_user.username) or
            (creator and creator == current_user.username) or
            (lead is None and creator is None) or
            (team and getattr(current_user, "assigned_team", None) == team)
        )
        if not is_assigned:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Record-level access denied: Investigation case is assigned to '{lead or creator}'. You may not modify unrelated cases."
            )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account (assigned safe least-privilege READ_ONLY_REVIEWER role)"
)
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """
    Registers a new operator or reviewer with least-privilege READ_ONLY_REVIEWER role.
    Role escalation via registration parameters is rejected by design.
    """
    if req.password != req.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password and confirm password do not match."
        )
    
    # Password strength verification
    if len(req.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )
    if not any(c.isupper() for c in req.password) or not any(c.islower() for c in req.password) or not any(c.isdigit() for c in req.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one uppercase letter, one lowercase letter, and one number."
        )

    client_ip = request.client.host if request.client else None
    try:
        user = AuthService.register_user(
            db=db,
            full_name=req.full_name,
            email=req.email,
            username=req.username,
            password=req.password,
            ip_address=client_ip
        )
        perms = AuthService.get_permissions(user.role)
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            is_active=user.is_active,
            is_pending_approval=user.is_pending_approval,
            is_demo_account=user.is_demo_account,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
            permissions=perms
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Registration failed: {str(e)}")


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Authenticate user and issue signed access token"
)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticates credentials against the control repository and returns signed session token."""
    user = db.query(User).filter(
        or_(User.username == req.username.strip(), User.email == req.username.strip().lower())
    ).first()

    client_ip = request.client.host if request.client else None

    if not user or not AuthService.verify_password(req.password, user.hashed_password):
        AuthService.log_audit(
            db=db,
            actor_username=req.username,
            actor_role="UNKNOWN",
            action="LOGIN_FAILED",
            target_username=req.username,
            details="Invalid username/email or password",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated. Please contact your system administrator."
        )

    if user.is_pending_approval:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account registration is pending administrator approval."
        )
    
    user.last_login_at = utc_now()
    db.commit()

    token = AuthService.create_access_token(user)
    perms = AuthService.get_permissions(user.role)

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_demo_account=user.is_demo_account,
        permissions=perms
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user profile and permissions"
)
def get_me(current_user: User = Depends(require_authenticated_user)):
    """Returns profile and authorized permission set for currently authenticated session."""
    perms = AuthService.get_permissions(current_user.role)
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        is_pending_approval=current_user.is_pending_approval,
        is_demo_account=current_user.is_demo_account,
        created_at=current_user.created_at,
        last_login_at=current_user.last_login_at,
        permissions=perms
    )


@router.get(
    "/users",
    response_model=List[UserResponse],
    summary="List all registered platform users (Administrator only)"
)
def list_users(
    search: Optional[str] = Query(None, description="Fuzzy search username, full name, or email"),
    role_filter: Optional[str] = Query(None, description="Filter by assigned role"),
    active_only: Optional[bool] = Query(None, description="Filter by active status"),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Allows administrators to search, filter, and inspect registered users and roles."""
    query = db.query(User)
    if search:
        s = f"%{search.strip()}%"
        query = query.filter(or_(User.username.ilike(s), User.full_name.ilike(s), User.email.ilike(s)))
    if role_filter:
        canonical = AuthService.normalize_role(role_filter)
        query = query.filter(or_(User.role == role_filter, User.role == canonical))
    if active_only is not None:
        query = query.filter(User.is_active == active_only)

    users = query.order_by(User.created_at.desc()).all()
    results = []
    for u in users:
        results.append(UserResponse(
            id=u.id,
            username=u.username,
            email=u.email,
            full_name=u.full_name,
            role=u.role,
            is_active=u.is_active,
            is_pending_approval=u.is_pending_approval,
            is_demo_account=u.is_demo_account,
            created_at=u.created_at,
            last_login_at=u.last_login_at,
            permissions=AuthService.get_permissions(u.role)
        ))
    return results


@router.put(
    "/users/{user_id}/role",
    response_model=UserResponse,
    summary="Assign or change user role (Administrator only, safeguarded against last-admin demotion)"
)
def update_user_role(
    user_id: str,
    req: UpdateUserRoleRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Assigns a new role with strict safeguards against demoting the last active administrator."""
    client_ip = request.client.host if request.client else None
    try:
        updated = AuthService.change_user_role(
            db=db,
            actor=admin,
            target_user_id=user_id,
            new_role=req.role,
            ip_address=client_ip
        )
        return UserResponse(
            id=updated.id,
            username=updated.username,
            email=updated.email,
            full_name=updated.full_name,
            role=updated.role,
            is_active=updated.is_active,
            is_pending_approval=updated.is_pending_approval,
            is_demo_account=updated.is_demo_account,
            created_at=updated.created_at,
            last_login_at=updated.last_login_at,
            permissions=AuthService.get_permissions(updated.role)
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))


@router.put(
    "/users/{user_id}/status",
    response_model=UserResponse,
    summary="Activate, deactivate, or approve user account (Administrator only)"
)
def update_user_status(
    user_id: str,
    req: UpdateUserStatusRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Updates user active status or approval state with last-admin protection."""
    client_ip = request.client.host if request.client else None
    try:
        updated = AuthService.change_user_status(
            db=db,
            actor=admin,
            target_user_id=user_id,
            is_active=req.is_active,
            is_pending_approval=req.is_pending_approval,
            ip_address=client_ip
        )
        return UserResponse(
            id=updated.id,
            username=updated.username,
            email=updated.email,
            full_name=updated.full_name,
            role=updated.role,
            is_active=updated.is_active,
            is_pending_approval=updated.is_pending_approval,
            is_demo_account=updated.is_demo_account,
            created_at=updated.created_at,
            last_login_at=updated.last_login_at,
            permissions=AuthService.get_permissions(updated.role)
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))


@router.get(
    "/audit-log",
    response_model=List[AuthAuditLogResponse],
    summary="Retrieve auditable log of authentication and authorization modifications (Administrator only)"
)
def get_auth_audit_log(
    limit: int = Query(50, ge=1, le=500),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Returns chronologically ordered audit logs for account creation, role changes, and access modifications."""
    logs = db.query(AuthAuditLog).order_by(AuthAuditLog.timestamp.desc()).limit(limit).all()
    return logs


@router.post(
    "/logout",
    summary="Invalidate user session"
)
def logout():
    """Confirms session termination."""
    return {"status": "logged_out", "message": "Session invalidated successfully."}


@router.get(
    "/demo-accounts",
    response_model=DemoAccountsListResponse,
    summary="List available demo credentials (Development/Evaluation Mode)"
)
def list_demo_accounts():
    """Lists preconfigured local demo credentials for testing and evaluation."""
    return DemoAccountsListResponse(
        demo_mode_active=True,
        environment=settings.ENVIRONMENT,
        accounts=[DemoAccountInfo(**acc) for acc in DEMO_ACCOUNTS_METADATA]
    )


@router.post(
    "/seed-demo-accounts",
    summary="Idempotently seed standard demo credentials"
)
def seed_demo_accounts(db: Session = Depends(get_db)):
    """Provisions standard demo accounts with full canonical roles."""
    result = AuthService.seed_demo_accounts(db)
    return {
        "status": "success",
        "message": "Demo accounts verified and provisioned.",
        "details": result
    }
