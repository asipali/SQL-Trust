"""
SQL-TRUST Authentication & Role-Based Access Control (RBAC) Service
Provides cryptographic password hashing, stateless token management,
user verification, canonical permission enforcement, and auditable user administration.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Set
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.config import settings
from backend.models.auth import User, AuthAuditLog
from backend.models.backup import utc_now


# Security Configuration
SECRET_KEY = os.getenv("SQLTRUST_AUTH_SECRET", "sqltrust-secure-dev-hmac-key-2026-production-isolated")
TOKEN_EXPIRATION_HOURS = 24
PBKDF2_ITERATIONS = 100_000

# Canonical Role Definitions & Explicit Permission Matrix
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    # 1. SECURITY_ADMIN / Admin (Highest application-level privileges)
    "SECURITY_ADMIN": [
        "dashboard.view",
        "backup.view", "backup.create", "backup.verify", "backup.restore.request",
        "security.view", "security.alerts.review", "security.manage",
        "forensics.view", "forensics.analyze", "forensics.capture",
        "recovery.view", "recovery.plan", "recovery.assess", "recovery.approve",
        "restore.read", "restore.create", "restore.approve", "restore.sandbox", "restore.teardown",
        "investigation.view", "investigation.create", "investigation.update", "investigation.assign", "investigation.close",
        "evidence.view", "evidence.collect", "evidence.verify", "evidence.export",
        "reports.view", "reports.create", "reports.review", "reports.sign",
        "users.view", "users.create", "users.update", "users.disable",
        "roles.view", "roles.manage", "permissions.manage", "system.settings.manage", "audit.view",
        # Colon-separated compatibility mappings
        "databases:read", "databases:write", "backups:create", "backups:verify", "backups:read",
        "security:read", "security:manage", "forensics:read", "forensics:capture",
        "recovery:read", "recovery:assess", "restore:create", "restore:approve",
        "restore:sandbox", "restore:teardown", "restore:read",
        "investigations:read", "investigations:write", "investigations:close",
        "response_plans:create", "response_plans:approve", "response_plans:execute", "response_plans:read"
    ],

    # 2. INCIDENT_APPROVER / Reviewer (Separation of Duties approver)
    "INCIDENT_APPROVER": [
        "dashboard.view",
        "backup.view",
        "security.view", "security.alerts.review",
        "forensics.view",
        "recovery.view", "recovery.plan", "recovery.approve",
        "restore.read", "restore.approve",
        "investigation.view", "investigation.update",
        "evidence.view", "evidence.verify",
        "reports.view", "reports.review", "reports.sign",
        "audit.view",
        # Legacy compatibility mappings
        "databases:read", "backups:read", "security:read", "forensics:read",
        "recovery:read", "restore:read", "restore:approve",
        "investigations:read", "response_plans:read", "response_plans:approve"
    ],

    # 3. SENIOR_ANALYST / Analyst (Senior DFIR triage and correlation)
    "SENIOR_ANALYST": [
        "dashboard.view",
        "backup.view",
        "security.view", "security.alerts.review", "security.manage",
        "forensics.view", "forensics.analyze", "forensics.capture",
        "recovery.view", "recovery.plan", "recovery.assess",
        "restore.read",
        "investigation.view", "investigation.create", "investigation.update", "investigation.assign",
        "evidence.view", "evidence.collect", "evidence.verify", "evidence.export",
        "reports.view", "reports.create", "reports.review",
        "audit.view",
        # Legacy compatibility mappings
        "databases:read", "backups:read", "security:read", "security:manage",
        "forensics:read", "forensics:capture", "recovery:read", "recovery:assess",
        "restore:read", "investigations:read", "investigations:write",
        "response_plans:create", "response_plans:read"
    ],

    # 4. INVESTIGATION_ANALYST / Investigator (Lead incident intake and task execution)
    "INVESTIGATION_ANALYST": [
        "dashboard.view",
        "backup.view",
        "security.view", "security.alerts.review",
        "forensics.view", "forensics.capture",
        "recovery.view",
        "restore.read",
        "investigation.view", "investigation.create", "investigation.update", "investigation.close",
        "evidence.view", "evidence.collect", "evidence.verify",
        "reports.view", "reports.create",
        # Legacy compatibility mappings
        "databases:read", "backups:read", "security:read", "forensics:read",
        "recovery:read", "restore:read",
        "investigations:read", "investigations:write", "investigations:close",
        "response_plans:create", "response_plans:execute", "response_plans:read"
    ],

    # 5. INCIDENT_REVIEWER (Case and evidence commentary)
    "INCIDENT_REVIEWER": [
        "dashboard.view",
        "security.view",
        "forensics.view",
        "investigation.view",
        "evidence.view",
        "reports.view",
        # Legacy compatibility mappings
        "databases:read", "backups:read", "security:read", "forensics:read",
        "investigations:read", "response_plans:read"
    ],

    # 6. AUDITOR / Auditor (Compliance and chain-of-custody reader)
    "AUDITOR": [
        "dashboard.view",
        "backup.view",
        "security.view",
        "forensics.view",
        "recovery.view",
        "restore.read",
        "investigation.view",
        "evidence.view",
        "reports.view",
        "audit.view",
        # Legacy compatibility mappings
        "databases:read", "backups:read", "security:read", "forensics:read",
        "recovery:read", "restore:read", "investigations:read", "response_plans:read"
    ],

    # 7. READ_ONLY_REVIEWER (Safe least-privilege default role for newly registered users)
    "READ_ONLY_REVIEWER": [
        "dashboard.view",
        "security.view",
        "reports.view",
        "databases:read"
    ]
}

# Role aliases for 100% backward compatibility
ROLE_ALIASES = {
    "Admin": "SECURITY_ADMIN",
    "Investigator": "INVESTIGATION_ANALYST",
    "Analyst": "SENIOR_ANALYST",
    "Reviewer": "INCIDENT_APPROVER",
    "Auditor": "AUDITOR",
    "Operator": "READ_ONLY_REVIEWER"
}

# Populate legacy names into permissions map so lookups by "Admin" or "SECURITY_ADMIN" both succeed
ROLE_PERMISSIONS["Admin"] = ROLE_PERMISSIONS["SECURITY_ADMIN"]
ROLE_PERMISSIONS["Investigator"] = ROLE_PERMISSIONS["INVESTIGATION_ANALYST"]
ROLE_PERMISSIONS["Analyst"] = ROLE_PERMISSIONS["SENIOR_ANALYST"]
ROLE_PERMISSIONS["Reviewer"] = ROLE_PERMISSIONS["INCIDENT_APPROVER"]
ROLE_PERMISSIONS["Auditor"] = ROLE_PERMISSIONS["AUDITOR"]

DEMO_ACCOUNTS_METADATA = [
    {
        "role": "SECURITY_ADMIN",
        "role_title": "Platform Administrator",
        "username": "demo_admin",
        "description": "Full administrative privileges across all SQL-TRUST control plane modules, users, and storage.",
        "permissions": ROLE_PERMISSIONS["SECURITY_ADMIN"]
    },
    {
        "role": "INVESTIGATION_ANALYST",
        "role_title": "Lead Cyber Investigator",
        "username": "demo_investigator",
        "description": "Creates investigations, links WORM evidence, assigns tasks, and executes containment plans.",
        "permissions": ROLE_PERMISSIONS["INVESTIGATION_ANALYST"]
    },
    {
        "role": "SENIOR_ANALYST",
        "role_title": "Senior Security Operations Analyst",
        "username": "demo_analyst",
        "description": "Triages security alerts, performs cryptographic baseline comparisons, and assesses recovery trust.",
        "permissions": ROLE_PERMISSIONS["SENIOR_ANALYST"]
    },
    {
        "role": "INCIDENT_APPROVER",
        "role_title": "Incident & Recovery Approver",
        "username": "demo_reviewer",
        "description": "Enforces Separation of Duties (SoD) approvals on recovery sandboxes and response plans.",
        "permissions": ROLE_PERMISSIONS["INCIDENT_APPROVER"]
    },
    {
        "role": "AUDITOR",
        "role_title": "Read-Only Compliance Auditor",
        "username": "demo_auditor",
        "description": "Audits chain-of-custody signatures, immutable WORM manifests, and platform access logs.",
        "permissions": ROLE_PERMISSIONS["AUDITOR"]
    }
]


class AuthService:
    """Manages user authentication, token cryptography, demo accounts, and RBAC authorization."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using salted PBKDF2-HMAC-SHA256."""
        salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
        salt_b64 = base64.b64encode(salt).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")
        return f"pbkdf2:sha256:{PBKDF2_ITERATIONS}${salt_b64}${key_b64}"

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verify a plaintext password against the stored PBKDF2 hash."""
        try:
            algorithm, salt_b64, key_b64 = hashed_password.split("$")
            iterations = int(algorithm.split(":")[2])
            salt = base64.b64decode(salt_b64.encode("ascii"))
            expected_key = base64.b64decode(key_b64.encode("ascii"))
            actual_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(actual_key, expected_key)
        except Exception:
            return False

    @classmethod
    def normalize_role(cls, role: str) -> str:
        """Map legacy or alternative casing to canonical role name."""
        if not role:
            return "READ_ONLY_REVIEWER"
        cleaned = role.strip()
        return ROLE_ALIASES.get(cleaned, cleaned)

    @classmethod
    def is_admin(cls, role: str) -> bool:
        """Returns True if the role represents administrative authority."""
        canonical = cls.normalize_role(role)
        return canonical in ("SECURITY_ADMIN", "Admin")

    @classmethod
    def get_permissions(cls, role: str) -> List[str]:
        """Returns all canonical permissions possessed by the given role."""
        if cls.is_admin(role):
            return list(set(ROLE_PERMISSIONS["SECURITY_ADMIN"]))
        canonical = cls.normalize_role(role)
        return list(set(ROLE_PERMISSIONS.get(canonical, ROLE_PERMISSIONS.get("READ_ONLY_REVIEWER", []))))

    @classmethod
    def has_permission(cls, role: str, permission: str) -> bool:
        """Check if a given role possesses a specific permission."""
        if cls.is_admin(role):
            return True
        perms = cls.get_permissions(role)
        if permission in perms:
            return True
        
        # Support cross-notation matching (e.g. "backup.create" <-> "backups:create")
        normalized = permission.replace(":", ".").replace("backups.", "backup.").replace("investigations.", "investigation.")
        for p in perms:
            p_norm = p.replace(":", ".").replace("backups.", "backup.").replace("investigations.", "investigation.")
            if p_norm == normalized:
                return True
        return False

    @classmethod
    def create_access_token(cls, user_or_data: Any, expires_minutes: Optional[int] = None) -> str:
        """Generate a cryptographically signed HMAC token for the user session."""
        now = datetime.now(timezone.utc)
        exp_delta = timedelta(minutes=expires_minutes) if expires_minutes else timedelta(hours=TOKEN_EXPIRATION_HOURS)
        
        if isinstance(user_or_data, dict):
            sub = str(user_or_data.get("sub", user_or_data.get("user_id", "anonymous")))
            username = user_or_data.get("username", user_or_data.get("sub", ""))
            role = user_or_data.get("role", "READ_ONLY_REVIEWER")
            full_name = user_or_data.get("full_name", username)
            email = user_or_data.get("email")
            is_demo = user_or_data.get("is_demo_account", False)
        else:
            sub = str(user_or_data.id)
            username = user_or_data.username
            role = user_or_data.role
            full_name = user_or_data.full_name
            email = getattr(user_or_data, "email", None)
            is_demo = user_or_data.is_demo_account

        permissions = cls.get_permissions(role)

        payload = {
            "sub": sub,
            "username": username,
            "email": email,
            "role": role,
            "full_name": full_name,
            "is_demo_account": is_demo,
            "permissions": permissions,
            "iat": int(now.timestamp()),
            "exp": int((now + exp_delta).timestamp())
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        signature = hmac.new(SECRET_KEY.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        return f"{payload_b64}.{sig_b64}"

    @staticmethod
    def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
        """Validate and decode a signed session token."""
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return None
            payload_b64, sig_b64 = parts
            
            # Verify signature
            expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
            actual_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
            if not hmac.compare_digest(expected_sig, actual_sig):
                return None
            
            # Decode payload
            payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
            payload = json.loads(payload_bytes.decode("utf-8"))
            
            # Check expiry
            if payload.get("exp", 0) < datetime.now(timezone.utc).timestamp():
                return None
            
            return payload
        except Exception:
            return None

    @classmethod
    def authenticate_user(cls, db: Session, identifier: str, password: str) -> Optional[User]:
        """Authenticate user by username or email."""
        clean_id = identifier.strip()
        user = db.query(User).filter(
            or_(User.username == clean_id, User.email == clean_id)
        ).first()

        if not user:
            return None
        if not cls.verify_password(password, user.hashed_password):
            return None
        
        user.last_login_at = utc_now()
        db.commit()
        return user

    @classmethod
    def log_audit(
        cls,
        db: Session,
        actor_username: str,
        actor_role: str,
        action: str,
        details: str,
        target_username: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> AuthAuditLog:
        """Records an auditable security event."""
        log_entry = AuthAuditLog(
            actor_username=actor_username,
            actor_role=actor_role,
            action=action,
            target_username=target_username,
            details=details,
            ip_address=ip_address
        )
        db.add(log_entry)
        db.commit()
        return log_entry

    @classmethod
    def register_user(
        cls,
        db: Session,
        full_name: str,
        email: str,
        username: str,
        password: str,
        ip_address: Optional[str] = None
    ) -> User:
        """
        Registers a new user with safe least-privilege READ_ONLY_REVIEWER role.
        Role escalation is impossible through registration.
        """
        clean_username = username.strip()
        clean_email = email.strip().lower()

        # Check existing username
        if db.query(User).filter(User.username == clean_username).first():
            raise ValueError(f"Username '{clean_username}' is already registered.")

        # Check existing email
        if db.query(User).filter(User.email == clean_email).first():
            raise ValueError(f"Email '{clean_email}' is already registered.")

        hashed = cls.hash_password(password)
        new_user = User(
            full_name=full_name.strip(),
            email=clean_email,
            username=clean_username,
            hashed_password=hashed,
            role="READ_ONLY_REVIEWER",  # Mandatory least-privilege default
            is_active=True,
            is_pending_approval=False,
            is_demo_account=False
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        cls.log_audit(
            db=db,
            actor_username=clean_username,
            actor_role="READ_ONLY_REVIEWER",
            action="USER_REGISTERED",
            target_username=clean_username,
            details=f"New user self-registered with default least-privilege role READ_ONLY_REVIEWER",
            ip_address=ip_address
        )

        return new_user

    @classmethod
    def change_user_role(
        cls,
        db: Session,
        actor: User,
        target_user_id: str,
        new_role: str,
        ip_address: Optional[str] = None
    ) -> User:
        """
        Updates a user's assigned role with last-admin demotion protection.
        """
        if not cls.is_admin(actor.role):
            raise PermissionError("Only administrators may modify user roles.")

        target = db.query(User).filter(User.id == target_user_id).first()
        if not target:
            raise ValueError(f"User with ID '{target_user_id}' does not exist.")

        canonical_new_role = cls.normalize_role(new_role)
        if canonical_new_role not in ROLE_PERMISSIONS:
            raise ValueError(f"Invalid role '{new_role}'. Valid roles: {list(ROLE_PERMISSIONS.keys())}")

        # Protect against removing the last active administrator
        if cls.is_admin(target.role) and not cls.is_admin(canonical_new_role):
            admin_count = db.query(User).filter(
                or_(User.role == "Admin", User.role == "SECURITY_ADMIN"),
                User.is_active == True
            ).count()
            if admin_count <= 1:
                raise ValueError("Operation rejected: Cannot demote or revoke the last active administrator account.")

        old_role = target.role
        target.role = canonical_new_role
        db.commit()
        db.refresh(target)

        cls.log_audit(
            db=db,
            actor_username=actor.username,
            actor_role=actor.role,
            action="ROLE_CHANGED",
            target_username=target.username,
            details=f"Role changed from {old_role} to {canonical_new_role}",
            ip_address=ip_address
        )

        return target

    @classmethod
    def change_user_status(
        cls,
        db: Session,
        actor: User,
        target_user_id: str,
        is_active: Optional[bool] = None,
        is_pending_approval: Optional[bool] = None,
        ip_address: Optional[str] = None
    ) -> User:
        """
        Updates user active/approval status with last-admin protection.
        """
        if not cls.is_admin(actor.role):
            raise PermissionError("Only administrators may modify account status.")

        target = db.query(User).filter(User.id == target_user_id).first()
        if not target:
            raise ValueError(f"User with ID '{target_user_id}' does not exist.")

        # Protect against disabling the last active administrator
        if is_active is False and cls.is_admin(target.role):
            admin_count = db.query(User).filter(
                or_(User.role == "Admin", User.role == "SECURITY_ADMIN"),
                User.is_active == True
            ).count()
            if admin_count <= 1:
                raise ValueError("Operation rejected: Cannot deactivate the last active administrator account.")

        changes = []
        if is_active is not None:
            target.is_active = is_active
            changes.append(f"is_active={is_active}")
        if is_pending_approval is not None:
            target.is_pending_approval = is_pending_approval
            changes.append(f"is_pending_approval={is_pending_approval}")

        db.commit()
        db.refresh(target)

        cls.log_audit(
            db=db,
            actor_username=actor.username,
            actor_role=actor.role,
            action="STATUS_CHANGED",
            target_username=target.username,
            details=f"Status modified: {', '.join(changes)}",
            ip_address=ip_address
        )

        return target

    @classmethod
    def seed_demo_accounts(cls, db: Session) -> Dict[str, Any]:
        """
        Idempotently provisions the 5 standard demo accounts.
        If an account already exists, it is preserved without modification.
        """
        created = []
        existing = []

        credentials_map = {
            "demo_admin": ("Administrator", "demo_admin", "admin@sqltrust.internal", "SQLTrustDemo!Admin2026", "SECURITY_ADMIN"),
            "demo_investigator": ("Lead Investigator", "demo_investigator", "investigator@sqltrust.internal", "SQLTrustDemo!Investigator2026", "INVESTIGATION_ANALYST"),
            "demo_analyst": ("Senior Analyst", "demo_analyst", "analyst@sqltrust.internal", "SQLTrustDemo!Analyst2026", "SENIOR_ANALYST"),
            "demo_reviewer": ("Incident Reviewer", "demo_reviewer", "reviewer@sqltrust.internal", "SQLTrustDemo!Reviewer2026", "INCIDENT_APPROVER"),
            "demo_auditor": ("Compliance Auditor", "demo_auditor", "auditor@sqltrust.internal", "SQLTrustDemo!Auditor2026", "AUDITOR")
        }

        for username, (full_name, uname, email, pwd, role) in credentials_map.items():
            user = db.query(User).filter(User.username == uname).first()
            if not user:
                hashed = cls.hash_password(pwd)
                new_user = User(
                    username=uname,
                    email=email,
                    hashed_password=hashed,
                    full_name=full_name,
                    role=role,
                    is_active=True,
                    is_pending_approval=False,
                    is_demo_account=True
                )
                db.add(new_user)
                created.append(uname)
            else:
                existing.append(uname)

        db.commit()
        return {
            "created": created,
            "existing": existing,
            "total_demo_accounts": len(credentials_map)
        }
