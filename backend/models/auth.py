"""
SQL-TRUST Authentication & User Models
Provides user identities, role-based access control (RBAC), and authentication audit logging.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime
from backend.models.backup import Base, utc_now


class User(Base):
    """Platform operator, analyst, or administrator account."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=True, index=True)
    hashed_password = Column(String(256), nullable=False)
    full_name = Column(String(128), nullable=False)
    role = Column(String(32), default="READ_ONLY_REVIEWER", nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_pending_approval = Column(Boolean, default=False, nullable=False)
    is_demo_account = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    last_login_at = Column(DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role,
            "is_active": self.is_active,
            "is_pending_approval": self.is_pending_approval,
            "is_demo_account": self.is_demo_account,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None
        }


class AuthAuditLog(Base):
    """Immutable audit log of all privileged account and permission modifications."""
    __tablename__ = "auth_audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    actor_username = Column(String(64), nullable=False)
    actor_role = Column(String(32), nullable=False)
    action = Column(String(64), nullable=False)  # USER_REGISTERED, ROLE_CHANGED, STATUS_CHANGED, LOGIN_FAILED, PERMISSION_DENIED
    target_username = Column(String(64), nullable=True)
    details = Column(String(512), nullable=False)
    ip_address = Column(String(64), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "actor_username": self.actor_username,
            "actor_role": self.actor_role,
            "action": self.action,
            "target_username": self.target_username,
            "details": self.details,
            "ip_address": self.ip_address
        }
