"""
SQL-TRUST Authentication & RBAC Schemas
"""
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=128, description="User's full legal or operational name")
    email: str = Field(..., min_length=5, max_length=128, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", description="User's valid email address")
    username: str = Field(..., min_length=3, max_length=64, description="Alphanumeric unique account handle")
    password: str = Field(..., min_length=8, max_length=128, description="Cryptographic account passphrase")
    confirm_password: str = Field(..., min_length=8, max_length=128, description="Password confirmation")


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128, description="Username or email address")
    password: str = Field(..., min_length=1, max_length=128, description="Password")


class UserResponse(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    full_name: str
    role: str
    is_active: bool
    is_pending_approval: bool = False
    is_demo_account: bool = False
    created_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    permissions: List[str] = []

    model_config = {"from_attributes": True}


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    email: Optional[str] = None
    full_name: str
    role: str
    is_demo_account: bool
    permissions: List[str] = []


class UpdateUserRoleRequest(BaseModel):
    role: str = Field(..., min_length=2, max_length=32, description="Target role to assign")


class UpdateUserStatusRequest(BaseModel):
    is_active: Optional[bool] = None
    is_pending_approval: Optional[bool] = None


class DemoAccountInfo(BaseModel):
    role: str
    role_title: str
    username: str
    description: str
    permissions: List[str]


class DemoAccountsListResponse(BaseModel):
    demo_mode_active: bool
    environment: str
    accounts: List[DemoAccountInfo]


class AuthAuditLogResponse(BaseModel):
    id: str
    timestamp: datetime
    actor_username: str
    actor_role: str
    action: str
    target_username: Optional[str] = None
    details: str
    ip_address: Optional[str] = None

    model_config = {"from_attributes": True}
