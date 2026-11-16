"""
SQL-TRUST Database API Schemas
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime


class DatabaseDiscoveredResponse(BaseModel):
    database_id: int
    name: str
    state: str
    recovery_model: str
    created_at: Optional[str] = None
    compatibility_level: Optional[int] = None
    is_system: bool
    is_registered: bool
    registration_id: Optional[str] = None
    registration_status: Optional[str] = None


class DatabaseRegisterRequest(BaseModel):
    database_name: str = Field(..., description="Exact database name on SQL Server instance")
    allow_system_override: bool = Field(default=False, description="Explicit administrator consent to register system DB")


class DatabaseRegisteredResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    server_name: str
    database_name: str
    database_identifier: Optional[str] = None
    recovery_model: str
    registration_status: str
    created_at: datetime


class ConnectionTestResponse(BaseModel):
    connected: bool
    server_name: Optional[str] = None
    version: Optional[str] = None
    driver: Optional[str] = None
    error: Optional[str] = None
