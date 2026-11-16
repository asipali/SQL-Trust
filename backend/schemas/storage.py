"""
SQL-TRUST Storage API Schemas
"""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class StorageHealthResponse(BaseModel):
    connected: bool
    endpoint: str
    bucket: str
    provider: str
    versioning_status: str
    object_lock_enabled: bool
    retention_mode: Optional[str] = None
    retention_period_days: Optional[int] = None
    immutability_guarantee: str
    warnings: List[str] = []
    error: Optional[str] = None


class StoredBackupObject(BaseModel):
    key: str
    size_bytes: int
    last_modified: str
    etag: str
