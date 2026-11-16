"""
SQL-TRUST Backup Schemas
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime


class BackupCreateRequest(BaseModel):
    database_id: str = Field(..., description="ID of registered database")
    notes: Optional[str] = Field(default=None, description="Operator notes or ticket reference")


class BackupOperationLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    operation: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_details: Optional[str] = None


class BackupRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    database_id: str
    database_name: Optional[str] = None
    backup_type: str
    backup_filename: str
    backup_path: str
    backup_size_bytes: int
    start_time: datetime
    finish_time: Optional[datetime] = None
    first_lsn: Optional[str] = None
    last_lsn: Optional[str] = None
    checkpoint_lsn: Optional[str] = None
    database_backup_lsn: Optional[str] = None
    sha256: Optional[str] = None
    sql_verification_status: str
    storage_upload_status: str
    storage_object_key: Optional[str] = None
    storage_object_version_id: Optional[str] = None
    retention_mode: Optional[str] = None
    retention_until: Optional[datetime] = None
    backup_status: str
    error_message: Optional[str] = None
    created_at: datetime


class BackupManifestResponse(BaseModel):
    id: str
    backup_id: str
    manifest_version: str
    manifest_hash: str
    manifest_data: Dict[str, Any]
    created_at: datetime


class BackupVerificationResponse(BaseModel):
    backup_id: str
    filename: str
    sql_verification: str
    file_integrity: str
    sha256_match: bool
    stored_sha256: Optional[str] = None
    calculated_sha256: Optional[str] = None
    verified_at: str
    downloaded_from_storage: bool
    sql_verification_error: Optional[str] = None
    file_integrity_error: Optional[str] = None


class BackupStatsResponse(BaseModel):
    total_backups: int
    successful_backups: int
    failed_backups: int
    total_size_bytes: int
    latest_backup_timestamp: Optional[str] = None
