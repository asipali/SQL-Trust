"""
SQL-TRUST Pydantic Schemas
Module 2: Security Monitoring Engine
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field


class SecuritySourceBase(BaseModel):
    source_name: str
    server_name: str
    source_type: str = "HYBRID"
    audit_target_path: Optional[str] = None
    xe_target_path: Optional[str] = None
    is_active: bool = True


class SecuritySourceCreate(SecuritySourceBase):
    pass


class SecuritySourceResponse(SecuritySourceBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    updated_at: datetime


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source_id: str
    event_source: str
    source_file: str
    source_event_id: Optional[str] = None
    event_type: str
    event_timestamp: datetime
    collection_timestamp: datetime
    server_name: str
    database_name: Optional[str] = None
    principal_name: Optional[str] = None
    session_id: Optional[int] = None
    client_ip: Optional[str] = None
    client_app: Optional[str] = None
    action: str
    target_object: Optional[str] = None
    success: bool
    severity: str
    event_fingerprint: str
    raw_payload: str
    evidence_reference: Optional[str] = None
    integrity_status: str
    created_at: datetime


class AlertStatusHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_id: str
    previous_status: str
    new_status: str
    changed_by: str
    comment: Optional[str] = None
    timestamp: datetime


class SecurityAlertStatusUpdate(BaseModel):
    status: str = Field(..., description="NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    changed_by: Optional[str] = "Administrator"
    comment: Optional[str] = None


class SecurityAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    status: str
    detection_timestamp: datetime
    principal_name: Optional[str] = None
    target_object: Optional[str] = None
    explanation: str
    confidence_score: float
    evidence_reference: Optional[str] = None
    related_event_count: int
    created_at: datetime
    updated_at: datetime
    status_history: Optional[List[AlertStatusHistoryResponse]] = None


class DetectionRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_id: str
    rule_name: str
    description: str
    condition_type: str
    threshold_value: int
    time_window_seconds: int
    severity: str
    is_enabled: bool
    created_at: datetime
    updated_at: datetime


class EvidenceArchiveResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source_id: str
    evidence_type: str
    source_file_path: str
    file_size_bytes: int
    sha256: str
    storage_bucket: str
    storage_object_key: str
    storage_version_id: Optional[str] = None
    retention_mode: str
    retention_until: Optional[datetime] = None
    manifest_id: str
    signature: Optional[str] = None
    collection_timestamp: datetime
    verification_status: str
    created_at: datetime


class CollectionTriggerResponse(BaseModel):
    success: bool
    source_id: str
    audit_collection: Optional[Dict[str, Any]] = None
    xe_collection: Optional[Dict[str, Any]] = None
    evidence_archived: Optional[List[Dict[str, Any]]] = None
