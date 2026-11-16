"""
SQL-TRUST Pydantic Schemas
Module 3: Database Forensics Engine
Defines request and response schemas for baseline captures, granular items,
forensic investigations, findings, correlations, and evidence verification.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class BaselineCaptureRequest(BaseModel):
    database_name: str = Field(..., description="Target database name to capture baseline for.")
    server_name: Optional[str] = Field("localhost\\SQLEXPRESS", description="SQL Server instance name.")
    baseline_name: Optional[str] = Field(None, description="Custom name for the baseline snapshot.")
    notes: Optional[str] = Field(None, description="Administrative context or reason for baseline capture.")
    archive_to_worm: Optional[bool] = Field(True, description="Whether to automatically archive signed baseline to SeaweedFS Object Lock.")


class BaselineItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    baseline_id: str
    item_type: str
    schema_name: Optional[str] = None
    item_name: str
    definition_hash: Optional[str] = None
    raw_definition: Optional[str] = None
    properties_json: str
    is_encrypted: bool
    created_at: datetime


class BaselineResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    database_id: Optional[str] = None
    server_name: str
    database_name: str
    baseline_name: str
    baseline_type: str
    status: str
    captured_at: datetime
    total_objects: int
    total_principals: int
    total_permissions: int
    sha256_manifest: str
    storage_object_key: Optional[str] = None
    storage_version_id: Optional[str] = None
    signature: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime


class InvestigationCreateRequest(BaseModel):
    ref_baseline_id: str = Field(..., description="Reference baseline ID (earlier trusted baseline).")
    target_baseline_id: str = Field(..., description="Target baseline ID (later or compromised state).")
    investigation_name: Optional[str] = Field(None, description="Investigation session name.")
    summary_notes: Optional[str] = Field(None, description="Investigator notes.")


class ForensicCorrelationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    event_id: str
    correlation_type: str
    time_delta_seconds: int
    confidence_score: float
    correlation_notes: Optional[str] = None
    created_at: datetime


class ForensicFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    category: str
    finding_type: str
    severity: str
    entity_name: str
    schema_name: Optional[str] = None
    before_state_json: Optional[str] = None
    after_state_json: Optional[str] = None
    explanation: str
    confidence_score: float
    detected_at: datetime
    correlations: List[ForensicCorrelationResponse] = []


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_name: str
    server_name: str
    database_name: str
    ref_baseline_id: str
    target_baseline_id: Optional[str] = None
    status: str
    findings_count: int
    critical_findings_count: int
    high_findings_count: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    summary_notes: Optional[str] = None
    manifest_sha256: Optional[str] = None
    signature: Optional[str] = None
    storage_object_key: Optional[str] = None
    storage_version_id: Optional[str] = None
    findings: List[ForensicFindingResponse] = []


class TimelineEntry(BaseModel):
    timestamp: str
    timeline_type: str
    title: str
    description: str
    severity: str
    metadata: Dict[str, Any] = {}


class EvidenceVerificationResponse(BaseModel):
    valid: bool
    archive_id: str
    evidence_type: Optional[str] = None
    sha256_match: Optional[bool] = None
    signature_valid: Optional[bool] = None
    worm_mode: Optional[str] = None
    retention_until: Optional[str] = None
    version_id: Optional[str] = None
    storage_object_key: Optional[str] = None
    error: Optional[str] = None
