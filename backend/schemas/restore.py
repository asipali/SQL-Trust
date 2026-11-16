"""
SQL-TRUST Pydantic Schemas
Module 5: Restore & Cyber Recovery Validation
Defines request and response validation contracts for recovery jobs,
lifecycle approvals, and state machine transition histories.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class RecoveryJobCreateRequest(BaseModel):
    """Payload to initiate a new cyber recovery validation job."""
    candidate_id: str = Field(..., description="UUID of the Module 4 RecoveryRecommendation")
    idempotency_key: Optional[str] = Field(None, max_length=128, description="Unique client key to prevent duplicate job creation")
    requested_by: Optional[str] = Field(None, max_length=128, description="User or service identity requesting the job")
    notes: Optional[str] = Field(None, description="Operational notes or investigation ticket references")


class RecoveryJobApproveRequest(BaseModel):
    """Payload to authorize execution of preflight and staging for a recovery job."""
    approved_by: Optional[str] = Field(None, max_length=128, description="Identity of authorizing administrator")
    approver_notes: Optional[str] = Field(None, description="Justification and approval context")


class RecoveryJobCancelRequest(BaseModel):
    """Payload to gracefully cancel an active recovery job without destroying evidence."""
    cancellation_reason: str = Field(..., min_length=3, description="Mandatory reason for job cancellation")
    cancelled_by: Optional[str] = Field(None, max_length=128, description="Identity of operator cancelling the job")


class RecoveryJobHistoryResponse(BaseModel):
    """Immutable transition audit record."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    from_state: str
    to_state: str
    actor: str
    reason: Optional[str] = None
    evidence_reference: Optional[str] = None
    transitioned_at: datetime


class RecoveryJobResponse(BaseModel):
    """Core recovery job status and metadata response."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_reference: str
    candidate_id: str
    recovery_point_id: str
    target_database_name: str
    status: str
    requested_by: str
    approved_by: Optional[str] = None
    requested_at: datetime
    approved_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    failure_code: Optional[str] = None
    failure_reason: Optional[str] = None
    idempotency_key: Optional[str] = None
    target_recovery_time: Optional[datetime] = None
    target_time_basis: str
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class RecoveryJobDetailResponse(RecoveryJobResponse):
    """Detailed recovery job view including transition history and candidate context."""
    history: List[RecoveryJobHistoryResponse] = []
    staging_records: List["BackupStagingResponse"] = []
    trust_classification: Optional[str] = None
    eligibility_status: Optional[str] = None
    ranking_score: Optional[float] = None


class BackupStagingResponse(BaseModel):
    """Status and metadata of an individual staged and verified backup file."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    recovery_point_id: str
    sequence_order: int
    backup_type: str
    storage_object_key: str
    staged_file_path: str
    file_size_bytes: int
    expected_sha256: str
    computed_sha256: Optional[str] = None
    verification_status: str
    error_message: Optional[str] = None
    staged_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class StagingStatusResponse(BaseModel):
    """Aggregate staging progress and integrity verification summary for a recovery job."""
    job_id: str
    job_reference: str
    overall_status: str
    total_artifacts: int
    staged_count: int
    verified_count: int
    total_bytes: int
    artifacts: List[BackupStagingResponse] = []


# ==============================================================================
# Phase 4: Recovery Sandbox Schemas
# ==============================================================================

class SandboxProvisionRequest(BaseModel):
    """Payload to provision a dedicated recovery sandbox container."""
    cpu_limit: Optional[str] = Field("2.0", description="Maximum CPU allocation (e.g. 2.0)")
    memory_limit: Optional[str] = Field("2048m", description="Maximum memory allocation (e.g. 2048m)")


class SandboxResponse(BaseModel):
    """Serialization model for an isolated recovery sandbox."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    container_id: Optional[str] = None
    container_name: str
    docker_image: str
    docker_network: str
    data_volume: str
    log_volume: str
    staging_mount_path: str
    host_port: int
    lifecycle_status: str
    is_isolated: bool
    network_isolated: bool
    storage_isolated: bool
    cpu_limit: str
    memory_limit: str
    health_checked_at: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    cleaned_at: Optional[datetime] = None


class SandboxHealthResponse(BaseModel):
    """Detailed health check and security isolation verification status."""
    job_id: str
    container_name: str
    lifecycle_status: str
    host_port: int
    is_healthy: bool
    all_isolation_checks_passed: bool
    isolation_evidence: Optional[Dict[str, Any]] = None


class SandboxQuarantineRequest(BaseModel):
    """Payload to freeze and quarantine a suspect sandbox."""
    reason: str = Field(..., min_length=3, description="Justification for quarantine")


class SandboxCleanupRequest(BaseModel):
    """Payload to request authorized sandbox teardown."""
    authorized_by: Optional[str] = Field(None, description="Authorizing administrator identity")
    force: Optional[bool] = Field(False, description="Force teardown if quarantined")


# ==============================================================================
# Phase 5: Restore Orchestration Schemas
# ==============================================================================

class RestorePlanCreateRequest(BaseModel):
    """Payload to generate a multi-step restore execution plan."""
    target_database_name: Optional[str] = Field(None, description="Target database name override")
    target_stopat_utc: Optional[datetime] = Field(None, description="Point-in-time STOPAT UTC timestamp")


class RestoreOperationResponse(BaseModel):
    """Execution status of an individual physical restore operation."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    plan_id: str
    job_id: str
    sequence_number: int
    operation_type: str
    backup_file_path: str
    t_sql_command: str
    status: str
    sql_server_messages: Optional[str] = None
    error_details: Optional[str] = None
    execution_duration_ms: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class RestorePlanResponse(BaseModel):
    """Multi-step restore execution plan with explicit LSN/STOPAT boundaries."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    sandbox_id: str
    target_database_name: str
    full_artifact_id: str
    differential_artifact_id: Optional[str] = None
    total_operations: int
    plan_steps_json: str
    target_stopat_utc: Optional[datetime] = None
    target_stopat_local: Optional[datetime] = None
    status: str
    created_at: datetime
    operations: List[RestoreOperationResponse] = []


class RestoreExecutionResponse(BaseModel):
    """Aggregate result of executing a restore plan."""
    job_id: str
    plan_id: str
    status: str
    operations_completed: int
    total_operations: int
    operations: List[RestoreOperationResponse] = []


# ==============================================================================
# Phase 6: Recovery Validation & Forensics Schemas
# ==============================================================================

class ValidationStartRequest(BaseModel):
    """Payload to initiate forensic inspection and DBCC CHECKDB."""
    baseline_id: Optional[str] = Field(None, description="Optional Module 3 ForensicBaseline ID for comparison")


class RecoveryFindingResponse(BaseModel):
    """Granular forensic or consistency finding."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    validation_id: str
    job_id: str
    category: str
    severity: str
    finding_type: str
    entity_name: str
    description: str
    evidence_reference: Optional[str] = None
    recommended_action: Optional[str] = None
    created_at: datetime


class RecoveryValidationResponse(BaseModel):
    """Central recovery validation report with 4-tier outcome."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    sandbox_id: str
    target_database_name: str
    dbcc_status: str
    dbcc_errors_count: int
    schema_validation_status: str
    baseline_comparison_status: str
    security_inspection_status: str
    unauthorized_principals_count: int
    suspicious_objects_count: int
    overall_assessment: str
    assessment_rationale: str
    validated_at: datetime
    findings: List[RecoveryFindingResponse] = []


# ==============================================================================
# Phase 7: Evidence, Chain of Custody & Reporting Schemas
# ==============================================================================

class RecoveryEvidenceResponse(BaseModel):
    """Cryptographically tracked evidence item."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    evidence_category: str
    source_artifact: str
    original_sha256: str
    verified_sha256: Optional[str] = None
    storage_object_key: Optional[str] = None
    collected_by: str
    collected_at: datetime
    integrity_status: str


class RecoveryCustodyResponse(BaseModel):
    """Chain-of-custody audit event."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_id: str
    job_id: str
    action: str
    actor: str
    action_details: Optional[str] = None
    recorded_at: datetime


class FinalReportResponse(BaseModel):
    """Authoritative final recovery validation report with digital signature."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    report_reference: str
    overall_assessment: str
    assessment_reason: str
    report_json: str
    report_sha256: str
    signature: Optional[str] = None
    pdf_path: Optional[str] = None
    generated_by: str
    generated_at: datetime


RecoveryJobDetailResponse.model_rebuild()
