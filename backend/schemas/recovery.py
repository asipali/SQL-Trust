"""
SQL-TRUST Pydantic Schemas
Module 4: Cyber Recovery & State Reconstruction
Defines request and response schemas for recovery points, backup chains,
trust assessments, eligibility evaluations, ranked recommendations, and WORM verification.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class RecoveryPointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    database_id: str
    backup_id: Optional[str] = None
    server_name: str
    database_name: str
    recovery_point_time: datetime
    recovery_point_type: str
    first_lsn: Optional[str] = None
    last_lsn: Optional[str] = None
    checkpoint_lsn: Optional[str] = None
    database_backup_lsn: Optional[str] = None
    differential_base_guid: Optional[str] = None
    recovery_fork_guid: Optional[str] = None
    integrity_status: str
    sha256: Optional[str] = None
    storage_object_key: Optional[str] = None
    storage_version_id: Optional[str] = None
    retention_mode: Optional[str] = None
    retention_until: Optional[datetime] = None
    metadata_json: Optional[str] = None
    created_at: datetime


class RecoveryChainSegmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    chain_id: str
    recovery_point_id: str
    sequence_order: int
    segment_type: str
    first_lsn: Optional[str] = None
    last_lsn: Optional[str] = None
    checkpoint_lsn: Optional[str] = None
    is_continuous: bool
    continuity_gap_lsn: Optional[str] = None
    created_at: datetime


class RecoveryChainResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    database_id: str
    server_name: str
    database_name: str
    chain_name: str
    target_recovery_point_id: str
    base_full_point_id: str
    differential_point_id: Optional[str] = None
    is_complete: bool
    is_valid: bool
    validation_status: str
    validation_details: Optional[str] = None
    first_lsn: Optional[str] = None
    last_lsn: Optional[str] = None
    segment_count: int
    created_at: datetime
    segments: List[RecoveryChainSegmentResponse] = []


class ChainAnalyzeRequest(BaseModel):
    target_recovery_point_id: str = Field(..., description="ID of the candidate recovery point to analyze chain for.")


class RecoveryAssessmentCreateRequest(BaseModel):
    recovery_point_id: str = Field(..., description="ID of the recovery point to evaluate.")
    chain_id: Optional[str] = Field(None, description="Optional specific backup chain ID to evaluate.")
    assessment_name: Optional[str] = Field(None, description="Custom name for the assessment session.")
    archive_to_worm: Optional[bool] = Field(True, description="Whether to automatically archive signed assessment to SeaweedFS Object Lock.")


class RecoveryAssessmentEvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    assessment_id: str
    evidence_source: str
    source_record_id: str
    relationship_type: str
    time_delta_seconds: int
    impact_direction: str
    weight_applied: float
    description: str
    metadata_json: Optional[str] = None
    created_at: datetime


class RecoveryAssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    recovery_point_id: str
    chain_id: Optional[str] = None
    assessment_name: str
    model_version: str
    trust_classification: str
    trust_score: Optional[float] = None
    has_sufficient_evidence: bool
    confidence_rationale: str
    positive_indicators_json: Optional[str] = None
    negative_indicators_json: Optional[str] = None
    missing_telemetry_json: Optional[str] = None
    uncertainty_factors_json: Optional[str] = None
    manifest_sha256: Optional[str] = None
    signature: Optional[str] = None
    storage_object_key: Optional[str] = None
    storage_version_id: Optional[str] = None
    assessed_at: datetime
    evidence_items: List[RecoveryAssessmentEvidenceResponse] = []


class RecoveryEligibilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    recovery_point_id: str
    chain_id: Optional[str] = None
    is_eligible: bool
    eligibility_status: str
    requires_offline_sandbox: bool
    chain_usable: bool
    chain_consistent: bool
    logs_available: bool
    identity_matched: bool
    files_accessible: bool
    integrity_verified: bool
    critical_evidence_missing: bool
    blocking_reasons_json: Optional[str] = None
    validation_checklist_json: Optional[str] = None
    evaluated_at: datetime


class RecoveryRecommendationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    database_id: str
    recovery_point_id: str
    assessment_id: str
    eligibility_id: str
    rank_order: int
    trust_classification: str
    eligibility_status: str
    ranking_score: float
    rank_rationale: str
    tradeoff_analysis: str
    recommended_next_step: str
    created_at: datetime


class RecoveryHealthResponse(BaseModel):
    status: str
    database_connected: bool
    storage_connected: bool
    storage_bucket: str
    worm_compliance_active: bool
    total_recovery_points: int
    total_valid_chains: int
    total_assessments: int
