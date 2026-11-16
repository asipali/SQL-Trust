"""
SQL-TRUST Pydantic Schemas
Module 6: Cyber Investigation & Incident Response Orchestration
Defines request and response validation contracts for investigation cases,
status transitions, analyst notes, cross-module evidence links, containment
actions, and tamper-evident audit logs.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class CaseCreateRequest(BaseModel):
    """Payload to create a new cyber investigation case."""
    title: str = Field(..., min_length=3, max_length=256, description="Concise investigation case summary")
    description: Optional[str] = Field(None, description="Detailed case narrative, context, or hypothesis")
    target_database_name: str = Field(..., min_length=1, max_length=128, description="Primary database under investigation")
    target_database_id: Optional[str] = Field(None, max_length=36, description="Optional UUID of ProtectedDatabase")
    priority: Optional[str] = Field("P3_MEDIUM", description="Case priority: P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW")
    incident_category: Optional[str] = Field("SUSPICIOUS_ACTIVITY", description="Category: RANSOMWARE, DATA_EXFILTRATION, PRIVILEGE_ESCALATION, SCHEMA_TAMPERING, SUSPICIOUS_ACTIVITY")
    created_by: str = Field(..., min_length=1, max_length=128, description="User or service identity opening the case")
    lead_investigator: Optional[str] = Field(None, max_length=128, description="Assigned lead investigator")
    assigned_team: Optional[str] = Field(None, max_length=128, description="Designated response team (e.g., SOC, DBA-SEC)")
    idempotency_key: Optional[str] = Field(None, max_length=128, description="Unique client key to prevent duplicate case creation")


class CaseUpdateRequest(BaseModel):
    """Payload to update investigation case metadata."""
    title: Optional[str] = Field(None, min_length=3, max_length=256)
    description: Optional[str] = None
    priority: Optional[str] = None
    incident_category: Optional[str] = None
    lead_investigator: Optional[str] = None
    assigned_team: Optional[str] = None
    blast_radius_summary: Optional[str] = None
    expected_version: Optional[int] = Field(None, description="Expected case version for optimistic concurrency control")


class CaseTransitionRequest(BaseModel):
    """Payload to transition an investigation case through the FSM."""
    to_status: str = Field(..., description="Target status: NEW, TRIAGED, ACTIVE, CONTAINMENT_REVIEW, RECOVERY_COORDINATION, RESOLVED, CLOSED, CANCELLED")
    changed_by: str = Field(..., min_length=1, max_length=128, description="Operator or service executing the transition")
    transition_reason: Optional[str] = Field(None, description="Justification for the state change")
    expected_version: Optional[int] = Field(None, description="Expected case version for optimistic concurrency control")


class CaseNoteCreateRequest(BaseModel):
    """Payload to add an analyst note to an investigation case."""
    author: str = Field(..., min_length=1, max_length=128)
    note_type: Optional[str] = Field("ANALYST_NOTE", description="ANALYST_NOTE, HYPOTHESIS, EXECUTIVE_UPDATE, REMEDIATION_NOTE")
    content: str = Field(..., min_length=1, description="Analyst observation, hypothesis, or note body")
    is_pinned: Optional[bool] = Field(False, description="Pin note to top of case summary")


class CaseEvidenceLinkCreateRequest(BaseModel):
    """Payload to link cross-module evidence into an investigation case."""
    source_module: str = Field(..., description="MODULE_1_BACKUP, MODULE_2_SECURITY, MODULE_3_FORENSICS, MODULE_4_RECOVERY, MODULE_5_RESTORE, EXTERNAL")
    source_entity: str = Field(..., description="Origin table or entity type (e.g. security_alerts, forensic_findings, recovery_jobs)")
    source_id: str = Field(..., description="Primary key of the source record")
    evidence_role: Optional[str] = Field("CORROBORATING", description="ROOT_CAUSE, CORROBORATING, INDICATOR_OF_COMPROMISE, RECOVERY_VERIFICATION, CONTEXT")
    sha256_hash: Optional[str] = Field(None, max_length=64, description="SHA-256 digest of evidence at time of linkage")
    tamper_status: Optional[str] = Field("VERIFIED", description="VERIFIED, TAMPERED, UNVERIFIED")
    metadata_snapshot: Optional[str] = Field(None, description="Serialized JSON or text summary of evidence")
    linked_by: str = Field(..., min_length=1, max_length=128)


class CaseContainmentActionCreateRequest(BaseModel):
    """Payload to recommend a non-automated containment playbook action."""
    action_type: str = Field(..., description="REVOKE_LOGIN, ISOLATE_USER, ROTATE_CREDENTIALS, DISABLE_TRIGGER, PAUSE_JOB, FIREWALL_RECOMMENDATION")
    target_principal: Optional[str] = None
    target_object: Optional[str] = None
    recommended_script: str = Field(..., min_length=5, description="Exact T-SQL or PowerShell command for manual operator review")
    risk_assessment: Optional[str] = Field(None, description="Evaluation of potential production workload impact")


class CaseContainmentActionUpdateRequest(BaseModel):
    """Payload to review and update containment recommendation status."""
    status: str = Field(..., description="APPROVED, REJECTED, EXECUTED_MANUALLY, SUPERSEDED")
    reviewed_by: str = Field(..., min_length=1, max_length=128)
    review_comment: Optional[str] = None


# Response Models
class CaseStatusHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    from_status: str
    to_status: str
    changed_by: str
    transition_reason: Optional[str] = None
    transitioned_at: datetime


class CaseNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    author: str
    note_type: str
    content: str
    is_pinned: bool
    created_at: datetime
    updated_at: datetime


class CaseEvidenceLinkResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    source_module: str
    source_entity: str
    source_id: str
    evidence_role: str
    sha256_hash: Optional[str] = None
    tamper_status: str
    metadata_snapshot: Optional[str] = None
    linked_by: str
    linked_at: datetime


class CaseContainmentActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    action_type: str
    target_principal: Optional[str] = None
    target_object: Optional[str] = None
    recommended_script: str
    risk_assessment: Optional[str] = None
    status: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_comment: Optional[str] = None
    created_at: datetime


class CaseAuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    sequence_number: int
    action: str
    actor: str
    client_ip: Optional[str] = None
    details: Optional[str] = None
    previous_hash: Optional[str] = None
    current_hash: str
    logged_at: datetime


class InvestigationCaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_number: str
    title: str
    description: Optional[str] = None
    target_database_name: str
    target_database_id: Optional[str] = None
    priority: str
    status: str
    incident_category: str
    lead_investigator: Optional[str] = None
    assigned_team: Optional[str] = None
    created_by: str
    idempotency_key: Optional[str] = None
    severity_score: float
    blast_radius_summary: Optional[str] = None
    containment_status: str
    version: int
    opened_at: datetime
    closed_at: Optional[datetime] = None
    closure_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class CaseMitreTechniqueResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    technique_id: str
    technique_name: str
    tactic: str
    detection_source: str
    confidence: float
    mapped_at: datetime


class ClassificationResultResponse(BaseModel):
    case_id: str
    severity_score: float
    priority: str
    incident_category: str
    blast_radius_summary: Optional[str] = None
    mitre_techniques: List[CaseMitreTechniqueResponse] = []


class InvestigationCaseDetailResponse(InvestigationCaseResponse):
    """Detailed case representation including sub-collections."""
    status_history: List[CaseStatusHistoryResponse] = []
    notes: List[CaseNoteResponse] = []
    evidence_links: List[CaseEvidenceLinkResponse] = []
    containment_actions: List[CaseContainmentActionResponse] = []
    mitre_techniques: List[CaseMitreTechniqueResponse] = []


class InvestigationCaseListResponse(BaseModel):
    items: List[InvestigationCaseResponse]
    total: int
    page: int
    page_size: int


# Phase 4: Timeline, Correlation, and Dossier Schemas
class TimelineEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    timestamp: datetime
    source_module: str
    source_entity: Optional[str] = None
    source_id: Optional[str] = None
    event_type: str
    severity: str
    summary: str
    details: Optional[str] = None
    actor: Optional[str] = None
    target_object: Optional[str] = None
    mitre_technique: Optional[str] = None
    is_milestone: bool = False


class CorrelationCandidate(BaseModel):
    source_module: str
    source_entity: str
    source_id: str
    correlation_type: str  # TEMPORAL, PRINCIPAL, TARGET_OBJECT, ATTACK_TECHNIQUE
    description: str
    timestamp: datetime
    confidence: float
    already_linked: bool = False


class CorrelationScanRequest(BaseModel):
    sliding_window_minutes: int = Field(30, ge=5, le=1440, description="Sliding temporal proximity window in minutes")
    auto_link: bool = Field(True, description="Whether to automatically link discovered evidence candidates")
    actor: str = Field("investigator", description="Analyst or service executing correlation")


class CorrelationScanResponse(BaseModel):
    case_id: str
    candidates_found: int
    candidates_linked: int
    discovered_principals: List[str]
    discovered_objects: List[str]
    correlation_summary: str
    candidates: List[CorrelationCandidate] = []


class InvestigationDossierResponse(BaseModel):
    case_id: str
    case_number: str
    title: str
    status: str
    priority: str
    severity_score: float
    incident_category: str
    target_database_name: str
    opened_at: datetime
    closed_at: Optional[datetime] = None
    lead_investigator: Optional[str] = None
    executive_summary: Dict[str, Any]
    mitre_matrix: List[Dict[str, Any]] = []
    evidence_inventory: List[Dict[str, Any]] = []
    timeline: List[TimelineEventResponse] = []
    containment_actions: List[Dict[str, Any]] = []
    audit_trail_summary: Dict[str, Any]


class CaseCloseRequest(BaseModel):
    closed_by: str = Field(..., min_length=2, max_length=128)
    closure_reason: str = Field(..., min_length=5, max_length=512)
    closure_notes: Optional[str] = None


class CaseCloseResponse(BaseModel):
    case_id: str
    case_number: str
    status: str
    closed_at: datetime
    closed_by: str
    closure_manifest_hash: str
    signature: str
    signature_valid: bool
    audit_chain_verified: bool
    storage_object_key: Optional[str] = None
    retention_mode: Optional[str] = None


class WorkflowTemplateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    incident_category: str
    description: Optional[str] = None
    stages_definition: Any
    tasks_definition: Any
    version: int
    is_active: bool
    created_at: datetime
    updated_at: datetime


class WorkflowTemplateCreateRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=128)
    incident_category: str = Field(..., min_length=2, max_length=64)
    description: Optional[str] = None
    stages: List[Dict[str, Any]]
    tasks: List[Dict[str, Any]]


class WorkflowCreateRequest(BaseModel):
    case_id: str
    template_id: Optional[str] = None
    name: Optional[str] = None
    created_by: str = Field(..., min_length=1, max_length=128)
    owner: Optional[str] = None
    custom_stages: Optional[List[Dict[str, Any]]] = None
    custom_tasks: Optional[List[Dict[str, Any]]] = None


class WorkflowTransitionRequest(BaseModel):
    to_status: str = Field(..., description="Target status: ACTIVE, BLOCKED, AWAITING_REVIEW, AWAITING_APPROVAL, ESCALATED, COMPLETED, CANCELLED, FAILED")
    to_stage: Optional[str] = None
    transition_reason: Optional[str] = None
    actor: str = Field(..., min_length=1, max_length=128)


class TaskDependencyCreateRequest(BaseModel):
    prerequisite_task_id: str
    dependency_type: Optional[str] = Field("BLOCKING", description="BLOCKING or INFORMATIONAL")


class TaskCreateRequest(BaseModel):
    workflow_id: str
    stage_name: str
    title: str = Field(..., min_length=3, max_length=256)
    description: Optional[str] = None
    task_type: Optional[str] = Field("MANUAL", description="MANUAL, AUTOMATED_CHECK, REVIEW, APPROVAL")
    priority: Optional[str] = Field("P3_MEDIUM", description="P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW")
    assigned_to: Optional[str] = None
    assigned_team: Optional[str] = None
    is_mandatory: Optional[bool] = True
    order_index: Optional[int] = 0
    due_date: Optional[datetime] = None
    prerequisite_task_ids: Optional[List[str]] = None


class TaskUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    assigned_team: Optional[str] = None
    is_mandatory: Optional[bool] = None
    order_index: Optional[int] = None
    due_date: Optional[datetime] = None
    completion_notes: Optional[str] = None


class TaskCompleteRequest(BaseModel):
    completed_by: str = Field(..., min_length=1, max_length=128)
    completion_notes: Optional[str] = None
    evidence_reference_id: Optional[str] = None
    status: Optional[str] = Field("COMPLETED", description="COMPLETED or SKIPPED")


class WorkflowEscalateRequest(BaseModel):
    task_id: Optional[str] = None
    escalation_level: str = Field("TIER_2", description="TIER_1, TIER_2, TIER_3, MANAGEMENT, CISO")
    escalation_reason: str = Field(..., min_length=5)
    escalated_by: str = Field(..., min_length=1, max_length=128)
    escalated_to: str = Field(..., min_length=1, max_length=128)
    reassign_owner: Optional[bool] = False


class WorkflowEscalationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workflow_id: str
    case_id: str
    task_id: Optional[str] = None
    escalation_level: str
    escalation_reason: str
    escalated_by: str
    escalated_to: str
    status: str
    resolution_notes: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime


class TaskDependencyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    task_id: str
    prerequisite_task_id: str
    dependency_type: str
    created_at: datetime


class WorkflowTaskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workflow_id: str
    case_id: str
    stage_name: str
    title: str
    description: Optional[str] = None
    task_type: str
    status: str
    priority: str
    assigned_to: Optional[str] = None
    assigned_team: Optional[str] = None
    is_mandatory: bool
    order_index: int
    due_date: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    completed_by: Optional[str] = None
    completion_notes: Optional[str] = None
    evidence_reference_id: Optional[str] = None
    prerequisites: List[str] = []
    created_at: datetime
    updated_at: datetime


class WorkflowHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workflow_id: str
    from_status: Optional[str] = None
    to_status: str
    from_stage: Optional[str] = None
    to_stage: Optional[str] = None
    transition_reason: Optional[str] = None
    actor: str
    transitioned_at: datetime


class WorkflowResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    template_id: Optional[str] = None
    name: str
    status: str
    current_stage: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    owner: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: datetime
    tasks_count: int = 0
    completed_tasks_count: int = 0
    tasks: List[WorkflowTaskResponse] = []
    history: List[WorkflowHistoryResponse] = []
    escalations: List[WorkflowEscalationResponse] = []


# --- PHASE 6: INCIDENT RESPONSE PLANS & COLLABORATION SCHEMAS ---

class ResponsePlanCreateRequest(BaseModel):
    case_id: str
    title: str = Field(..., min_length=3, max_length=256)
    summary: Optional[str] = None
    plan_type: Optional[str] = Field("CONTAINMENT_AND_RECOVERY", description="CONTAINMENT, ERADICATION, RECOVERY_PREPARATION, FULL_INCIDENT_RESPONSE")
    created_by: str = Field(..., min_length=1, max_length=128)


class ResponsePlanUpdateRequest(BaseModel):
    title: Optional[str] = None
    summary: Optional[str] = None
    plan_type: Optional[str] = None
    status: Optional[str] = None


class ResponseActionCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=256)
    action_category: Optional[str] = Field("CONTAINMENT", description="CONTAINMENT, ERADICATION, RECOVERY_PREPARATION, POST_INCIDENT")
    target_type: Optional[str] = Field("LOGIN", description="LOGIN, USER, DATABASE, TABLE, ENDPOINT, AUDIT_CONFIG")
    target_identifier: Optional[str] = None
    risk_level: Optional[str] = Field("MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    proposed_script: str = Field(..., min_length=3, description="T-SQL or PowerShell command for manual operator review")
    rollback_script: Optional[str] = None
    execution_order: Optional[int] = 0
    requires_multi_party_approval: Optional[bool] = True
    proposed_by: str = Field(..., min_length=1, max_length=128)


class ResponseActionApprovalRequest(BaseModel):
    approved_by: str = Field(..., min_length=1, max_length=128)
    approval_status: str = Field("APPROVED", description="APPROVED or REJECTED")
    approval_notes: Optional[str] = None


class ResponseActionExecutionRequest(BaseModel):
    executed_by: str = Field(..., min_length=1, max_length=128)
    execution_status: str = Field("EXECUTED_SUCCESS", description="EXECUTED_SUCCESS, EXECUTED_FAILED, SKIPPED")
    execution_notes: Optional[str] = None
    evidence_reference_id: Optional[str] = None


class AnalystCommentCreateRequest(BaseModel):
    author: str = Field(..., min_length=1, max_length=128)
    content: str = Field(..., min_length=1)
    comment_type: Optional[str] = Field("COMMENT", description="COMMENT, PEER_REVIEW, APPROVAL_NOTE, EXECUTION_REPORT")
    parent_comment_id: Optional[str] = None
    plan_id: Optional[str] = None
    action_id: Optional[str] = None
    task_id: Optional[str] = None


class AnalystCollaborationCommentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    plan_id: Optional[str] = None
    action_id: Optional[str] = None
    task_id: Optional[str] = None
    parent_comment_id: Optional[str] = None
    author: str
    comment_type: str
    content: str
    is_resolved: bool
    created_at: datetime
    updated_at: datetime
    replies: List["AnalystCollaborationCommentResponse"] = []


class ResponsePlanActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    plan_id: str
    case_id: str
    title: str
    action_category: str
    target_type: str
    target_identifier: Optional[str] = None
    risk_level: str
    proposed_script: str
    rollback_script: Optional[str] = None
    execution_order: int
    requires_multi_party_approval: bool
    approval_status: str
    proposed_by: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    approval_notes: Optional[str] = None
    execution_status: str
    executed_by: Optional[str] = None
    executed_at: Optional[datetime] = None
    execution_notes: Optional[str] = None
    execution_evidence_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ResponsePlanRevisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    plan_id: str
    version: int
    snapshot_data: str
    revised_by: str
    revision_summary: Optional[str] = None
    created_at: datetime


class IncidentResponsePlanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    title: str
    summary: Optional[str] = None
    plan_type: str
    status: str
    version: int
    created_by: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    approval_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    actions: List[ResponsePlanActionResponse] = []
    revisions: List[ResponsePlanRevisionResponse] = []



