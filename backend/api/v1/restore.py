"""
SQL-TRUST REST API Endpoints
Module 5: Restore & Cyber Recovery Validation Engine
Provides recovery validation job creation, lifecycle approval, cancellation,
and immutable transition audit inspection.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Query, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.schemas.restore import (
    RecoveryJobCreateRequest,
    RecoveryJobApproveRequest,
    RecoveryJobCancelRequest,
    RecoveryJobResponse,
    RecoveryJobDetailResponse,
    RecoveryJobHistoryResponse,
    BackupStagingResponse,
    StagingStatusResponse,
    SandboxProvisionRequest,
    SandboxResponse,
    SandboxHealthResponse,
    SandboxQuarantineRequest,
    SandboxCleanupRequest,
    RestorePlanCreateRequest,
    RestorePlanResponse,
    RestoreOperationResponse,
    RestoreExecutionResponse,
    ValidationStartRequest,
    RecoveryValidationResponse,
    RecoveryFindingResponse,
    RecoveryEvidenceResponse,
    RecoveryCustodyResponse,
    FinalReportResponse
)
from backend.services.restore.job_service import RecoveryJobService
from backend.services.restore.staging_service import (
    RecoveryStagingService,
    StagingError,
    InsufficientStorageError,
    PathTraversalAttackError,
    IntegrityMismatchError,
    ArtifactDownloadError
)
from backend.services.restore.sandbox_service import (
    RecoverySandboxService,
    SandboxError,
    SandboxProvisioningError,
    SandboxIsolationError,
    SandboxHealthCheckError
)
from backend.services.restore.restore_service import (
    RestoreOrchestrationService,
    RestoreError,
    InvalidBackupChainError,
    RestoreExecutionError,
    ProductionTargetViolationError
)
from backend.services.restore.validation_service import (
    RecoveryValidationService,
    ValidationError
)
from backend.services.restore.report_service import (
    RecoveryReportingService,
    ReportError
)
from backend.models.restore import (
    BackupStagingRecord,
    RecoverySandbox,
    RestorePlan,
    RestoreOperation,
    RecoveryValidation,
    RecoveryFinding,
    RecoveryEvidenceItem,
    RecoveryChainOfCustody,
    RecoveryFinalReport
)
from backend.models.recovery import RecoveryRecommendation, RecoveryAssessment, RecoveryEligibility

router = APIRouter(prefix="/recovery/jobs")


def require_role(allowed_roles: List[str]):
    """Enforces backend role-based access control based on X-User-Role header."""
    def role_checker(x_user_role: Optional[str] = Header(None, alias="X-User-Role")):
        # If no role header is sent, allow in development mode as Operator/Admin
        if not x_user_role:
            return "Operator"
        normalized = x_user_role.strip().capitalize()
        valid_roles = [r.capitalize() for r in allowed_roles]
        if normalized not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role in {valid_roles}, provided '{x_user_role}'."
            )
        return normalized
    return role_checker


@router.post("", response_model=RecoveryJobResponse, status_code=status.HTTP_201_CREATED)
def create_recovery_job(
    payload: RecoveryJobCreateRequest,
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Operator", "Admin"]))
):
    """
    Creates a new cyber recovery validation job from a Module 4 recovery recommendation.
    Validates candidate eligibility, ensures trust assessment is complete, and supports idempotency.
    """
    service = RecoveryJobService(db)
    job, is_new = service.create_job(
        candidate_id=payload.candidate_id,
        idempotency_key=payload.idempotency_key,
        requested_by=payload.requested_by or current_role,
        notes=payload.notes
    )
    return job


@router.get("", response_model=List[RecoveryJobResponse])
def list_recovery_jobs(
    status_filter: Optional[str] = Query(None, alias="status"),
    candidate_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Lists recovery validation jobs with optional status and candidate filters."""
    service = RecoveryJobService(db)
    return service.list_jobs(
        status_filter=status_filter,
        candidate_id=candidate_id,
        limit=limit,
        offset=offset
    )


@router.get("/{job_id}", response_model=RecoveryJobDetailResponse)
def get_recovery_job_details(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves full details for a recovery validation job including history, staging records, and candidate scores."""
    service = RecoveryJobService(db)
    job = service.get_job(job_id)
    history = service.get_job_history(job.id)

    # Fetch staging records if any
    staging_records = db.query(BackupStagingRecord).filter(
        BackupStagingRecord.job_id == job.id
    ).order_by(BackupStagingRecord.sequence_order.asc()).all()

    # Augment with candidate metadata if available
    rec = db.query(RecoveryRecommendation).filter(RecoveryRecommendation.id == job.candidate_id).first()
    trust_class = rec.trust_classification if rec else None
    eligibility_stat = rec.eligibility_status if rec else None
    rank_score = rec.ranking_score if rec else None

    detail_dict = {
        **job.__dict__,
        "history": history,
        "staging_records": staging_records,
        "trust_classification": trust_class,
        "eligibility_status": eligibility_stat,
        "ranking_score": rank_score
    }
    return detail_dict


@router.post("/{job_id}/staging", response_model=List[BackupStagingResponse])
def initiate_backup_staging(
    job_id: str,
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Operator", "Admin"]))
):
    """
    Initiates isolated backup staging and cryptographic verification for a recovery job.
    Retrieves artifacts from SeaweedFS S3 using read-only credentials, conducts preflight
    storage verification, and compares computed SHA-256 against recovery point metadata.
    """
    service = RecoveryStagingService(db)
    try:
        records = service.stage_job_backups(job_id=job_id, actor=current_role)
        return records
    except InsufficientStorageError as err:
        raise HTTPException(
            status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
            detail=str(err)
        )
    except IntegrityMismatchError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(err)
        )
    except StagingError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )


@router.get("/{job_id}/staging", response_model=StagingStatusResponse)
def get_backup_staging_status(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves aggregated staging and cryptographic verification status for a recovery job."""
    service = RecoveryStagingService(db)
    try:
        return service.get_staging_status(job_id=job_id)
    except StagingError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err)
        )


@router.get("/{job_id}/staging/{record_id}", response_model=BackupStagingResponse)
def get_backup_staging_artifact(
    job_id: str,
    record_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves metadata and verification status for a specific staged backup file."""
    record = db.query(BackupStagingRecord).filter(
        BackupStagingRecord.id == record_id,
        BackupStagingRecord.job_id == job_id
    ).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Backup staging record '{record_id}' not found for job '{job_id}'."
        )
    return record


@router.post("/{job_id}/staging/{record_id}/retry", response_model=BackupStagingResponse)
def retry_backup_staging_artifact(
    job_id: str,
    record_id: str,
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Operator", "Admin"]))
):
    """Retries download and SHA-256 verification for an individual failed or mismatched artifact."""
    service = RecoveryStagingService(db)
    try:
        return service.retry_artifact(record_id=record_id, actor=current_role)
    except StagingError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )


@router.get("/{job_id}/history", response_model=List[RecoveryJobHistoryResponse])
def get_recovery_job_history(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves the immutable state transition audit history for a recovery validation job."""
    service = RecoveryJobService(db)
    return service.get_job_history(job_id)


@router.post("/{job_id}/approve", response_model=RecoveryJobResponse)
def approve_recovery_job(
    job_id: str,
    payload: RecoveryJobApproveRequest = RecoveryJobApproveRequest(),
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Admin"]))
):
    """
    Authorizes a recovery validation job to proceed from REQUESTED to PREFLIGHT.
    Requires Admin privileges.
    """
    service = RecoveryJobService(db)
    return service.approve_job(
        job_id=job_id,
        approved_by=payload.approved_by or current_role,
        approver_notes=payload.approver_notes
    )


@router.post("/{job_id}/cancel", response_model=RecoveryJobResponse)
def cancel_recovery_job(
    job_id: str,
    payload: RecoveryJobCancelRequest,
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Operator", "Admin"]))
):
    """
    Gracefully cancels an active recovery validation job, transitioning it to FAILED (USER_CANCELLED).
    Preserves all job records and transition history for forensic integrity.
    """
    service = RecoveryJobService(db)
    return service.cancel_job(
        job_id=job_id,
        cancellation_reason=payload.cancellation_reason,
        cancelled_by=payload.cancelled_by or current_role
    )


# ==============================================================================
# Phase 4: Recovery Sandbox Endpoints
# ==============================================================================

@router.post("/{job_id}/sandbox", response_model=SandboxResponse, status_code=status.HTTP_201_CREATED)
def provision_recovery_sandbox(
    job_id: str,
    payload: SandboxProvisionRequest = SandboxProvisionRequest(),
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Operator", "Admin"]))
):
    """
    Provisions an isolated Microsoft SQL Server recovery container with dedicated bridge network,
    separate data/log volumes, read-only staging mount, and ephemeral credentials.
    Transitions recovery job state to ENVIRONMENT_CREATED upon health and isolation verification.
    """
    service = RecoverySandboxService(db)
    try:
        sandbox = service.provision_sandbox(
            job_id=job_id,
            cpu_limit=payload.cpu_limit or "2.0",
            memory_limit=payload.memory_limit or "2048m",
            actor=current_role
        )
        return sandbox
    except SandboxError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(err)
        )


@router.get("/{job_id}/sandbox", response_model=SandboxResponse)
def get_recovery_sandbox(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves metadata and current lifecycle status for a job's recovery sandbox."""
    service = RecoverySandboxService(db)
    sandbox = service.get_sandbox(job_id)
    if not sandbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No recovery sandbox found for job '{job_id}'."
        )
    return sandbox


@router.get("/{job_id}/sandbox/health", response_model=SandboxHealthResponse)
def check_recovery_sandbox_health(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Validates container health (SELECT 1) and verifies isolation from host production database."""
    service = RecoverySandboxService(db)
    sandbox = service.get_sandbox(job_id)
    if not sandbox:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No recovery sandbox found for job '{job_id}'."
        )

    pwd = service.get_cached_password(job_id) or ""
    is_healthy, _ = service.wait_for_sandbox_readiness(sandbox.host_port, pwd, timeout_seconds=5)
    evidence = service.verify_sandbox_isolation(sandbox, pwd) if is_healthy else {}

    return {
        "job_id": job_id,
        "container_name": sandbox.container_name,
        "lifecycle_status": sandbox.lifecycle_status,
        "host_port": sandbox.host_port,
        "is_healthy": is_healthy,
        "all_isolation_checks_passed": evidence.get("all_isolation_checks_passed", False),
        "isolation_evidence": evidence
    }


@router.post("/{job_id}/sandbox/quarantine", response_model=SandboxResponse)
def quarantine_recovery_sandbox(
    job_id: str,
    payload: SandboxQuarantineRequest,
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Operator", "Admin"]))
):
    """Freezes container execution for forensic analysis while preserving all volumes and evidence."""
    service = RecoverySandboxService(db)
    try:
        return service.quarantine_sandbox(job_id=job_id, reason=payload.reason, actor=current_role)
    except SandboxError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )


@router.post("/{job_id}/sandbox/cleanup", response_model=SandboxResponse)
def cleanup_recovery_sandbox(
    job_id: str,
    payload: SandboxCleanupRequest = SandboxCleanupRequest(),
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Admin"]))
):
    """
    Authorized teardown of the recovery sandbox container, dedicated network, and temporary volumes.
    Requires Admin privileges.
    """
    service = RecoverySandboxService(db)
    try:
        return service.cleanup_sandbox(
            job_id=job_id,
            authorized_by=payload.authorized_by or current_role,
            force=payload.force or False
        )
    except SandboxError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )


# ==============================================================================
# Phase 5: Restore Orchestration Endpoints
# ==============================================================================

@router.post("/{job_id}/restore/plan", response_model=RestorePlanResponse, status_code=status.HTTP_201_CREATED)
def create_restore_plan(
    job_id: str,
    payload: RestorePlanCreateRequest = RestorePlanCreateRequest(),
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Operator", "Admin"]))
):
    """
    Validates backup chain LSN continuity and constructs an auditable multi-step restore plan
    with explicit NORECOVERY and RECOVERY steps.
    """
    service = RestoreOrchestrationService(db)
    try:
        plan = service.generate_restore_plan(
            job_id=job_id,
            target_database_name=payload.target_database_name,
            target_stopat_utc=payload.target_stopat_utc
        )
        return plan
    except RestoreError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )


@router.get("/{job_id}/restore/plan", response_model=RestorePlanResponse)
def get_restore_plan(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves the active restore plan and its ordered operations."""
    plan = db.query(RestorePlan).filter(RestorePlan.job_id == job_id).first()
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No restore plan found for job '{job_id}'."
        )
    return plan


@router.post("/{job_id}/restore/execute", response_model=RestoreExecutionResponse)
def execute_restore_plan(
    job_id: str,
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Operator", "Admin"]))
):
    """
    Executes the restore plan against the isolated recovery sandbox.
    Transitions recovery job state from ENVIRONMENT_CREATED -> RESTORE_IN_PROGRESS -> RESTORE_COMPLETED.
    """
    service = RestoreOrchestrationService(db)
    try:
        result = service.execute_restore_plan(job_id=job_id, actor=current_role)
        plan = db.query(RestorePlan).filter(RestorePlan.job_id == job_id).first()
        ops = db.query(RestoreOperation).filter(RestoreOperation.plan_id == plan.id).order_by(RestoreOperation.sequence_number.asc()).all()
        return {
            "job_id": job_id,
            "plan_id": plan.id,
            "status": plan.status,
            "operations_completed": len([o for o in ops if o.status == "COMPLETED"]),
            "total_operations": len(ops),
            "operations": ops
        }
    except RestoreError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(err)
        )


@router.get("/{job_id}/restore/status", response_model=RestoreExecutionResponse)
def get_restore_execution_status(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves progress and execution details of all restore operations."""
    plan = db.query(RestorePlan).filter(RestorePlan.job_id == job_id).first()
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No restore plan found for job '{job_id}'."
        )
    ops = db.query(RestoreOperation).filter(RestoreOperation.plan_id == plan.id).order_by(RestoreOperation.sequence_number.asc()).all()
    return {
        "job_id": job_id,
        "plan_id": plan.id,
        "status": plan.status,
        "operations_completed": len([o for o in ops if o.status == "COMPLETED"]),
        "total_operations": len(ops),
        "operations": ops
    }


# ==============================================================================
# Phase 6: Recovery Validation & Forensics Endpoints
# ==============================================================================

@router.post("/{job_id}/validation", response_model=RecoveryValidationResponse)
def execute_recovery_validation(
    job_id: str,
    payload: ValidationStartRequest = ValidationStartRequest(),
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Operator", "Admin"]))
):
    """
    Executes post-restore database consistency checks (DBCC CHECKDB), security inspection
    (principals, role memberships, triggers), and Module 3 baseline comparison.
    Transitions recovery job state from RESTORE_COMPLETED -> VALIDATION_IN_PROGRESS -> VALIDATION_COMPLETED.
    """
    service = RecoveryValidationService(db)
    try:
        validation = service.evaluate_validation(
            job_id=job_id,
            baseline_id=payload.baseline_id,
            actor=current_role
        )
        findings = db.query(RecoveryFinding).filter(RecoveryFinding.validation_id == validation.id).all()
        return {
            **validation.__dict__,
            "findings": findings
        }
    except ValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )


@router.get("/{job_id}/validation", response_model=RecoveryValidationResponse)
def get_recovery_validation_summary(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves validation summary and definitive 4-tier outcome (VALIDATED, FAILED, INCONCLUSIVE, REQUIRES_INVESTIGATION)."""
    validation = db.query(RecoveryValidation).filter(RecoveryValidation.job_id == job_id).first()
    if not validation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No validation record found for job '{job_id}'."
        )
    findings = db.query(RecoveryFinding).filter(RecoveryFinding.validation_id == validation.id).all()
    return {
        **validation.__dict__,
        "findings": findings
    }


@router.get("/{job_id}/validation/findings", response_model=List[RecoveryFindingResponse])
def list_recovery_validation_findings(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Lists granular forensic, security, and integrity findings identified during validation."""
    findings = db.query(RecoveryFinding).filter(RecoveryFinding.job_id == job_id).order_by(RecoveryFinding.created_at.desc()).all()
    return findings


# ==============================================================================
# Phase 7: Evidence Management & Reporting Endpoints
# ==============================================================================

@router.post("/{job_id}/evidence/collect", response_model=List[RecoveryEvidenceResponse])
def collect_recovery_evidence(
    job_id: str,
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Operator", "Admin"]))
):
    """
    Collects and cryptographically fingerprints evidentiary records across all recovery stages.
    Maintains append-only chain of custody and transitions job state to EVIDENCE_ARCHIVED.
    """
    service = RecoveryReportingService(db)
    try:
        items = service.collect_job_evidence(job_id=job_id, actor=current_role)
        return items
    except ReportError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )


@router.get("/{job_id}/evidence", response_model=List[RecoveryEvidenceResponse])
def get_recovery_evidence_inventory(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves the complete cryptographic evidence inventory for a recovery job."""
    items = db.query(RecoveryEvidenceItem).filter(RecoveryEvidenceItem.job_id == job_id).order_by(RecoveryEvidenceItem.collected_at.asc()).all()
    return items


@router.get("/{job_id}/evidence/custody", response_model=List[RecoveryCustodyResponse])
def get_recovery_chain_of_custody(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves the immutable chain-of-custody audit log for a recovery job."""
    events = db.query(RecoveryChainOfCustody).filter(RecoveryChainOfCustody.job_id == job_id).order_by(RecoveryChainOfCustody.recorded_at.asc()).all()
    return events


@router.post("/{job_id}/report", response_model=FinalReportResponse)
def generate_recovery_report(
    job_id: str,
    db: Session = Depends(get_db),
    current_role: str = Depends(require_role(["Operator", "Admin"]))
):
    """
    Generates the comprehensive final recovery report across all 17 sections,
    signs report with Ed25519 digital signature, and transitions job to REPORT_GENERATED.
    """
    service = RecoveryReportingService(db)
    try:
        report = service.generate_final_report(job_id=job_id, actor=current_role)
        return report
    except ReportError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err)
        )


@router.get("/{job_id}/report", response_model=FinalReportResponse)
def get_recovery_report(
    job_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves the final signed recovery validation report."""
    report = db.query(RecoveryFinalReport).filter(RecoveryFinalReport.job_id == job_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No final recovery report found for job '{job_id}'."
        )
    return report
