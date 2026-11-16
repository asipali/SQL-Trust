"""
SQL-TRUST REST API Endpoints
Module 6: Cyber Investigation & Incident Response Orchestration
Provides endpoints for case lifecycle management, status transitions,
analyst notes, cross-module evidence links, containment tracking, and tamper-evident audit logs.
"""
from typing import List, Optional, Union, Any
from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.auth import User
from backend.api.v1.auth import require_permission, check_case_access
from backend.schemas.investigation import (
    CaseCreateRequest,
    CaseUpdateRequest,
    CaseTransitionRequest,
    CaseNoteCreateRequest,
    CaseNoteResponse,
    CaseEvidenceLinkCreateRequest,
    CaseEvidenceLinkResponse,
    CaseContainmentActionCreateRequest,
    CaseContainmentActionUpdateRequest,
    CaseContainmentActionResponse,
    CaseAuditLogResponse,
    ClassificationResultResponse,
    InvestigationCaseResponse,
    InvestigationCaseDetailResponse,
    InvestigationCaseListResponse,
    TimelineEventResponse,
    CorrelationScanRequest,
    CorrelationScanResponse,
    InvestigationDossierResponse,
    CaseCloseRequest,
    CaseCloseResponse,
    WorkflowResponse,
    WorkflowCreateRequest,
    WorkflowTaskResponse,
    WorkflowHistoryResponse,
    WorkflowEscalationResponse
)
from backend.services.investigation.case_service import CaseService  # pyrefly: ignore[missing-import]
from backend.services.investigation.audit_service import CaseAuditService  # pyrefly: ignore[missing-import]
from backend.services.investigation.classification_engine import ClassificationEngine  # pyrefly: ignore[missing-import]
from backend.services.investigation.intake_service import IncidentIntakeService  # pyrefly: ignore[missing-import]
from backend.services.investigation.timeline_engine import TimelineEngine  # pyrefly: ignore[missing-import]
from backend.services.investigation.correlation_engine import CorrelationEngine  # pyrefly: ignore[missing-import]
from backend.services.investigation.dossier_service import DossierService  # pyrefly: ignore[missing-import]
from backend.services.investigation.workflow_service import InvestigationWorkflowService  # pyrefly: ignore[missing-import]


def serialize_task(t: Any) -> WorkflowTaskResponse:
    prereq_ids = [d.prerequisite_task_id for d in getattr(t, "prerequisites", [])]
    return WorkflowTaskResponse(
        id=t.id,
        workflow_id=t.workflow_id,
        case_id=t.case_id,
        stage_name=t.stage_name,
        title=t.title,
        description=t.description,
        task_type=t.task_type,
        status=t.status,
        priority=t.priority,
        assigned_to=t.assigned_to,
        assigned_team=t.assigned_team,
        is_mandatory=getattr(t, "is_mandatory", True),
        order_index=getattr(t, "order_index", 0),
        due_date=t.due_date,
        completed_at=t.completed_at,
        completed_by=t.completed_by,
        completion_notes=t.completion_notes,
        evidence_reference_id=getattr(t, "evidence_reference_id", None),
        prerequisites=prereq_ids,
        created_at=t.created_at,
        updated_at=t.updated_at
    )


def serialize_workflow(wf: Any) -> WorkflowResponse:
    tasks = [serialize_task(t) for t in getattr(wf, "tasks", [])]
    completed_count = sum(1 for t in tasks if getattr(t, "status", None) in ("COMPLETED", "SKIPPED"))
    return WorkflowResponse(
        id=wf.id,
        case_id=wf.case_id,
        template_id=wf.template_id,
        name=wf.name,
        status=wf.status,
        current_stage=wf.current_stage,
        started_at=wf.started_at,
        completed_at=wf.completed_at,
        owner=wf.owner,
        created_by=wf.created_by,
        created_at=wf.created_at,
        updated_at=wf.updated_at,
        tasks_count=len(tasks),
        completed_tasks_count=completed_count,
        tasks=tasks,
        history=[
            WorkflowHistoryResponse.model_validate(h)
            for h in getattr(wf, "history", [])
        ],
        escalations=[
            WorkflowEscalationResponse.model_validate(e)
            for e in getattr(wf, "escalations", [])
        ]
    )

router = APIRouter(prefix="/investigations", tags=["Cyber Investigation & Response"])


@router.post(
    "",
    response_model=InvestigationCaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new cyber investigation case"
)
def create_case(
    req: CaseCreateRequest,
    request: Request,
    idempotency_key: Optional[str] = Header(None, alias="X-Idempotency-Key"),
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    """
    Initiates a new investigation case. Enforces idempotency via body or header.
    Initial state is NEW.
    """
    if idempotency_key and not req.idempotency_key:
        req.idempotency_key = idempotency_key

    client_ip = request.client.host if request.client else None
    try:
        case = CaseService.create_case(db=db, req=req, client_ip=client_ip)
        return case
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Case creation failed: {str(e)}")


@router.get(
    "",
    response_model=InvestigationCaseListResponse,
    summary="List investigation cases with filtering and pagination"
)
def list_cases(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by case status"),
    priority: Optional[str] = Query(None, description="Filter by priority (P1_CRITICAL to P4_LOW)"),
    database_name: Optional[str] = Query(None, description="Filter by target database name"),
    assigned_to: Optional[str] = Query(None, description="Filter by lead investigator"),
    category: Optional[str] = Query(None, description="Filter by incident category"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Page size"),
    current_user: User = Depends(require_permission("investigations:read")),
    db: Session = Depends(get_db)
):
    """Retrieves paginated list of investigation cases matching criteria."""
    items, total = CaseService.list_cases(
        db=db,
        status=status_filter,
        priority=priority,
        database_name=database_name,
        assigned_to=assigned_to,
        category=category,
        page=page,
        page_size=page_size
    )
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size
    }


@router.get(
    "/{case_identifier}",
    response_model=InvestigationCaseDetailResponse,
    summary="Get detailed investigation case by UUID or Case Number"
)
def get_case_detail(
    case_identifier: str,
    current_user: User = Depends(require_permission("investigations:read")),
    db: Session = Depends(get_db)
):
    """Retrieves comprehensive case details including notes, evidence links, and status history."""
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation case '{case_identifier}' not found"
        )
    return case


@router.patch(
    "/{case_identifier}",
    response_model=InvestigationCaseResponse,
    summary="Update case metadata with optimistic concurrency validation"
)
def update_case(
    case_identifier: str,
    req: CaseUpdateRequest,
    request: Request,
    actor: str = Query("system", description="Identity making the update"),
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    """Updates case fields. Prohibits updating CLOSED cases."""
    existing_case = CaseService.get_case(db, case_identifier)
    if not existing_case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{case_identifier}' not found")
    check_case_access(current_user, existing_case, "modify")

    client_ip = request.client.host if request.client else None
    try:
        case = CaseService.update_case(db=db, case_id=case_identifier, req=req, actor=actor, client_ip=client_ip)
        return case
    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        if "concurrency conflict" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch(
    "/{case_identifier}/transition",
    response_model=InvestigationCaseResponse,
    summary="Transition case through the investigation state machine"
)
def transition_case(
    case_identifier: str,
    req: CaseTransitionRequest,
    request: Request,
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    """Transitions case to target status if allowed by FSM."""
    existing_case = CaseService.get_case(db, case_identifier)
    if not existing_case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{case_identifier}' not found")
    check_case_access(current_user, existing_case, "transition")

    client_ip = request.client.host if request.client else None
    try:
        case = CaseService.transition_status(db=db, case_id=case_identifier, req=req, client_ip=client_ip)
        return case
    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        if "concurrency conflict" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{case_identifier}/notes",
    response_model=CaseNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add an analyst note to the case"
)
def add_case_note(
    case_identifier: str,
    req: CaseNoteCreateRequest,
    request: Request,
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    """Appends an analyst note and logs NOTE_ADDED in the case audit trail."""
    existing_case = CaseService.get_case(db, case_identifier)
    if not existing_case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{case_identifier}' not found")
    check_case_access(current_user, existing_case, "add notes to")

    client_ip = request.client.host if request.client else None
    try:
        note = CaseService.add_note(db=db, case_id=case_identifier, req=req, client_ip=client_ip)
        return note
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/{case_identifier}/notes",
    response_model=List[CaseNoteResponse],
    summary="List all notes attached to a case"
)
def list_case_notes(
    case_identifier: str,
    current_user: User = Depends(require_permission("investigations:read")),
    db: Session = Depends(get_db)
):
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")
    return case.notes


@router.post(
    "/{case_identifier}/evidence",
    response_model=CaseEvidenceLinkResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Link cross-module evidence to the case"
)
def link_evidence(
    case_identifier: str,
    req: CaseEvidenceLinkCreateRequest,
    request: Request,
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    """Pointers to Module 1-5 records without data duplication."""
    existing_case = CaseService.get_case(db, case_identifier)
    if not existing_case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")
    check_case_access(current_user, existing_case, "link evidence to")

    client_ip = request.client.host if request.client else None
    try:
        link = CaseService.link_evidence(db=db, case_id=case_identifier, req=req, client_ip=client_ip)
        return link
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/{case_identifier}/evidence",
    response_model=List[CaseEvidenceLinkResponse],
    summary="List cross-module evidence links for a case"
)
def list_case_evidence(
    case_identifier: str,
    current_user: User = Depends(require_permission("investigations:read")),
    db: Session = Depends(get_db)
):
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")
    return case.evidence_links


@router.post(
    "/{case_identifier}/containment",
    response_model=CaseContainmentActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Recommend a non-automated containment action for human review"
)
def add_containment_action(
    case_identifier: str,
    req: CaseContainmentActionCreateRequest,
    request: Request,
    actor: str = Query("system", description="Author recommending containment"),
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    """Records recommended containment scripts. Never executes scripts automatically."""
    existing_case = CaseService.get_case(db, case_identifier)
    if not existing_case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")
    check_case_access(current_user, existing_case, "add containment actions to")

    client_ip = request.client.host if request.client else None
    try:
        action = CaseService.add_containment_action(db=db, case_id=case_identifier, req=req, actor=actor, client_ip=client_ip)
        return action
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch(
    "/containment/{action_id}",
    response_model=CaseContainmentActionResponse,
    summary="Review and update containment recommendation status"
)
def update_containment_action(
    action_id: str,
    req: CaseContainmentActionUpdateRequest,
    request: Request,
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    """Approve or reject a containment action."""
    client_ip = request.client.host if request.client else None
    try:
        action = CaseService.update_containment_action(db=db, action_id=action_id, req=req, client_ip=client_ip)
        return action
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/{case_identifier}/audit-logs",
    response_model=List[CaseAuditLogResponse],
    summary="Retrieve immutable append-only audit trail for a case"
)
def get_case_audit_logs(
    case_identifier: str,
    current_user: User = Depends(require_permission("audit.view")),
    db: Session = Depends(get_db)
):
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")
    return case.audit_logs


@router.get(
    "/{case_identifier}/audit-logs/verify",
    summary="Cryptographically verify SHA-256 hash chain of case audit logs"
)
def verify_case_audit_chain(
    case_identifier: str,
    current_user: User = Depends(require_permission("audit.view")),
    db: Session = Depends(get_db)
):
    """Validates that no audit entry has been inserted, deleted, or tampered with."""
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")
    result = CaseAuditService.verify_audit_chain(db, case.id)
    return result


# ---------------------------------------------------------
# Phase 3: Intake and Classification Endpoints
# ---------------------------------------------------------

@router.post(
    "/intake/alert/{alert_id}",
    response_model=InvestigationCaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a Module 2 Security Alert into an investigation case"
)
def intake_from_security_alert(
    alert_id: str,
    request: Request,
    actor: str = Query("automated_collector", description="Actor triggering intake"),
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    """Correlates into existing active case on database or spawns a new case."""
    client_ip = request.client.host if request.client else None
    try:
        case = IncidentIntakeService.intake_from_security_alert(
            db=db, alert_id=alert_id, actor=actor, client_ip=client_ip
        )
        return case
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/intake/finding/{finding_id}",
    response_model=InvestigationCaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a Module 3 Forensic Finding into an investigation case"
)
def intake_from_forensic_finding(
    finding_id: str,
    request: Request,
    actor: str = Query("forensic_collector", description="Actor triggering intake"),
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    """Correlates drift findings into active case or spawns a new case."""
    client_ip = request.client.host if request.client else None
    try:
        case = IncidentIntakeService.intake_from_forensic_finding(
            db=db, finding_id=finding_id, actor=actor, client_ip=client_ip
        )
        return case
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/intake/recovery-risk/{recovery_point_id}",
    response_model=InvestigationCaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a Module 4 compromised recovery point into an investigation case"
)
def intake_from_recovery_risk(
    recovery_point_id: str,
    request: Request,
    actor: str = Query("recovery_engine", description="Actor triggering intake"),
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    """Intakes a compromised or high-risk recovery candidate into an investigation case."""
    client_ip = request.client.host if request.client else None
    try:
        case = IncidentIntakeService.intake_from_recovery_risk(
            db=db, recovery_point_id=recovery_point_id, actor=actor, client_ip=client_ip
        )
        return case
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/intake/validation/{job_id}",
    response_model=InvestigationCaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a Module 5 validation failure into an investigation case"
)
def intake_from_validation_failure(
    job_id: str,
    request: Request,
    actor: str = Query("restore_validator", description="Actor triggering intake"),
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    """Intakes a corrupt or baseline-drifted recovery job into an investigation case."""
    client_ip = request.client.host if request.client else None
    try:
        case = IncidentIntakeService.intake_from_validation_failure(
            db=db, job_id=job_id, actor=actor, client_ip=client_ip
        )
        return case
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/{case_identifier}/classify",
    response_model=ClassificationResultResponse,
    summary="Recalculate case severity, priority, category, and MITRE ATT&CK mapping"
)
def classify_case(
    case_identifier: str,
    request: Request,
    actor: str = Query("system", description="Actor triggering classification"),
    current_user: User = Depends(require_permission("investigations:read")),
    db: Session = Depends(get_db)
):
    """Analyzes all evidence, re-maps MITRE TTPs, and updates multi-factor severity."""
    client_ip = request.client.host if request.client else None
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    result = ClassificationEngine.classify_case(db=db, case_id=case.id, actor=actor, client_ip=client_ip)
    return result


@router.get(
    "/{case_identifier}/timeline",
    response_model=List[TimelineEventResponse],
    summary="Retrieve normalized chronological investigation timeline"
)
def get_case_timeline(
    case_identifier: str,
    current_user: User = Depends(require_permission("investigations:read")),
    db: Session = Depends(get_db)
):
    """Collates all cross-module evidence, notes, transitions, and containment actions into a chronological timeline."""
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    timeline = TimelineEngine.build_case_timeline(db=db, case_id=case.id)
    return timeline


@router.post(
    "/{case_identifier}/correlate",
    response_model=CorrelationScanResponse,
    summary="Execute multi-dimensional evidence correlation scan"
)
def correlate_case_evidence(
    case_identifier: str,
    request: Request,
    req: Optional[CorrelationScanRequest] = None,
    current_user: User = Depends(require_permission("investigations:read")),
    db: Session = Depends(get_db)
):
    """Scans for temporally and contextually related alerts, findings, and recovery points."""
    client_ip = request.client.host if request.client else None
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    sliding_window = req.sliding_window_minutes if req else 30
    auto_link = req.auto_link if req else True
    actor = req.actor if req else "investigator"

    res = CorrelationEngine.correlate_case_evidence(
        db=db,
        case_id=case.id,
        sliding_window_minutes=sliding_window,
        auto_link=auto_link,
        actor=actor,
        client_ip=client_ip
    )
    return res


@router.get(
    "/{case_identifier}/dossier",
    summary="Export comprehensive forensic investigation dossier"
)
def get_case_dossier(
    case_identifier: str,
    format: str = Query("json", description="Output format: 'json' or 'markdown'"),
    current_user: User = Depends(require_permission("investigations:read")),
    db: Session = Depends(get_db)
):
    """Exports full forensic dossier including executive summary, MITRE matrix, evidence, and timeline."""
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    dossier = DossierService.generate_dossier(db=db, case_id=case.id)
    if format.lower() == "markdown":
        md_text = DossierService.export_markdown(dossier)
        return PlainTextResponse(content=md_text, media_type="text/markdown")
    return dossier


@router.get(
    "/{case_identifier}/canonical-report",
    summary="Export full canonical investigation report covering all 6 modules"
)
def get_canonical_report(
    case_identifier: str,
    format: str = Query("json", description="Output format: 'json' or 'markdown'"),
    current_user: User = Depends(require_permission("investigations:read")),
    db: Session = Depends(get_db)
):
    """Exports canonical investigation report with workflows, response plans, evidence, and audit verification."""
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    report = DossierService.generate_canonical_report(db=db, case_id=case.id)
    if format.lower() == "markdown":
        md_text = DossierService.export_canonical_markdown(report)
        return PlainTextResponse(content=md_text, media_type="text/markdown")
    return report


@router.post(
    "/{case_identifier}/archive-worm",
    summary="Archive signed canonical report package to SeaweedFS Object Lock WORM storage"
)
def archive_case_to_worm(
    case_identifier: str,
    operator: str = Query("investigator", min_length=1),
    retention_days: int = Query(30, ge=1, le=3650),
    current_user: User = Depends(require_permission("investigations:close")),
    db: Session = Depends(get_db)
):
    """Generates canonical report, computes Ed25519 signature, and archives to Object Lock storage."""
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    try:
        archive_res = DossierService.archive_canonical_report(
            db=db,
            case_id=case.id,
            operator=operator,
            retention_days=retention_days
        )
        return archive_res
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{case_identifier}/close",
    response_model=CaseCloseResponse,
    summary="Digitally sign closure manifest with Ed25519 and close case"
)
def close_case(
    case_identifier: str,
    req: CaseCloseRequest,
    request: Request,
    current_user: User = Depends(require_permission("investigations:close")),
    db: Session = Depends(get_db)
):
    """Validates resolution, verifies audit chain, constructs closure manifest, and signs with Ed25519."""
    client_ip = request.client.host if request.client else None
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    try:
        res = DossierService.close_and_sign_case(
            db=db,
            case_id=case.id,
            closed_by=req.closed_by,
            closure_reason=req.closure_reason,
            closure_notes=req.closure_notes,
            client_ip=client_ip
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{case_identifier}/workflow",
    response_model=WorkflowResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Instantiate investigation workflow for a case"
)
def create_case_workflow(
    case_identifier: str,
    req: WorkflowCreateRequest,
    current_user: User = Depends(require_permission("investigations:write")),
    db: Session = Depends(get_db)
):
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    req.case_id = case.id
    try:
        wf = InvestigationWorkflowService.create_workflow(db, req)
        return serialize_workflow(wf)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/{case_identifier}/workflow",
    response_model=WorkflowResponse,
    summary="Retrieve latest workflow for an investigation case"
)
def get_case_workflow(
    case_identifier: str,
    current_user: User = Depends(require_permission("investigations:read")),
    db: Session = Depends(get_db)
):
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    wf = InvestigationWorkflowService.get_case_workflow(db, case.id)
    if not wf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No workflow found for case '{case_identifier}'")
    return serialize_workflow(wf)
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    wf = InvestigationWorkflowService.get_case_workflow(db, case.id)
    if not wf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No workflow found for case '{case_identifier}'")
    return serialize_workflow(wf)


