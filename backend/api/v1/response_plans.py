"""
SQL-TRUST REST API Endpoints
Module 6: Cyber Investigation & Incident Response Orchestration
Phase 6: Incident Response Plans, Versioning, Separation of Duties (SoD) Approvals,
Manual Execution Acknowledgement, and Analyst Collaboration Comments.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.investigation import (
    IncidentResponsePlan,
    ResponsePlanAction,
    ResponsePlanRevision,
    AnalystCollaborationComment
)
from backend.schemas.investigation import (
    ResponsePlanCreateRequest,
    ResponsePlanUpdateRequest,
    ResponseActionCreateRequest,
    ResponseActionApprovalRequest,
    ResponseActionExecutionRequest,
    AnalystCommentCreateRequest,
    IncidentResponsePlanResponse,
    ResponsePlanActionResponse,
    ResponsePlanRevisionResponse,
    AnalystCollaborationCommentResponse
)
from backend.services.investigation.response_service import IncidentResponseService  # pyrefly: ignore[missing-import]
from backend.services.investigation.case_service import CaseService  # pyrefly: ignore[missing-import]

router = APIRouter(tags=["Incident Response Plans & Collaboration"])


def serialize_action(a: ResponsePlanAction) -> ResponsePlanActionResponse:
    return ResponsePlanActionResponse.model_validate(a)


def serialize_revision(r: ResponsePlanRevision) -> ResponsePlanRevisionResponse:
    return ResponsePlanRevisionResponse.model_validate(r)


def serialize_plan(p: IncidentResponsePlan) -> IncidentResponsePlanResponse:
    return IncidentResponsePlanResponse(
        id=p.id,
        case_id=p.case_id,
        title=p.title,
        summary=p.summary,
        plan_type=p.plan_type,
        status=p.status,
        version=p.version,
        created_by=p.created_by,
        approved_by=p.approved_by,
        approved_at=p.approved_at,
        approval_notes=p.approval_notes,
        created_at=p.created_at,
        updated_at=p.updated_at,
        actions=[serialize_action(a) for a in p.actions],
        revisions=[serialize_revision(r) for r in p.revisions]
    )


def serialize_comment(c: AnalystCollaborationComment) -> AnalystCollaborationCommentResponse:
    return AnalystCollaborationCommentResponse(
        id=c.id,
        case_id=c.case_id,
        plan_id=c.plan_id,
        action_id=c.action_id,
        task_id=c.task_id,
        parent_comment_id=c.parent_comment_id,
        author=c.author,
        comment_type=c.comment_type,
        content=c.content,
        is_resolved=c.is_resolved,
        created_at=c.created_at,
        updated_at=c.updated_at,
        replies=[serialize_comment(reply) for reply in c.replies]
    )


# --- RESPONSE PLANS ---

@router.post(
    "/investigations/{case_identifier}/response-plans",
    response_model=IncidentResponsePlanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new versioned incident response plan"
)
def create_response_plan(
    case_identifier: str,
    req: ResponsePlanCreateRequest,
    db: Session = Depends(get_db)
):
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    req.case_id = case.id
    try:
        plan = IncidentResponseService.create_response_plan(db, req)
        return serialize_plan(plan)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/investigations/{case_identifier}/response-plans",
    response_model=List[IncidentResponsePlanResponse],
    summary="List all response plans for an investigation case"
)
def list_case_response_plans(
    case_identifier: str,
    db: Session = Depends(get_db)
):
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    plans = IncidentResponseService.list_case_plans(db, case.id)
    return [serialize_plan(p) for p in plans]


@router.get(
    "/response-plans/{plan_id}",
    response_model=IncidentResponsePlanResponse,
    summary="Retrieve response plan details, actions, and revision history"
)
def get_response_plan(
    plan_id: str,
    db: Session = Depends(get_db)
):
    plan = IncidentResponseService.get_plan(db, plan_id)
    if not plan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Response Plan '{plan_id}' not found")
    return serialize_plan(plan)


@router.post(
    "/response-plans/{plan_id}/actions",
    response_model=ResponsePlanActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a discrete response or containment action to a plan"
)
def add_response_action(
    plan_id: str,
    req: ResponseActionCreateRequest,
    db: Session = Depends(get_db)
):
    try:
        action = IncidentResponseService.add_action(db, plan_id, req)
        return serialize_action(action)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/response-actions/{action_id}/approve",
    response_model=ResponsePlanActionResponse,
    summary="Approve or reject a response action (enforces Separation of Duties)"
)
def approve_response_action(
    action_id: str,
    req: ResponseActionApprovalRequest,
    db: Session = Depends(get_db)
):
    try:
        action = IncidentResponseService.approve_action(db, action_id, req)
        return serialize_action(action)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/response-actions/{action_id}/execute",
    response_model=ResponsePlanActionResponse,
    summary="Acknowledge manual execution of an approved response action"
)
def acknowledge_response_action_execution(
    action_id: str,
    req: ResponseActionExecutionRequest,
    db: Session = Depends(get_db)
):
    try:
        action = IncidentResponseService.acknowledge_execution(db, action_id, req)
        return serialize_action(action)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/response-plans/{plan_id}/revisions",
    response_model=ResponsePlanRevisionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new revision snapshot and increment plan version"
)
def create_plan_revision(
    plan_id: str,
    revised_by: str = Query(..., min_length=1),
    revision_summary: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    try:
        rev = IncidentResponseService.create_revision(db, plan_id, revised_by, revision_summary)
        return serialize_revision(rev)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# --- ANALYST COLLABORATION ---

@router.post(
    "/investigations/{case_identifier}/comments",
    response_model=AnalystCollaborationCommentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Post an analyst collaboration comment or threaded peer-review note"
)
def post_collaboration_comment(
    case_identifier: str,
    req: AnalystCommentCreateRequest,
    db: Session = Depends(get_db)
):
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    try:
        comment = IncidentResponseService.add_comment(db, case.id, req)
        return serialize_comment(comment)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/investigations/{case_identifier}/comments",
    response_model=List[AnalystCollaborationCommentResponse],
    summary="List top-level collaboration comments with threaded replies"
)
def list_collaboration_comments(
    case_identifier: str,
    db: Session = Depends(get_db)
):
    case = CaseService.get_case(db, case_identifier)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_identifier}' not found")

    comments = IncidentResponseService.list_comments(db, case.id)
    return [serialize_comment(c) for c in comments]
