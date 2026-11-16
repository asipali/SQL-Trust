"""
SQL-TRUST REST API Endpoints
Module 6: Cyber Investigation & Incident Response Orchestration
Endpoints for workflow lifecycle management, stage progression,
task manipulation, DAG prerequisite resolution, and escalations.
"""
import json
from typing import List, Optional, Any, Dict
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.investigation import (
    InvestigationWorkflow,
    InvestigationTask,
    InvestigationWorkflowTemplate,
    InvestigationWorkflowHistory,
    InvestigationEscalation
)
from backend.schemas.investigation import (
    WorkflowResponse,
    WorkflowTaskResponse,
    WorkflowHistoryResponse,
    WorkflowEscalationResponse,
    WorkflowTemplateResponse,
    WorkflowTransitionRequest,
    WorkflowEscalateRequest,
    TaskCreateRequest,
    TaskUpdateRequest,
    TaskCompleteRequest,
    TaskDependencyCreateRequest
)
from backend.services.investigation.workflow_service import InvestigationWorkflowService  # pyrefly: ignore[missing-import]
from backend.services.investigation.task_service import InvestigationTaskService  # pyrefly: ignore[missing-import]

router = APIRouter(tags=["Investigation Workflows & Tasks"])


def serialize_task(t: InvestigationTask) -> WorkflowTaskResponse:
    prereq_ids = [d.prerequisite_task_id for d in t.prerequisites]
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
        is_mandatory=t.is_mandatory,
        order_index=t.order_index,
        due_date=t.due_date,
        completed_at=t.completed_at,
        completed_by=t.completed_by,
        completion_notes=t.completion_notes,
        evidence_reference_id=t.evidence_reference_id,
        prerequisites=prereq_ids,
        created_at=t.created_at,
        updated_at=t.updated_at
    )


def serialize_workflow(wf: InvestigationWorkflow) -> WorkflowResponse:
    tasks = [serialize_task(t) for t in wf.tasks]
    completed_count = sum(1 for t in tasks if t.status in ("COMPLETED", "SKIPPED"))
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
            for h in wf.history
        ],
        escalations=[
            WorkflowEscalationResponse.model_validate(e)
            for e in wf.escalations
        ]
    )


# --- TEMPLATES ---

@router.get(
    "/workflow-templates",
    response_model=List[WorkflowTemplateResponse],
    summary="List available investigation workflow templates"
)
def list_workflow_templates(
    active_only: bool = Query(True),
    db: Session = Depends(get_db)
):
    templates = InvestigationWorkflowService.list_templates(db, active_only=active_only)
    if not templates:
        templates = InvestigationWorkflowService.seed_default_templates(db)
    
    res = []
    for t in templates:
        res.append(WorkflowTemplateResponse(
            id=t.id,
            name=t.name,
            incident_category=t.incident_category,
            description=t.description,
            stages_definition=json.loads(t.stages_definition),
            tasks_definition=json.loads(t.tasks_definition),
            version=t.version,
            is_active=t.is_active,
            created_at=t.created_at,
            updated_at=t.updated_at
        ))
    return res


@router.post(
    "/workflow-templates/seed",
    response_model=List[WorkflowTemplateResponse],
    summary="Seed default investigation playbook templates"
)
def seed_workflow_templates(db: Session = Depends(get_db)):
    templates = InvestigationWorkflowService.seed_default_templates(db)
    res = []
    for t in templates:
        res.append(WorkflowTemplateResponse(
            id=t.id,
            name=t.name,
            incident_category=t.incident_category,
            description=t.description,
            stages_definition=json.loads(t.stages_definition),
            tasks_definition=json.loads(t.tasks_definition),
            version=t.version,
            is_active=t.is_active,
            created_at=t.created_at,
            updated_at=t.updated_at
        ))
    return res


# --- WORKFLOWS ---

@router.get(
    "/workflows/{workflow_id}",
    response_model=WorkflowResponse,
    summary="Retrieve workflow details with tasks, history, and escalations"
)
def get_workflow(
    workflow_id: str,
    db: Session = Depends(get_db)
):
    wf = InvestigationWorkflowService.get_workflow_details(db, workflow_id)
    if not wf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Workflow '{workflow_id}' not found")
    return serialize_workflow(wf)


@router.post(
    "/workflows/{workflow_id}/start",
    response_model=WorkflowResponse,
    summary="Start workflow execution (NOT_STARTED -> ACTIVE)"
)
def start_workflow(
    workflow_id: str,
    actor: str = Query("investigator"),
    db: Session = Depends(get_db)
):
    try:
        wf = InvestigationWorkflowService.start_workflow(db, workflow_id, actor=actor)
        return serialize_workflow(wf)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/workflows/{workflow_id}/transition",
    response_model=WorkflowResponse,
    summary="Transition workflow status or stage with completion guard"
)
def transition_workflow(
    workflow_id: str,
    req: WorkflowTransitionRequest,
    db: Session = Depends(get_db)
):
    try:
        wf = InvestigationWorkflowService.transition_workflow(
            db=db,
            workflow_id=workflow_id,
            to_status=req.to_status,
            actor=req.actor,
            to_stage=req.to_stage,
            transition_reason=req.transition_reason
        )
        return serialize_workflow(wf)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/workflows/{workflow_id}/tasks",
    response_model=List[WorkflowTaskResponse],
    summary="List all tasks in a workflow"
)
def list_workflow_tasks(
    workflow_id: str,
    db: Session = Depends(get_db)
):
    wf = db.query(InvestigationWorkflow).filter(InvestigationWorkflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Workflow '{workflow_id}' not found")
    tasks = InvestigationTaskService.get_workflow_tasks(db, workflow_id)
    return [serialize_task(t) for t in tasks]


@router.post(
    "/workflows/{workflow_id}/tasks",
    response_model=WorkflowTaskResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a new task to a workflow"
)
def create_workflow_task(
    workflow_id: str,
    req: TaskCreateRequest,
    actor: str = Query("investigator"),
    db: Session = Depends(get_db)
):
    try:
        task = InvestigationTaskService.create_task(
            db=db,
            workflow_id=workflow_id,
            stage_name=req.stage_name,
            title=req.title,
            description=req.description,
            task_type=req.task_type or "MANUAL",
            priority=req.priority or "P3_MEDIUM",
            assigned_to=req.assigned_to,
            assigned_team=req.assigned_team,
            is_mandatory=req.is_mandatory if req.is_mandatory is not None else True,
            order_index=req.order_index or 0,
            due_date=req.due_date,
            prerequisite_task_ids=req.prerequisite_task_ids,
            actor=actor
        )
        return serialize_task(task)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/workflows/{workflow_id}/escalate",
    response_model=WorkflowEscalationResponse,
    summary="Escalate workflow or task to senior team or management"
)
def escalate_workflow(
    workflow_id: str,
    req: WorkflowEscalateRequest,
    db: Session = Depends(get_db)
):
    try:
        escalation = InvestigationWorkflowService.escalate_workflow(db, workflow_id, req)
        return WorkflowEscalationResponse.model_validate(escalation)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/workflows/{workflow_id}/history",
    response_model=List[WorkflowHistoryResponse],
    summary="Retrieve workflow state and stage audit transition history"
)
def get_workflow_history(
    workflow_id: str,
    db: Session = Depends(get_db)
):
    wf = db.query(InvestigationWorkflow).filter(InvestigationWorkflow.id == workflow_id).first()
    if not wf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Workflow '{workflow_id}' not found")
    history = (
        db.query(InvestigationWorkflowHistory)
        .filter(InvestigationWorkflowHistory.workflow_id == workflow_id)
        .order_by(InvestigationWorkflowHistory.transitioned_at.asc())
        .all()
    )
    return [WorkflowHistoryResponse.model_validate(h) for h in history]


# --- TASKS ---

@router.patch(
    "/workflow-tasks/{task_id}",
    response_model=WorkflowTaskResponse,
    summary="Update task details, assignment, or status"
)
def update_task(
    task_id: str,
    req: TaskUpdateRequest,
    actor: str = Query("investigator"),
    db: Session = Depends(get_db)
):
    try:
        task = InvestigationTaskService.update_task(
            db=db,
            task_id=task_id,
            title=req.title,
            description=req.description,
            status=req.status,
            priority=req.priority,
            assigned_to=req.assigned_to,
            assigned_team=req.assigned_team,
            is_mandatory=req.is_mandatory,
            order_index=req.order_index,
            due_date=req.due_date,
            completion_notes=req.completion_notes,
            actor=actor
        )
        return serialize_task(task)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/workflow-tasks/{task_id}/complete",
    response_model=WorkflowTaskResponse,
    summary="Mark task as COMPLETED or SKIPPED with prerequisite validation"
)
def complete_task(
    task_id: str,
    req: TaskCompleteRequest,
    db: Session = Depends(get_db)
):
    try:
        task = InvestigationTaskService.complete_task(
            db=db,
            task_id=task_id,
            completed_by=req.completed_by,
            completion_notes=req.completion_notes,
            evidence_reference_id=req.evidence_reference_id,
            status=req.status or "COMPLETED"
        )
        return serialize_task(task)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
