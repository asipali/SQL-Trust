"""
SQL-TRUST Investigation Task Service
Module 6: Cyber Investigation & Incident Response Orchestration
Manages discrete tasks, ordered stages, task completion enforcement,
and circular dependency detection using DAG cycle analysis.
"""
import logging
from datetime import datetime, timezone
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict, deque
from sqlalchemy.orm import Session
from sqlalchemy import select

from backend.models.investigation import (
    InvestigationCase,
    InvestigationWorkflow,
    InvestigationTask,
    InvestigationTaskDependency
)
from backend.models.backup import utc_now
from backend.services.investigation.audit_service import CaseAuditService  # pyrefly: ignore[missing-import]

logger = logging.getLogger("sqltrust.investigation.tasks")

VALID_TASK_STATUSES = {"PENDING", "IN_PROGRESS", "BLOCKED", "COMPLETED", "SKIPPED", "CANCELLED", "FAILED"}
VALID_TASK_TYPES = {"MANUAL", "AUTOMATED_CHECK", "REVIEW", "APPROVAL"}
VALID_PRIORITIES = {"P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"}


class InvestigationTaskService:
    """
    Manages task lifecycle, prerequisite gating, and dependency DAG cycle validation.
    """

    @staticmethod
    def create_task(
        db: Session,
        workflow_id: str,
        stage_name: str,
        title: str,
        description: Optional[str] = None,
        task_type: str = "MANUAL",
        priority: str = "P3_MEDIUM",
        assigned_to: Optional[str] = None,
        assigned_team: Optional[str] = None,
        is_mandatory: bool = True,
        order_index: int = 0,
        due_date: Optional[datetime] = None,
        prerequisite_task_ids: Optional[List[str]] = None,
        actor: str = "system"
    ) -> InvestigationTask:
        """
        Creates a new task in a workflow and optionally registers prerequisite dependencies.
        """
        workflow = db.query(InvestigationWorkflow).filter(InvestigationWorkflow.id == workflow_id).first()
        if not workflow:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        if task_type not in VALID_TASK_TYPES:
            raise ValueError(f"Invalid task_type '{task_type}'. Valid: {VALID_TASK_TYPES}")
        if priority not in VALID_PRIORITIES:
            raise ValueError(f"Invalid priority '{priority}'. Valid: {VALID_PRIORITIES}")

        task = InvestigationTask(
            workflow_id=workflow.id,
            case_id=workflow.case_id,
            stage_name=stage_name,
            title=title,
            description=description,
            task_type=task_type,
            status="PENDING",
            priority=priority,
            assigned_to=assigned_to,
            assigned_team=assigned_team,
            is_mandatory=is_mandatory,
            order_index=order_index,
            due_date=due_date
        )
        db.add(task)
        db.flush()

        if prerequisite_task_ids:
            for prereq_id in prerequisite_task_ids:
                InvestigationTaskService.add_dependency(
                    db=db,
                    task_id=task.id,
                    prerequisite_task_id=prereq_id,
                    dependency_type="BLOCKING",
                    actor=actor
                )

        CaseAuditService.log_action(
            db=db,
            case_id=workflow.case_id,
            action="TASK_CREATED",
            actor=actor,
            details=f"Task '{task.title}' created in stage '{stage_name}' (mandatory={is_mandatory})"
        )
        db.commit()
        db.refresh(task)
        return task

    @staticmethod
    def add_dependency(
        db: Session,
        task_id: str,
        prerequisite_task_id: str,
        dependency_type: str = "BLOCKING",
        actor: str = "system"
    ) -> InvestigationTaskDependency:
        """
        Adds a directed dependency from prerequisite_task to task.
        Performs DAG cycle detection using Kahn's algorithm or DFS.
        Rejects with ValueError if a cycle would be created.
        """
        if task_id == prerequisite_task_id:
            raise ValueError("A task cannot depend on itself")

        task = db.query(InvestigationTask).filter(InvestigationTask.id == task_id).first()
        if not task:
            raise ValueError(f"Target task '{task_id}' not found")

        prereq = db.query(InvestigationTask).filter(InvestigationTask.id == prerequisite_task_id).first()
        if not prereq:
            raise ValueError(f"Prerequisite task '{prerequisite_task_id}' not found")

        if task.workflow_id != prereq.workflow_id:
            raise ValueError("Tasks in a dependency relationship must belong to the same workflow")

        # Check if already exists
        existing = db.query(InvestigationTaskDependency).filter(
            InvestigationTaskDependency.task_id == task_id,
            InvestigationTaskDependency.prerequisite_task_id == prerequisite_task_id
        ).first()
        if existing:
            return existing

        # Check for cycles
        if InvestigationTaskService._would_create_cycle(db, task.workflow_id, task_id, prerequisite_task_id):
            raise ValueError("Circular dependency detected in workflow tasks")

        dep = InvestigationTaskDependency(
            task_id=task_id,
            prerequisite_task_id=prerequisite_task_id,
            dependency_type=dependency_type
        )
        db.add(dep)
        db.commit()
        db.refresh(dep)
        return dep

    @staticmethod
    def _would_create_cycle(db: Session, workflow_id: str, task_id: str, prerequisite_task_id: str) -> bool:
        """
        Tests if adding edge (prerequisite_task_id -> task_id) creates a cycle in workflow's task graph.
        An edge exists from A -> B if B depends on A (A is prerequisite of B).
        Adding prerequisite_task_id -> task_id means task_id is reachable from prerequisite_task_id.
        If prerequisite_task_id is ALREADY reachable from task_id, adding this edge creates a cycle!
        """
        # Fetch all existing dependencies in this workflow
        deps = (
            db.query(InvestigationTaskDependency.prerequisite_task_id, InvestigationTaskDependency.task_id)
            .join(InvestigationTask, InvestigationTask.id == InvestigationTaskDependency.task_id)
            .filter(InvestigationTask.workflow_id == workflow_id)
            .all()
        )

        adj: Dict[str, List[str]] = defaultdict(list)
        for p_id, t_id in deps:
            adj[p_id].append(t_id)

        # We want to check if prerequisite_task_id is reachable from task_id in the current graph
        visited: Set[str] = set()
        queue: deque[str] = deque([task_id])

        while queue:
            curr = queue.popleft()
            if curr == prerequisite_task_id:
                return True
            if curr not in visited:
                visited.add(curr)
                for neighbor in adj.get(curr, []):
                    if neighbor not in visited:
                        queue.append(neighbor)

        return False

    @staticmethod
    def check_prerequisites_satisfied(db: Session, task_id: str) -> Tuple[bool, List[str]]:
        """
        Checks whether all BLOCKING prerequisite tasks are in COMPLETED or SKIPPED state.
        Returns (is_satisfied, list_of_unmet_prerequisite_titles).
        """
        deps = (
            db.query(InvestigationTaskDependency, InvestigationTask)
            .join(InvestigationTask, InvestigationTask.id == InvestigationTaskDependency.prerequisite_task_id)
            .filter(
                InvestigationTaskDependency.task_id == task_id,
                InvestigationTaskDependency.dependency_type == "BLOCKING"
            )
            .all()
        )

        unmet = []
        for dep, prereq in deps:
            if prereq.status not in ("COMPLETED", "SKIPPED"):
                unmet.append(f"{prereq.title} ({prereq.status})")

        return len(unmet) == 0, unmet

    @staticmethod
    def update_task(
        db: Session,
        task_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        assigned_to: Optional[str] = None,
        assigned_team: Optional[str] = None,
        is_mandatory: Optional[bool] = None,
        order_index: Optional[int] = None,
        due_date: Optional[datetime] = None,
        completion_notes: Optional[str] = None,
        actor: str = "system"
    ) -> InvestigationTask:
        """
        Updates task attributes with validation.
        """
        task = db.query(InvestigationTask).filter(InvestigationTask.id == task_id).first()
        if not task:
            raise ValueError(f"Task '{task_id}' not found")

        if status:
            if status not in VALID_TASK_STATUSES:
                raise ValueError(f"Invalid task status '{status}'. Valid: {VALID_TASK_STATUSES}")
            if status in ("IN_PROGRESS", "COMPLETED"):
                satisfied, unmet = InvestigationTaskService.check_prerequisites_satisfied(db, task.id)
                if not satisfied:
                    raise ValueError(f"Cannot transition task to '{status}': Unmet prerequisites: {', '.join(unmet)}")
            task.status = status

        if title is not None:
            task.title = title
        if description is not None:
            task.description = description
        if priority is not None:
            if priority not in VALID_PRIORITIES:
                raise ValueError(f"Invalid priority '{priority}'. Valid: {VALID_PRIORITIES}")
            task.priority = priority
        if assigned_to is not None:
            task.assigned_to = assigned_to
        if assigned_team is not None:
            task.assigned_team = assigned_team
        if is_mandatory is not None:
            task.is_mandatory = is_mandatory
        if order_index is not None:
            task.order_index = order_index
        if due_date is not None:
            task.due_date = due_date
        if completion_notes is not None:
            task.completion_notes = completion_notes

        task.updated_at = utc_now()
        db.commit()
        db.refresh(task)
        return task

    @staticmethod
    def complete_task(
        db: Session,
        task_id: str,
        completed_by: str,
        completion_notes: Optional[str] = None,
        evidence_reference_id: Optional[str] = None,
        status: str = "COMPLETED"
    ) -> InvestigationTask:
        """
        Completes or skips a task after verifying all prerequisite tasks are satisfied.
        """
        if status not in ("COMPLETED", "SKIPPED"):
            raise ValueError("Completion status must be either 'COMPLETED' or 'SKIPPED'")

        task = db.query(InvestigationTask).filter(InvestigationTask.id == task_id).first()
        if not task:
            raise ValueError(f"Task '{task_id}' not found")

        # Verify prerequisite blocking tasks
        satisfied, unmet = InvestigationTaskService.check_prerequisites_satisfied(db, task.id)
        if not satisfied and status == "COMPLETED":
            raise ValueError(
                f"Cannot complete task '{task.title}': Blocking prerequisite tasks not completed: {', '.join(unmet)}"
            )

        task.status = status
        task.completed_at = utc_now()
        task.completed_by = completed_by
        if completion_notes:
            task.completion_notes = completion_notes
        if evidence_reference_id:
            task.evidence_reference_id = evidence_reference_id
        task.updated_at = utc_now()

        CaseAuditService.log_action(
            db=db,
            case_id=task.case_id,
            action="TASK_COMPLETED" if status == "COMPLETED" else "TASK_SKIPPED",
            actor=completed_by,
            details=f"Task '{task.title}' marked {status}. Notes: {completion_notes or 'None'}"
        )
        db.commit()
        db.refresh(task)
        return task

    @staticmethod
    def get_workflow_tasks(db: Session, workflow_id: str) -> List[InvestigationTask]:
        """Returns all tasks for a workflow ordered by stage and order_index."""
        return (
            db.query(InvestigationTask)
            .filter(InvestigationTask.workflow_id == workflow_id)
            .order_by(InvestigationTask.order_index.asc(), InvestigationTask.created_at.asc())
            .all()
        )
