"""
SQL-TRUST Incident Response & Collaboration Service
Module 6: Cyber Investigation & Incident Response Orchestration
Manages versioned Incident Response Plans (IRPs), containment/eradication actions,
strict Separation of Duties (SoD) multi-party approvals, manual execution tracking,
and threaded analyst collaboration comments.
"""
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session, joinedload

from backend.models.investigation import (
    InvestigationCase,
    IncidentResponsePlan,
    ResponsePlanAction,
    ResponsePlanRevision,
    AnalystCollaborationComment,
    CaseEvidenceLink
)
from backend.models.backup import utc_now
from backend.services.investigation.audit_service import CaseAuditService  # pyrefly: ignore[missing-import]
from backend.schemas.investigation import (
    ResponsePlanCreateRequest,
    ResponsePlanUpdateRequest,
    ResponseActionCreateRequest,
    ResponseActionApprovalRequest,
    ResponseActionExecutionRequest,
    AnalystCommentCreateRequest
)

logger = logging.getLogger("sqltrust.investigation.response")

VALID_PLAN_STATUSES = {"DRAFT", "IN_REVIEW", "APPROVED", "ACTIVE", "EXECUTED", "SUPERSEDED", "CANCELLED"}
VALID_ACTION_CATEGORIES = {"CONTAINMENT", "ERADICATION", "RECOVERY_PREPARATION", "POST_INCIDENT"}
VALID_TARGET_TYPES = {"LOGIN", "USER", "DATABASE", "TABLE", "ENDPOINT", "AUDIT_CONFIG"}
VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_APPROVAL_STATUSES = {"PENDING_APPROVAL", "APPROVED", "REJECTED", "SUPERSEDED"}
VALID_EXECUTION_STATUSES = {"NOT_EXECUTED", "EXECUTED_SUCCESS", "EXECUTED_FAILED", "SKIPPED"}


class IncidentResponseService:
    """
    Coordinates response plan versioning, action lifecycle, multi-party approvals,
    execution acknowledgements, and analyst threaded collaboration.
    """

    @staticmethod
    def create_response_plan(
        db: Session,
        req: ResponsePlanCreateRequest
    ) -> IncidentResponsePlan:
        """
        Creates a new version-controlled incident response plan for a case.
        """
        case = db.query(InvestigationCase).filter(InvestigationCase.id == req.case_id).first()
        if not case:
            raise ValueError(f"Investigation Case '{req.case_id}' not found")

        plan = IncidentResponsePlan(
            case_id=case.id,
            title=req.title,
            summary=req.summary,
            plan_type=req.plan_type or "CONTAINMENT_AND_RECOVERY",
            status="DRAFT",
            version=1,
            created_by=req.created_by
        )
        db.add(plan)
        db.flush()

        # Initial revision snapshot
        snapshot = {
            "version": 1,
            "title": plan.title,
            "summary": plan.summary,
            "plan_type": plan.plan_type,
            "status": plan.status,
            "actions": []
        }
        revision = ResponsePlanRevision(
            plan_id=plan.id,
            version=1,
            snapshot_data=json.dumps(snapshot),
            revised_by=req.created_by,
            revision_summary="Initial plan creation"
        )
        db.add(revision)

        CaseAuditService.log_action(
            db=db,
            case_id=case.id,
            action="RESPONSE_PLAN_CREATED",
            actor=req.created_by,
            details=f"Response Plan '{plan.title}' created (version 1) for case {case.case_number}"
        )
        db.commit()
        db.refresh(plan)
        return plan

    @staticmethod
    def get_plan(db: Session, plan_id: str) -> Optional[IncidentResponsePlan]:
        """Retrieves a response plan with actions and revisions."""
        return (
            db.query(IncidentResponsePlan)
            .filter(IncidentResponsePlan.id == plan_id)
            .first()
        )

    @staticmethod
    def list_case_plans(db: Session, case_id: str) -> List[IncidentResponsePlan]:
        """Lists all response plans for a given investigation case."""
        return (
            db.query(IncidentResponsePlan)
            .filter(IncidentResponsePlan.case_id == case_id)
            .order_by(IncidentResponsePlan.created_at.desc())
            .all()
        )

    @staticmethod
    def add_action(
        db: Session,
        plan_id: str,
        req: ResponseActionCreateRequest
    ) -> ResponsePlanAction:
        """
        Adds a discrete response/containment action to an incident response plan.
        Enforces multi-party approval requirement for HIGH and CRITICAL actions.
        """
        plan = db.query(IncidentResponsePlan).filter(IncidentResponsePlan.id == plan_id).first()
        if not plan:
            raise ValueError(f"Response Plan '{plan_id}' not found")

        risk_level = (req.risk_level or "MEDIUM").upper()
        if risk_level not in VALID_RISK_LEVELS:
            raise ValueError(f"Invalid risk_level '{risk_level}'. Valid: {VALID_RISK_LEVELS}")

        # High and critical risk actions unconditionally require multi-party approval
        requires_multi_party = True if risk_level in ("HIGH", "CRITICAL") else (
            req.requires_multi_party_approval if req.requires_multi_party_approval is not None else False
        )

        action = ResponsePlanAction(
            plan_id=plan.id,
            case_id=plan.case_id,
            title=req.title,
            action_category=req.action_category or "CONTAINMENT",
            target_type=req.target_type or "LOGIN",
            target_identifier=req.target_identifier,
            risk_level=risk_level,
            proposed_script=req.proposed_script,
            rollback_script=req.rollback_script,
            execution_order=req.execution_order or 0,
            requires_multi_party_approval=requires_multi_party,
            approval_status="PENDING_APPROVAL",
            proposed_by=req.proposed_by,
            execution_status="NOT_EXECUTED"
        )
        db.add(action)

        CaseAuditService.log_action(
            db=db,
            case_id=plan.case_id,
            action="RESPONSE_ACTION_PROPOSED",
            actor=req.proposed_by,
            details=f"Action '{action.title}' proposed (category: {action.action_category}, risk: {risk_level}, multi-party: {requires_multi_party})"
        )
        db.commit()
        db.refresh(action)
        return action

    @staticmethod
    def approve_action(
        db: Session,
        action_id: str,
        req: ResponseActionApprovalRequest
    ) -> ResponsePlanAction:
        """
        Approves or rejects a proposed response action.
        Enforces strict Separation of Duties (SoD):
        The proposer of a high-risk or multi-party action CANNOT approve their own action.
        """
        action = db.query(ResponsePlanAction).filter(ResponsePlanAction.id == action_id).first()
        if not action:
            raise ValueError(f"Response action '{action_id}' not found")

        if req.approval_status not in ("APPROVED", "REJECTED"):
            raise ValueError("approval_status must be either 'APPROVED' or 'REJECTED'")

        # Separation of Duties (SoD) Enforcement:
        if action.requires_multi_party_approval or action.risk_level in ("HIGH", "CRITICAL"):
            if action.proposed_by.strip().lower() == req.approved_by.strip().lower():
                raise ValueError(
                    f"Separation of duties violation: Operator '{req.approved_by}' proposed this {action.risk_level} "
                    f"risk action and cannot approve it. An independent analyst or security lead must review."
                )

        action.approval_status = req.approval_status
        action.approved_by = req.approved_by
        action.approved_at = utc_now()
        action.approval_notes = req.approval_notes
        action.updated_at = utc_now()

        CaseAuditService.log_action(
            db=db,
            case_id=action.case_id,
            action=f"RESPONSE_ACTION_{req.approval_status}",
            actor=req.approved_by,
            details=f"Action '{action.title}' ({action.id}) marked {req.approval_status}. Notes: {req.approval_notes or 'None'}"
        )
        db.commit()
        db.refresh(action)
        return action

    @staticmethod
    def acknowledge_execution(
        db: Session,
        action_id: str,
        req: ResponseActionExecutionRequest
    ) -> ResponsePlanAction:
        """
        Records manual execution results by a human DBA or security operator.
        Enforces that only APPROVED actions can be executed.
        """
        action = db.query(ResponsePlanAction).filter(ResponsePlanAction.id == action_id).first()
        if not action:
            raise ValueError(f"Response action '{action_id}' not found")

        if action.approval_status != "APPROVED":
            raise ValueError(
                f"Execution blocked: Action '{action.title}' is in '{action.approval_status}' state and must be APPROVED before execution."
            )

        if req.execution_status not in VALID_EXECUTION_STATUSES:
            raise ValueError(f"Invalid execution_status '{req.execution_status}'. Valid: {VALID_EXECUTION_STATUSES}")

        # Validate evidence reference if provided
        if req.evidence_reference_id:
            ev = db.query(CaseEvidenceLink).filter(CaseEvidenceLink.id == req.evidence_reference_id).first()
            if not ev:
                raise ValueError(f"Evidence link '{req.evidence_reference_id}' not found")
            action.execution_evidence_id = ev.id

        action.execution_status = req.execution_status
        action.executed_by = req.executed_by
        action.executed_at = utc_now()
        action.execution_notes = req.execution_notes
        action.updated_at = utc_now()

        CaseAuditService.log_action(
            db=db,
            case_id=action.case_id,
            action="RESPONSE_ACTION_EXECUTED",
            actor=req.executed_by,
            details=f"Action '{action.title}' executed with status {req.execution_status}. Notes: {req.execution_notes or 'None'}"
        )
        db.commit()
        db.refresh(action)
        return action

    @staticmethod
    def create_revision(
        db: Session,
        plan_id: str,
        revised_by: str,
        revision_summary: Optional[str] = None
    ) -> ResponsePlanRevision:
        """
        Generates an immutable revision snapshot and increments plan version.
        """
        plan = db.query(IncidentResponsePlan).filter(IncidentResponsePlan.id == plan_id).first()
        if not plan:
            raise ValueError(f"Response Plan '{plan_id}' not found")

        plan.version += 1
        plan.updated_at = utc_now()

        # Capture snapshot of actions
        actions_data = [
            {
                "id": a.id,
                "title": a.title,
                "action_category": a.action_category,
                "target_type": a.target_type,
                "target_identifier": a.target_identifier,
                "risk_level": a.risk_level,
                "proposed_script": a.proposed_script,
                "rollback_script": a.rollback_script,
                "approval_status": a.approval_status,
                "approved_by": a.approved_by,
                "execution_status": a.execution_status,
                "executed_by": a.executed_by
            }
            for a in plan.actions
        ]

        snapshot = {
            "version": plan.version,
            "title": plan.title,
            "summary": plan.summary,
            "plan_type": plan.plan_type,
            "status": plan.status,
            "actions": actions_data
        }

        revision = ResponsePlanRevision(
            plan_id=plan.id,
            version=plan.version,
            snapshot_data=json.dumps(snapshot),
            revised_by=revised_by,
            revision_summary=revision_summary or f"Version {plan.version} incremented"
        )
        db.add(revision)

        CaseAuditService.log_action(
            db=db,
            case_id=plan.case_id,
            action="RESPONSE_PLAN_REVISED",
            actor=revised_by,
            details=f"Plan '{plan.title}' incremented to version {plan.version}. Summary: {revision_summary}"
        )
        db.commit()
        db.refresh(revision)
        return revision

    @staticmethod
    def add_comment(
        db: Session,
        case_id: str,
        req: AnalystCommentCreateRequest
    ) -> AnalystCollaborationComment:
        """
        Adds an analyst collaboration comment or threaded peer-review reply.
        """
        case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Case '{case_id}' not found")

        if req.parent_comment_id:
            parent = db.query(AnalystCollaborationComment).filter(
                AnalystCollaborationComment.id == req.parent_comment_id,
                AnalystCollaborationComment.case_id == case.id
            ).first()
            if not parent:
                raise ValueError(f"Parent comment '{req.parent_comment_id}' not found on this case")

        comment = AnalystCollaborationComment(
            case_id=case.id,
            plan_id=req.plan_id,
            action_id=req.action_id,
            task_id=req.task_id,
            parent_comment_id=req.parent_comment_id,
            author=req.author,
            comment_type=req.comment_type or "COMMENT",
            content=req.content,
            is_resolved=False
        )
        db.add(comment)

        CaseAuditService.log_action(
            db=db,
            case_id=case.id,
            action="ANALYST_COMMENT_ADDED",
            actor=req.author,
            details=f"Analyst comment added ({comment.comment_type}) by {comment.author}"
        )
        db.commit()
        db.refresh(comment)
        return comment

    @staticmethod
    def list_comments(db: Session, case_id: str) -> List[AnalystCollaborationComment]:
        """
        Retrieves all top-level collaboration comments for a case with replies.
        """
        return (
            db.query(AnalystCollaborationComment)
            .filter(
                AnalystCollaborationComment.case_id == case_id,
                AnalystCollaborationComment.parent_comment_id == None
            )
            .order_by(AnalystCollaborationComment.created_at.asc())
            .all()
        )
