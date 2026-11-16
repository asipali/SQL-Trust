"""
SQL-TRUST Control Database Models
Module 6: Cyber Investigation & Incident Response Orchestration
Defines models for investigation case management, evidence references,
append-only audit trails, analyst notes, and containment recommendations.
Enforces ondelete="NO ACTION" on foreign keys to external modules.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    DateTime,
    Text,
    ForeignKey,
    Index,
    Boolean,
    Integer,
    Float,
    text
)
from sqlalchemy.orm import relationship
from backend.models.backup import Base, generate_uuid, utc_now


def generate_case_reference() -> str:
    """Generates a human-readable unique reference for an investigation case."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_suffix = uuid.uuid4().hex[:4].upper()
    return f"INV-{date_str}-{short_suffix}"


class InvestigationCase(Base):
    """
    Central orchestration record tracking the complete cyber investigation lifecycle
    for a database incident.
    """
    __tablename__ = "investigation_cases"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_number = Column(String(64), nullable=False, unique=True, index=True, default=generate_case_reference)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)

    target_database_id = Column(
        String(36),
        ForeignKey("protected_databases.id", ondelete="NO ACTION"),
        nullable=True,
        index=True
    )
    target_database_name = Column(String(128), nullable=False, index=True)

    priority = Column(String(32), default="P3_MEDIUM", nullable=False, index=True)
    status = Column(String(32), default="NEW", nullable=False, index=True)
    incident_category = Column(String(64), default="SUSPICIOUS_ACTIVITY", nullable=False, index=True)

    lead_investigator = Column(String(128), nullable=True)
    assigned_team = Column(String(128), nullable=True)
    created_by = Column(String(128), nullable=False)

    idempotency_key = Column(String(128), nullable=True)
    severity_score = Column(Float, default=0.0, nullable=False)
    blast_radius_summary = Column(Text, nullable=True)
    containment_status = Column(String(32), default="NONE", nullable=False)

    version = Column(Integer, default=1, nullable=False)

    opened_at = Column(DateTime, default=utc_now, nullable=False)
    closed_at = Column(DateTime, nullable=True)
    closure_reason = Column(Text, nullable=True)

    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        Index(
            "ix_investigation_cases_idempotency_key",
            "idempotency_key",
            unique=True,
            mssql_where=text("idempotency_key IS NOT NULL")
        ),
    )

    # Relationships
    database = relationship("ProtectedDatabase", foreign_keys=[target_database_id])
    status_history = relationship(
        "CaseStatusHistory",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseStatusHistory.transitioned_at.asc()"
    )
    notes = relationship(
        "CaseNote",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseNote.created_at.asc()"
    )
    audit_logs = relationship(
        "CaseAuditLog",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseAuditLog.sequence_number.asc()"
    )
    evidence_links = relationship(
        "CaseEvidenceLink",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseEvidenceLink.linked_at.asc()"
    )
    containment_actions = relationship(
        "CaseContainmentAction",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseContainmentAction.created_at.asc()"
    )
    workflows = relationship(
        "InvestigationWorkflow",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="InvestigationWorkflow.created_at.desc()"
    )
    tasks = relationship(
        "InvestigationTask",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="InvestigationTask.created_at.asc()"
    )
    escalations = relationship(
        "InvestigationEscalation",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="InvestigationEscalation.created_at.asc()"
    )
    mitre_techniques = relationship(
        "CaseMitreTechnique",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseMitreTechnique.mapped_at.asc()"
    )
    response_plans = relationship(
        "IncidentResponsePlan",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="IncidentResponsePlan.created_at.desc()"
    )
    collaboration_comments = relationship(
        "AnalystCollaborationComment",
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="AnalystCollaborationComment.created_at.asc()"
    )


class CaseStatusHistory(Base):
    """
    Append-only log of case state transitions through the investigation finite state machine.
    """
    __tablename__ = "case_status_history"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    from_status = Column(String(32), nullable=False)
    to_status = Column(String(32), nullable=False)
    changed_by = Column(String(128), nullable=False)
    transition_reason = Column(Text, nullable=True)
    transitioned_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("InvestigationCase", back_populates="status_history")


class CaseNote(Base):
    """
    Internal analyst notes, hypotheses, and collaborative comments attached to a case.
    """
    __tablename__ = "case_notes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    author = Column(String(128), nullable=False)
    note_type = Column(String(32), default="ANALYST_NOTE", nullable=False)
    content = Column(Text, nullable=False)
    is_pinned = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case = relationship("InvestigationCase", back_populates="notes")


class CaseAuditLog(Base):
    """
    Cryptographically chained, append-only audit trail capturing every action on a case.
    """
    __tablename__ = "case_audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    sequence_number = Column(Integer, nullable=False)
    action = Column(String(64), nullable=False)
    actor = Column(String(128), nullable=False)
    client_ip = Column(String(64), nullable=True)
    details = Column(Text, nullable=True)
    previous_hash = Column(String(64), nullable=True)
    current_hash = Column(String(64), nullable=False)
    logged_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("InvestigationCase", back_populates="audit_logs")


class CaseEvidenceLink(Base):
    """
    Polymorphic cross-module evidence reference linking events, findings, backups,
    or validation reports to a case without data duplication.
    """
    __tablename__ = "case_evidence_links"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    source_module = Column(String(32), nullable=False, index=True)
    source_entity = Column(String(64), nullable=False)
    source_id = Column(String(128), nullable=False, index=True)
    evidence_role = Column(String(32), default="CORROBORATING", nullable=False)
    sha256_hash = Column(String(64), nullable=True)
    tamper_status = Column(String(32), default="VERIFIED", nullable=False)
    metadata_snapshot = Column(Text, nullable=True)
    linked_by = Column(String(128), nullable=False)
    linked_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("InvestigationCase", back_populates="evidence_links")


class CaseContainmentAction(Base):
    """
    Prescribed containment recommendation with human approval tracking.
    Never executes automated destructive actions against production.
    """
    __tablename__ = "case_containment_actions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    action_type = Column(String(64), nullable=False)
    target_principal = Column(String(128), nullable=True)
    target_object = Column(String(128), nullable=True)
    recommended_script = Column(Text, nullable=False)
    risk_assessment = Column(Text, nullable=True)
    status = Column(String(32), default="PENDING", nullable=False)
    reviewed_by = Column(String(128), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("InvestigationCase", back_populates="containment_actions")


class CaseMitreTechnique(Base):
    """
    Mapped MITRE ATT&CK for Enterprise technique associated with an investigation case.
    Tracks tactic, technique ID, technique name, detection source, and confidence.
    """
    __tablename__ = "case_mitre_techniques"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    technique_id = Column(String(32), nullable=False, index=True)
    technique_name = Column(String(128), nullable=False)
    tactic = Column(String(64), nullable=False, index=True)
    detection_source = Column(String(64), nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)
    mapped_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("InvestigationCase", back_populates="mitre_techniques")


class InvestigationWorkflowTemplate(Base):
    """
    Standardized investigation playbook template defining predefined stages,
    ordered tasks, and required evidence collection per incident category.
    """
    __tablename__ = "investigation_workflow_templates"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(128), nullable=False, unique=True, index=True)
    incident_category = Column(String(64), nullable=False, index=True)
    description = Column(Text, nullable=True)
    stages_definition = Column(Text, nullable=False)  # JSON-encoded list of stage dicts
    tasks_definition = Column(Text, nullable=False)   # JSON-encoded list of task template dicts
    version = Column(Integer, default=1, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    workflows = relationship("InvestigationWorkflow", back_populates="template")


class InvestigationWorkflow(Base):
    """
    Active or historical investigation workflow instance bound to a case.
    Orchestrates investigation lifecycle through structured stages and task completion.
    """
    __tablename__ = "investigation_workflows"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    template_id = Column(
        String(36),
        ForeignKey("investigation_workflow_templates.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    name = Column(String(128), nullable=False)
    status = Column(String(32), default="NOT_STARTED", nullable=False, index=True)
    current_stage = Column(String(64), nullable=True, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    owner = Column(String(128), nullable=True)
    created_by = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case = relationship("InvestigationCase", back_populates="workflows")
    template = relationship("InvestigationWorkflowTemplate", back_populates="workflows")
    tasks = relationship(
        "InvestigationTask",
        back_populates="workflow",
        cascade="all, delete-orphan",
        order_by="InvestigationTask.order_index.asc()"
    )
    history = relationship(
        "InvestigationWorkflowHistory",
        back_populates="workflow",
        cascade="all, delete-orphan",
        order_by="InvestigationWorkflowHistory.transitioned_at.asc()"
    )
    escalations = relationship(
        "InvestigationEscalation",
        back_populates="workflow",
        cascade="all, delete-orphan",
        order_by="InvestigationEscalation.created_at.asc()"
    )


class InvestigationWorkflowHistory(Base):
    """
    Immutable audit record of workflow stage and status transitions.
    """
    __tablename__ = "investigation_workflow_history"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workflow_id = Column(
        String(36),
        ForeignKey("investigation_workflows.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    from_status = Column(String(32), nullable=True)
    to_status = Column(String(32), nullable=False)
    from_stage = Column(String(64), nullable=True)
    to_stage = Column(String(64), nullable=True)
    transition_reason = Column(Text, nullable=True)
    actor = Column(String(128), nullable=False)
    transitioned_at = Column(DateTime, default=utc_now, nullable=False)

    workflow = relationship("InvestigationWorkflow", back_populates="history")


class InvestigationTask(Base):
    """
    Discrete investigative task within a workflow stage.
    Supports prerequisite tracking, assignment, evidence linking, and completion enforcement.
    """
    __tablename__ = "investigation_tasks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workflow_id = Column(
        String(36),
        ForeignKey("investigation_workflows.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    stage_name = Column(String(64), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    task_type = Column(String(32), default="MANUAL", nullable=False)  # MANUAL, AUTOMATED_CHECK, REVIEW, APPROVAL
    status = Column(String(32), default="PENDING", nullable=False, index=True)  # PENDING, IN_PROGRESS, BLOCKED, COMPLETED, SKIPPED, CANCELLED, FAILED
    priority = Column(String(32), default="P3_MEDIUM", nullable=False)  # P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW
    assigned_to = Column(String(128), nullable=True)
    assigned_team = Column(String(128), nullable=True)
    is_mandatory = Column(Boolean, default=True, nullable=False)
    order_index = Column(Integer, default=0, nullable=False)
    due_date = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    completed_by = Column(String(128), nullable=True)
    completion_notes = Column(Text, nullable=True)
    evidence_reference_id = Column(
        String(36),
        ForeignKey("case_evidence_links.id", ondelete="NO ACTION"),
        nullable=True
    )
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    workflow = relationship("InvestigationWorkflow", back_populates="tasks")
    case = relationship("InvestigationCase", back_populates="tasks")
    prerequisites = relationship(
        "InvestigationTaskDependency",
        foreign_keys="InvestigationTaskDependency.task_id",
        back_populates="task",
        cascade="all, delete-orphan"
    )
    dependents = relationship(
        "InvestigationTaskDependency",
        foreign_keys="InvestigationTaskDependency.prerequisite_task_id",
        back_populates="prerequisite_task",
        cascade="all, delete-orphan"
    )
    escalations = relationship(
        "InvestigationEscalation",
        back_populates="task",
        cascade="all, delete-orphan"
    )


class InvestigationTaskDependency(Base):
    """
    Explicit directed dependency between two tasks in a workflow.
    Prevents circular references and enforces prerequisites before task execution.
    """
    __tablename__ = "investigation_task_dependencies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    task_id = Column(
        String(36),
        ForeignKey("investigation_tasks.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    prerequisite_task_id = Column(
        String(36),
        ForeignKey("investigation_tasks.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    dependency_type = Column(String(32), default="BLOCKING", nullable=False)  # BLOCKING, INFORMATIONAL
    created_at = Column(DateTime, default=utc_now, nullable=False)

    task = relationship("InvestigationTask", foreign_keys=[task_id], back_populates="prerequisites")
    prerequisite_task = relationship("InvestigationTask", foreign_keys=[prerequisite_task_id], back_populates="dependents")


class InvestigationEscalation(Base):
    """
    Incident escalation record tracking elevated severity, SLA breaches,
    or blocker alerts requiring senior response team or management intervention.
    """
    __tablename__ = "investigation_escalations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workflow_id = Column(
        String(36),
        ForeignKey("investigation_workflows.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    task_id = Column(
        String(36),
        ForeignKey("investigation_tasks.id", ondelete="NO ACTION"),
        nullable=True,
        index=True
    )
    escalation_level = Column(String(32), default="TIER_2", nullable=False)  # TIER_1, TIER_2, TIER_3, MANAGEMENT, CISO
    escalation_reason = Column(Text, nullable=False)
    escalated_by = Column(String(128), nullable=False)
    escalated_to = Column(String(128), nullable=False)
    status = Column(String(32), default="OPEN", nullable=False)  # OPEN, ACKNOWLEDGED, RESOLVED, DISMISSED
    resolution_notes = Column(Text, nullable=True)
    resolved_by = Column(String(128), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    workflow = relationship("InvestigationWorkflow", back_populates="escalations")
    case = relationship("InvestigationCase", back_populates="escalations")
    task = relationship("InvestigationTask", back_populates="escalations")


class IncidentResponsePlan(Base):
    """
    Structured, versioned incident response plan coordinating containment,
    eradication, and recovery tasks with multi-party authorization tracking.
    """
    __tablename__ = "incident_response_plans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    title = Column(String(256), nullable=False)
    summary = Column(Text, nullable=True)
    plan_type = Column(String(64), default="CONTAINMENT_AND_RECOVERY", nullable=False)
    status = Column(String(32), default="DRAFT", nullable=False, index=True)  # DRAFT, IN_REVIEW, APPROVED, ACTIVE, EXECUTED, SUPERSEDED, CANCELLED
    version = Column(Integer, default=1, nullable=False)
    created_by = Column(String(128), nullable=False)
    approved_by = Column(String(128), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approval_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case = relationship("InvestigationCase", back_populates="response_plans")
    actions = relationship(
        "ResponsePlanAction",
        back_populates="plan",
        cascade="all, delete-orphan",
        order_by="ResponsePlanAction.execution_order.asc()"
    )
    revisions = relationship(
        "ResponsePlanRevision",
        back_populates="plan",
        cascade="all, delete-orphan",
        order_by="ResponsePlanRevision.version.desc()"
    )
    comments = relationship(
        "AnalystCollaborationComment",
        back_populates="plan",
        cascade="all, delete-orphan",
        order_by="AnalystCollaborationComment.created_at.asc()"
    )


class ResponsePlanAction(Base):
    """
    Discrete containment, eradication, or recovery step with mandatory separation of duties,
    explicit operator approval requirements, and manual execution tracking.
    Never executes automated destructive actions against production.
    """
    __tablename__ = "response_plan_actions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    plan_id = Column(
        String(36),
        ForeignKey("incident_response_plans.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    title = Column(String(256), nullable=False)
    action_category = Column(String(64), default="CONTAINMENT", nullable=False)  # CONTAINMENT, ERADICATION, RECOVERY_PREPARATION, POST_INCIDENT
    target_type = Column(String(64), default="LOGIN", nullable=False)  # LOGIN, USER, DATABASE, TABLE, ENDPOINT, AUDIT_CONFIG
    target_identifier = Column(String(256), nullable=True)
    risk_level = Column(String(32), default="MEDIUM", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    proposed_script = Column(Text, nullable=False)  # T-SQL or PowerShell command for manual operator review
    rollback_script = Column(Text, nullable=True)  # Rollback T-SQL or recovery steps
    execution_order = Column(Integer, default=0, nullable=False)
    requires_multi_party_approval = Column(Boolean, default=True, nullable=False)
    approval_status = Column(String(32), default="PENDING_APPROVAL", nullable=False, index=True)  # PENDING_APPROVAL, APPROVED, REJECTED, SUPERSEDED
    proposed_by = Column(String(128), nullable=False)
    approved_by = Column(String(128), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approval_notes = Column(Text, nullable=True)
    execution_status = Column(String(32), default="NOT_EXECUTED", nullable=False, index=True)  # NOT_EXECUTED, EXECUTED_SUCCESS, EXECUTED_FAILED, SKIPPED
    executed_by = Column(String(128), nullable=True)
    executed_at = Column(DateTime, nullable=True)
    execution_notes = Column(Text, nullable=True)
    execution_evidence_id = Column(
        String(36),
        ForeignKey("case_evidence_links.id", ondelete="NO ACTION"),
        nullable=True
    )
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    plan = relationship("IncidentResponsePlan", back_populates="actions")
    case = relationship("InvestigationCase")
    comments = relationship(
        "AnalystCollaborationComment",
        back_populates="action",
        cascade="all, delete-orphan",
        order_by="AnalystCollaborationComment.created_at.asc()"
    )


class ResponsePlanRevision(Base):
    """
    Immutable audit snapshot capturing full response plan definition and actions
    at each formal revision or version increment.
    """
    __tablename__ = "response_plan_revisions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    plan_id = Column(
        String(36),
        ForeignKey("incident_response_plans.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    version = Column(Integer, nullable=False)
    snapshot_data = Column(Text, nullable=False)  # JSON-serialized snapshot of plan and actions
    revised_by = Column(String(128), nullable=False)
    revision_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    plan = relationship("IncidentResponsePlan", back_populates="revisions")


class AnalystCollaborationComment(Base):
    """
    Threaded analyst observation, hypothesis review, or peer approval annotation.
    """
    __tablename__ = "analyst_collaboration_comments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(
        String(36),
        ForeignKey("investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    plan_id = Column(
        String(36),
        ForeignKey("incident_response_plans.id", ondelete="NO ACTION"),
        nullable=True,
        index=True
    )
    action_id = Column(
        String(36),
        ForeignKey("response_plan_actions.id", ondelete="NO ACTION"),
        nullable=True,
        index=True
    )
    task_id = Column(
        String(36),
        ForeignKey("investigation_tasks.id", ondelete="NO ACTION"),
        nullable=True,
        index=True
    )
    parent_comment_id = Column(
        String(36),
        ForeignKey("analyst_collaboration_comments.id", ondelete="NO ACTION"),
        nullable=True,
        index=True
    )
    author = Column(String(128), nullable=False)
    comment_type = Column(String(32), default="COMMENT", nullable=False)  # COMMENT, PEER_REVIEW, APPROVAL_NOTE, EXECUTION_REPORT
    content = Column(Text, nullable=False)
    is_resolved = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    case = relationship("InvestigationCase", back_populates="collaboration_comments")
    plan = relationship("IncidentResponsePlan", back_populates="comments")
    action = relationship("ResponsePlanAction", back_populates="comments")
    parent_comment = relationship(
        "AnalystCollaborationComment",
        remote_side=[id],
        back_populates="replies"
    )
    replies = relationship(
        "AnalystCollaborationComment",
        back_populates="parent_comment",
        cascade="all, delete-orphan",
        order_by="AnalystCollaborationComment.created_at.asc()"
    )

