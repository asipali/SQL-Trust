"""
SQL-TRUST Investigation Workflow Engine Service
Module 6: Cyber Investigation & Incident Response Orchestration
Manages investigation playbook templates, workflow state transitions,
stage progression, mandatory task validation, and incident escalations.
"""
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set
from sqlalchemy.orm import Session

from backend.models.investigation import (
    InvestigationCase,
    InvestigationWorkflowTemplate,
    InvestigationWorkflow,
    InvestigationWorkflowHistory,
    InvestigationTask,
    InvestigationTaskDependency,
    InvestigationEscalation
)
from backend.models.backup import utc_now
from backend.services.investigation.audit_service import CaseAuditService  # pyrefly: ignore[missing-import]
from backend.services.investigation.task_service import InvestigationTaskService  # pyrefly: ignore[missing-import]
from backend.schemas.investigation import (
    WorkflowCreateRequest,
    WorkflowTransitionRequest,
    WorkflowEscalateRequest
)

logger = logging.getLogger("sqltrust.investigation.workflows")

# Workflow FSM Transition Matrix
WORKFLOW_VALID_TRANSITIONS: Dict[str, Set[str]] = {
    "NOT_STARTED": {"ACTIVE", "CANCELLED"},
    "ACTIVE": {"BLOCKED", "AWAITING_REVIEW", "AWAITING_APPROVAL", "ESCALATED", "COMPLETED", "CANCELLED", "FAILED"},
    "BLOCKED": {"ACTIVE", "ESCALATED", "CANCELLED"},
    "AWAITING_REVIEW": {"ACTIVE", "AWAITING_APPROVAL", "COMPLETED", "ESCALATED", "CANCELLED"},
    "AWAITING_APPROVAL": {"ACTIVE", "COMPLETED", "BLOCKED", "ESCALATED", "CANCELLED"},
    "ESCALATED": {"ACTIVE", "AWAITING_REVIEW", "BLOCKED", "CANCELLED"},
    "COMPLETED": set(),
    "CANCELLED": set(),
    "FAILED": set(),
}

DEFAULT_PLAYBOOK_TEMPLATES = [
    {
        "name": "Unauthorized Access Playbook",
        "incident_category": "UNAUTHORIZED_ACCESS",
        "description": "Standard response workflow for unauthorized logins, anomalous credential usage, and authentication attacks.",
        "stages": [
            {"name": "INTAKE_TRIAGE", "order": 1, "description": "Verify alerts and identify suspect connections"},
            {"name": "EVIDENCE_PRESERVATION", "order": 2, "description": "Capture active sessions and freeze audit logs"},
            {"name": "ANALYSIS_CORRELATION", "order": 3, "description": "Correlate client IPs, accounts, and queries"},
            {"name": "CONTAINMENT_REMEDIATION", "order": 4, "description": "Recommend credential rotations and session termination"},
            {"name": "RECOVERY_REVIEW", "order": 5, "description": "Validate permissions and review post-incident status"}
        ],
        "tasks": [
            {
                "stage": "INTAKE_TRIAGE",
                "title": "Verify authentication failure and login alert records",
                "description": "Cross-check SecurityAlert records and login failure spikes against SQL Server Error Log.",
                "task_type": "AUTOMATED_CHECK",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 1,
                "prereq_indices": []
            },
            {
                "stage": "INTAKE_TRIAGE",
                "title": "Identify compromised database principal and source IP",
                "description": "Determine target account and originating client host or IP address.",
                "task_type": "MANUAL",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 2,
                "prereq_indices": [1]
            },
            {
                "stage": "EVIDENCE_PRESERVATION",
                "title": "Capture active session state and running requests",
                "description": "Preserve sys.dm_exec_sessions and sys.dm_exec_requests snapshots.",
                "task_type": "AUTOMATED_CHECK",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 3,
                "prereq_indices": [2]
            },
            {
                "stage": "ANALYSIS_CORRELATION",
                "title": "Analyze executed query history for data exfiltration",
                "description": "Inspect recent SQL text executed by suspect principal.",
                "task_type": "MANUAL",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 4,
                "prereq_indices": [3]
            },
            {
                "stage": "CONTAINMENT_REMEDIATION",
                "title": "Draft credential rotation and isolation script",
                "description": "Generate operator-reviewed containment recommendations for account lockout.",
                "task_type": "REVIEW",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 5,
                "prereq_indices": [4]
            },
            {
                "stage": "RECOVERY_REVIEW",
                "title": "Review containment verification and permission baseline",
                "description": "Verify compromised access is eliminated and sign off on post-incident state.",
                "task_type": "APPROVAL",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 6,
                "prereq_indices": [5]
            }
        ]
    },
    {
        "name": "Suspicious Modification Playbook",
        "incident_category": "SUSPICIOUS_ACTIVITY",
        "description": "Playbook for unexpected schema alterations, dropped objects, or unauthorized data changes.",
        "stages": [
            {"name": "INTAKE_TRIAGE", "order": 1, "description": "Identify altered objects and incident window"},
            {"name": "EVIDENCE_COLLECTION", "order": 2, "description": "Gather baseline comparisons and transaction logs"},
            {"name": "FORENSIC_ANALYSIS", "order": 3, "description": "Diff objects and trace modifying user"},
            {"name": "CONTAINMENT_REMEDIATION", "order": 4, "description": "Formulate rollback scripts or revoke rights"},
            {"name": "RECOVERY_VALIDATION", "order": 5, "description": "Validate database integrity and schema consistency"}
        ],
        "tasks": [
            {
                "stage": "INTAKE_TRIAGE",
                "title": "Identify altered tables, triggers, or stored procedures",
                "description": "Inspect schema monitoring alerts and DDL modification events.",
                "task_type": "AUTOMATED_CHECK",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 1,
                "prereq_indices": []
            },
            {
                "stage": "EVIDENCE_COLLECTION",
                "title": "Query forensic baseline diff for affected database objects",
                "description": "Compare current schema against latest certified Module 3 baseline.",
                "task_type": "AUTOMATED_CHECK",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 2,
                "prereq_indices": [1]
            },
            {
                "stage": "FORENSIC_ANALYSIS",
                "title": "Correlate DDL/DML event with user and application context",
                "description": "Trace modifying login, SPID, and application name.",
                "task_type": "MANUAL",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 3,
                "prereq_indices": [2]
            },
            {
                "stage": "CONTAINMENT_REMEDIATION",
                "title": "Prepare rollback T-SQL and evaluate isolated restore candidate",
                "description": "Formulate repair script or select recovery point before the malicious DDL.",
                "task_type": "REVIEW",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 4,
                "prereq_indices": [3]
            },
            {
                "stage": "RECOVERY_VALIDATION",
                "title": "Validate database integrity and schema consistency post-remediation",
                "description": "Verify DBCC consistency and schema equivalence.",
                "task_type": "APPROVAL",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 5,
                "prereq_indices": [4]
            }
        ]
    },
    {
        "name": "Backup Integrity Playbook",
        "incident_category": "BACKUP_TAMPERING",
        "description": "Playbook for backup chain discontinuity, invalid checksums, or storage tampering.",
        "stages": [
            {"name": "INTAKE_TRIAGE", "order": 1, "description": "Review backup verification failure alerts"},
            {"name": "INTEGRITY_VERIFICATION", "order": 2, "description": "Recheck SHA-256 and RESTORE VERIFYONLY"},
            {"name": "FORENSIC_VALIDATION", "order": 3, "description": "Inspect SeaweedFS object lock and immutability"},
            {"name": "RECOVERY_ASSESSMENT", "order": 4, "description": "Identify last verified uncompromised backup"},
            {"name": "CLOSURE_DOCUMENTATION", "order": 5, "description": "Document findings and sign off on trusted backup"}
        ],
        "tasks": [
            {
                "stage": "INTAKE_TRIAGE",
                "title": "Inspect backup verification alerts and backup logs",
                "description": "Review BackupOperationLog for failed VERIFYONLY or hash mismatch.",
                "task_type": "AUTOMATED_CHECK",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 1,
                "prereq_indices": []
            },
            {
                "stage": "INTEGRITY_VERIFICATION",
                "title": "Recompute SHA-256 hash and run RESTORE VERIFYONLY",
                "description": "Verify cryptographic integrity and page checksums of suspect backup file.",
                "task_type": "AUTOMATED_CHECK",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 2,
                "prereq_indices": [1]
            },
            {
                "stage": "FORENSIC_VALIDATION",
                "title": "Inspect SeaweedFS Object Lock status and immutability",
                "description": "Verify whether backup object in SeaweedFS was altered or prematurely unlocked.",
                "task_type": "MANUAL",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 3,
                "prereq_indices": [2]
            },
            {
                "stage": "RECOVERY_ASSESSMENT",
                "title": "Evaluate candidate confidence score and clean recovery point",
                "description": "Cross-reference Module 4 trust score to establish uncompromised restore point.",
                "task_type": "REVIEW",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 4,
                "prereq_indices": [3]
            },
            {
                "stage": "CLOSURE_DOCUMENTATION",
                "title": "Document tampering findings and sign off on clean backup state",
                "description": "Confirm quarantined compromised backup and designate new trusted baseline.",
                "task_type": "APPROVAL",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 5,
                "prereq_indices": [4]
            }
        ]
    },
    {
        "name": "Audit Tampering Playbook",
        "incident_category": "AUDIT_TAMPERING",
        "description": "Playbook for disabled SQL Server audit specifications, stopped traces, or deleted audit files.",
        "stages": [
            {"name": "INTAKE_TRIAGE", "order": 1, "description": "Detect altered audit specifications"},
            {"name": "EVIDENCE_PRESERVATION", "order": 2, "description": "Harvest error logs and system event logs"},
            {"name": "IMPACT_ASSESSMENT", "order": 3, "description": "Determine blind spot duration and unmonitored actions"},
            {"name": "HARDENING_CONTAINMENT", "order": 4, "description": "Re-enable audit specifications and tighten ALTER TRACE"},
            {"name": "REPORTING_COMPLIANCE", "order": 5, "description": "Generate compliance impact report and notify CISO"}
        ],
        "tasks": [
            {
                "stage": "INTAKE_TRIAGE",
                "title": "Identify disabled or dropped audit specification",
                "description": "Check MonitoringHealth and audit collection gaps.",
                "task_type": "AUTOMATED_CHECK",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 1,
                "prereq_indices": []
            },
            {
                "stage": "EVIDENCE_PRESERVATION",
                "title": "Preserve SQL Server error logs and Windows Event Logs",
                "description": "Capture log entries covering the exact moment audit stopped.",
                "task_type": "AUTOMATED_CHECK",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 2,
                "prereq_indices": [1]
            },
            {
                "stage": "IMPACT_ASSESSMENT",
                "title": "Assess potential untracked activities during blind spot",
                "description": "Reconstruct database activity during the unmonitored window.",
                "task_type": "MANUAL",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 3,
                "prereq_indices": [2]
            },
            {
                "stage": "HARDENING_CONTAINMENT",
                "title": "Draft script to re-enable audit and restrict ALTER TRACE rights",
                "description": "Produce containment script to immediately restore auditing and strip dangerous rights.",
                "task_type": "REVIEW",
                "priority": "P1_CRITICAL",
                "is_mandatory": True,
                "order_index": 4,
                "prereq_indices": [3]
            },
            {
                "stage": "REPORTING_COMPLIANCE",
                "title": "Generate compliance notification dossier and submit for review",
                "description": "Compile formal disclosure of the audit outage for compliance stakeholders.",
                "task_type": "APPROVAL",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 5,
                "prereq_indices": [4]
            }
        ]
    },
    {
        "name": "General Security Playbook",
        "incident_category": "GENERAL",
        "description": "Standard incident response coordination workflow for multi-vector or unclassified database incidents.",
        "stages": [
            {"name": "INTAKE_TRIAGE", "order": 1, "description": "Initial case assessment and responder assignment"},
            {"name": "INVESTIGATION_ANALYSIS", "order": 2, "description": "Cross-module correlation and timeline reconstruction"},
            {"name": "CONTAINMENT_RESPONSE", "order": 3, "description": "Containment action formulation and review"},
            {"name": "RECOVERY_POSTMORTEM", "order": 4, "description": "Post-incident review and final dossier sign-off"}
        ],
        "tasks": [
            {
                "stage": "INTAKE_TRIAGE",
                "title": "Perform initial triage, severity rating, and team assignment",
                "description": "Confirm scope, database targets, and incident priority.",
                "task_type": "MANUAL",
                "priority": "P3_MEDIUM",
                "is_mandatory": True,
                "order_index": 1,
                "prereq_indices": []
            },
            {
                "stage": "INVESTIGATION_ANALYSIS",
                "title": "Reconstruct incident timeline across audit and forensic sources",
                "description": "Execute correlation scan and populate unified timeline.",
                "task_type": "AUTOMATED_CHECK",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 2,
                "prereq_indices": [1]
            },
            {
                "stage": "CONTAINMENT_RESPONSE",
                "title": "Prepare and peer-review containment actions",
                "description": "Draft operator containment scripts with risk assessments.",
                "task_type": "REVIEW",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 3,
                "prereq_indices": [2]
            },
            {
                "stage": "RECOVERY_POSTMORTEM",
                "title": "Compile final forensic investigation dossier and archive evidence",
                "description": "Review complete evidence inventory and sign closure manifest.",
                "task_type": "APPROVAL",
                "priority": "P2_HIGH",
                "is_mandatory": True,
                "order_index": 4,
                "prereq_indices": [3]
            }
        ]
    }
]


class InvestigationWorkflowService:
    """
    Core service coordinating investigation workflow templates, stage transitions,
    task prerequisite gating, and escalations.
    """

    @staticmethod
    def seed_default_templates(db: Session) -> List[InvestigationWorkflowTemplate]:
        """
        Seeds the 5 standardized investigation playbook templates if they do not already exist.
        """
        seeded = []
        for tmpl_data in DEFAULT_PLAYBOOK_TEMPLATES:
            existing = db.query(InvestigationWorkflowTemplate).filter(
                InvestigationWorkflowTemplate.name == tmpl_data["name"]
            ).first()

            if not existing:
                tmpl = InvestigationWorkflowTemplate(
                    name=tmpl_data["name"],
                    incident_category=tmpl_data["incident_category"],
                    description=tmpl_data["description"],
                    stages_definition=json.dumps(tmpl_data["stages"]),
                    tasks_definition=json.dumps(tmpl_data["tasks"]),
                    version=1,
                    is_active=True
                )
                db.add(tmpl)
                db.flush()
                seeded.append(tmpl)
            else:
                seeded.append(existing)

        db.commit()
        return seeded

    @staticmethod
    def get_template(db: Session, template_id: str) -> Optional[InvestigationWorkflowTemplate]:
        """Retrieves a workflow template by ID."""
        return db.query(InvestigationWorkflowTemplate).filter(
            InvestigationWorkflowTemplate.id == template_id
        ).first()

    @staticmethod
    def list_templates(db: Session, active_only: bool = True) -> List[InvestigationWorkflowTemplate]:
        """Lists available playbook templates."""
        q = db.query(InvestigationWorkflowTemplate)
        if active_only:
            q = q.filter(InvestigationWorkflowTemplate.is_active == True)
        return q.order_by(InvestigationWorkflowTemplate.name.asc()).all()

    @staticmethod
    def create_workflow(
        db: Session,
        request: WorkflowCreateRequest
    ) -> InvestigationWorkflow:
        """
        Creates an investigation workflow instance for a case.
        If a template is specified, populates the workflow's stages and tasks
        according to the template definition, including task dependencies.
        """
        case = db.query(InvestigationCase).filter(InvestigationCase.id == request.case_id).first()
        if not case:
            raise ValueError(f"Case '{request.case_id}' not found")

        template = None
        if request.template_id:
            template = db.query(InvestigationWorkflowTemplate).filter(
                InvestigationWorkflowTemplate.id == request.template_id
            ).first()
            if not template:
                raise ValueError(f"Template '{request.template_id}' not found")
        else:
            # Auto-select matching template based on case incident_category
            matched = (
                db.query(InvestigationWorkflowTemplate)
                .filter(InvestigationWorkflowTemplate.incident_category == case.incident_category)
                .first()
            )
            template = matched or db.query(InvestigationWorkflowTemplate).filter(
                InvestigationWorkflowTemplate.name == "General Security Playbook"
            ).first()

        wf_name = request.name or (template.name if template else f"Workflow for {case.case_number}")
        stages_data = json.loads(template.stages_definition) if template else (request.custom_stages or [])
        initial_stage = stages_data[0]["name"] if stages_data else "INTAKE_TRIAGE"

        workflow = InvestigationWorkflow(
            case_id=case.id,
            template_id=template.id if template else None,
            name=wf_name,
            status="NOT_STARTED",
            current_stage=initial_stage,
            owner=request.owner or case.lead_investigator,
            created_by=request.created_by
        )
        db.add(workflow)
        db.flush()

        # Instantiate tasks from template
        created_tasks: Dict[int, InvestigationTask] = {}
        if template:
            tasks_data = json.loads(template.tasks_definition)
            for idx, td in enumerate(tasks_data, start=1):
                task = InvestigationTask(
                    workflow_id=workflow.id,
                    case_id=case.id,
                    stage_name=td.get("stage", initial_stage),
                    title=td.get("title", f"Task {idx}"),
                    description=td.get("description"),
                    task_type=td.get("task_type", "MANUAL"),
                    status="PENDING",
                    priority=td.get("priority", "P3_MEDIUM"),
                    assigned_to=workflow.owner,
                    assigned_team=case.assigned_team,
                    is_mandatory=td.get("is_mandatory", True),
                    order_index=td.get("order_index", idx)
                )
                db.add(task)
                db.flush()
                created_tasks[td.get("order_index", idx)] = task

            # Connect task dependencies based on prereq_indices
            for td in tasks_data:
                target_order = td.get("order_index")
                target_task = created_tasks.get(target_order)
                if not target_task:
                    continue
                for prereq_idx in td.get("prereq_indices", []):
                    prereq_task = created_tasks.get(prereq_idx)
                    if prereq_task and prereq_task.id != target_task.id:
                        InvestigationTaskService.add_dependency(
                            db=db,
                            task_id=target_task.id,
                            prerequisite_task_id=prereq_task.id,
                            dependency_type="BLOCKING",
                            actor=request.created_by
                        )

        # Record initial history
        history = InvestigationWorkflowHistory(
            workflow_id=workflow.id,
            from_status=None,
            to_status="NOT_STARTED",
            from_stage=None,
            to_stage=initial_stage,
            transition_reason="Workflow initialized",
            actor=request.created_by
        )
        db.add(history)

        CaseAuditService.log_action(
            db=db,
            case_id=case.id,
            action="WORKFLOW_CREATED",
            actor=request.created_by,
            details=f"Workflow '{workflow.name}' created with {len(created_tasks)} tasks"
        )
        db.commit()
        db.refresh(workflow)
        return workflow

    @staticmethod
    def start_workflow(db: Session, workflow_id: str, actor: str) -> InvestigationWorkflow:
        """
        Transitions workflow from NOT_STARTED to ACTIVE.
        """
        return InvestigationWorkflowService.transition_workflow(
            db=db,
            workflow_id=workflow_id,
            to_status="ACTIVE",
            actor=actor,
            transition_reason="Workflow initiated by operator"
        )

    @staticmethod
    def transition_workflow(
        db: Session,
        workflow_id: str,
        to_status: str,
        actor: str,
        to_stage: Optional[str] = None,
        transition_reason: Optional[str] = None
    ) -> InvestigationWorkflow:
        """
        Validates and executes a status and/or stage transition on a workflow.
        Enforces mandatory task completion before transitioning to COMPLETED.
        """
        workflow = db.query(InvestigationWorkflow).filter(InvestigationWorkflow.id == workflow_id).first()
        if not workflow:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        curr_status = workflow.status
        allowed = WORKFLOW_VALID_TRANSITIONS.get(curr_status, set())
        if to_status != curr_status and to_status not in allowed:
            raise ValueError(
                f"Illegal workflow status transition from '{curr_status}' to '{to_status}'. "
                f"Allowed target states: {sorted(list(allowed))}"
            )

        # Guard on completion: All mandatory tasks must be COMPLETED or SKIPPED
        if to_status == "COMPLETED":
            mandatory_tasks = (
                db.query(InvestigationTask)
                .filter(
                    InvestigationTask.workflow_id == workflow.id,
                    InvestigationTask.is_mandatory == True
                )
                .all()
            )
            uncompleted = [t for t in mandatory_tasks if t.status not in ("COMPLETED", "SKIPPED")]
            if uncompleted:
                task_summaries = [f"'{t.title}' ({t.status})" for t in uncompleted]
                raise ValueError(
                    f"Cannot complete workflow: {len(uncompleted)} mandatory task(s) are incomplete: {', '.join(task_summaries)}"
                )

        from_status = workflow.status
        from_stage = workflow.current_stage

        workflow.status = to_status
        if to_stage:
            workflow.current_stage = to_stage

        now = utc_now()
        if to_status == "ACTIVE" and not workflow.started_at:
            workflow.started_at = now
        elif to_status in ("COMPLETED", "CANCELLED", "FAILED"):
            workflow.completed_at = now

        workflow.updated_at = now

        history = InvestigationWorkflowHistory(
            workflow_id=workflow.id,
            from_status=from_status,
            to_status=to_status,
            from_stage=from_stage,
            to_stage=workflow.current_stage,
            transition_reason=transition_reason or f"Transitioned to {to_status}",
            actor=actor
        )
        db.add(history)

        CaseAuditService.log_action(
            db=db,
            case_id=workflow.case_id,
            action="WORKFLOW_TRANSITION",
            actor=actor,
            details=f"Transitioned from {from_status} to {to_status} (stage: {workflow.current_stage}). Reason: {transition_reason}"
        )
        db.commit()
        db.refresh(workflow)
        return workflow

    @staticmethod
    def escalate_workflow(
        db: Session,
        workflow_id: str,
        request: WorkflowEscalateRequest
    ) -> InvestigationEscalation:
        """
        Escalates an investigation workflow or specific task.
        Transitions the workflow to ESCALATED status and optionally reassigns the owner.
        """
        workflow = db.query(InvestigationWorkflow).filter(InvestigationWorkflow.id == workflow_id).first()
        if not workflow:
            raise ValueError(f"Workflow '{workflow_id}' not found")

        escalation = InvestigationEscalation(
            workflow_id=workflow.id,
            case_id=workflow.case_id,
            task_id=request.task_id,
            escalation_level=request.escalation_level,
            escalation_reason=request.escalation_reason,
            escalated_by=request.escalated_by,
            escalated_to=request.escalated_to,
            status="OPEN"
        )
        db.add(escalation)

        # Transition workflow to ESCALATED if not already terminal
        if workflow.status not in ("COMPLETED", "CANCELLED", "FAILED"):
            InvestigationWorkflowService.transition_workflow(
                db=db,
                workflow_id=workflow.id,
                to_status="ESCALATED",
                actor=request.escalated_by,
                transition_reason=f"Escalation ({request.escalation_level}): {request.escalation_reason}"
            )

        if request.reassign_owner:
            workflow.owner = request.escalated_to

        CaseAuditService.log_action(
            db=db,
            case_id=workflow.case_id,
            action="WORKFLOW_ESCALATED",
            actor=request.escalated_by,
            details=f"Escalated to {request.escalation_level} ({request.escalated_to}). Reason: {request.escalation_reason}"
        )
        db.commit()
        db.refresh(escalation)
        return escalation

    @staticmethod
    def get_workflow_details(db: Session, workflow_id: str) -> Optional[InvestigationWorkflow]:
        """Retrieves full workflow details with tasks, history, and escalations."""
        return db.query(InvestigationWorkflow).filter(InvestigationWorkflow.id == workflow_id).first()

    @staticmethod
    def get_case_workflow(db: Session, case_id: str) -> Optional[InvestigationWorkflow]:
        """Retrieves the latest workflow for an investigation case."""
        return (
            db.query(InvestigationWorkflow)
            .filter(InvestigationWorkflow.case_id == case_id)
            .order_by(InvestigationWorkflow.created_at.desc())
            .first()
        )
