"""
SQL-TRUST Module 6 Phase 7 End-to-End Integration Test Suite
Complete Cyber Investigation & Incident Response Lifecycle:
Intake -> Classification -> Evidence Correlation -> Timeline -> Workflow Execution
-> Response Plan (SoD Multi-Party Approval & Manual Execution Tracking)
-> Threaded Collaboration -> Canonical Report Generation -> Ed25519 Signing -> WORM Archival.
"""
import uuid
import json
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.database import SessionLocal
from backend.models.backup import ProtectedDatabase
from backend.models.security import SecuritySource, DetectionRule, SecurityAlert, SecurityEvent
from backend.models.investigation import (
    InvestigationCase,
    CaseEvidenceLink,
    InvestigationWorkflow,
    IncidentResponsePlan,
    ResponsePlanAction,
    AnalystCollaborationComment
)
from backend.services.investigation.intake_service import IncidentIntakeService
from backend.services.investigation.classification_engine import ClassificationEngine
from backend.services.investigation.correlation_engine import CorrelationEngine
from backend.services.investigation.timeline_engine import TimelineEngine
from backend.services.investigation.workflow_service import InvestigationWorkflowService
from backend.services.investigation.task_service import InvestigationTaskService
from backend.services.investigation.response_service import IncidentResponseService
from backend.services.investigation.dossier_service import DossierService
from backend.services.investigation.audit_service import CaseAuditService
from backend.schemas.investigation import (
    WorkflowCreateRequest,
    ResponsePlanCreateRequest,
    ResponseActionCreateRequest,
    ResponseActionApprovalRequest,
    ResponseActionExecutionRequest,
    AnalystCommentCreateRequest,
    CaseCloseRequest
)
from backend.services.security.signer import signer


@pytest.fixture(scope="module")
def db_session():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture(scope="module")
def api_client():
    client = TestClient(app)
    return client


@pytest.fixture(scope="module")
def setup_e2e_db(db_session: Session):
    """Provisions an isolated protected database for full end-to-end investigation lifecycle."""
    suffix = uuid.uuid4().hex[:8]
    db_name = f"SQLTrust_E2E_{suffix}"
    prot_db = ProtectedDatabase(
        database_name=db_name,
        server_name="localhost\\SQLEXPRESS",
        database_identifier=f"e2e_{suffix}"
    )
    db_session.add(prot_db)
    db_session.commit()
    db_session.refresh(prot_db)
    yield prot_db

    # Teardown
    cases = db_session.query(InvestigationCase).filter(InvestigationCase.target_database_name == db_name).all()
    for c in cases:
        db_session.delete(c)
    db_session.commit()
    db_session.delete(prot_db)
    db_session.commit()


def test_complete_investigation_lifecycle_e2e(db_session: Session, setup_e2e_db: ProtectedDatabase):
    """
    Executes the complete, unbroken end-to-end investigation lifecycle:
    1. Incident Intake & Alert Ingestion (Module 2)
    2. Incident Classification & MITRE ATT&CK Mapping (Phases 3-4)
    3. Multi-Dimensional Evidence Correlation (Phase 4)
    4. Chronological Timeline Reconstruction with Milestones (Phase 4)
    5. Investigation Playbook Workflow Instantiation & Completion (Phase 5)
    6. Incident Response Plan & Separation of Duties (SoD) Approvals (Phase 6)
    7. Manual Execution Acknowledgement by Operator (Phase 6)
    8. Threaded Analyst Collaboration Comments (Phase 6)
    9. Canonical Report Generation & Markdown Export (Phase 7)
    10. Cryptographic Audit Chain Verification (Phase 7)
    11. Ed25519 Closure Manifest Signing & SeaweedFS WORM Archival (Phase 7)
    """
    now = datetime.now(timezone.utc)

    # --- STEP 1: Ingest Incident Alert ---
    source = db_session.query(SecuritySource).first()
    if not source:
        source = SecuritySource(
            source_name="SQLServer-LocalHost",
            source_type="AUDIT",
            server_name="localhost\\SQLEXPRESS",
            is_active=True
        )
        db_session.add(source)
        db_session.flush()

    rule = db_session.query(DetectionRule).first()
    if not rule:
        rule = DetectionRule(
            rule_id="RULE_001_AUTH",
            name="Auth Anomaly",
            description="Auth",
            severity="CRITICAL"
        )
        db_session.add(rule)
        db_session.flush()

    alert = SecurityAlert(
        source_id=source.id,
        rule_id=rule.id,
        title="Unauthorized SA Login & High Volume Data Exfiltration",
        description="Detected credential abuse on SA account from untrusted client endpoint.",
        severity="CRITICAL",
        status="NEW",
        principal_name="sa_attacker",
        target_object=f"{setup_e2e_db.database_name}.sa",
        explanation="Explainable rule trigger on SA credential abuse",
        confidence_score=1.0,
        detection_timestamp=datetime.now(timezone.utc)
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    case = IncidentIntakeService.intake_from_security_alert(
        db=db_session,
        alert_id=alert.id,
        actor="soc_tier1_analyst"
    )
    assert case.id is not None
    assert case.case_number.startswith("INV-")
    assert case.status in ("NEW", "TRIAGED")

    # --- STEP 2: Classification & MITRE ATT&CK Mapping ---
    class_res = ClassificationEngine.classify_case(db=db_session, case_id=case.id)
    assert class_res["priority"] in ("P1_CRITICAL", "P2_HIGH")
    assert class_res["severity_score"] > 0
    assert len(class_res["mitre_techniques"]) > 0

    # Add a correlated secondary alert (same attacker principal) to be discovered by correlation engine
    alert_2 = SecurityAlert(
        source_id=source.id,
        rule_id=rule.id,
        title="Unauthorized DDL Execution",
        description="DROP TABLE command executed by attacker",
        severity="HIGH",
        status="NEW",
        principal_name="sa_attacker",
        target_object=f"{setup_e2e_db.database_name}.dbo.customers",
        explanation="Explainable rule trigger on DDL drop",
        confidence_score=0.9,
        detection_timestamp=datetime.now(timezone.utc)
    )
    db_session.add(alert_2)
    db_session.commit()

    # --- STEP 3: Multi-Dimensional Correlation ---
    scan_res = CorrelationEngine.correlate_case_evidence(
        db=db_session,
        case_id=case.id,
        sliding_window_minutes=60,
        auto_link=True,
        actor="correlation_engine"
    )
    assert scan_res["candidates_found"] >= 1

    # --- STEP 4: Chronological Timeline Reconstruction ---
    timeline = TimelineEngine.build_case_timeline(db_session, case.id)
    assert len(timeline) >= 2
    milestones = TimelineEngine.get_milestones(timeline)
    assert len(milestones) >= 1

    # --- STEP 5: Playbook Workflow Instantiation & Completion ---
    wf = InvestigationWorkflowService.create_workflow(
        db=db_session,
        request=WorkflowCreateRequest(
            case_id=case.id,
            name="E2E Unauthorized Access Playbook",
            created_by="lead_investigator",
            owner="senior_investigator"
        )
    )
    assert wf.status == "NOT_STARTED"
    assert len(wf.tasks) > 0

    # Start workflow
    InvestigationWorkflowService.start_workflow(db_session, wf.id, actor="senior_investigator")
    assert wf.status == "ACTIVE"

    # Complete all tasks in order
    for task in wf.tasks:
        InvestigationTaskService.complete_task(
            db=db_session,
            task_id=task.id,
            completed_by="senior_investigator",
            completion_notes=f"E2E automated completion of {task.title}",
            status="COMPLETED"
        )

    # Transition workflow to COMPLETED
    InvestigationWorkflowService.transition_workflow(
        db=db_session,
        workflow_id=wf.id,
        to_status="COMPLETED",
        actor="senior_investigator",
        transition_reason="All playbook investigation tasks verified and completed."
    )
    assert wf.status == "COMPLETED"

    # --- STEP 6: Response Plan & Separation of Duties (SoD) Approvals ---
    plan = IncidentResponseService.create_response_plan(
        db=db_session,
        req=ResponsePlanCreateRequest(
            case_id=case.id,
            title="E2E Incident Response Plan",
            summary="Emergency containment of compromised SA credentials and firewall lockdown",
            plan_type="CONTAINMENT",
            created_by="security_engineer_alice"
        )
    )
    assert plan.version == 1

    action = IncidentResponseService.add_action(
        db=db_session,
        plan_id=plan.id,
        req=ResponseActionCreateRequest(
            title="Disable compromised login and disconnect sessions",
            action_category="CONTAINMENT",
            target_type="LOGIN",
            target_identifier="sa_attacker",
            risk_level="CRITICAL",
            proposed_script="ALTER LOGIN [sa_attacker] DISABLE;",
            rollback_script="ALTER LOGIN [sa_attacker] ENABLE;",
            proposed_by="security_engineer_alice"
        )
    )
    assert action.requires_multi_party_approval is True

    # Test SoD: Proposer cannot approve
    with pytest.raises(ValueError, match="Separation of duties violation"):
        IncidentResponseService.approve_action(
            db=db_session,
            action_id=action.id,
            req=ResponseActionApprovalRequest(
                approved_by="security_engineer_alice",
                approval_status="APPROVED",
                approval_notes="Self-approval attempt"
            )
        )

    # Independent peer/CISO approval succeeds
    IncidentResponseService.approve_action(
        db=db_session,
        action_id=action.id,
        req=ResponseActionApprovalRequest(
            approved_by="ciso_officer_bob",
            approval_status="APPROVED",
            approval_notes="Approved after validating zero production dependency on sa_attacker."
        )
    )
    assert action.approval_status == "APPROVED"

    # --- STEP 7: Manual Execution Acknowledgement ---
    IncidentResponseService.acknowledge_execution(
        db=db_session,
        action_id=action.id,
        req=ResponseActionExecutionRequest(
            executed_by="lead_dba_charlie",
            execution_status="EXECUTED_SUCCESS",
            execution_notes="Executed command in SSMS on primary instance. Verified login disabled."
        )
    )
    assert action.execution_status == "EXECUTED_SUCCESS"

    # --- STEP 8: Threaded Analyst Collaboration Comments ---
    c1 = IncidentResponseService.add_comment(
        db=db_session,
        case_id=case.id,
        req=AnalystCommentCreateRequest(
            author="lead_investigator",
            content="Host 192.168.10.45 has been blacklisted at perimeter gateway.",
            comment_type="COMMENT"
        )
    )
    c2 = IncidentResponseService.add_comment(
        db=db_session,
        case_id=case.id,
        req=AnalystCommentCreateRequest(
            author="ciso_officer_bob",
            content="Confirmed. Containment is complete. Ready for formal case closure.",
            comment_type="APPROVAL_NOTE",
            parent_comment_id=c1.id
        )
    )
    assert c2.parent_comment_id == c1.id

    # --- STEP 9: Canonical Report Generation & Markdown Export ---
    report = DossierService.generate_canonical_report(db_session, case.id)
    assert report["case_id"] == case.id
    assert report["executive_summary"]["workflows_count"] >= 1
    assert report["executive_summary"]["response_plans_count"] >= 1
    assert len(report["workflows"]) >= 1
    assert len(report["response_plans"]) >= 1

    md_report = DossierService.export_canonical_markdown(report)
    assert "# SQL-TRUST Cyber Incident Investigation Dossier" in md_report
    assert "Executive Incident Summary" in md_report
    assert "MITRE ATT&CK" in md_report
    assert "Chronological Incident Timeline" in md_report
    assert "Investigation Workflows & Tasks Execution" in md_report

    # --- STEP 10: Cryptographic Audit Trail Verification ---
    audit_res = CaseAuditService.verify_audit_chain(db_session, case.id)
    assert audit_res["valid"] is True
    assert audit_res["total_entries"] >= 6

    # --- STEP 11: Case Closure, Ed25519 Signing & WORM Archival ---
    close_res = DossierService.close_and_sign_case(
        db=db_session,
        case_id=case.id,
        closed_by="ciso_officer_bob",
        closure_reason="Threat eradicated, accounts isolated, perimeter secured, forensics documented.",
        closure_notes="Formal Ed25519 closure sign-off."
    )
    assert close_res["status"] == "CLOSED"
    assert close_res["signature_valid"] is True
    assert close_res["audit_chain_verified"] is True
    assert close_res["closure_manifest_hash"] is not None
    assert close_res["storage_object_key"] is not None


def test_closure_validation_guards(db_session: Session, setup_e2e_db: ProtectedDatabase):
    """
    Verifies closure checklist enforcement:
    1. Blocks closure if active workflows exist.
    2. Blocks closure if response actions remain pending approval.
    """
    case = InvestigationCase(
        title="Closure Guard Test Case",
        target_database_name=setup_e2e_db.database_name,
        created_by="test_lead",
        status="ACTIVE"
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)

    # 1. Add active workflow
    wf = InvestigationWorkflow(
        case_id=case.id,
        name="Unfinished Workflow",
        status="ACTIVE",
        current_stage="INTAKE_TRIAGE",
        created_by="test_lead"
    )
    db_session.add(wf)
    db_session.commit()

    # Attempting to close must fail
    with pytest.raises(ValueError, match="Active workflows remain incomplete"):
        DossierService.close_and_sign_case(
            db=db_session,
            case_id=case.id,
            closed_by="lead_auditor",
            closure_reason="Attempted premature closure"
        )

    # Complete workflow
    wf.status = "COMPLETED"
    db_session.commit()

    # 2. Add unapproved response action
    plan = IncidentResponsePlan(
        case_id=case.id,
        title="Unfinished Response Plan",
        created_by="test_lead"
    )
    db_session.add(plan)
    db_session.commit()

    action = ResponsePlanAction(
        plan_id=plan.id,
        case_id=case.id,
        title="Pending Lockdown Action",
        risk_level="HIGH",
        proposed_script="ALTER DATABASE [X] SET OFFLINE;",
        approval_status="PENDING_APPROVAL",
        proposed_by="test_lead"
    )
    db_session.add(action)
    db_session.commit()

    # Attempting to close must fail due to pending action
    with pytest.raises(ValueError, match="response action.*remain pending approval"):
        DossierService.close_and_sign_case(
            db=db_session,
            case_id=case.id,
            closed_by="lead_auditor",
            closure_reason="Attempted premature closure"
        )


def test_canonical_report_api_endpoints(api_client: TestClient, setup_e2e_db: ProtectedDatabase, db_session: Session):
    """Verifies Phase 7 REST API endpoints for canonical report and WORM archival."""
    case = InvestigationCase(
        title="API Canonical Report Test Case",
        target_database_name=setup_e2e_db.database_name,
        created_by="api_tester",
        status="ACTIVE"
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)

    # 1. GET /api/v1/investigations/{case_id}/canonical-report (JSON)
    res = api_client.get(f"/api/v1/investigations/{case.id}/canonical-report?format=json")
    assert res.status_code == 200
    report_json = res.json()
    assert report_json["case_id"] == case.id
    assert "executive_summary" in report_json

    # 2. GET /api/v1/investigations/{case_id}/canonical-report (Markdown)
    res = api_client.get(f"/api/v1/investigations/{case.id}/canonical-report?format=markdown")
    assert res.status_code == 200
    assert "SQL-TRUST Cyber Incident Investigation Dossier" in res.text

    # 3. POST /api/v1/investigations/{case_id}/archive-worm
    res = api_client.post(f"/api/v1/investigations/{case.id}/archive-worm?operator=api_tester&retention_days=30")
    assert res.status_code == 200
    archive_data = res.json()
    assert archive_data["case_id"] == case.id
    assert archive_data["signature_valid"] is True
    assert archive_data["storage_object_key"] is not None
