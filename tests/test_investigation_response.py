"""
SQL-TRUST Module 6 Phase 6 Test Suite
Incident Response Tasks & Analyst Collaboration:
Response Plans, Plan Versioning, Separation of Duties (SoD) Multi-Party Approvals,
Manual Execution Acknowledgement, Threaded Analyst Collaboration, and REST APIs.
"""
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.database import SessionLocal
from backend.models.investigation import (
    InvestigationCase,
    IncidentResponsePlan,
    ResponsePlanAction,
    ResponsePlanRevision,
    AnalystCollaborationComment
)
from backend.services.investigation.case_service import CaseService
from backend.services.investigation.response_service import IncidentResponseService
from backend.schemas.investigation import (
    CaseCreateRequest,
    ResponsePlanCreateRequest,
    ResponseActionCreateRequest,
    ResponseActionApprovalRequest,
    ResponseActionExecutionRequest,
    AnalystCommentCreateRequest
)


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
def test_case(db_session: Session):
    req = CaseCreateRequest(
        title="Ransomware & Credential Dumping Response Plan Test",
        target_database_name="CustomerVault_Phase6",
        created_by="incident_commander",
        incident_category="RANSOMWARE",
        priority="P1_CRITICAL"
    )
    case = CaseService.create_case(db=db_session, req=req)
    yield case
    # Teardown
    case_db = db_session.query(InvestigationCase).filter(InvestigationCase.id == case.id).first()
    if case_db:
        db_session.delete(case_db)
        db_session.commit()


def test_response_plan_creation_and_initial_revision(db_session: Session, test_case: InvestigationCase):
    """Verifies response plan creation with version 1 and initial revision snapshot."""
    req = ResponsePlanCreateRequest(
        case_id=test_case.id,
        title="Immediate Compromised Credential Isolation Plan",
        summary="Emergency containment steps to isolate suspect SA session and rotate keys.",
        plan_type="CONTAINMENT",
        created_by="secops_lead"
    )
    plan = IncidentResponseService.create_response_plan(db_session, req)

    assert plan.id is not None
    assert plan.version == 1
    assert plan.status == "DRAFT"
    assert len(plan.revisions) == 1
    assert plan.revisions[0].version == 1


def test_action_creation_and_risk_level_assignment(db_session: Session, test_case: InvestigationCase):
    """Verifies response action creation and automatic multi-party approval requirement for high-risk actions."""
    plan = IncidentResponseService.create_response_plan(
        db_session,
        ResponsePlanCreateRequest(
            case_id=test_case.id,
            title="Database Lockdown Plan",
            created_by="secops_lead"
        )
    )

    # 1. Low risk action
    low_action = IncidentResponseService.add_action(
        db_session,
        plan_id=plan.id,
        req=ResponseActionCreateRequest(
            title="Check active session count",
            action_category="CONTAINMENT",
            target_type="LOGIN",
            risk_level="LOW",
            proposed_script="SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE login_name = 'suspect_user';",
            proposed_by="analyst_alice",
            requires_multi_party_approval=False
        )
    )
    assert low_action.risk_level == "LOW"
    assert low_action.requires_multi_party_approval is False

    # 2. Critical risk action (unconditionally requires multi-party approval)
    crit_action = IncidentResponseService.add_action(
        db_session,
        plan_id=plan.id,
        req=ResponseActionCreateRequest(
            title="Disable compromised administrative login",
            action_category="CONTAINMENT",
            target_type="LOGIN",
            target_identifier="sa_compromised",
            risk_level="CRITICAL",
            proposed_script="ALTER LOGIN [sa_compromised] DISABLE;",
            rollback_script="ALTER LOGIN [sa_compromised] ENABLE;",
            proposed_by="analyst_alice"
        )
    )
    assert crit_action.risk_level == "CRITICAL"
    assert crit_action.requires_multi_party_approval is True
    assert crit_action.approval_status == "PENDING_APPROVAL"


def test_separation_of_duties_approval_enforcement(db_session: Session, test_case: InvestigationCase):
    """Verifies that an operator who proposes a critical action CANNOT approve it (SoD enforcement)."""
    plan = IncidentResponseService.create_response_plan(
        db_session,
        ResponsePlanCreateRequest(
            case_id=test_case.id,
            title="SoD Enforcement Plan",
            created_by="operator_alice"
        )
    )

    action = IncidentResponseService.add_action(
        db_session,
        plan_id=plan.id,
        req=ResponseActionCreateRequest(
            title="Emergency Deny All Access to Financial Schema",
            action_category="CONTAINMENT",
            target_type="DATABASE",
            risk_level="HIGH",
            proposed_script="DENY SELECT, INSERT, UPDATE, DELETE ON SCHEMA::finance TO [guest];",
            rollback_script="REVOKE SELECT, INSERT, UPDATE, DELETE ON SCHEMA::finance TO [guest];",
            proposed_by="operator_alice"
        )
    )

    # Self-approval must be rejected
    with pytest.raises(ValueError, match="Separation of duties violation"):
        IncidentResponseService.approve_action(
            db=db_session,
            action_id=action.id,
            req=ResponseActionApprovalRequest(
                approved_by="operator_alice",  # Same as proposed_by!
                approval_status="APPROVED",
                approval_notes="I approve my own proposed lockdown script"
            )
        )

    # Independent peer/lead approval succeeds
    approved_action = IncidentResponseService.approve_action(
        db=db_session,
        action_id=action.id,
        req=ResponseActionApprovalRequest(
            approved_by="security_officer_bob",
            approval_status="APPROVED",
            approval_notes="Peer-reviewed and verified safe against prod revenue impact."
        )
    )
    assert approved_action.approval_status == "APPROVED"
    assert approved_action.approved_by == "security_officer_bob"
    assert approved_action.approved_at is not None


def test_manual_execution_tracking_and_approval_guard(db_session: Session, test_case: InvestigationCase):
    """Verifies that execution acknowledgement requires approval first, and tracks execution status."""
    plan = IncidentResponseService.create_response_plan(
        db_session,
        ResponsePlanCreateRequest(
            case_id=test_case.id,
            title="Execution Protocol Plan",
            created_by="lead_investigator"
        )
    )

    action = IncidentResponseService.add_action(
        db_session,
        plan_id=plan.id,
        req=ResponseActionCreateRequest(
            title="Revoke Control Server permission from suspect role",
            action_category="ERADICATION",
            target_type="LOGIN",
            risk_level="HIGH",
            proposed_script="REVOKE CONTROL SERVER FROM [LegacyAppAdmin];",
            proposed_by="analyst_carol"
        )
    )

    # Attempting to execute unapproved action must fail
    with pytest.raises(ValueError, match="Execution blocked.*must be APPROVED"):
        IncidentResponseService.acknowledge_execution(
            db=db_session,
            action_id=action.id,
            req=ResponseActionExecutionRequest(
                executed_by="dba_dave",
                execution_status="EXECUTED_SUCCESS"
            )
        )

    # Approve action
    IncidentResponseService.approve_action(
        db=db_session,
        action_id=action.id,
        req=ResponseActionApprovalRequest(
            approved_by="ciso_dan",
            approval_status="APPROVED",
            approval_notes="Approved for immediate maintenance window execution."
        )
    )

    # Now acknowledge execution
    executed_action = IncidentResponseService.acknowledge_execution(
        db=db_session,
        action_id=action.id,
        req=ResponseActionExecutionRequest(
            executed_by="dba_dave",
            execution_status="EXECUTED_SUCCESS",
            execution_notes="Executed in SSMS on primary node. Query affected 0 rows, permissions verified revoked."
        )
    )
    assert executed_action.execution_status == "EXECUTED_SUCCESS"
    assert executed_action.executed_by == "dba_dave"
    assert executed_action.executed_at is not None


def test_plan_versioning_and_revision_snapshots(db_session: Session, test_case: InvestigationCase):
    """Verifies that response plans can increment versions and capture immutable revision snapshots."""
    plan = IncidentResponseService.create_response_plan(
        db_session,
        ResponsePlanCreateRequest(
            case_id=test_case.id,
            title="Version Increment Test Plan",
            created_by="lead_investigator"
        )
    )
    assert plan.version == 1

    rev2 = IncidentResponseService.create_revision(
        db=db_session,
        plan_id=plan.id,
        revised_by="security_architect",
        revision_summary="Added secondary host containment procedures."
    )
    assert rev2.version == 2
    assert plan.version == 2
    assert len(plan.revisions) == 2


def test_analyst_collaboration_and_threaded_comments(db_session: Session, test_case: InvestigationCase):
    """Verifies threaded analyst comments, peer reviews, and hierarchical reply tracking."""
    # Top-level comment
    c1 = IncidentResponseService.add_comment(
        db=db_session,
        case_id=test_case.id,
        req=AnalystCommentCreateRequest(
            author="forensic_analyst_1",
            content="Evidence from Extended Events shows password spray occurred from 192.168.10.45",
            comment_type="COMMENT"
        )
    )
    assert c1.id is not None
    assert c1.parent_comment_id is None

    # Threaded reply
    c2 = IncidentResponseService.add_comment(
        db=db_session,
        case_id=test_case.id,
        req=AnalystCommentCreateRequest(
            author="secops_lead",
            content="Confirmed. Corroborating firewall logs indicate connection dropped at 02:15 UTC.",
            comment_type="PEER_REVIEW",
            parent_comment_id=c1.id
        )
    )
    assert c2.parent_comment_id == c1.id

    # Retrieve all top-level comments and verify reply hierarchy
    comments = IncidentResponseService.list_comments(db_session, test_case.id)
    target = [c for c in comments if c.id == c1.id][0]
    assert len(target.replies) == 1
    assert target.replies[0].id == c2.id


def test_response_api_endpoints(api_client: TestClient, test_case: InvestigationCase):
    """Verifies all Phase 6 REST API endpoints through TestClient."""
    # 1. POST /api/v1/investigations/{case_id}/response-plans
    res = api_client.post(
        f"/api/v1/investigations/{test_case.id}/response-plans",
        json={
            "case_id": test_case.id,
            "title": "API Managed Incident Response Plan",
            "summary": "Plan created via REST API endpoint",
            "plan_type": "CONTAINMENT",
            "created_by": "api_user"
        }
    )
    assert res.status_code == 201
    plan_data = res.json()
    plan_id = plan_data["id"]
    assert plan_data["version"] == 1

    # 2. GET /api/v1/investigations/{case_id}/response-plans
    res = api_client.get(f"/api/v1/investigations/{test_case.id}/response-plans")
    assert res.status_code == 200
    plans = res.json()
    assert any(p["id"] == plan_id for p in plans)

    # 3. GET /api/v1/response-plans/{plan_id}
    res = api_client.get(f"/api/v1/response-plans/{plan_id}")
    assert res.status_code == 200
    assert res.json()["title"] == "API Managed Incident Response Plan"

    # 4. POST /api/v1/response-plans/{plan_id}/actions
    res = api_client.post(
        f"/api/v1/response-plans/{plan_id}/actions",
        json={
            "title": "Isolate Database by Setting to RESTRICTED_USER",
            "action_category": "CONTAINMENT",
            "target_type": "DATABASE",
            "risk_level": "HIGH",
            "proposed_script": "ALTER DATABASE [CustomerVault] SET RESTRICTED_USER WITH ROLLBACK IMMEDIATE;",
            "rollback_script": "ALTER DATABASE [CustomerVault] SET MULTI_USER;",
            "proposed_by": "api_proposer"
        }
    )
    assert res.status_code == 201
    action_data = res.json()
    action_id = action_data["id"]
    assert action_data["approval_status"] == "PENDING_APPROVAL"

    # 5. POST /api/v1/response-actions/{action_id}/approve - test SoD rejection
    res = api_client.post(
        f"/api/v1/response-actions/{action_id}/approve",
        json={
            "approved_by": "api_proposer",  # Proposer self-approval -> must be 400
            "approval_status": "APPROVED",
            "approval_notes": "Self approval attempt"
        }
    )
    assert res.status_code == 400
    assert "Separation of duties violation" in res.json()["detail"]

    # 5b. Valid approval by independent user
    res = api_client.post(
        f"/api/v1/response-actions/{action_id}/approve",
        json={
            "approved_by": "independent_ciso",
            "approval_status": "APPROVED",
            "approval_notes": "Approved by senior security officer"
        }
    )
    assert res.status_code == 200
    assert res.json()["approval_status"] == "APPROVED"

    # 6. POST /api/v1/response-actions/{action_id}/execute
    res = api_client.post(
        f"/api/v1/response-actions/{action_id}/execute",
        json={
            "executed_by": "senior_dba",
            "execution_status": "EXECUTED_SUCCESS",
            "execution_notes": "Database restricted mode active. Verified via sys.databases."
        }
    )
    assert res.status_code == 200
    assert res.json()["execution_status"] == "EXECUTED_SUCCESS"

    # 7. POST /api/v1/response-plans/{plan_id}/revisions
    res = api_client.post(
        f"/api/v1/response-plans/{plan_id}/revisions?revised_by=security_lead&revision_summary=Formalized+actions"
    )
    assert res.status_code == 201
    assert res.json()["version"] == 2

    # 8. POST /api/v1/investigations/{case_id}/comments
    res = api_client.post(
        f"/api/v1/investigations/{test_case.id}/comments",
        json={
            "author": "analyst_emma",
            "content": "Containment completed successfully. Ready for Module 5 isolated recovery validation.",
            "comment_type": "PEER_REVIEW"
        }
    )
    assert res.status_code == 201
    comment_id = res.json()["id"]

    # 9. GET /api/v1/investigations/{case_id}/comments
    res = api_client.get(f"/api/v1/investigations/{test_case.id}/comments")
    assert res.status_code == 200
    comments = res.json()
    assert any(c["id"] == comment_id for c in comments)
