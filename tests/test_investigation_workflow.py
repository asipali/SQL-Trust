"""
SQL-TRUST Module 6 Phase 5 Test Suite
Investigation Workflow Engine: Playbook Templates, State Machine, Task DAG,
Circular Dependency Detection, Completion Guards, Escalation, and API Endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.database import SessionLocal
from backend.models.investigation import (
    InvestigationCase,
    InvestigationWorkflow,
    InvestigationTask,
    InvestigationWorkflowTemplate,
    InvestigationWorkflowHistory,
    InvestigationEscalation
)
from backend.services.investigation.case_service import CaseService
from backend.services.investigation.workflow_service import InvestigationWorkflowService
from backend.services.investigation.task_service import InvestigationTaskService
from backend.schemas.investigation import (
    CaseCreateRequest,
    WorkflowCreateRequest,
    WorkflowTransitionRequest,
    WorkflowEscalateRequest
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
        title="Unauthorized Access Incident - Workflow Engine Test",
        target_database_name="CustomerVault_Test",
        created_by="secops_lead",
        incident_category="UNAUTHORIZED_ACCESS",
        priority="P1_CRITICAL"
    )
    case = CaseService.create_case(db=db_session, req=req)
    yield case
    # Teardown
    case_db = db_session.query(InvestigationCase).filter(InvestigationCase.id == case.id).first()
    if case_db:
        db_session.delete(case_db)
        db_session.commit()


def test_seed_default_templates(db_session: Session):
    """Verifies that all 5 standardized investigation playbook templates seed properly."""
    templates = InvestigationWorkflowService.seed_default_templates(db_session)
    assert len(templates) >= 5

    names = {t.name for t in templates}
    assert "Unauthorized Access Playbook" in names
    assert "Suspicious Modification Playbook" in names
    assert "Backup Integrity Playbook" in names
    assert "Audit Tampering Playbook" in names
    assert "General Security Playbook" in names


def test_workflow_instantiation_from_template(db_session: Session, test_case: InvestigationCase):
    """Verifies workflow creation from template populates stages, tasks, and task dependencies."""
    tmpl = db_session.query(InvestigationWorkflowTemplate).filter(
        InvestigationWorkflowTemplate.name == "Unauthorized Access Playbook"
    ).first()
    assert tmpl is not None

    req = WorkflowCreateRequest(
        case_id=test_case.id,
        template_id=tmpl.id,
        created_by="lead_investigator",
        owner="lead_investigator"
    )
    wf = InvestigationWorkflowService.create_workflow(db_session, req)
    assert wf.id is not None
    assert wf.status == "NOT_STARTED"
    assert wf.current_stage == "INTAKE_TRIAGE"
    assert len(wf.tasks) == 6

    # Verify task ordering and mandatory flags
    orders = [t.order_index for t in wf.tasks]
    assert orders == [1, 2, 3, 4, 5, 6]
    assert all(t.is_mandatory for t in wf.tasks)

    # Verify dependencies created: task 2 depends on task 1
    task1 = [t for t in wf.tasks if t.order_index == 1][0]
    task2 = [t for t in wf.tasks if t.order_index == 2][0]
    assert len(task2.prerequisites) == 1
    assert task2.prerequisites[0].prerequisite_task_id == task1.id


def test_circular_dependency_detection(db_session: Session, test_case: InvestigationCase):
    """Verifies that the task dependency engine detects and rejects circular dependencies."""
    # Create an independent test workflow
    wf = InvestigationWorkflow(
        case_id=test_case.id,
        name="Cycle Test Workflow",
        status="NOT_STARTED",
        current_stage="STAGE_1",
        created_by="test_user"
    )
    db_session.add(wf)
    db_session.commit()
    db_session.refresh(wf)

    # Create 3 tasks: A, B, C
    tA = InvestigationTaskService.create_task(db_session, wf.id, "STAGE_1", "Task A")
    tB = InvestigationTaskService.create_task(db_session, wf.id, "STAGE_1", "Task B")
    tC = InvestigationTaskService.create_task(db_session, wf.id, "STAGE_1", "Task C")

    # Self dependency should fail
    with pytest.raises(ValueError, match="cannot depend on itself"):
        InvestigationTaskService.add_dependency(db_session, tA.id, tA.id)

    # Add dependencies: A -> B (B depends on A), B -> C (C depends on B)
    InvestigationTaskService.add_dependency(db_session, task_id=tB.id, prerequisite_task_id=tA.id)
    InvestigationTaskService.add_dependency(db_session, task_id=tC.id, prerequisite_task_id=tB.id)

    # Now attempt to make A depend on C (C -> A), which forms cycle A -> B -> C -> A
    with pytest.raises(ValueError, match="Circular dependency detected"):
        InvestigationTaskService.add_dependency(db_session, task_id=tA.id, prerequisite_task_id=tC.id)


def test_prerequisite_completion_guard(db_session: Session, test_case: InvestigationCase):
    """Verifies that a task cannot be completed until all blocking prerequisite tasks are completed."""
    wf = InvestigationWorkflow(
        case_id=test_case.id,
        name="Prereq Test Workflow",
        status="ACTIVE",
        current_stage="STAGE_1",
        created_by="test_user"
    )
    db_session.add(wf)
    db_session.commit()
    db_session.refresh(wf)

    t1 = InvestigationTaskService.create_task(db_session, wf.id, "STAGE_1", "Prereq Task 1")
    t2 = InvestigationTaskService.create_task(db_session, wf.id, "STAGE_1", "Dependent Task 2")

    InvestigationTaskService.add_dependency(db_session, task_id=t2.id, prerequisite_task_id=t1.id)

    # Attempting to complete t2 directly should fail
    with pytest.raises(ValueError, match="Blocking prerequisite tasks not completed"):
        InvestigationTaskService.complete_task(db_session, task_id=t2.id, completed_by="analyst_1")

    # Complete t1
    InvestigationTaskService.complete_task(db_session, task_id=t1.id, completed_by="analyst_1")

    # Now t2 can be completed
    completed_t2 = InvestigationTaskService.complete_task(
        db_session,
        task_id=t2.id,
        completed_by="analyst_1",
        completion_notes="Prerequisites satisfied, task finished."
    )
    assert completed_t2.status == "COMPLETED"


def test_workflow_state_machine_and_completion_guard(db_session: Session, test_case: InvestigationCase):
    """Verifies workflow FSM valid transitions and mandatory task completion enforcement."""
    wf = InvestigationWorkflow(
        case_id=test_case.id,
        name="FSM Guard Test Workflow",
        status="NOT_STARTED",
        current_stage="INTAKE_TRIAGE",
        created_by="test_user"
    )
    db_session.add(wf)
    db_session.commit()
    db_session.refresh(wf)

    # Add a mandatory task
    m_task = InvestigationTaskService.create_task(
        db_session,
        workflow_id=wf.id,
        stage_name="INTAKE_TRIAGE",
        title="Mandatory Review Task",
        is_mandatory=True
    )

    # Illegal transition: NOT_STARTED directly to COMPLETED
    with pytest.raises(ValueError, match="Illegal workflow status transition"):
        InvestigationWorkflowService.transition_workflow(
            db=db_session,
            workflow_id=wf.id,
            to_status="COMPLETED",
            actor="test_user"
        )

    # Transition to ACTIVE
    InvestigationWorkflowService.start_workflow(db_session, wf.id, actor="operator_1")
    assert wf.status == "ACTIVE"

    # Transition to BLOCKED
    InvestigationWorkflowService.transition_workflow(
        db_session, wf.id, to_status="BLOCKED", actor="operator_1", transition_reason="Waiting for DBA access"
    )
    assert wf.status == "BLOCKED"

    # Resume to ACTIVE
    InvestigationWorkflowService.transition_workflow(
        db_session, wf.id, to_status="ACTIVE", actor="operator_1", transition_reason="Access granted"
    )
    assert wf.status == "ACTIVE"

    # Attempting to transition to COMPLETED while mandatory task is PENDING should fail
    with pytest.raises(ValueError, match="mandatory task.*incomplete"):
        InvestigationWorkflowService.transition_workflow(
            db_session, wf.id, to_status="COMPLETED", actor="operator_1"
        )

    # Complete the mandatory task
    InvestigationTaskService.complete_task(db_session, m_task.id, completed_by="operator_1")

    # Now transition to COMPLETED succeeds
    completed_wf = InvestigationWorkflowService.transition_workflow(
        db_session, wf.id, to_status="COMPLETED", actor="operator_1", transition_reason="All tasks verified"
    )
    assert completed_wf.status == "COMPLETED"
    assert completed_wf.completed_at is not None

    # Transition out of terminal state should fail
    with pytest.raises(ValueError, match="Illegal workflow status transition"):
        InvestigationWorkflowService.transition_workflow(
            db_session, wf.id, to_status="ACTIVE", actor="operator_1"
        )


def test_workflow_escalation(db_session: Session, test_case: InvestigationCase):
    """Verifies incident escalation records and status update to ESCALATED."""
    wf = InvestigationWorkflow(
        case_id=test_case.id,
        name="Escalation Test Workflow",
        status="ACTIVE",
        current_stage="ANALYSIS_CORRELATION",
        created_by="lead_investigator",
        owner="junior_analyst"
    )
    db_session.add(wf)
    db_session.commit()
    db_session.refresh(wf)

    esc_req = WorkflowEscalateRequest(
        escalation_level="MANAGEMENT",
        escalation_reason="Detected lateral movement into production financial tables",
        escalated_by="junior_analyst",
        escalated_to="ciso_executive",
        reassign_owner=True
    )
    escalation = InvestigationWorkflowService.escalate_workflow(db_session, wf.id, esc_req)

    assert escalation.id is not None
    assert escalation.escalation_level == "MANAGEMENT"
    assert escalation.status == "OPEN"
    assert wf.status == "ESCALATED"
    assert wf.owner == "ciso_executive"


def test_workflow_api_endpoints(api_client: TestClient, test_case: InvestigationCase):
    """Verifies all Phase 5 REST API endpoints through TestClient."""
    # 1. GET /api/v1/workflow-templates
    res = api_client.get("/api/v1/workflow-templates")
    assert res.status_code == 200
    templates = res.json()
    assert len(templates) >= 5

    # 2. POST /api/v1/investigations/{case_id}/workflow
    tmpl_id = templates[0]["id"]
    res = api_client.post(
        f"/api/v1/investigations/{test_case.id}/workflow",
        json={
            "case_id": test_case.id,
            "template_id": tmpl_id,
            "name": "API Instantiated Workflow",
            "created_by": "api_tester"
        }
    )
    assert res.status_code == 201
    wf_data = res.json()
    wf_id = wf_data["id"]
    assert wf_data["status"] == "NOT_STARTED"
    assert wf_data["tasks_count"] > 0

    # 3. GET /api/v1/investigations/{case_id}/workflow
    res = api_client.get(f"/api/v1/investigations/{test_case.id}/workflow")
    assert res.status_code == 200
    assert res.json()["id"] == wf_id

    # 4. GET /api/v1/workflows/{workflow_id}
    res = api_client.get(f"/api/v1/workflows/{wf_id}")
    assert res.status_code == 200
    assert res.json()["id"] == wf_id

    # 5. POST /api/v1/workflows/{workflow_id}/start
    res = api_client.post(f"/api/v1/workflows/{wf_id}/start?actor=api_tester")
    assert res.status_code == 200
    assert res.json()["status"] == "ACTIVE"

    # 6. GET /api/v1/workflows/{workflow_id}/tasks
    res = api_client.get(f"/api/v1/workflows/{wf_id}/tasks")
    assert res.status_code == 200
    tasks = res.json()
    assert len(tasks) > 0
    first_task_id = tasks[0]["id"]

    # 7. POST /api/v1/workflows/{workflow_id}/tasks (add custom task)
    res = api_client.post(
        f"/api/v1/workflows/{wf_id}/tasks?actor=api_tester",
        json={
            "workflow_id": wf_id,
            "stage_name": "INTAKE_TRIAGE",
            "title": "Ad-Hoc Network Sniffing Check",
            "task_type": "MANUAL",
            "priority": "P2_HIGH",
            "is_mandatory": False
        }
    )
    assert res.status_code == 201
    custom_task_id = res.json()["id"]

    # 8. PATCH /api/v1/workflow-tasks/{task_id}
    res = api_client.patch(
        f"/api/v1/workflow-tasks/{custom_task_id}?actor=api_tester",
        json={"assigned_to": "netsec_specialist"}
    )
    assert res.status_code == 200
    assert res.json()["assigned_to"] == "netsec_specialist"

    # 9. POST /api/v1/workflow-tasks/{task_id}/complete
    res = api_client.post(
        f"/api/v1/workflow-tasks/{custom_task_id}/complete",
        json={
            "completed_by": "netsec_specialist",
            "completion_notes": "Completed manual traffic inspection.",
            "status": "COMPLETED"
        }
    )
    assert res.status_code == 200
    assert res.json()["status"] == "COMPLETED"

    # 10. POST /api/v1/workflows/{workflow_id}/escalate
    res = api_client.post(
        f"/api/v1/workflows/{wf_id}/escalate",
        json={
            "escalation_level": "TIER_3",
            "escalation_reason": "Suspected nation-state threat group TTPs",
            "escalated_by": "api_tester",
            "escalated_to": "tier3_incident_commander"
        }
    )
    assert res.status_code == 200
    assert res.json()["escalation_level"] == "TIER_3"

    # 11. GET /api/v1/workflows/{workflow_id}/history
    res = api_client.get(f"/api/v1/workflows/{wf_id}/history")
    assert res.status_code == 200
    history = res.json()
    assert len(history) >= 2
