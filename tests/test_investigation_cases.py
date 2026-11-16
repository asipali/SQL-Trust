"""
SQL-TRUST Unit & Integration Tests: Module 6 Phase 2
Investigation Case Management Foundation
Tests case creation, reference generation, FSM transitions, idempotency,
optimistic concurrency control, cross-module evidence links, containment workflows,
and tamper-evident append-only audit hash chains.
"""
import re
import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.database import SessionLocal
from backend.models.backup import ProtectedDatabase
from backend.models.investigation import (
    InvestigationCase,
    CaseStatusHistory,
    CaseNote,
    CaseEvidenceLink,
    CaseContainmentAction,
    CaseAuditLog
)
from backend.schemas.investigation import (
    CaseCreateRequest,
    CaseUpdateRequest,
    CaseTransitionRequest,
    CaseNoteCreateRequest,
    CaseEvidenceLinkCreateRequest,
    CaseContainmentActionCreateRequest,
    CaseContainmentActionUpdateRequest
)
from backend.services.investigation.case_service import CaseService
from backend.services.investigation.audit_service import CaseAuditService

client = TestClient(app)


@pytest.fixture(scope="module")
def db_session():
    """Provides a dedicated database session for tests."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def setup_test_db(db_session: Session):
    """Provisions a test ProtectedDatabase for foreign key linkage."""
    suffix = uuid.uuid4().hex[:8]
    db_name = f"SQLTrust_InvTest_{suffix}"
    prot_db = ProtectedDatabase(
        database_name=db_name,
        server_name="localhost\\SQLEXPRESS",
        database_identifier=f"inv_test_{suffix}"
    )
    db_session.add(prot_db)
    db_session.commit()
    db_session.refresh(prot_db)
    yield prot_db

    # Teardown: Clean up cases for this db first so NO ACTION foreign key doesn't block deletion
    db_session.query(InvestigationCase).filter(InvestigationCase.target_database_name == db_name).delete(synchronize_session=False)
    db_session.commit()
    db_session.delete(prot_db)
    db_session.commit()


def test_case_creation_and_reference_generation(db_session: Session, setup_test_db: ProtectedDatabase):
    """Verifies case creation, INV-YYYYMMDD-XXXX reference format, and audit log generation."""
    req = CaseCreateRequest(
        title="Unauthorized SA Login Spike and Data Modification",
        description="Extended Events detected multiple failed and succeeded SA logins followed by TRUNCATE",
        target_database_name=setup_test_db.database_name,
        target_database_id=setup_test_db.id,
        priority="P1_CRITICAL",
        incident_category="DATA_EXFILTRATION",
        created_by="secops_analyst_1",
        lead_investigator="investigator_lead",
        assigned_team="SOC-TIER2"
    )

    case = CaseService.create_case(db=db_session, req=req)

    assert case.id is not None
    assert re.match(r"^INV-\d{8}-[A-F0-9]{4}$", case.case_number)
    assert case.status == "NEW"
    assert case.priority == "P1_CRITICAL"
    assert case.version == 1
    assert case.target_database_name == setup_test_db.database_name

    # Verify initial status history
    history = db_session.query(CaseStatusHistory).filter(CaseStatusHistory.case_id == case.id).all()
    assert len(history) == 1
    assert history[0].from_status == "NONE"
    assert history[0].to_status == "NEW"

    # Verify initial audit log
    audit_logs = db_session.query(CaseAuditLog).filter(CaseAuditLog.case_id == case.id).all()
    assert len(audit_logs) == 1
    assert audit_logs[0].action == "CASE_CREATED"
    assert audit_logs[0].sequence_number == 1
    assert audit_logs[0].previous_hash == CaseAuditService.GENESIS_HASH


def test_case_idempotency(db_session: Session, setup_test_db: ProtectedDatabase):
    """Verifies that duplicate requests with the same idempotency_key return the existing case."""
    idempotency_key = f"idemp-{uuid.uuid4().hex}"
    req = CaseCreateRequest(
        title="Idempotent Test Case",
        target_database_name=setup_test_db.database_name,
        created_by="automated_collector",
        idempotency_key=idempotency_key
    )

    case_1 = CaseService.create_case(db=db_session, req=req)
    case_2 = CaseService.create_case(db=db_session, req=req)

    assert case_1.id == case_2.id
    assert case_1.case_number == case_2.case_number


def test_case_fsm_valid_lifecycle(db_session: Session, setup_test_db: ProtectedDatabase):
    """
    Tests complete valid FSM lifecycle:
    NEW -> TRIAGED -> ACTIVE -> CONTAINMENT_REVIEW -> RECOVERY_COORDINATION -> RESOLVED -> CLOSED
    """
    req = CaseCreateRequest(
        title="Full Lifecycle Test Case",
        target_database_name=setup_test_db.database_name,
        created_by="analyst_alice"
    )
    case = CaseService.create_case(db=db_session, req=req)

    # 1. NEW -> TRIAGED
    case = CaseService.transition_status(
        db=db_session,
        case_id=case.id,
        req=CaseTransitionRequest(to_status="TRIAGED", changed_by="analyst_alice", transition_reason="Initial triage confirmed")
    )
    assert case.status == "TRIAGED"
    assert case.version == 2

    # 2. TRIAGED -> ACTIVE
    case = CaseService.transition_status(
        db=db_session,
        case_id=case.id,
        req=CaseTransitionRequest(to_status="ACTIVE", changed_by="lead_bob", transition_reason="Investigation active")
    )
    assert case.status == "ACTIVE"
    assert case.version == 3

    # 3. ACTIVE -> CONTAINMENT_REVIEW
    case = CaseService.transition_status(
        db=db_session,
        case_id=case.id,
        req=CaseTransitionRequest(to_status="CONTAINMENT_REVIEW", changed_by="lead_bob", transition_reason="Containment required")
    )
    assert case.status == "CONTAINMENT_REVIEW"

    # 4. CONTAINMENT_REVIEW -> RECOVERY_COORDINATION
    case = CaseService.transition_status(
        db=db_session,
        case_id=case.id,
        req=CaseTransitionRequest(to_status="RECOVERY_COORDINATION", changed_by="dba_charlie", transition_reason="Coordinating recovery point")
    )
    assert case.status == "RECOVERY_COORDINATION"

    # 5. RECOVERY_COORDINATION -> RESOLVED
    case = CaseService.transition_status(
        db=db_session,
        case_id=case.id,
        req=CaseTransitionRequest(to_status="RESOLVED", changed_by="lead_bob", transition_reason="Database restore validated clean")
    )
    assert case.status == "RESOLVED"

    # 6. RESOLVED -> CLOSED
    case = CaseService.transition_status(
        db=db_session,
        case_id=case.id,
        req=CaseTransitionRequest(to_status="CLOSED", changed_by="ciso_dan", transition_reason="Incident successfully remediated and closed")
    )
    assert case.status == "CLOSED"
    assert case.closed_at is not None
    assert case.closure_reason == "Incident successfully remediated and closed"

    # Verify status history count (initial + 6 transitions = 7)
    histories = db_session.query(CaseStatusHistory).filter(CaseStatusHistory.case_id == case.id).all()
    assert len(histories) == 7


def test_case_fsm_invalid_transitions(db_session: Session, setup_test_db: ProtectedDatabase):
    """Verifies that illegal transitions raise ValueError and are blocked."""
    req = CaseCreateRequest(
        title="Invalid Transition Test Case",
        target_database_name=setup_test_db.database_name,
        created_by="tester"
    )
    case = CaseService.create_case(db=db_session, req=req)

    # Illegal transition: NEW cannot jump directly to RESOLVED or CLOSED
    with pytest.raises(ValueError, match="Illegal state transition"):
        CaseService.transition_status(
            db=db_session,
            case_id=case.id,
            req=CaseTransitionRequest(to_status="RESOLVED", changed_by="tester")
        )

    with pytest.raises(ValueError, match="Illegal state transition"):
        CaseService.transition_status(
            db=db_session,
            case_id=case.id,
            req=CaseTransitionRequest(to_status="CLOSED", changed_by="tester")
        )


def test_optimistic_concurrency_control(db_session: Session, setup_test_db: ProtectedDatabase):
    """Verifies optimistic locking rejects updates when expected_version mismatches."""
    req = CaseCreateRequest(
        title="Concurrency Test Case",
        target_database_name=setup_test_db.database_name,
        created_by="tester"
    )
    case = CaseService.create_case(db=db_session, req=req)
    assert case.version == 1

    # Update with correct version
    case = CaseService.update_case(
        db=db_session,
        case_id=case.id,
        req=CaseUpdateRequest(title="Updated Title Once", expected_version=1),
        actor="tester_1"
    )
    assert case.version == 2

    # Attempt update with stale version 1 (should fail)
    with pytest.raises(ValueError, match="Concurrency conflict"):
        CaseService.update_case(
            db=db_session,
            case_id=case.id,
            req=CaseUpdateRequest(title="Stale Update Attempt", expected_version=1),
            actor="tester_2"
        )


def test_case_notes_management(db_session: Session, setup_test_db: ProtectedDatabase):
    """Verifies analyst notes addition, types, pinning, and audit recording."""
    case = CaseService.create_case(
        db=db_session,
        req=CaseCreateRequest(
            title="Notes Test Case",
            target_database_name=setup_test_db.database_name,
            created_by="analyst"
        )
    )

    note = CaseService.add_note(
        db=db_session,
        case_id=case.id,
        req=CaseNoteCreateRequest(
            author="forensic_analyst",
            note_type="HYPOTHESIS",
            content="Attacker used compromised app login to execute xp_cmdshell",
            is_pinned=True
        )
    )

    assert note.id is not None
    assert note.is_pinned is True
    assert note.note_type == "HYPOTHESIS"

    # Verify note in case relations
    db_session.refresh(case)
    assert len(case.notes) == 1
    assert case.notes[0].content == "Attacker used compromised app login to execute xp_cmdshell"


def test_cross_module_evidence_linking(db_session: Session, setup_test_db: ProtectedDatabase):
    """Verifies linking cross-module evidence records with roles and SHA-256 hashes."""
    case = CaseService.create_case(
        db=db_session,
        req=CaseCreateRequest(
            title="Evidence Link Test Case",
            target_database_name=setup_test_db.database_name,
            created_by="analyst"
        )
    )

    # Link Module 2 Security Alert
    mock_alert_id = str(uuid.uuid4())
    link = CaseService.link_evidence(
        db=db_session,
        case_id=case.id,
        req=CaseEvidenceLinkCreateRequest(
            source_module="MODULE_2_SECURITY",
            source_entity="security_alerts",
            source_id=mock_alert_id,
            evidence_role="ROOT_CAUSE",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            metadata_snapshot='{"rule_code": "RULE-001", "severity": "CRITICAL"}',
            linked_by="auto_correlator"
        )
    )

    assert link.id is not None
    assert link.source_module == "MODULE_2_SECURITY"
    assert link.evidence_role == "ROOT_CAUSE"
    assert link.tamper_status == "VERIFIED"

    # Duplicate link request should return existing link
    duplicate_link = CaseService.link_evidence(
        db=db_session,
        case_id=case.id,
        req=CaseEvidenceLinkCreateRequest(
            source_module="MODULE_2_SECURITY",
            source_entity="security_alerts",
            source_id=mock_alert_id,
            linked_by="auto_correlator"
        )
    )
    assert duplicate_link.id == link.id


def test_containment_action_workflow(db_session: Session, setup_test_db: ProtectedDatabase):
    """Verifies containment recommendation, human review, and status updates."""
    case = CaseService.create_case(
        db=db_session,
        req=CaseCreateRequest(
            title="Containment Test Case",
            target_database_name=setup_test_db.database_name,
            created_by="analyst"
        )
    )
    assert case.containment_status == "NONE"

    action = CaseService.add_containment_action(
        db=db_session,
        case_id=case.id,
        req=CaseContainmentActionCreateRequest(
            action_type="REVOKE_LOGIN",
            target_principal="malicious_sa",
            recommended_script="ALTER LOGIN [malicious_sa] DISABLE; ALTER SERVER ROLE [sysadmin] DROP MEMBER [malicious_sa];",
            risk_assessment="Low risk; non-application account used solely during incident"
        ),
        actor="secops_lead"
    )

    assert action.id is not None
    assert action.status == "PENDING"
    assert case.containment_status == "RECOMMENDED"

    # Operator approves the containment action
    updated_action = CaseService.update_containment_action(
        db=db_session,
        action_id=action.id,
        req=CaseContainmentActionUpdateRequest(
            status="APPROVED",
            reviewed_by="ciso_approver",
            review_comment="Approved for manual execution by lead DBA"
        )
    )

    assert updated_action.status == "APPROVED"
    assert updated_action.reviewed_by == "ciso_approver"
    assert case.containment_status == "CONTAINED"


def test_append_only_audit_chain_verification(db_session: Session, setup_test_db: ProtectedDatabase):
    """Verifies SHA-256 hash chaining across audit log entries and tamper detection."""
    case = CaseService.create_case(
        db=db_session,
        req=CaseCreateRequest(
            title="Audit Chain Test Case",
            target_database_name=setup_test_db.database_name,
            created_by="auditor"
        )
    )

    # Perform multiple actions
    CaseService.add_note(
        db=db_session,
        case_id=case.id,
        req=CaseNoteCreateRequest(author="auditor", content="First investigative note")
    )
    CaseService.transition_status(
        db=db_session,
        case_id=case.id,
        req=CaseTransitionRequest(to_status="TRIAGED", changed_by="auditor")
    )
    CaseService.add_note(
        db=db_session,
        case_id=case.id,
        req=CaseNoteCreateRequest(author="auditor", content="Second investigative note")
    )

    # Verify clean audit chain
    verification = CaseAuditService.verify_audit_chain(db=db_session, case_id=case.id)
    assert verification["valid"] is True
    assert verification["total_entries"] == 4
    assert len(verification["discrepancies"]) == 0

    # Tamper simulation: artificially modify an entry in the database
    third_log = (
        db_session.query(CaseAuditLog)
        .filter(CaseAuditLog.case_id == case.id, CaseAuditLog.sequence_number == 3)
        .first()
    )
    original_details = third_log.details
    third_log.details = "TAMPERED DETAILS TO COMPROMISE INTEGRITY"
    db_session.commit()

    # Re-verify audit chain: must detect discrepancy
    tampered_verification = CaseAuditService.verify_audit_chain(db=db_session, case_id=case.id)
    assert tampered_verification["valid"] is False
    assert len(tampered_verification["discrepancies"]) > 0

    # Restore original details to leave database clean
    third_log.details = original_details
    db_session.commit()

    clean_check = CaseAuditService.verify_audit_chain(db=db_session, case_id=case.id)
    assert clean_check["valid"] is True


def test_investigation_api_endpoints(setup_test_db: ProtectedDatabase):
    """Verifies FastAPI REST API endpoints for Module 6."""
    # 1. Create Case
    create_payload = {
        "title": "API Test Investigation Case",
        "description": "Created via REST API test",
        "target_database_name": setup_test_db.database_name,
        "priority": "P2_HIGH",
        "incident_category": "SCHEMA_TAMPERING",
        "created_by": "api_test_user"
    }
    res = client.post("/api/v1/investigations", json=create_payload)
    assert res.status_code == 201, res.text
    data = res.json()
    case_id = data["id"]
    case_number = data["case_number"]
    assert data["status"] == "NEW"

    # 2. List Cases
    res = client.get(f"/api/v1/investigations?database_name={setup_test_db.database_name}")
    assert res.status_code == 200
    list_data = res.json()
    assert list_data["total"] >= 1

    # 3. Get Case Detail
    res = client.get(f"/api/v1/investigations/{case_number}")
    assert res.status_code == 200
    detail = res.json()
    assert detail["id"] == case_id
    assert len(detail["status_history"]) >= 1

    # 4. Add Note
    res = client.post(
        f"/api/v1/investigations/{case_id}/notes",
        json={"author": "analyst", "note_type": "ANALYST_NOTE", "content": "API Note Content"}
    )
    assert res.status_code == 201
    assert res.json()["content"] == "API Note Content"

    # 5. Link Evidence
    res = client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        json={
            "source_module": "MODULE_3_FORENSICS",
            "source_entity": "forensic_findings",
            "source_id": str(uuid.uuid4()),
            "evidence_role": "INDICATOR_OF_COMPROMISE",
            "linked_by": "api_user"
        }
    )
    assert res.status_code == 201

    # 6. Recommend Containment
    res = client.post(
        f"/api/v1/investigations/{case_id}/containment",
        json={
            "action_type": "DISABLE_TRIGGER",
            "target_object": "tr_security_override",
            "recommended_script": "DISABLE TRIGGER tr_security_override ON DATABASE;",
            "risk_assessment": "Safe"
        }
    )
    assert res.status_code == 201
    action_id = res.json()["id"]

    # 7. Review Containment
    res = client.patch(
        f"/api/v1/investigations/containment/{action_id}",
        json={"status": "APPROVED", "reviewed_by": "dba_manager", "review_comment": "Approved"}
    )
    assert res.status_code == 200
    assert res.json()["status"] == "APPROVED"

    # 8. Transition Case
    res = client.patch(
        f"/api/v1/investigations/{case_id}/transition",
        json={"to_status": "TRIAGED", "changed_by": "api_user", "transition_reason": "Triaged via API"}
    )
    assert res.status_code == 200
    assert res.json()["status"] == "TRIAGED"

    # 9. Verify Audit Chain
    res = client.get(f"/api/v1/investigations/{case_id}/audit-logs/verify")
    assert res.status_code == 200
    assert res.json()["valid"] is True
