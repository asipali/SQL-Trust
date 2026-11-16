"""
SQL-TRUST Unit & Integration Tests: Module 5 Phase 2
Recovery Job Management Foundation
Tests candidate intake gating, state machine transitions, idempotency,
authorization rules, job cancellation, and history immutability.
"""
import uuid
import pytest
from datetime import datetime, timezone
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.database import SessionLocal
from backend.models.backup import ProtectedDatabase
from backend.models.recovery import (
    RecoveryPoint,
    RecoveryChain,
    RecoveryAssessment,
    RecoveryEligibility,
    RecoveryRecommendation
)
from backend.models.restore import RecoveryJob, RecoveryJobHistory
from backend.services.restore.job_service import RecoveryJobService
from backend.services.restore.state_machine import RecoveryJobStateMachine, InvalidStateTransitionError

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
def setup_test_candidate(db_session: Session):
    """
    Provisions isolated, synthetic Module 1 & 4 test entities:
    - ProtectedDatabase
    - RecoveryPoint
    - RecoveryAssessment (HIGH_CONFIDENCE)
    - RecoveryEligibility (is_eligible=True)
    - RecoveryRecommendation
    """
    unique_suffix = uuid.uuid4().hex[:8]
    db_name = f"SQLTrust_TestDB_{unique_suffix}"

    prot_db = ProtectedDatabase(
        database_name=db_name,
        server_name="localhost\\SQLEXPRESS",
        database_identifier=f"db_{unique_suffix}"
    )
    db_session.add(prot_db)
    db_session.flush()

    rp = RecoveryPoint(
        database_id=prot_db.id,
        server_name="localhost\\SQLEXPRESS",
        database_name=db_name,
        recovery_point_time=datetime.now(timezone.utc),
        recovery_point_type="FULL",
        integrity_status="VERIFIED",
        storage_object_key=f"backups/test_{unique_suffix}.bak",
        sha256="a" * 64
    )
    db_session.add(rp)
    db_session.flush()

    assess = RecoveryAssessment(
        recovery_point_id=rp.id,
        assessment_name="Test Assessment",
        trust_classification="HIGH_CONFIDENCE",
        trust_score=85.0,
        confidence_rationale="Synthetic assessment rationale"
    )
    db_session.add(assess)
    db_session.flush()

    elig = RecoveryEligibility(
        recovery_point_id=rp.id,
        is_eligible=True,
        eligibility_status="ELIGIBLE",
        requires_offline_sandbox=True,
        chain_usable=True,
        chain_consistent=True
    )
    db_session.add(elig)
    db_session.flush()

    rec = RecoveryRecommendation(
        database_id=prot_db.id,
        recovery_point_id=rp.id,
        assessment_id=assess.id,
        eligibility_id=elig.id,
        rank_order=1,
        trust_classification="HIGH_CONFIDENCE",
        eligibility_status="ELIGIBLE",
        ranking_score=85.0,
        rank_rationale="Clean candidate with verified baseline.",
        tradeoff_analysis="Minimal data loss, no incident overlap.",
        recommended_next_step="Proceed with isolated sandbox validation."
    )
    db_session.add(rec)
    db_session.commit()

    yield {
        "protected_db": prot_db,
        "recovery_point": rp,
        "assessment": assess,
        "eligibility": elig,
        "recommendation": rec
    }

    # Cleanup test entities
    try:
        # Delete any jobs created for this candidate first
        jobs = db_session.query(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for j in jobs:
            db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == j.id).delete()
            db_session.delete(j)
        db_session.commit()

        db_session.delete(rec)
        db_session.delete(elig)
        db_session.delete(assess)
        db_session.delete(rp)
        db_session.delete(prot_db)
        db_session.commit()
    except Exception:
        db_session.rollback()


def test_job_creation_success(db_session: Session, setup_test_candidate: dict):
    """Verifies successful creation of a recovery job from an eligible candidate."""
    service = RecoveryJobService(db_session)
    candidate_id = setup_test_candidate["recommendation"].id

    job, is_new = service.create_job(
        candidate_id=candidate_id,
        requested_by="SecOps_Analyst",
        notes="Automated cyber recovery validation test"
    )

    assert is_new is True
    assert job.id is not None
    assert job.job_reference.startswith("RECOV-")
    assert job.status == "REQUESTED"
    assert job.requested_by == "SecOps_Analyst"
    assert job.target_database_name == setup_test_candidate["protected_db"].database_name

    # Verify history entry was appended
    history = service.get_job_history(job.id)
    assert len(history) == 1
    assert history[0].from_state == "NONE"
    assert history[0].to_state == "REQUESTED"


def test_idempotent_job_creation(db_session: Session, setup_test_candidate: dict):
    """Verifies that duplicate requests with the same idempotency key return the existing job."""
    service = RecoveryJobService(db_session)
    candidate_id = setup_test_candidate["recommendation"].id
    idemp_key = f"IDEMP-{uuid.uuid4().hex}"

    job1, is_new1 = service.create_job(
        candidate_id=candidate_id,
        idempotency_key=idemp_key,
        requested_by="SecOps_1"
    )
    assert is_new1 is True

    # Second call with identical key
    job2, is_new2 = service.create_job(
        candidate_id=candidate_id,
        idempotency_key=idemp_key,
        requested_by="SecOps_2"
    )
    assert is_new2 is False
    assert job1.id == job2.id
    assert job1.job_reference == job2.job_reference


def test_invalid_candidate_rejection(db_session: Session):
    """Verifies that non-existent recovery candidates are rejected with 404."""
    service = RecoveryJobService(db_session)
    non_existent_id = str(uuid.uuid4())

    with pytest.raises(HTTPException) as exc_info:
        service.create_job(candidate_id=non_existent_id)
    assert exc_info.value.status_code == 404
    assert "not found" in exc_info.value.detail.lower()


def test_ineligible_candidate_gating(db_session: Session, setup_test_candidate: dict):
    """Verifies that an ineligible recovery candidate is rejected at intake."""
    # Temporarily mark eligibility as False
    elig = setup_test_candidate["eligibility"]
    elig.is_eligible = False
    db_session.commit()

    service = RecoveryJobService(db_session)
    try:
        with pytest.raises(HTTPException) as exc_info:
            service.create_job(candidate_id=setup_test_candidate["recommendation"].id)
        assert exc_info.value.status_code == 400
        assert "ineligible" in exc_info.value.detail.lower()
    finally:
        elig.is_eligible = True
        db_session.commit()


def test_unassessed_candidate_gating(db_session: Session, setup_test_candidate: dict):
    """Verifies that an UNASSESSED candidate cannot bypass the trust confidence gate."""
    assess = setup_test_candidate["assessment"]
    orig_class = assess.trust_classification
    assess.trust_classification = "UNASSESSED"
    db_session.commit()

    service = RecoveryJobService(db_session)
    try:
        with pytest.raises(HTTPException) as exc_info:
            service.create_job(candidate_id=setup_test_candidate["recommendation"].id)
        assert exc_info.value.status_code == 400
        assert "unassessed" in exc_info.value.detail.lower()
    finally:
        assess.trust_classification = orig_class
        db_session.commit()


def test_job_approval_flow(db_session: Session, setup_test_candidate: dict):
    """Verifies administrative approval transitions a job from REQUESTED to PREFLIGHT."""
    service = RecoveryJobService(db_session)
    job, _ = service.create_job(
        candidate_id=setup_test_candidate["recommendation"].id,
        requested_by="Analyst_A"
    )

    approved_job = service.approve_job(
        job_id=job.id,
        approved_by="Lead_Admin_Bob",
        approver_notes="Verified target recovery point is prior to exfiltration."
    )

    assert approved_job.status == "PREFLIGHT"
    assert approved_job.approved_by == "Lead_Admin_Bob"
    assert approved_job.approved_at is not None

    # Verify history chain
    history = service.get_job_history(job.id)
    assert len(history) == 2
    assert history[1].from_state == "REQUESTED"
    assert history[1].to_state == "PREFLIGHT"
    assert history[1].actor == "Lead_Admin_Bob"


def test_invalid_state_transition_rejected(db_session: Session, setup_test_candidate: dict):
    """Verifies that illegal or premature transitions are rejected by the state machine."""
    service = RecoveryJobService(db_session)
    job, _ = service.create_job(
        candidate_id=setup_test_candidate["recommendation"].id,
        requested_by="Analyst_A"
    )

    # Attempt illegal jump: REQUESTED -> RESTORE_COMPLETED
    with pytest.raises(InvalidStateTransitionError):
        RecoveryJobStateMachine.transition(
            db=db_session,
            job=job,
            target_state="RESTORE_COMPLETED",
            actor="Rogue_Process"
        )

    # Attempt unimplemented milestone jump: REQUESTED -> IMAGE_VERIFIED
    with pytest.raises(InvalidStateTransitionError):
        RecoveryJobStateMachine.transition(
            db=db_session,
            job=job,
            target_state="IMAGE_VERIFIED",
            actor="Rogue_Process"
        )


def test_job_cancellation_preserves_history(db_session: Session, setup_test_candidate: dict):
    """Verifies graceful cancellation transitions to FAILED without deleting forensic history."""
    service = RecoveryJobService(db_session)
    job, _ = service.create_job(
        candidate_id=setup_test_candidate["recommendation"].id,
        requested_by="Operator_Cancel"
    )

    cancelled_job = service.cancel_job(
        job_id=job.id,
        cancellation_reason="Incident window shifted; re-assessment requested",
        cancelled_by="Lead_Operator"
    )

    assert cancelled_job.status == "FAILED"
    assert cancelled_job.failure_code == "USER_CANCELLED"
    assert "Incident window shifted" in cancelled_job.failure_reason

    # Verify all history records are strictly preserved
    history = service.get_job_history(job.id)
    assert len(history) == 2
    assert history[-1].to_state == "FAILED"
    assert history[-1].actor == "Lead_Operator"


def test_api_endpoints_e2e(setup_test_candidate: dict):
    """End-to-end test of the REST API for recovery jobs (create, list, get, approve, cancel)."""
    candidate_id = setup_test_candidate["recommendation"].id

    # 1. Create Job via POST /api/v1/recovery/jobs
    create_resp = client.post(
        "/api/v1/recovery/jobs",
        json={"candidate_id": candidate_id, "notes": "E2E API Test Job"},
        headers={"X-User-Role": "Operator"}
    )
    assert create_resp.status_code == 201
    job_data = create_resp.json()
    job_id = job_data["id"]
    assert job_data["status"] == "REQUESTED"

    # 2. List Jobs via GET /api/v1/recovery/jobs
    list_resp = client.get("/api/v1/recovery/jobs?status=REQUESTED")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert any(j["id"] == job_id for j in items)

    # 3. Get Details via GET /api/v1/recovery/jobs/{id}
    detail_resp = client.get(f"/api/v1/recovery/jobs/{job_id}")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()
    assert detail_data["id"] == job_id
    assert len(detail_data["history"]) >= 1
    assert detail_data["trust_classification"] == "HIGH_CONFIDENCE"

    # 4. Non-Admin Approval Attempt -> 403 Forbidden
    forbidden_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/approve",
        json={"approver_notes": "Unauthorized attempt"},
        headers={"X-User-Role": "Viewer"}
    )
    assert forbidden_resp.status_code == 403

    # 5. Admin Approval -> 200 OK
    approve_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/approve",
        json={"approver_notes": "Authorized by Security Officer"},
        headers={"X-User-Role": "Admin"}
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "PREFLIGHT"

    # 6. Cancel Job -> 200 OK
    cancel_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/cancel",
        json={"cancellation_reason": "End-of-test teardown"},
        headers={"X-User-Role": "Operator"}
    )
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "FAILED"
    assert cancel_resp.json()["failure_code"] == "USER_CANCELLED"
