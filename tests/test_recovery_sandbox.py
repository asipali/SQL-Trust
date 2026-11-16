"""
SQL-TRUST Unit & Integration Tests: Module 5 Phase 4
Isolated Recovery Environment & Sandbox Provisioning
Tests ephemeral credentials, loopback port allocation, container lifecycle,
production isolation verification, quarantine, authorized cleanup, and REST API.
"""
import os
import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from unittest.mock import MagicMock, patch

from backend.main import app
from backend.database import SessionLocal
from backend.models.backup import ProtectedDatabase
from backend.models.recovery import (
    RecoveryPoint,
    RecoveryAssessment,
    RecoveryEligibility,
    RecoveryRecommendation
)
from backend.models.restore import RecoveryJob, RecoverySandbox
from backend.services.restore.job_service import RecoveryJobService
from backend.services.restore.sandbox_service import (
    RecoverySandboxService,
    generate_strong_ephemeral_password,
    find_free_loopback_port,
    SandboxError,
    SandboxProvisioningError
)
from backend.services.restore.state_machine import InvalidStateTransitionError

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
def setup_sandbox_candidate(db_session: Session):
    """Provisions an isolated candidate for sandbox testing."""
    unique_suffix = uuid.uuid4().hex[:8]
    db_name = f"SQLTrust_SandboxDB_{unique_suffix}"

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
        storage_object_key=f"backups/sandbox_{unique_suffix}.bak",
        sha256="b" * 64
    )
    db_session.add(rp)
    db_session.flush()

    assess = RecoveryAssessment(
        recovery_point_id=rp.id,
        assessment_name="Sandbox Test Assessment",
        trust_classification="HIGH_CONFIDENCE",
        trust_score=95.0,
        confidence_rationale="Sandbox isolation test baseline"
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
        ranking_score=95.0,
        rank_rationale="High confidence candidate for sandbox test.",
        tradeoff_analysis="No incident overlap.",
        recommended_next_step="Provision sandbox environment."
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

    # Teardown
    try:
        sandboxes = db_session.query(RecoverySandbox).join(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for s in sandboxes:
            db_session.delete(s)
        jobs = db_session.query(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for j in jobs:
            from backend.models.restore import RecoveryJobHistory
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


def test_ephemeral_password_complexity():
    """Verifies that generated SA passwords satisfy SQL Server complexity requirements."""
    pwd = generate_strong_ephemeral_password()
    assert len(pwd) >= 30
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in "!@#$%^&*()-_=+" for c in pwd)


def test_loopback_port_allocation():
    """Verifies that find_free_loopback_port discovers an available loopback port."""
    port = find_free_loopback_port(start_port=12000, max_attempts=50)
    assert port >= 12000


def test_sandbox_provisioning_guard(db_session: Session, setup_sandbox_candidate: dict):
    """Verifies that provisioning is rejected if the job has not completed preflight/staging."""
    service = RecoveryJobService(db_session)
    job, _ = service.create_job(
        candidate_id=setup_sandbox_candidate["recommendation"].id,
        requested_by="Operator_Test"
    )

    sandbox_service = RecoverySandboxService(db_session)
    # Job is in REQUESTED state; should be rejected
    with pytest.raises(InvalidStateTransitionError):
        sandbox_service.provision_sandbox(job_id=job.id)

    # Teardown
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_sandbox_provisioning_lifecycle_mocked(db_session: Session, setup_sandbox_candidate: dict):
    """
    Verifies full sandbox provisioning lifecycle with mocked Docker commands:
    - Dedicated network and separate volume creation
    - Safe port binding to 127.0.0.1
    - State machine progression: PREFLIGHT -> ENVIRONMENT_CREATED
    """
    service = RecoveryJobService(db_session)
    job, _ = service.create_job(
        candidate_id=setup_sandbox_candidate["recommendation"].id,
        requested_by="Operator_Test"
    )
    service.approve_job(job_id=job.id, approved_by="Admin_Lead")

    sandbox_service = RecoverySandboxService(db_session)

    # Mock docker execution and readiness/isolation checks
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "a1b2c3d4e5f6\n"
    mock_proc.stderr = ""

    with patch.object(sandbox_service, "_run_docker_cmd", return_value=mock_proc), \
         patch.object(sandbox_service, "wait_for_sandbox_readiness", return_value=(True, None)), \
         patch.object(sandbox_service, "verify_sandbox_isolation", return_value={
             "all_isolation_checks_passed": True,
             "checks": {
                 "engine_platform": {"passed": True},
                 "production_db_isolated": {"passed": True},
                 "staging_mount_read_only": {"passed": True}
             }
         }):

        sandbox = sandbox_service.provision_sandbox(job.id, cpu_limit="2.0", memory_limit="2048m")
        assert sandbox is not None
        assert sandbox.lifecycle_status == "HEALTHY"
        assert sandbox.is_isolated is True
        assert sandbox.network_isolated is True
        assert sandbox.storage_isolated is True
        assert sandbox.container_name.startswith("sqltrust-rec-sbx-")

        db_session.refresh(job)
        assert job.status == "ENVIRONMENT_CREATED"

        # Verify duplicate provisioning returns existing record
        duplicate = sandbox_service.provision_sandbox(job.id)
        assert duplicate.id == sandbox.id

        # Verify quarantine
        quarantined = sandbox_service.quarantine_sandbox(job.id, reason="Security review required")
        assert quarantined.lifecycle_status == "QUARANTINED"
        assert "Security review required" in quarantined.error_message

        # Verify cleanup
        cleaned = sandbox_service.cleanup_sandbox(job.id, authorized_by="Admin_Lead")
        assert cleaned.lifecycle_status == "CLEANED"
        assert cleaned.cleaned_at is not None

        # Teardown
        db_session.delete(sandbox)
        from backend.models.restore import RecoveryJobHistory
        db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
        db_session.delete(job)
        db_session.commit()


def test_sandbox_rest_api_e2e(db_session: Session, setup_sandbox_candidate: dict):
    """End-to-end REST API verification for sandbox endpoints."""
    candidate_id = setup_sandbox_candidate["recommendation"].id

    # 1. Create & Approve Job
    create_resp = client.post(
        "/api/v1/recovery/jobs",
        json={"candidate_id": candidate_id, "notes": "Sandbox API Test"},
        headers={"X-User-Role": "Operator"}
    )
    assert create_resp.status_code == 201
    job_id = create_resp.json()["id"]

    approve_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/approve",
        headers={"X-User-Role": "Admin"}
    )
    assert approve_resp.status_code == 200

    # Mock provisioning inside API router
    with patch("backend.services.restore.sandbox_service.RecoverySandboxService._run_docker_cmd") as mock_run, \
         patch("backend.services.restore.sandbox_service.RecoverySandboxService.wait_for_sandbox_readiness", return_value=(True, None)), \
         patch("backend.services.restore.sandbox_service.RecoverySandboxService.verify_sandbox_isolation", return_value={"all_isolation_checks_passed": True}):

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "123456abcdef\n"
        mock_run.return_value = mock_proc

        # 2. Provision Sandbox via POST /api/v1/recovery/jobs/{id}/sandbox
        prov_resp = client.post(
            f"/api/v1/recovery/jobs/{job_id}/sandbox",
            json={"cpu_limit": "2.0", "memory_limit": "2048m"},
            headers={"X-User-Role": "Operator"}
        )
        assert prov_resp.status_code == 201
        sbx_data = prov_resp.json()
        assert sbx_data["lifecycle_status"] == "HEALTHY"
        assert sbx_data["is_isolated"] is True

        # 3. Get Sandbox via GET /api/v1/recovery/jobs/{id}/sandbox
        get_resp = client.get(f"/api/v1/recovery/jobs/{job_id}/sandbox")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == sbx_data["id"]

        # 4. Quarantine Sandbox via POST /api/v1/recovery/jobs/{id}/sandbox/quarantine
        quar_resp = client.post(
            f"/api/v1/recovery/jobs/{job_id}/sandbox/quarantine",
            json={"reason": "Suspicious baseline deviation"},
            headers={"X-User-Role": "Operator"}
        )
        assert quar_resp.status_code == 200
        assert quar_resp.json()["lifecycle_status"] == "QUARANTINED"

        # 5. Non-admin cleanup forbidden (403)
        forbid_clean = client.post(
            f"/api/v1/recovery/jobs/{job_id}/sandbox/cleanup",
            headers={"X-User-Role": "Operator"}
        )
        assert forbid_clean.status_code == 403

        # 6. Admin Cleanup via POST /api/v1/recovery/jobs/{id}/sandbox/cleanup
        clean_resp = client.post(
            f"/api/v1/recovery/jobs/{job_id}/sandbox/cleanup",
            json={"authorized_by": "SecOps_Lead", "force": True},
            headers={"X-User-Role": "Admin"}
        )
        assert clean_resp.status_code == 200
        assert clean_resp.json()["lifecycle_status"] == "CLEANED"
