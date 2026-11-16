"""
SQL-TRUST Unit & Integration Tests: Module 5 Phase 5
Restore Orchestration & Execution
Tests backup chain validation, restore plan generation (Full, Diff, Log STOPAT),
production target protection, sequential execution against sandbox, and REST API.
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
from backend.config import settings
from backend.models.backup import ProtectedDatabase
from backend.models.recovery import (
    RecoveryPoint,
    RecoveryAssessment,
    RecoveryEligibility,
    RecoveryRecommendation
)
from backend.models.restore import (
    RecoveryJob,
    RecoverySandbox,
    BackupStagingRecord,
    RestorePlan,
    RestoreOperation
)
from backend.services.restore.job_service import RecoveryJobService
from backend.services.restore.restore_service import (
    RestoreOrchestrationService,
    InvalidBackupChainError,
    RestoreExecutionError,
    ProductionTargetViolationError
)
from backend.services.restore.sandbox_service import RecoverySandboxService

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
def setup_restore_candidate(db_session: Session):
    """Provisions a candidate with staged Full, Diff, and Log backup records."""
    unique_suffix = uuid.uuid4().hex[:8]
    db_name = f"SQLTrust_RestoreDB_{unique_suffix}"

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
        storage_object_key=f"backups/restore_{unique_suffix}.bak",
        sha256="c" * 64
    )
    db_session.add(rp)
    db_session.flush()

    assess = RecoveryAssessment(
        recovery_point_id=rp.id,
        assessment_name="Restore Test Assessment",
        trust_classification="HIGH_CONFIDENCE",
        trust_score=95.0,
        confidence_rationale="Restore test baseline"
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
        rank_rationale="Candidate for restore test.",
        tradeoff_analysis="Clean lineage.",
        recommended_next_step="Generate restore plan."
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
        plans = db_session.query(RestorePlan).join(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for p in plans:
            db_session.query(RestoreOperation).filter(RestoreOperation.plan_id == p.id).delete()
            db_session.delete(p)
        db_session.flush()
        sandboxes = db_session.query(RecoverySandbox).join(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for s in sandboxes:
            db_session.delete(s)
        db_session.flush()
        jobs = db_session.query(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for j in jobs:
            db_session.query(BackupStagingRecord).filter(BackupStagingRecord.job_id == j.id).delete()
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


def test_missing_full_backup_rejection(db_session: Session, setup_restore_candidate: dict):
    """Verifies that backup chain validation fails if no FULL backup exists."""
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=setup_restore_candidate["recommendation"].id, requested_by="Tester")

    service = RestoreOrchestrationService(db_session)
    # No staging records created yet
    with pytest.raises(InvalidBackupChainError) as exc_info:
        service.validate_backup_chain(job.id)
    assert "no staged backup records" in str(exc_info.value).lower()

    # Teardown
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_restore_plan_generation_full_diff_log(db_session: Session, setup_restore_candidate: dict):
    """
    Verifies that generate_restore_plan creates an ordered plan:
    1. RESTORE_FULL WITH NORECOVERY, MOVE
    2. RESTORE_DIFF WITH NORECOVERY
    3. RESTORE_LOG WITH NORECOVERY, STOPAT
    4. RESTORE_RECOVERY
    """
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=setup_restore_candidate["recommendation"].id, requested_by="Tester")

    # Add synthetic sandbox
    sandbox = RecoverySandbox(
        job_id=job.id,
        container_name=f"test-sbx-{job.id[:6]}",
        docker_network="test-net",
        data_volume="test-vol-d",
        log_volume="test-vol-l",
        staging_mount_path="test-staging",
        host_port=12500,
        sa_password_hash="testhash",
        lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)

    # Add staged artifacts: Full, Diff, Log
    rp_id = setup_restore_candidate["recovery_point"].id
    full_rec = BackupStagingRecord(
        job_id=job.id, recovery_point_id=rp_id, sequence_order=1, backup_type="FULL",
        storage_object_key="backups/full.bak", staged_file_path="/tmp/full.bak",
        expected_sha256="c" * 64, verification_status="VERIFIED"
    )
    diff_rec = BackupStagingRecord(
        job_id=job.id, recovery_point_id=rp_id, sequence_order=2, backup_type="DIFFERENTIAL",
        storage_object_key="backups/diff.bak", staged_file_path="/tmp/diff.bak",
        expected_sha256="d" * 64, verification_status="VERIFIED"
    )
    log_rec = BackupStagingRecord(
        job_id=job.id, recovery_point_id=rp_id, sequence_order=3, backup_type="LOG",
        storage_object_key="backups/log1.trn", staged_file_path="/tmp/log1.trn",
        expected_sha256="e" * 64, verification_status="VERIFIED"
    )
    db_session.add_all([full_rec, diff_rec, log_rec])
    db_session.commit()

    service = RestoreOrchestrationService(db_session)
    stopat_time = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
    plan = service.generate_restore_plan(job.id, target_stopat_utc=stopat_time)

    assert plan is not None
    assert plan.total_operations == 4  # Full + Diff + Log + Recovery

    ops = db_session.query(RestoreOperation).filter(RestoreOperation.plan_id == plan.id).order_by(RestoreOperation.sequence_number.asc()).all()
    assert len(ops) == 4
    assert ops[0].operation_type == "RESTORE_FULL"
    assert "WITH NORECOVERY" in ops[0].t_sql_command
    assert "MOVE" in ops[0].t_sql_command

    assert ops[1].operation_type == "RESTORE_DIFF"
    assert "WITH NORECOVERY" in ops[1].t_sql_command

    assert ops[2].operation_type == "RESTORE_LOG"
    assert "WITH NORECOVERY" in ops[2].t_sql_command
    assert "STOPAT = N'2026-11-14T12:00:00'" in ops[2].t_sql_command

    assert ops[3].operation_type == "RESTORE_RECOVERY"
    assert "WITH RECOVERY" in ops[3].t_sql_command

    # Teardown
    for o in ops:
        db_session.delete(o)
    db_session.delete(plan)
    db_session.flush()
    db_session.delete(full_rec)
    db_session.delete(diff_rec)
    db_session.delete(log_rec)
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_production_port_protection(db_session: Session, setup_restore_candidate: dict):
    """Verifies that attempting to connect to host SQL Server port raises ProductionTargetViolationError."""
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=setup_restore_candidate["recommendation"].id, requested_by="Tester")

    # Sandbox pointing illegally to host port
    sandbox = RecoverySandbox(
        job_id=job.id,
        container_name=f"illegal-sbx-{job.id[:6]}",
        docker_network="test-net",
        data_volume="test-vol-d",
        log_volume="test-vol-l",
        staging_mount_path="test-staging",
        host_port=settings.SQL_PORT or 1764,  # Host port!
        sa_password_hash="testhash",
        lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    db_session.commit()

    service = RestoreOrchestrationService(db_session)
    with pytest.raises(ProductionTargetViolationError):
        service.get_sandbox_connection(sandbox)

    # Teardown
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_restore_execution_workflow_mocked(db_session: Session, setup_restore_candidate: dict):
    """
    Verifies execution workflow:
    - Transitions job state from ENVIRONMENT_CREATED -> RESTORE_IN_PROGRESS -> RESTORE_COMPLETED
    - Validates target database state is ONLINE
    """
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=setup_restore_candidate["recommendation"].id, requested_by="Tester")
    job_service.approve_job(job.id, approved_by="Admin_Lead")
    job.status = "ENVIRONMENT_CREATED"
    db_session.commit()

    sandbox = RecoverySandbox(
        job_id=job.id,
        container_name=f"test-sbx-{job.id[:6]}",
        docker_network="test-net",
        data_volume="test-vol-d",
        log_volume="test-vol-l",
        staging_mount_path="test-staging",
        host_port=12501,
        sa_password_hash="testhash",
        lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    RecoverySandboxService.set_cached_password(job.id, "TestPassword123!")

    full_rec = BackupStagingRecord(
        job_id=job.id, recovery_point_id=setup_restore_candidate["recovery_point"].id,
        sequence_order=1, backup_type="FULL",
        storage_object_key="backups/full.bak", staged_file_path="/tmp/full.bak",
        expected_sha256="c" * 64, verification_status="VERIFIED"
    )
    db_session.add(full_rec)
    db_session.commit()

    service = RestoreOrchestrationService(db_session)
    plan = service.generate_restore_plan(job.id)

    # Mock pyodbc connection
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = ("ONLINE",)
    mock_cursor.nextset.return_value = False
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    with patch.object(service, "get_sandbox_connection", return_value=mock_conn):
        result = service.execute_restore_plan(job.id)
        assert result["success"] is True
        assert result["database_state"] == "ONLINE"

        db_session.refresh(job)
        assert job.status == "RESTORE_COMPLETED"

        db_session.refresh(plan)
        assert plan.status == "COMPLETED"

    # Teardown
    RecoverySandboxService.clear_cached_password(job.id)
    ops = db_session.query(RestoreOperation).filter(RestoreOperation.plan_id == plan.id).all()
    for o in ops:
        db_session.delete(o)
    db_session.delete(plan)
    db_session.flush()
    db_session.delete(full_rec)
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_restore_rest_api_e2e(db_session: Session, setup_restore_candidate: dict):
    """End-to-end REST API test for restore planning, inspection, and execution."""
    candidate_id = setup_restore_candidate["recommendation"].id

    create_resp = client.post(
        "/api/v1/recovery/jobs",
        json={"candidate_id": candidate_id, "notes": "Restore API Test"},
        headers={"X-User-Role": "Operator"}
    )
    assert create_resp.status_code == 201
    job_id = create_resp.json()["id"]

    approve_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/approve",
        headers={"X-User-Role": "Admin"}
    )
    assert approve_resp.status_code == 200

    # Provision synthetic sandbox & staging record
    sandbox = RecoverySandbox(
        job_id=job_id, container_name=f"api-sbx-{job_id[:6]}", docker_network="net",
        data_volume="vd", log_volume="vl", staging_mount_path="/tmp",
        host_port=12502, sa_password_hash="hash", lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    RecoverySandboxService.set_cached_password(job_id, "ApiPwd123!")

    full_rec = BackupStagingRecord(
        job_id=job_id, recovery_point_id=setup_restore_candidate["recovery_point"].id,
        sequence_order=1, backup_type="FULL",
        storage_object_key="backups/full.bak", staged_file_path="/tmp/full.bak",
        expected_sha256="c" * 64, verification_status="VERIFIED"
    )
    db_session.add(full_rec)
    job = db_session.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
    job.status = "ENVIRONMENT_CREATED"
    db_session.commit()

    # 1. Create Restore Plan via POST /api/v1/recovery/jobs/{id}/restore/plan
    plan_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/restore/plan",
        json={"target_database_name": "SQLTrust_TestRestored"},
        headers={"X-User-Role": "Operator"}
    )
    assert plan_resp.status_code == 201
    plan_data = plan_resp.json()
    assert plan_data["target_database_name"] == "SQLTrust_TestRestored"
    assert len(plan_data["operations"]) == 2  # Full + Recovery

    # 2. Get Plan via GET /api/v1/recovery/jobs/{id}/restore/plan
    get_plan_resp = client.get(f"/api/v1/recovery/jobs/{job_id}/restore/plan")
    assert get_plan_resp.status_code == 200
    assert get_plan_resp.json()["id"] == plan_data["id"]

    # 3. Execute Plan via POST /api/v1/recovery/jobs/{id}/restore/execute
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = ("ONLINE",)
    mock_cursor.nextset.return_value = False
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    with patch("backend.services.restore.restore_service.RestoreOrchestrationService.get_sandbox_connection", return_value=mock_conn):
        exec_resp = client.post(
            f"/api/v1/recovery/jobs/{job_id}/restore/execute",
            headers={"X-User-Role": "Operator"}
        )
        assert exec_resp.status_code == 200
        exec_data = exec_resp.json()
        assert exec_data["status"] == "COMPLETED"
        assert exec_data["operations_completed"] == 2

    # 4. Get Status via GET /api/v1/recovery/jobs/{id}/restore/status
    status_resp = client.get(f"/api/v1/recovery/jobs/{job_id}/restore/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "COMPLETED"

    # Cleanup
    RecoverySandboxService.clear_cached_password(job_id)
    plan = db_session.query(RestorePlan).filter(RestorePlan.job_id == job_id).first()
    if plan:
        db_session.query(RestoreOperation).filter(RestoreOperation.plan_id == plan.id).delete()
        db_session.delete(plan)
        db_session.flush()
    db_session.delete(full_rec)
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job_id).delete()
    db_session.delete(job)
    db_session.commit()
