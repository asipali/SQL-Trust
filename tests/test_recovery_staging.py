"""
SQL-TRUST Unit & Integration Tests: Module 5 Phase 3
Backup Staging and Verification
Tests read-only S3 identity, storage preflight checks, multi-layer path containment,
chunked streaming SHA-256 verification, integrity mismatch quarantine, retry mechanics,
and REST API endpoints.
"""
import os
import uuid
import shutil
import hashlib
import tempfile
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.database import SessionLocal
from backend.config import settings
from backend.models.backup import ProtectedDatabase, BackupRecord
from backend.models.recovery import (
    RecoveryPoint,
    RecoveryChain,
    RecoveryChainSegment,
    RecoveryAssessment,
    RecoveryEligibility,
    RecoveryRecommendation
)
from backend.models.restore import RecoveryJob, BackupStagingRecord
from backend.services.restore.job_service import RecoveryJobService
from backend.services.restore.staging_service import (
    RecoveryStagingService,
    InsufficientStorageError,
    PathTraversalAttackError,
    IntegrityMismatchError,
    StagingError
)

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
def staging_temp_dir():
    """Creates an isolated temporary staging directory for test fixtures."""
    temp_dir = tempfile.mkdtemp(prefix="sqltrust_test_staging_")
    yield temp_dir
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass


@pytest.fixture(scope="module")
def setup_staging_candidate(db_session: Session):
    """
    Provisions a synthetic candidate with a genuine local mock backup file
    and valid SHA-256 for staging and verification tests.
    """
    unique_suffix = uuid.uuid4().hex[:8]
    db_name = f"SQLTrust_StagingDB_{unique_suffix}"

    # Create dummy backup file in BACKUP_LOCAL_DIR
    os.makedirs(settings.BACKUP_LOCAL_DIR, exist_ok=True)
    mock_filename = f"SQLTrust_StagingMock_{unique_suffix}.bak"
    mock_path = os.path.join(settings.BACKUP_LOCAL_DIR, mock_filename)
    mock_content = f"SQL Server Backup Header Mock Payload {unique_suffix} - Safe Cyber Recovery".encode("utf-8")
    with open(mock_path, "wb") as f:
        f.write(mock_content)

    mock_sha256 = hashlib.sha256(mock_content).hexdigest().lower()
    mock_size = len(mock_content)

    prot_db = ProtectedDatabase(
        database_name=db_name,
        server_name="localhost\\SQLEXPRESS",
        database_identifier=f"db_{unique_suffix}"
    )
    db_session.add(prot_db)
    db_session.flush()

    brec = BackupRecord(
        database_id=prot_db.id,
        backup_type="FULL",
        backup_filename=mock_filename,
        backup_path=mock_path,
        backup_size_bytes=mock_size,
        sha256=mock_sha256,
        sql_verification_status="PASSED",
        storage_upload_status="COMPLETED",
        storage_object_key=f"backups/{mock_filename}"
    )
    db_session.add(brec)
    db_session.flush()

    rp = RecoveryPoint(
        database_id=prot_db.id,
        backup_id=brec.id,
        server_name="localhost\\SQLEXPRESS",
        database_name=db_name,
        recovery_point_time=datetime.now(timezone.utc),
        recovery_point_type="FULL",
        integrity_status="VERIFIED",
        storage_object_key=f"backups/{mock_filename}",
        sha256=mock_sha256
    )
    db_session.add(rp)
    db_session.flush()

    assess = RecoveryAssessment(
        recovery_point_id=rp.id,
        assessment_name="Staging Test Assessment",
        trust_classification="HIGH_CONFIDENCE",
        trust_score=90.0,
        confidence_rationale="Synthetic assessment for staging test"
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
        ranking_score=90.0,
        rank_rationale="Clean candidate for staging test.",
        tradeoff_analysis="No incident overlap.",
        recommended_next_step="Proceed with staging."
    )
    db_session.add(rec)
    db_session.commit()

    yield {
        "protected_db": prot_db,
        "backup_record": brec,
        "recovery_point": rp,
        "assessment": assess,
        "eligibility": elig,
        "recommendation": rec,
        "mock_path": mock_path,
        "mock_sha256": mock_sha256,
        "mock_filename": mock_filename
    }

    # Teardown
    try:
        # Delete staging records and jobs
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
        db_session.delete(brec)
        db_session.delete(prot_db)
        db_session.commit()
    except Exception:
        db_session.rollback()

    if os.path.exists(mock_path):
        try:
            os.remove(mock_path)
        except Exception:
            pass


def test_read_only_credentials_configuration():
    """Verifies that the recovery staging client uses the dedicated read-only identity."""
    assert settings.SEAWEEDFS_RECOVERY_ACCESS_KEY == "sqltrust_recovery_reader"
    assert settings.SEAWEEDFS_RECOVERY_SECRET_KEY == "sqltrust_reader_secret_key"
    assert settings.effective_recovery_s3_access_key == "sqltrust_recovery_reader"
    assert settings.effective_recovery_s3_secret_key == "sqltrust_reader_secret_key"


def test_storage_capacity_check_pass(db_session: Session, staging_temp_dir: str):
    """Verifies that preflight check succeeds when available disk space is adequate."""
    service = RecoveryStagingService(db_session, staging_dir=staging_temp_dir)
    # Requesting 10 MB should comfortably pass
    assert service.check_storage_capacity(10 * 1024 * 1024) is True


def test_storage_capacity_check_fail(db_session: Session, staging_temp_dir: str):
    """Verifies that preflight check raises InsufficientStorageError when space is inadequate."""
    service = RecoveryStagingService(db_session, staging_dir=staging_temp_dir)
    # Requesting 1,000,000 TB should raise InsufficientStorageError
    with pytest.raises(InsufficientStorageError) as exc_info:
        service.check_storage_capacity(1_000_000 * 1024 * 1024 * 1024 * 1024)
    assert "insufficient disk space" in str(exc_info.value).lower()


def test_path_traversal_attack_prevention(db_session: Session, staging_temp_dir: str):
    """Verifies that directory traversal vectors are strictly caught and rejected."""
    service = RecoveryStagingService(db_session, staging_dir=staging_temp_dir)
    job_id = str(uuid.uuid4())

    malicious_vectors = [
        "../../etc/passwd",
        r"..\..\windows\system32\cmd.exe",
        "/etc/shadow",
        r"C:\Windows\System32\config\SAM",
        "nested/../../escape.bak",
        "backup.bak:alternate_stream",
        "backup;rm -rf /",
        "../job_other/stolen.bak",
        ""
    ]

    for vec in malicious_vectors:
        with pytest.raises(PathTraversalAttackError):
            service.sanitize_and_resolve_staging_path(job_id, vec)


def test_safe_path_containment(db_session: Session, staging_temp_dir: str):
    """Verifies that safe filenames resolve within the dedicated job subfolder."""
    service = RecoveryStagingService(db_session, staging_dir=staging_temp_dir)
    job_id = str(uuid.uuid4())
    safe_name = "SQLTrust_Full_20261114_000000.bak"

    resolved = service.sanitize_and_resolve_staging_path(job_id, safe_name)
    assert resolved.endswith(safe_name)
    assert job_id in resolved
    assert os.path.commonpath([staging_temp_dir, resolved]) == os.path.realpath(staging_temp_dir)


def test_download_and_verify_artifact_success(db_session: Session, staging_temp_dir: str, setup_staging_candidate: dict):
    """Verifies that a valid backup artifact is staged and verified with matched SHA-256."""
    candidate_id = setup_staging_candidate["recommendation"].id
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=candidate_id, requested_by="Staging_Tester")

    service = RecoveryStagingService(db_session, staging_dir=staging_temp_dir)
    safe_dest = service.sanitize_and_resolve_staging_path(job.id, setup_staging_candidate["mock_filename"])

    record = BackupStagingRecord(
        job_id=job.id,
        recovery_point_id=setup_staging_candidate["recovery_point"].id,
        sequence_order=1,
        backup_type="FULL",
        storage_object_key=f"backups/{setup_staging_candidate['mock_filename']}",
        staged_file_path=safe_dest,
        expected_sha256=setup_staging_candidate["mock_sha256"],
        verification_status="PENDING"
    )
    db_session.add(record)
    db_session.commit()

    verified_record = service.download_and_verify_artifact(record)
    assert verified_record.verification_status == "VERIFIED"
    assert verified_record.computed_sha256 == setup_staging_candidate["mock_sha256"]
    assert verified_record.verified_at is not None
    assert os.path.isfile(verified_record.staged_file_path)

    # Cleanup staging record
    db_session.delete(record)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_download_and_verify_sha256_mismatch(db_session: Session, staging_temp_dir: str, setup_staging_candidate: dict):
    """Verifies that a corrupted or mismatched artifact is caught and marked MISMATCH."""
    candidate_id = setup_staging_candidate["recommendation"].id
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=candidate_id, requested_by="Staging_Tester")

    service = RecoveryStagingService(db_session, staging_dir=staging_temp_dir)
    safe_dest = service.sanitize_and_resolve_staging_path(job.id, setup_staging_candidate["mock_filename"])

    record = BackupStagingRecord(
        job_id=job.id,
        recovery_point_id=setup_staging_candidate["recovery_point"].id,
        sequence_order=1,
        backup_type="FULL",
        storage_object_key=f"backups/{setup_staging_candidate['mock_filename']}",
        staged_file_path=safe_dest,
        expected_sha256="0" * 64,  # Intentional invalid hash
        verification_status="PENDING"
    )
    db_session.add(record)
    db_session.commit()

    with pytest.raises(IntegrityMismatchError):
        service.download_and_verify_artifact(record)

    db_session.refresh(record)
    assert record.verification_status == "MISMATCH"
    assert "Cryptographic SHA-256 mismatch" in record.error_message
    # Verify temporary partial file was cleaned up
    assert not os.path.exists(f"{safe_dest}.part")

    # Cleanup
    db_session.delete(record)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_job_staging_lifecycle_success(db_session: Session, staging_temp_dir: str, setup_staging_candidate: dict):
    """
    Verifies the complete job staging workflow:
    REQUESTED -> (Admin Approve) -> PREFLIGHT -> (Staging) -> BACKUP_STAGING -> BACKUP_VERIFIED.
    """
    candidate_id = setup_staging_candidate["recommendation"].id
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=candidate_id, requested_by="Analyst_Staging")
    job_service.approve_job(job_id=job.id, approved_by="SecOps_Lead", approver_notes="Approved for staging test")

    service = RecoveryStagingService(db_session, staging_dir=staging_temp_dir)
    staged_records = service.stage_job_backups(job_id=job.id)

    db_session.refresh(job)
    assert job.status == "BACKUP_VERIFIED"
    assert len(staged_records) == 1
    assert staged_records[0].verification_status == "VERIFIED"

    # Verify history chain: REQUESTED -> PREFLIGHT -> BACKUP_STAGING -> BACKUP_VERIFIED
    history = job_service.get_job_history(job.id)
    states = [h.to_state for h in history]
    assert "REQUESTED" in states
    assert "PREFLIGHT" in states
    assert "BACKUP_STAGING" in states
    assert "BACKUP_VERIFIED" in states

    # Teardown job
    for r in staged_records:
        db_session.delete(r)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_job_staging_lifecycle_mismatch_failure(db_session: Session, staging_temp_dir: str, setup_staging_candidate: dict):
    """Verifies that an integrity mismatch transitions the recovery job to FAILED (INTEGRITY_MISMATCH)."""
    rp = setup_staging_candidate["recovery_point"]
    orig_sha = rp.sha256
    rp.sha256 = "f" * 64  # Corrupt expected SHA
    db_session.commit()

    candidate_id = setup_staging_candidate["recommendation"].id
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=candidate_id, requested_by="Analyst_Staging")
    job_service.approve_job(job_id=job.id, approved_by="SecOps_Lead", approver_notes="Approved for staging test")

    service = RecoveryStagingService(db_session, staging_dir=staging_temp_dir)
    try:
        with pytest.raises(IntegrityMismatchError):
            service.stage_job_backups(job_id=job.id)

        db_session.refresh(job)
        assert job.status == "FAILED"
        assert job.failure_code == "INTEGRITY_MISMATCH"
        assert "failed integrity check" in job.failure_reason
    finally:
        rp.sha256 = orig_sha
        db_session.commit()

        # Teardown
        db_session.query(BackupStagingRecord).filter(BackupStagingRecord.job_id == job.id).delete()
        from backend.models.restore import RecoveryJobHistory
        db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
        db_session.delete(job)
        db_session.commit()


def test_staging_rest_api_e2e(setup_staging_candidate: dict):
    """End-to-end API test for staging endpoints: initiate, status, get record, and retry."""
    candidate_id = setup_staging_candidate["recommendation"].id

    # 1. Create Job via POST /api/v1/recovery/jobs
    create_resp = client.post(
        "/api/v1/recovery/jobs",
        json={"candidate_id": candidate_id, "notes": "API Staging Test"},
        headers={"X-User-Role": "Operator"}
    )
    assert create_resp.status_code == 201
    job_id = create_resp.json()["id"]

    # 2. Approve Job via POST /api/v1/recovery/jobs/{id}/approve
    approve_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/approve",
        headers={"X-User-Role": "Admin"}
    )
    assert approve_resp.status_code == 200

    # 3. Initiate Staging via POST /api/v1/recovery/jobs/{id}/staging
    stage_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/staging",
        headers={"X-User-Role": "Operator"}
    )
    assert stage_resp.status_code == 200
    staged_items = stage_resp.json()
    assert len(staged_items) == 1
    record_id = staged_items[0]["id"]
    assert staged_items[0]["verification_status"] == "VERIFIED"

    # 4. Query Staging Status via GET /api/v1/recovery/jobs/{id}/staging
    status_resp = client.get(f"/api/v1/recovery/jobs/{job_id}/staging")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["overall_status"] == "VERIFIED"
    assert status_data["verified_count"] == 1

    # 5. Query Specific Artifact via GET /api/v1/recovery/jobs/{id}/staging/{record_id}
    artifact_resp = client.get(f"/api/v1/recovery/jobs/{job_id}/staging/{record_id}")
    assert artifact_resp.status_code == 200
    assert artifact_resp.json()["id"] == record_id

    # 6. Retry Artifact via POST /api/v1/recovery/jobs/{id}/staging/{record_id}/retry
    retry_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/staging/{record_id}/retry",
        headers={"X-User-Role": "Operator"}
    )
    assert retry_resp.status_code == 200
    assert retry_resp.json()["verification_status"] == "VERIFIED"
