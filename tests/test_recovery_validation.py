"""
SQL-TRUST Unit & Integration Tests: Module 5 Phase 6
Recovery Validation & Forensic Analysis Engine
Tests DBCC CHECKDB consistency validation, security inspection, Module 3 baseline comparison,
and the 4-tier assessment outcomes: VALIDATED, FAILED, INCONCLUSIVE, REQUIRES_INVESTIGATION.
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
from backend.models.forensics import ForensicBaseline, ForensicBaselineItem
from backend.models.recovery import (
    RecoveryPoint,
    RecoveryAssessment,
    RecoveryEligibility,
    RecoveryRecommendation
)
from backend.models.restore import (
    RecoveryJob,
    RecoverySandbox,
    RecoveryValidation,
    RecoveryFinding
)
from backend.services.restore.job_service import RecoveryJobService
from backend.services.restore.validation_service import RecoveryValidationService

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
def setup_validation_candidate(db_session: Session):
    """Provisions a candidate and a synthetic baseline for validation testing."""
    unique_suffix = uuid.uuid4().hex[:8]
    db_name = f"SQLTrust_ValDB_{unique_suffix}"

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
        storage_object_key=f"backups/val_{unique_suffix}.bak",
        sha256="d" * 64
    )
    db_session.add(rp)
    db_session.flush()

    assess = RecoveryAssessment(
        recovery_point_id=rp.id,
        assessment_name="Validation Assessment",
        trust_classification="HIGH_CONFIDENCE",
        trust_score=95.0,
        confidence_rationale="Validation test baseline"
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
        rank_rationale="Validation test candidate.",
        tradeoff_analysis="Clean lineage.",
        recommended_next_step="Execute validation."
    )
    db_session.add(rec)
    db_session.commit()

    # Create Module 3 baseline for this DB
    baseline = ForensicBaseline(
        database_id=prot_db.id,
        server_name="localhost\\SQLEXPRESS",
        database_name=db_name,
        baseline_name=f"Baseline_{unique_suffix}",
        status="COMPLETED",
        sha256_manifest="e" * 64
    )
    db_session.add(baseline)
    db_session.flush()

    item = ForensicBaselineItem(
        baseline_id=baseline.id,
        item_type="TABLE",
        item_name="Customers",
        properties_json="{}"
    )
    db_session.add(item)
    db_session.commit()

    yield {
        "protected_db": prot_db,
        "recovery_point": rp,
        "recommendation": rec,
        "baseline": baseline
    }

    # Teardown
    try:
        validations = db_session.query(RecoveryValidation).join(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for v in validations:
            db_session.query(RecoveryFinding).filter(RecoveryFinding.validation_id == v.id).delete()
            db_session.delete(v)
        sandboxes = db_session.query(RecoverySandbox).join(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for s in sandboxes:
            db_session.delete(s)
        jobs = db_session.query(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for j in jobs:
            from backend.models.restore import RecoveryJobHistory
            db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == j.id).delete()
            db_session.delete(j)
        db_session.commit()

        db_session.delete(item)
        db_session.delete(baseline)
        db_session.delete(rec)
        db_session.delete(elig)
        db_session.delete(assess)
        db_session.delete(rp)
        db_session.delete(prot_db)
        db_session.commit()
    except Exception:
        db_session.rollback()


def test_validation_outcome_validated(db_session: Session, setup_validation_candidate: dict):
    """Verifies that clean DBCC, zero findings, and matching baseline produces VALIDATED."""
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=setup_validation_candidate["recommendation"].id, requested_by="Auditor")
    job_service.approve_job(job.id, approved_by="Admin")
    job.status = "RESTORE_COMPLETED"

    sandbox = RecoverySandbox(
        job_id=job.id, container_name=f"val-sbx-{job.id[:6]}", docker_network="net",
        data_volume="vd", log_volume="vl", staging_mount_path="/tmp",
        host_port=12601, sa_password_hash="hash", lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    db_session.commit()

    service = RecoveryValidationService(db_session)

    # Mock DBCC passed, security passed
    with patch.object(service, "run_dbcc_checkdb", return_value=("PASSED", 0, [])), \
         patch.object(service, "inspect_security_principals", return_value=([], [])):

        val = service.evaluate_validation(job.id, baseline_id=setup_validation_candidate["baseline"].id)
        assert val.overall_assessment == "VALIDATED"
        assert val.dbcc_status == "PASSED"
        assert val.dbcc_errors_count == 0

        db_session.refresh(job)
        assert job.status == "VALIDATION_COMPLETED"

    # Cleanup
    db_session.query(RecoveryFinding).filter(RecoveryFinding.validation_id == val.id).delete()
    db_session.delete(val)
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_validation_outcome_failed_on_dbcc(db_session: Session, setup_validation_candidate: dict):
    """Verifies that DBCC CHECKDB error strictly produces FAILED outcome."""
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=setup_validation_candidate["recommendation"].id, requested_by="Auditor")
    job_service.approve_job(job.id, approved_by="Admin")
    job.status = "RESTORE_COMPLETED"

    sandbox = RecoverySandbox(
        job_id=job.id, container_name=f"val-sbx-{job.id[:6]}", docker_network="net",
        data_volume="vd", log_volume="vl", staging_mount_path="/tmp",
        host_port=12602, sa_password_hash="hash", lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    db_session.commit()

    service = RecoveryValidationService(db_session)

    # Mock DBCC failure
    mock_dbcc_errors = [{"error_number": 8938, "severity": 16, "message": "Corrupt allocation page detected in PFS"}]
    with patch.object(service, "run_dbcc_checkdb", return_value=("FAILED", 1, mock_dbcc_errors)), \
         patch.object(service, "inspect_security_principals", return_value=([], [])):

        val = service.evaluate_validation(job.id, baseline_id=setup_validation_candidate["baseline"].id)
        assert val.overall_assessment == "FAILED"
        assert val.dbcc_status == "FAILED"
        assert val.dbcc_errors_count == 1
        assert "allocation errors" in val.assessment_rationale

    # Cleanup
    db_session.query(RecoveryFinding).filter(RecoveryFinding.validation_id == val.id).delete()
    db_session.delete(val)
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_validation_outcome_requires_investigation(db_session: Session, setup_validation_candidate: dict):
    """Verifies that security findings (unexpected db_owner / persistence trigger) produce REQUIRES_INVESTIGATION."""
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=setup_validation_candidate["recommendation"].id, requested_by="Auditor")
    job_service.approve_job(job.id, approved_by="Admin")
    job.status = "RESTORE_COMPLETED"

    sandbox = RecoverySandbox(
        job_id=job.id, container_name=f"val-sbx-{job.id[:6]}", docker_network="net",
        data_volume="vd", log_volume="vl", staging_mount_path="/tmp",
        host_port=12603, sa_password_hash="hash", lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    db_session.commit()

    service = RecoveryValidationService(db_session)

    suspicious_findings = [{
        "category": "PRINCIPAL",
        "severity": "HIGH",
        "finding_type": "UNEXPECTED_DB_OWNER",
        "entity_name": "attacker_svc",
        "description": "User 'attacker_svc' holds privileged role 'db_owner'."
    }]

    with patch.object(service, "run_dbcc_checkdb", return_value=("PASSED", 0, [])), \
         patch.object(service, "inspect_security_principals", return_value=([], suspicious_findings)):

        val = service.evaluate_validation(job.id, baseline_id=setup_validation_candidate["baseline"].id)
        assert val.overall_assessment == "REQUIRES_INVESTIGATION"
        assert "require human review" in val.assessment_rationale

    # Cleanup
    db_session.query(RecoveryFinding).filter(RecoveryFinding.validation_id == val.id).delete()
    db_session.delete(val)
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_validation_outcome_inconclusive_missing_baseline(db_session: Session, setup_validation_candidate: dict):
    """Verifies that clean DBCC but missing Module 3 baseline produces INCONCLUSIVE."""
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=setup_validation_candidate["recommendation"].id, requested_by="Auditor")
    job_service.approve_job(job.id, approved_by="Admin")
    job.status = "RESTORE_COMPLETED"

    sandbox = RecoverySandbox(
        job_id=job.id, container_name=f"val-sbx-{job.id[:6]}", docker_network="net",
        data_volume="vd", log_volume="vl", staging_mount_path="/tmp",
        host_port=12604, sa_password_hash="hash", lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    db_session.commit()

    service = RecoveryValidationService(db_session)

    with patch.object(service, "run_dbcc_checkdb", return_value=("PASSED", 0, [])), \
         patch.object(service, "inspect_security_principals", return_value=([], [])), \
         patch.object(service, "compare_against_baseline", return_value=("NO_BASELINE", [], None)):

        val = service.evaluate_validation(job.id)
        assert val.overall_assessment == "INCONCLUSIVE"
        assert "no Module 3 forensic baseline exists" in val.assessment_rationale

    # Cleanup
    db_session.query(RecoveryFinding).filter(RecoveryFinding.validation_id == val.id).delete()
    db_session.delete(val)
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_validation_rest_api_e2e(db_session: Session, setup_validation_candidate: dict):
    """End-to-end REST API verification for validation trigger, summary, and findings."""
    candidate_id = setup_validation_candidate["recommendation"].id

    create_resp = client.post(
        "/api/v1/recovery/jobs",
        json={"candidate_id": candidate_id, "notes": "Validation API Test"},
        headers={"X-User-Role": "Operator"}
    )
    assert create_resp.status_code == 201
    job_id = create_resp.json()["id"]

    approve_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/approve",
        headers={"X-User-Role": "Admin"}
    )
    assert approve_resp.status_code == 200

    sandbox = RecoverySandbox(
        job_id=job_id, container_name=f"api-val-sbx-{job_id[:6]}", docker_network="net",
        data_volume="vd", log_volume="vl", staging_mount_path="/tmp",
        host_port=12605, sa_password_hash="hash", lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    job = db_session.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
    job.status = "RESTORE_COMPLETED"
    db_session.commit()

    with patch("backend.services.restore.validation_service.RecoveryValidationService.run_dbcc_checkdb", return_value=("PASSED", 0, [])), \
         patch("backend.services.restore.validation_service.RecoveryValidationService.inspect_security_principals", return_value=([], [])), \
         patch("backend.services.restore.validation_service.RecoveryValidationService.compare_against_baseline", return_value=("MATCHED", [], setup_validation_candidate["baseline"])):

        # 1. Trigger Validation via POST /api/v1/recovery/jobs/{id}/validation
        val_resp = client.post(
            f"/api/v1/recovery/jobs/{job_id}/validation",
            headers={"X-User-Role": "Operator"}
        )
        assert val_resp.status_code == 200
        val_data = val_resp.json()
        assert val_data["overall_assessment"] == "VALIDATED"
        assert val_data["dbcc_status"] == "PASSED"

        # 2. Get Summary via GET /api/v1/recovery/jobs/{id}/validation
        get_val_resp = client.get(f"/api/v1/recovery/jobs/{job_id}/validation")
        assert get_val_resp.status_code == 200
        assert get_val_resp.json()["id"] == val_data["id"]

        # 3. Get Findings via GET /api/v1/recovery/jobs/{id}/validation/findings
        findings_resp = client.get(f"/api/v1/recovery/jobs/{job_id}/validation/findings")
        assert findings_resp.status_code == 200
        assert isinstance(findings_resp.json(), list)

    # Cleanup
    val = db_session.query(RecoveryValidation).filter(RecoveryValidation.job_id == job_id).first()
    if val:
        db_session.query(RecoveryFinding).filter(RecoveryFinding.validation_id == val.id).delete()
        db_session.delete(val)
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job_id).delete()
    db_session.delete(job)
    db_session.commit()
