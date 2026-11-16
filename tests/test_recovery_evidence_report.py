"""
SQL-TRUST Unit & Integration Tests: Module 5 Phase 7
Evidence Management, Reporting & Final Audit
Tests multi-stage evidence harvesting, chain-of-custody tracking, canonical 17-section
report generation, Ed25519 digital signatures, tamper detection, and REST API.
"""
import os
import uuid
import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric import ed25519

from backend.main import app
from backend.database import SessionLocal
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
    RecoveryValidation,
    RecoveryFinding,
    RecoveryEvidenceItem,
    RecoveryChainOfCustody,
    RecoveryFinalReport
)
from backend.services.restore.job_service import RecoveryJobService
from backend.services.restore.report_service import RecoveryReportingService

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
def setup_report_candidate(db_session: Session):
    """Provisions a candidate with complete lifecycle data for reporting."""
    unique_suffix = uuid.uuid4().hex[:8]
    db_name = f"SQLTrust_ReportDB_{unique_suffix}"

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
        storage_object_key=f"backups/rep_{unique_suffix}.bak",
        sha256="f" * 64
    )
    db_session.add(rp)
    db_session.flush()

    assess = RecoveryAssessment(
        recovery_point_id=rp.id,
        assessment_name="Report Test Assessment",
        trust_classification="HIGH_CONFIDENCE",
        trust_score=98.0,
        confidence_rationale="Report test baseline"
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
        ranking_score=98.0,
        rank_rationale="Candidate for report test.",
        tradeoff_analysis="No incident overlap.",
        recommended_next_step="Generate final recovery report."
    )
    db_session.add(rec)
    db_session.commit()

    yield {
        "protected_db": prot_db,
        "recovery_point": rp,
        "recommendation": rec
    }

    # Teardown
    try:
        reports = db_session.query(RecoveryFinalReport).join(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for r in reports:
            db_session.delete(r)
        custodies = db_session.query(RecoveryChainOfCustody).join(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for c in custodies:
            db_session.delete(c)
        evidences = db_session.query(RecoveryEvidenceItem).join(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for e in evidences:
            db_session.delete(e)
        validations = db_session.query(RecoveryValidation).join(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for v in validations:
            db_session.query(RecoveryFinding).filter(RecoveryFinding.validation_id == v.id).delete()
            db_session.delete(v)
        plans = db_session.query(RestorePlan).join(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for p in plans:
            db_session.delete(p)
        sandboxes = db_session.query(RecoverySandbox).join(RecoveryJob).filter(RecoveryJob.candidate_id == rec.id).all()
        for s in sandboxes:
            db_session.delete(s)
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


def test_evidence_collection_and_chain_of_custody(db_session: Session, setup_report_candidate: dict):
    """Verifies that collect_job_evidence harvests items across stages and logs custody events."""
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=setup_report_candidate["recommendation"].id, requested_by="SecOps_Auditor")
    job_service.approve_job(job.id, approved_by="Admin")
    job.status = "VALIDATION_COMPLETED"

    # Add synthetic sandbox
    sandbox = RecoverySandbox(
        job_id=job.id, container_name=f"sbx-{job.id[:6]}", docker_network="net",
        data_volume="vd", log_volume="vl", staging_mount_path="/tmp",
        host_port=12701, sa_password_hash="hash", lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    db_session.flush()

    # Add synthetic staging record
    staging = BackupStagingRecord(
        job_id=job.id, recovery_point_id=setup_report_candidate["recovery_point"].id,
        sequence_order=1, backup_type="FULL",
        storage_object_key="backups/test.bak", staged_file_path="/tmp/test.bak",
        expected_sha256="f" * 64, computed_sha256="f" * 64, verification_status="VERIFIED"
    )
    db_session.add(staging)

    # Add synthetic validation
    validation = RecoveryValidation(
        job_id=job.id, sandbox_id=sandbox.id, target_database_name=job.target_database_name,
        dbcc_status="PASSED", dbcc_errors_count=0, overall_assessment="VALIDATED",
        assessment_rationale="Clean consistency check"
    )
    db_session.add(validation)
    db_session.commit()

    service = RecoveryReportingService(db_session)
    evidence_items = service.collect_job_evidence(job.id, actor="Forensic_Agent")

    assert len(evidence_items) >= 3
    categories = [e.evidence_category for e in evidence_items]
    assert "JOB_CREATION" in categories
    assert "BACKUP_STAGING" in categories
    assert "FINAL_VALIDATION" in categories

    db_session.refresh(job)
    assert job.status == "EVIDENCE_ARCHIVED"

    # Verify chain of custody logged
    custody_events = db_session.query(RecoveryChainOfCustody).filter(RecoveryChainOfCustody.job_id == job.id).all()
    assert len(custody_events) == len(evidence_items)
    assert all(c.action == "COLLECTED" for c in custody_events)

    # Cleanup
    for c in custody_events:
        db_session.delete(c)
    for e in evidence_items:
        db_session.delete(e)
    db_session.delete(validation)
    db_session.flush()
    db_session.delete(staging)
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_final_report_generation_and_ed25519_signature(db_session: Session, setup_report_candidate: dict):
    """
    Verifies that generate_final_report produces canonical JSON,
    generates a valid Ed25519 signature, and detects tampering.
    """
    job_service = RecoveryJobService(db_session)
    job, _ = job_service.create_job(candidate_id=setup_report_candidate["recommendation"].id, requested_by="SecOps_Auditor")
    job_service.approve_job(job.id, approved_by="Admin")
    job.status = "EVIDENCE_ARCHIVED"

    sandbox = RecoverySandbox(
        job_id=job.id, container_name=f"sbx-{job.id[:6]}", docker_network="net",
        data_volume="vd", log_volume="vl", staging_mount_path="/tmp",
        host_port=12702, sa_password_hash="hash", lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    db_session.flush()

    validation = RecoveryValidation(
        job_id=job.id, sandbox_id=sandbox.id, target_database_name=job.target_database_name,
        dbcc_status="PASSED", dbcc_errors_count=0, overall_assessment="VALIDATED",
        assessment_rationale="Validated clean recovery"
    )
    db_session.add(validation)
    db_session.commit()

    service = RecoveryReportingService(db_session)
    report = service.generate_final_report(job.id, actor="Compliance_Officer")

    assert report is not None
    assert report.overall_assessment == "VALIDATED"
    assert report.report_reference.startswith("REP-")
    assert report.signature is not None
    assert len(report.report_sha256) == 64

    # Cryptographic Verification of Ed25519 Signature
    signing_key = service._get_signing_key()
    verify_key = signing_key.public_key()
    signature_bytes = bytes.fromhex(report.signature)

    # Valid signature check: should not raise
    verify_key.verify(signature_bytes, report.report_json.encode("utf-8"))

    # Tamper check: modifying JSON payload must cause signature verification failure
    tampered_json = report.report_json + " "
    with pytest.raises(Exception):
        verify_key.verify(signature_bytes, tampered_json.encode("utf-8"))

    db_session.refresh(job)
    assert job.status == "REPORT_GENERATED"

    # Cleanup
    custodies = db_session.query(RecoveryChainOfCustody).filter(RecoveryChainOfCustody.job_id == job.id).all()
    for c in custodies:
        db_session.delete(c)
    evidences = db_session.query(RecoveryEvidenceItem).filter(RecoveryEvidenceItem.job_id == job.id).all()
    for e in evidences:
        db_session.delete(e)
    db_session.delete(report)
    db_session.delete(validation)
    db_session.flush()
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job.id).delete()
    db_session.delete(job)
    db_session.commit()


def test_reporting_rest_api_e2e(db_session: Session, setup_report_candidate: dict):
    """End-to-end REST API verification for evidence harvesting, custody, and report generation."""
    candidate_id = setup_report_candidate["recommendation"].id

    create_resp = client.post(
        "/api/v1/recovery/jobs",
        json={"candidate_id": candidate_id, "notes": "Reporting API Test"},
        headers={"X-User-Role": "Operator"}
    )
    assert create_resp.status_code == 201
    job_id = create_resp.json()["id"]

    approve_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/approve",
        headers={"X-User-Role": "Admin"}
    )
    assert approve_resp.status_code == 200

    job = db_session.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
    job.status = "VALIDATION_COMPLETED"

    sandbox = RecoverySandbox(
        job_id=job_id, container_name=f"sbx-{job_id[:6]}", docker_network="net",
        data_volume="vd", log_volume="vl", staging_mount_path="/tmp",
        host_port=12703, sa_password_hash="hash", lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    db_session.flush()

    validation = RecoveryValidation(
        job_id=job_id, sandbox_id=sandbox.id, target_database_name="ReportAPI_DB",
        dbcc_status="PASSED", dbcc_errors_count=0, overall_assessment="VALIDATED",
        assessment_rationale="API Validation Passed"
    )
    db_session.add(validation)
    db_session.commit()

    # 1. Collect Evidence via POST /api/v1/recovery/jobs/{id}/evidence/collect
    col_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/evidence/collect",
        headers={"X-User-Role": "Operator"}
    )
    assert col_resp.status_code == 200
    evidence_items = col_resp.json()
    assert len(evidence_items) >= 2

    # 2. Get Evidence Inventory via GET /api/v1/recovery/jobs/{id}/evidence
    inv_resp = client.get(f"/api/v1/recovery/jobs/{job_id}/evidence")
    assert inv_resp.status_code == 200
    assert len(inv_resp.json()) == len(evidence_items)

    # 3. Get Chain of Custody via GET /api/v1/recovery/jobs/{id}/evidence/custody
    cust_resp = client.get(f"/api/v1/recovery/jobs/{job_id}/evidence/custody")
    assert cust_resp.status_code == 200
    assert len(cust_resp.json()) >= 2

    # 4. Generate Final Report via POST /api/v1/recovery/jobs/{id}/report
    rep_resp = client.post(
        f"/api/v1/recovery/jobs/{job_id}/report",
        headers={"X-User-Role": "Admin"}
    )
    assert rep_resp.status_code == 200
    rep_data = rep_resp.json()
    assert rep_data["overall_assessment"] == "VALIDATED"
    assert rep_data["signature"] is not None

    # 5. Get Report via GET /api/v1/recovery/jobs/{id}/report
    get_rep_resp = client.get(f"/api/v1/recovery/jobs/{job_id}/report")
    assert get_rep_resp.status_code == 200
    assert get_rep_resp.json()["id"] == rep_data["id"]

    # Cleanup
    report = db_session.query(RecoveryFinalReport).filter(RecoveryFinalReport.job_id == job_id).first()
    if report:
        db_session.delete(report)
    custodies = db_session.query(RecoveryChainOfCustody).filter(RecoveryChainOfCustody.job_id == job_id).all()
    for c in custodies:
        db_session.delete(c)
    evidences = db_session.query(RecoveryEvidenceItem).filter(RecoveryEvidenceItem.job_id == job_id).all()
    for e in evidences:
        db_session.delete(e)
    db_session.delete(validation)
    db_session.flush()
    db_session.delete(sandbox)
    from backend.models.restore import RecoveryJobHistory
    db_session.query(RecoveryJobHistory).filter(RecoveryJobHistory.job_id == job_id).delete()
    db_session.delete(job)
    db_session.commit()
