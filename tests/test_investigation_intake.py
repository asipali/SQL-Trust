"""
SQL-TRUST Unit & Integration Tests: Module 6 Phase 3
Incident Intake and Classification
Tests automated intake triggers (Module 2 Alerts, Module 3 Drift Findings,
Module 4 Recovery Risks, Module 5 Validation Failures), 30-minute temporal clustering,
MITRE ATT&CK Enterprise taxonomy mapping, and multi-factor severity scoring.
"""
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.database import SessionLocal
from backend.models.backup import ProtectedDatabase
from backend.models.security import SecurityAlert, DetectionRule, SecuritySource
from backend.models.forensics import ForensicFinding, ForensicInvestigation, ForensicBaseline
from backend.models.recovery import (
    RecoveryPoint,
    RecoveryAssessment,
    RecoveryEligibility,
    RecoveryRecommendation
)
from backend.models.restore import RecoveryJob, RecoveryValidation, RecoverySandbox
from backend.models.investigation import (
    InvestigationCase,
    CaseEvidenceLink,
    CaseMitreTechnique,
    CaseAuditLog
)
from backend.services.investigation.intake_service import IncidentIntakeService
from backend.services.investigation.classification_engine import ClassificationEngine

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
def setup_test_context(db_session: Session):
    """Provisions isolated test environment with ProtectedDatabase, SecuritySource, and DetectionRules."""
    suffix = uuid.uuid4().hex[:8]
    db_name = f"SQLTrust_IntakeTest_{suffix}"
    prot_db = ProtectedDatabase(
        database_name=db_name,
        server_name="localhost\\SQLEXPRESS",
        database_identifier=f"intake_{suffix}"
    )
    db_session.add(prot_db)

    # Get or create SecuritySource
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

    # Query existing seeded detection rules
    rule_003 = db_session.query(DetectionRule).filter(DetectionRule.rule_id == "RULE_003_SYSADMIN_CHANGE").first()
    rule_007 = db_session.query(DetectionRule).filter(DetectionRule.rule_id == "RULE_007_SCHEMA_MUTATION").first()

    db_session.commit()
    db_session.refresh(prot_db)
    if rule_003:
        db_session.refresh(rule_003)
    if rule_007:
        db_session.refresh(rule_007)

    yield {
        "db": prot_db,
        "source": source,
        "rule_003": rule_003,
        "rule_007": rule_007,
        "db_name": db_name
    }

    # Teardown
    try:
        db_session.query(InvestigationCase).filter(InvestigationCase.target_database_name == db_name).delete(synchronize_session=False)
        db_session.delete(prot_db)
        db_session.commit()
    except Exception:
        db_session.rollback()


def test_intake_from_security_alert_new_case(db_session: Session, setup_test_context: dict):
    """Verifies creating a new investigation case from a critical SecurityAlert."""
    db_name = setup_test_context["db_name"]
    source = setup_test_context["source"]
    rule = setup_test_context["rule_003"]

    alert = SecurityAlert(
        source_id=source.id,
        rule_id=rule.id,
        title="Unauthorized Sysadmin Role Mutation Detected",
        description=f"Compromised SA login added to sysadmin role on {db_name}",
        severity="CRITICAL",
        status="NEW",
        principal_name="sa",
        target_object=f"{db_name}.sysadmin",
        explanation="Explainable rule trigger on sysadmin role grant",
        confidence_score=1.0,
        detection_timestamp=datetime.now(timezone.utc)
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    case = IncidentIntakeService.intake_from_security_alert(
        db=db_session,
        alert_id=alert.id,
        actor="soc_analyst"
    )

    assert case.id is not None
    assert case.target_database_name == db_name
    assert case.incident_category == "PRIVILEGE_ESCALATION"
    assert case.priority == "P1_CRITICAL"
    assert case.severity_score >= 80.0
    assert case.status == "NEW"

    # Verify evidence link
    links = db_session.query(CaseEvidenceLink).filter(CaseEvidenceLink.case_id == case.id).all()
    assert len(links) == 1
    assert links[0].source_id == alert.id
    assert links[0].evidence_role == "ROOT_CAUSE"

    # Verify MITRE techniques mapped
    mitre = db_session.query(CaseMitreTechnique).filter(CaseMitreTechnique.case_id == case.id).all()
    tech_ids = {m.technique_id for m in mitre}
    assert "T1068" in tech_ids or "T1078" in tech_ids


def test_intake_from_security_alert_clustering(db_session: Session, setup_test_context: dict):
    """Verifies that alerts within 30 mins on the same database are clustered into the existing case."""
    db_name = setup_test_context["db_name"]
    source = setup_test_context["source"]
    rule_007 = setup_test_context["rule_007"]

    # Retrieve existing case from previous test
    existing_case = (
        db_session.query(InvestigationCase)
        .filter(InvestigationCase.target_database_name == db_name)
        .first()
    )
    assert existing_case is not None

    # Spawn second alert 5 minutes later on the same database
    alert_2 = SecurityAlert(
        source_id=source.id,
        rule_id=rule_007.id,
        title="Follow-on Schema Object Deletion",
        description=f"Mass table drop on {db_name}",
        severity="HIGH",
        status="NEW",
        principal_name="sa",
        target_object=f"{db_name}.dbo.customers",
        explanation="Explainable rule trigger on mass table drop",
        confidence_score=0.95,
        detection_timestamp=datetime.now(timezone.utc)
    )
    db_session.add(alert_2)
    db_session.commit()
    db_session.refresh(alert_2)

    # Ingest second alert: should cluster into existing_case
    correlated_case = IncidentIntakeService.intake_from_security_alert(
        db=db_session,
        alert_id=alert_2.id,
        actor="auto_correlator"
    )

    assert correlated_case.id == existing_case.id

    # Verify evidence count increased to 2
    links = db_session.query(CaseEvidenceLink).filter(CaseEvidenceLink.case_id == existing_case.id).all()
    assert len(links) == 2
    second_link = [l for l in links if l.source_id == alert_2.id][0]
    assert second_link.evidence_role == "INDICATOR_OF_COMPROMISE"


def test_intake_from_forensic_finding(db_session: Session, setup_test_context: dict):
    """Verifies case creation or correlation from a Module 3 ForensicFinding."""
    db_name = f"SQLTrust_ForensicDB_{uuid.uuid4().hex[:6]}"
    prot_db = ProtectedDatabase(
        database_name=db_name,
        server_name="localhost\\SQLEXPRESS",
        database_identifier=f"fdb_{uuid.uuid4().hex[:6]}"
    )
    db_session.add(prot_db)
    db_session.flush()

    baseline = ForensicBaseline(
        database_id=prot_db.id,
        server_name="localhost\\SQLEXPRESS",
        database_name=db_name,
        baseline_name="Initial Golden Baseline",
        status="ACTIVE",
        sha256_manifest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    db_session.add(baseline)
    db_session.flush()

    inv = ForensicInvestigation(
        investigation_name=f"Forensic Audit for {db_name}",
        server_name="localhost\\SQLEXPRESS",
        database_name=db_name,
        ref_baseline_id=baseline.id,
        status="COMPLETED",
        started_at=datetime.now(timezone.utc)
    )
    db_session.add(inv)
    db_session.flush()

    finding = ForensicFinding(
        investigation_id=inv.id,
        category="SCHEMA",
        finding_type="OBJECT_MODIFIED",
        severity="HIGH",
        entity_name="sp_process_payroll",
        explanation="Unauthorized stored procedure alteration detected",
        confidence_score=0.95
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    case = IncidentIntakeService.intake_from_forensic_finding(
        db=db_session,
        finding_id=finding.id,
        actor="forensic_daemon"
    )

    assert case.id is not None
    assert case.target_database_name == db_name
    assert case.incident_category == "SCHEMA_TAMPERING"

    # Verify MITRE technique T1505.001 mapped
    mitre = db_session.query(CaseMitreTechnique).filter(CaseMitreTechnique.case_id == case.id).all()
    assert any(m.technique_id == "T1505.001" for m in mitre)


def test_intake_from_recovery_risk(db_session: Session, setup_test_context: dict):
    """Verifies case creation when Module 4 flags a compromised recovery point."""
    prot_db = setup_test_context["db"]
    db_name = setup_test_context["db_name"]

    point = RecoveryPoint(
        database_id=prot_db.id,
        server_name="localhost\\SQLEXPRESS",
        database_name=db_name,
        recovery_point_time=datetime.now(timezone.utc) - timedelta(hours=2),
        recovery_point_type="TRANSACTION_LOG",
        integrity_status="VERIFIED"
    )
    db_session.add(point)
    db_session.flush()

    assessment = RecoveryAssessment(
        recovery_point_id=point.id,
        assessment_name="Compromise Assessment",
        trust_classification="LOW_CONFIDENCE",
        trust_score=15.0,
        confidence_rationale="Proximity to ransomware encryption window"
    )
    db_session.add(assessment)
    db_session.commit()
    db_session.refresh(point)

    case = IncidentIntakeService.intake_from_recovery_risk(
        db=db_session,
        recovery_point_id=point.id,
        actor="recovery_analyzer"
    )

    assert case.id is not None
    assert case.priority == "P1_CRITICAL"
    assert "LOW_CONFIDENCE" in case.title or "Recovery Risk" in case.title


def test_intake_from_validation_failure(db_session: Session, setup_test_context: dict):
    """Verifies case creation when Module 5 restore validation fails."""
    prot_db = setup_test_context["db"]
    db_name = setup_test_context["db_name"]

    point = RecoveryPoint(
        database_id=prot_db.id,
        server_name="localhost\\SQLEXPRESS",
        database_name=db_name,
        recovery_point_time=datetime.now(timezone.utc) - timedelta(hours=1),
        recovery_point_type="FULL",
        integrity_status="VERIFIED"
    )
    db_session.add(point)
    db_session.flush()

    assessment = RecoveryAssessment(
        recovery_point_id=point.id,
        assessment_name="Pre-validation Assessment",
        trust_classification="MEDIUM_CONFIDENCE",
        trust_score=60.0,
        confidence_rationale="Candidate evaluated"
    )
    db_session.add(assessment)
    db_session.flush()

    eligibility = RecoveryEligibility(
        recovery_point_id=point.id,
        is_eligible=True,
        eligibility_status="ELIGIBLE"
    )
    db_session.add(eligibility)
    db_session.flush()

    candidate = RecoveryRecommendation(
        database_id=prot_db.id,
        recovery_point_id=point.id,
        assessment_id=assessment.id,
        eligibility_id=eligibility.id,
        rank_order=1,
        trust_classification="HIGH_CONFIDENCE",
        eligibility_status="ELIGIBLE",
        ranking_score=95.0,
        rank_rationale="Candidate evaluated for validation",
        tradeoff_analysis="Minimal data loss",
        recommended_next_step="Mount in isolated recovery sandbox"
    )
    db_session.add(candidate)
    db_session.flush()

    job = RecoveryJob(
        candidate_id=candidate.id,
        recovery_point_id=point.id,
        target_database_name=db_name,
        status="TERMINATED",
        requested_by="admin"
    )
    db_session.add(job)
    db_session.flush()

    sandbox = RecoverySandbox(
        job_id=job.id,
        container_name=f"sbx-{uuid.uuid4().hex[:8]}",
        docker_network="sqltrust-recovery-net",
        data_volume=f"v_data_{uuid.uuid4().hex[:6]}",
        log_volume=f"v_log_{uuid.uuid4().hex[:6]}",
        staging_mount_path="/var/opt/mssql/staging",
        host_port=12799,
        sa_password_hash="synthetic_hash_123",
        lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    db_session.flush()

    val = RecoveryValidation(
        job_id=job.id,
        sandbox_id=sandbox.id,
        target_database_name=job.target_database_name,
        dbcc_status="CORRUPTED",
        dbcc_errors_count=2,
        overall_assessment="FAILED",
        assessment_rationale="Database consistency check DBCC failed with corruption"
    )
    db_session.add(val)
    db_session.commit()
    db_session.refresh(job)

    case = IncidentIntakeService.intake_from_validation_failure(
        db=db_session,
        job_id=job.id,
        actor="validation_daemon"
    )

    assert case.id is not None
    assert case.priority == "P1_CRITICAL"
    assert "FAILED" in case.description


def test_multi_factor_severity_scoring():
    """Verifies explainable multi-factor severity scoring and priority derivation."""
    # Critical ransomware attack by sa against 10 tables
    score_p1, prio_p1, _ = ClassificationEngine.calculate_severity_score(
        max_rule_severity="CRITICAL",
        affected_objects_count=10,
        principal_name="sa",
        impact_type="DESTRUCTION"
    )
    assert score_p1 == 100.0
    assert prio_p1 == "P1_CRITICAL"

    # Moderate schema drift by application user
    score_p3, prio_p3, _ = ClassificationEngine.calculate_severity_score(
        max_rule_severity="MEDIUM",
        affected_objects_count=1,
        principal_name="app_service",
        impact_type="MODIFICATION"
    )
    assert 40.0 <= score_p3 < 60.0
    assert prio_p3 == "P3_MEDIUM"

    # Low severity policy scan
    score_p4, prio_p4, _ = ClassificationEngine.calculate_severity_score(
        max_rule_severity="LOW",
        affected_objects_count=0,
        principal_name="readonly_audit",
        impact_type="RECONNAISSANCE"
    )
    assert score_p4 < 40.0
    assert prio_p4 == "P4_LOW"


def test_mitre_attack_catalog_mapping():
    """Verifies that all 10 detection rules map to valid MITRE ATT&CK techniques."""
    for rule_code in [
        "RULE_001_FAILED_LOGINS",
        "RULE_002_NEW_PRIVILEGED_LOGIN",
        "RULE_003_SYSADMIN_CHANGE",
        "RULE_004_DATABASE_ROLE_ESCALATION",
        "RULE_005_PERMISSION_CHANGE",
        "RULE_006_PRINCIPAL_DELETION",
        "RULE_007_SCHEMA_MUTATION",
        "RULE_008_AUDIT_TAMPERING",
        "RULE_009_XE_INTERRUPTION",
        "RULE_010_COLLECTION_GAP"
    ]:
        mappings = ClassificationEngine.RULE_TECHNIQUE_MAP.get(rule_code, [])
        assert len(mappings) > 0, f"Missing MITRE mapping for {rule_code}"
        for tech_id, conf in mappings:
            assert tech_id in ClassificationEngine.MITRE_CATALOG
            assert 0.0 < conf <= 1.0


def test_intake_api_endpoints(db_session: Session, setup_test_context: dict):
    """Verifies REST API endpoints for automated intake and classification."""
    db_name = setup_test_context["db_name"]
    source = setup_test_context["source"]
    rule = setup_test_context["rule_003"]

    alert = SecurityAlert(
        source_id=source.id,
        rule_id=rule.id,
        title="API Intake Test Alert",
        description="Triggered via API test",
        severity="HIGH",
        status="NEW",
        principal_name="api_tester",
        target_object=f"{db_name}_api.sysadmin",
        explanation="Testing API intake",
        detection_timestamp=datetime.now(timezone.utc)
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    # 1. POST /api/v1/investigations/intake/alert/{id}
    res = client.post(f"/api/v1/investigations/intake/alert/{alert.id}")
    assert res.status_code == 201, res.text
    case_data = res.json()
    case_id = case_data["id"]
    assert case_data["target_database_name"] == f"{db_name}_api"

    # 2. POST /api/v1/investigations/{id}/classify
    res = client.post(f"/api/v1/investigations/{case_id}/classify")
    assert res.status_code == 200, res.text
    class_data = res.json()
    assert class_data["case_id"] == case_id
    assert "severity_score" in class_data
    assert len(class_data["mitre_techniques"]) > 0
