"""
SQL-TRUST Unit & Integration Tests: Module 6 Phase 4
Timeline Engine, Correlation Engine, Dossier Service & Cryptographic Closure Signing
Tests chronological timeline collation, milestone detection, multi-dimensional correlation,
forensic dossier generation (JSON/Markdown), and Ed25519 digital signature closure verification.
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
    CaseNote,
    CaseContainmentAction,
    CaseAuditLog
)
from backend.schemas.investigation import (
    CaseCreateRequest,
    CaseNoteCreateRequest,
    CaseContainmentActionCreateRequest,
    CaseEvidenceLinkCreateRequest,
    CaseCloseRequest
)
from backend.services.investigation.case_service import CaseService
from backend.services.investigation.timeline_engine import TimelineEngine
from backend.services.investigation.correlation_engine import CorrelationEngine
from backend.services.investigation.dossier_service import DossierService
from backend.services.investigation.audit_service import CaseAuditService
from backend.services.security.signer import signer

client = TestClient(app)


@pytest.fixture(scope="module")
def setup_timeline_context():
    """Initializes isolated database context for Phase 4 timeline tests."""
    db: Session = SessionLocal()
    db_name = f"SQLTrust_TimelineTest_{uuid.uuid4().hex[:8]}"

    prot_db = ProtectedDatabase(
        database_name=db_name,
        server_name="localhost\\SQLEXPRESS",
        database_identifier=f"timeline_db_{uuid.uuid4().hex[:8]}",
        recovery_model="FULL"
    )
    db.add(prot_db)
    db.flush()

    source = db.query(SecuritySource).filter(SecuritySource.server_name == "localhost\\SQLEXPRESS").first()
    created_new_source = False
    if not source:
        source = SecuritySource(
            source_name=f"TimelineSource_{uuid.uuid4().hex[:6]}",
            server_name="localhost\\SQLEXPRESS",
            source_type="SQL_AUDIT",
            is_active=True
        )
        db.add(source)
        db.flush()
        created_new_source = True

    rule_003 = db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE_003_SYSADMIN_CHANGE").first()
    if not rule_003:
        rule_003 = DetectionRule(
            rule_id="RULE_003_SYSADMIN_CHANGE",
            rule_name="Sysadmin Role Change",
            severity="CRITICAL",
            mitre_technique="T1068",
            description="Detects additions to sysadmin",
            is_enabled=True
        )
        db.add(rule_003)
        db.flush()

    db.commit()

    context = {
        "db": prot_db,
        "db_name": db_name,
        "source": source,
        "rule_003": rule_003
    }

    yield context

    # Teardown
    cleanup_db: Session = SessionLocal()
    try:
        cases = cleanup_db.query(InvestigationCase).filter(InvestigationCase.target_database_name.like("SQLTrust_TimelineTest%")).all()
        for c in cases:
            cleanup_db.query(CaseEvidenceLink).filter(CaseEvidenceLink.case_id == c.id).delete()
            cleanup_db.query(CaseNote).filter(CaseNote.case_id == c.id).delete()
            cleanup_db.query(CaseContainmentAction).filter(CaseContainmentAction.case_id == c.id).delete()
            cleanup_db.query(CaseAuditLog).filter(CaseAuditLog.case_id == c.id).delete()
            cleanup_db.delete(c)
        cleanup_db.commit()

        cleanup_db.query(SecurityAlert).filter(SecurityAlert.title.in_([
            "Unauthorized SA elevation",
            "Critical Privilege Escalation",
            "Multi-Source Alert",
            "Initial Probe",
            "Subsequent Privilege Escalation by Attacker"
        ])).delete()
        if created_new_source:
            cleanup_db.query(SecuritySource).filter(SecuritySource.id == source.id).delete()
        cleanup_db.query(ProtectedDatabase).filter(ProtectedDatabase.id == prot_db.id).delete()
        cleanup_db.commit()
    except Exception:
        cleanup_db.rollback()
    finally:
        cleanup_db.close()
        db.close()


@pytest.fixture
def db_session():
    """Provides a transactional database session for each test."""
    session: Session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_timeline_reconstruction_chronological_ordering(db_session: Session, setup_timeline_context: dict):
    """Verifies that the timeline engine collates events and sorts them strictly chronologically."""
    db_name = setup_timeline_context["db_name"]
    source = setup_timeline_context["source"]
    rule = setup_timeline_context["rule_003"]

    now = datetime.now(timezone.utc)
    t0 = now - timedelta(minutes=45)
    t1 = now - timedelta(minutes=30)
    t2 = now - timedelta(minutes=15)
    t3 = now - timedelta(minutes=5)

    # 1. Create Case
    create_req = CaseCreateRequest(
        title="Chronological Timeline Test Case",
        description="Testing chronological collation",
        target_database_name=db_name,
        priority="P1_CRITICAL",
        incident_category="PRIVILEGE_ESCALATION",
        created_by="lead_investigator"
    )
    case = CaseService.create_case(db=db_session, req=create_req)
    case.opened_at = t0
    db_session.commit()

    # 2. Add Security Alert at t1
    alert = SecurityAlert(
        source_id=source.id,
        rule_id=rule.id,
        title="Unauthorized SA elevation",
        description="SA login granted sysadmin role",
        explanation="Explainable rule trigger on SA privilege escalation",
        severity="CRITICAL",
        principal_name="sa",
        target_object=f"{db_name}.sysadmin",
        detection_timestamp=t1
    )
    db_session.add(alert)
    db_session.commit()

    link_req = CaseEvidenceLinkCreateRequest(
        source_module="MODULE_2_SECURITY",
        source_entity="security_alerts",
        source_id=alert.id,
        evidence_role="ROOT_CAUSE",
        linked_by="lead_investigator"
    )
    CaseService.link_evidence(db=db_session, case_id=case.id, req=link_req)

    # 3. Add Analyst Note at t2
    note_req = CaseNoteCreateRequest(
        author="lead_investigator",
        note_type="ANALYSIS",
        content="Analyzed SA elevation root cause; privilege granted via unauthorized trigger",
        is_pinned=True
    )
    note = CaseService.add_note(db=db_session, case_id=case.id, req=note_req)
    note.created_at = t2
    db_session.commit()

    # 4. Add Containment Action at t3
    act_req = CaseContainmentActionCreateRequest(
        action_type="DISABLE_LOGIN",
        target_principal="sa",
        recommended_script="ALTER LOGIN [sa] DISABLE;",
        risk_assessment="High operational impact if SA is used by apps"
    )
    action = CaseService.add_containment_action(db=db_session, case_id=case.id, req=act_req, actor="lead_investigator")
    action.created_at = t3
    db_session.commit()

    # Reconstruct timeline
    timeline = TimelineEngine.build_case_timeline(db=db_session, case_id=case.id)

    assert len(timeline) >= 4

    # Verify chronological ordering (ascending)
    for i in range(len(timeline) - 1):
        assert timeline[i]["timestamp"] <= timeline[i + 1]["timestamp"], (
            f"Out of order: {timeline[i]['timestamp']} > {timeline[i+1]['timestamp']}"
        )


def test_timeline_milestone_tagging(db_session: Session, setup_timeline_context: dict):
    """Verifies that key incident milestones are correctly tagged and filterable."""
    db_name = setup_timeline_context["db_name"]
    source = setup_timeline_context["source"]
    rule = setup_timeline_context["rule_003"]

    create_req = CaseCreateRequest(
        title="Milestone Tagging Test",
        target_database_name=db_name,
        priority="P1_CRITICAL",
        incident_category="PRIVILEGE_ESCALATION",
        created_by="analyst"
    )
    case = CaseService.create_case(db=db_session, req=create_req)

    alert = SecurityAlert(
        source_id=source.id,
        rule_id=rule.id,
        title="Critical Privilege Escalation",
        description="Attacker added to sysadmin",
        explanation="Explainable rule trigger on attacker",
        severity="CRITICAL",
        principal_name="attacker",
        target_object=f"{db_name}.sysadmin"
    )
    db_session.add(alert)
    db_session.commit()

    link_req = CaseEvidenceLinkCreateRequest(
        source_module="MODULE_2_SECURITY",
        source_entity="security_alerts",
        source_id=alert.id,
        evidence_role="ROOT_CAUSE",
        linked_by="analyst"
    )
    CaseService.link_evidence(db=db_session, case_id=case.id, req=link_req)

    timeline = TimelineEngine.build_case_timeline(db=db_session, case_id=case.id)
    milestones = TimelineEngine.get_milestones(timeline)

    assert len(milestones) >= 2
    # Case Opened must be a milestone
    assert any(m["event_type"] == "CASE_OPENED" for m in milestones)
    # Root cause critical alert must be a milestone
    assert any(m["event_type"] == "SECURITY_ALERT_TRIGGERED" and m["is_milestone"] for m in milestones)


def test_multi_source_timeline_integration(db_session: Session, setup_timeline_context: dict):
    """Verifies that evidence from Modules 2, 3, 4, and 5 is collated into the timeline."""
    prot_db = setup_timeline_context["db"]
    db_name = setup_timeline_context["db_name"]
    source = setup_timeline_context["source"]
    rule = setup_timeline_context["rule_003"]

    case = CaseService.create_case(
        db=db_session,
        req=CaseCreateRequest(
            title="Multi-Source Integration Test",
            target_database_name=db_name,
            priority="P1_CRITICAL",
            incident_category="RANSOMWARE",
            created_by="soc_lead"
        )
    )

    # 1. Module 2: Security Alert
    alert = SecurityAlert(
        source_id=source.id,
        rule_id=rule.id,
        title="Multi-Source Alert",
        description="Multi-source security test alert",
        explanation="Explainable rule trigger on test secret table",
        severity="HIGH",
        principal_name="suspect",
        target_object=f"{db_name}.dbo.secret"
    )
    db_session.add(alert)
    db_session.commit()
    CaseService.link_evidence(
        db=db_session, case_id=case.id,
        req=CaseEvidenceLinkCreateRequest(source_module="MODULE_2_SECURITY", source_entity="security_alerts", source_id=alert.id, evidence_role="ROOT_CAUSE", linked_by="soc_lead")
    )

    # 2. Module 3: Forensic Finding
    baseline = ForensicBaseline(
        database_id=prot_db.id,
        server_name="localhost\\SQLEXPRESS",
        database_name=db_name,
        baseline_name="Timeline Baseline",
        status="ACTIVE",
        sha256_manifest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    db_session.add(baseline)
    db_session.flush()

    inv = ForensicInvestigation(
        investigation_name=f"Forensic Audit {db_name}",
        server_name="localhost\\SQLEXPRESS",
        database_name=db_name,
        ref_baseline_id=baseline.id,
        status="COMPLETED"
    )
    db_session.add(inv)
    db_session.flush()

    finding = ForensicFinding(
        investigation_id=inv.id,
        category="SCHEMA",
        finding_type="OBJECT_MODIFIED",
        severity="CRITICAL",
        entity_name="tbl_orders",
        explanation="Orders table schema corrupted"
    )
    db_session.add(finding)
    db_session.commit()
    CaseService.link_evidence(
        db=db_session, case_id=case.id,
        req=CaseEvidenceLinkCreateRequest(source_module="MODULE_3_FORENSICS", source_entity="forensic_findings", source_id=finding.id, evidence_role="INDICATOR_OF_COMPROMISE", linked_by="soc_lead")
    )

    # 3. Module 4: Recovery Point
    rp = RecoveryPoint(
        database_id=prot_db.id,
        server_name="localhost\\SQLEXPRESS",
        database_name=db_name,
        recovery_point_time=datetime.now(timezone.utc) - timedelta(hours=1),
        recovery_point_type="FULL",
        integrity_status="VERIFIED"
    )
    db_session.add(rp)
    db_session.flush()

    assess = RecoveryAssessment(
        recovery_point_id=rp.id,
        assessment_name="Compromise Assessment",
        trust_classification="LOW_CONFIDENCE",
        trust_score=20.0,
        confidence_rationale="Tampered backup"
    )
    db_session.add(assess)
    db_session.commit()
    CaseService.link_evidence(
        db=db_session, case_id=case.id,
        req=CaseEvidenceLinkCreateRequest(source_module="MODULE_4_RECOVERY", source_entity="recovery_points", source_id=rp.id, evidence_role="RECOVERY_VERIFICATION", linked_by="soc_lead")
    )

    # 4. Module 5: Recovery Job
    elig = RecoveryEligibility(recovery_point_id=rp.id, is_eligible=True, eligibility_status="ELIGIBLE")
    db_session.add(elig)
    db_session.flush()

    rec = RecoveryRecommendation(
        database_id=prot_db.id, recovery_point_id=rp.id, assessment_id=assess.id, eligibility_id=elig.id,
        rank_order=1, trust_classification="LOW_CONFIDENCE", eligibility_status="ELIGIBLE", ranking_score=20.0,
        rank_rationale="Test candidate", tradeoff_analysis="None", recommended_next_step="Validate"
    )
    db_session.add(rec)
    db_session.flush()

    job = RecoveryJob(candidate_id=rec.id, recovery_point_id=rp.id, target_database_name=db_name, status="TERMINATED", requested_by="admin")
    db_session.add(job)
    db_session.flush()

    sandbox = RecoverySandbox(
        job_id=job.id, container_name=f"sbx-{uuid.uuid4().hex[:6]}", docker_network="net",
        data_volume="vd", log_volume="vl", staging_mount_path="/tmp", host_port=12798,
        sa_password_hash="h", lifecycle_status="HEALTHY"
    )
    db_session.add(sandbox)
    db_session.flush()

    val = RecoveryValidation(
        job_id=job.id, sandbox_id=sandbox.id, target_database_name=db_name, dbcc_status="FAILED",
        dbcc_errors_count=5, overall_assessment="FAILED", assessment_rationale="DBCC CHECKDB failed"
    )
    db_session.add(val)
    db_session.commit()

    CaseService.link_evidence(
        db=db_session, case_id=case.id,
        req=CaseEvidenceLinkCreateRequest(source_module="MODULE_5_RESTORE", source_entity="recovery_jobs", source_id=job.id, evidence_role="RECOVERY_VERIFICATION", linked_by="soc_lead")
    )

    # Reconstruct timeline
    timeline = TimelineEngine.build_case_timeline(db=db_session, case_id=case.id)

    # Verify representations of all 4 modules
    modules_present = {item["source_module"] for item in timeline}
    assert "MODULE_2_SECURITY" in modules_present
    assert "MODULE_3_FORENSICS" in modules_present
    assert "MODULE_4_RECOVERY" in modules_present
    assert "MODULE_5_RESTORE" in modules_present
    assert "MODULE_6_INVESTIGATION" in modules_present


def test_correlation_engine_temporal_and_principal(db_session: Session, setup_timeline_context: dict):
    """Verifies that the correlation engine scans and auto-links related telemetry."""
    db_name = setup_timeline_context["db_name"]
    source = setup_timeline_context["source"]
    rule = setup_timeline_context["rule_003"]

    case = CaseService.create_case(
        db=db_session,
        req=CaseCreateRequest(
            title="Correlation Scan Test Case",
            target_database_name=db_name,
            priority="P2_HIGH",
            incident_category="PRIVILEGE_ESCALATION",
            created_by="analyst"
        )
    )

    # Add initial alert by "attacker_x"
    alert_1 = SecurityAlert(
        source_id=source.id,
        rule_id=rule.id,
        title="Initial Probe",
        description="Probe attempt by attacker_x",
        explanation="Explainable rule trigger on probe",
        severity="MEDIUM",
        principal_name="attacker_x",
        target_object=f"{db_name}.dbo.test"
    )
    db_session.add(alert_1)
    db_session.commit()
    CaseService.link_evidence(
        db=db_session, case_id=case.id,
        req=CaseEvidenceLinkCreateRequest(source_module="MODULE_2_SECURITY", source_entity="security_alerts", source_id=alert_1.id, evidence_role="ROOT_CAUSE", linked_by="analyst")
    )

    # Create unlinked alert by "attacker_x" occurring 5 minutes after case opened
    alert_2 = SecurityAlert(
        source_id=source.id,
        rule_id=rule.id,
        title="Subsequent Privilege Escalation by Attacker",
        description="Escalation attempt by attacker_x",
        explanation="Explainable rule trigger on escalation",
        severity="CRITICAL",
        principal_name="attacker_x",
        target_object=f"{db_name}.dbo.admin_table",
        created_at=case.opened_at + timedelta(minutes=5)
    )
    db_session.add(alert_2)
    db_session.commit()

    # Execute correlation scan with auto_link=True
    scan_res = CorrelationEngine.correlate_case_evidence(
        db=db_session,
        case_id=case.id,
        sliding_window_minutes=30,
        auto_link=True,
        actor="auto_correlator"
    )

    assert scan_res["candidates_found"] >= 1
    assert scan_res["candidates_linked"] >= 1
    assert "attacker_x" in scan_res["discovered_principals"]

    # Verify that the unlinked alert is now linked as CORRELATED_INDICATOR
    links = db_session.query(CaseEvidenceLink).filter(CaseEvidenceLink.case_id == case.id).all()
    correlated_link = [l for l in links if l.source_id == alert_2.id]
    assert len(correlated_link) == 1
    assert correlated_link[0].evidence_role == "CORRELATED_INDICATOR"


def test_dossier_generation_json_and_markdown(db_session: Session, setup_timeline_context: dict):
    """Verifies that complete forensic dossiers and GFM Markdown can be generated."""
    db_name = setup_timeline_context["db_name"]

    case = CaseService.create_case(
        db=db_session,
        req=CaseCreateRequest(
            title="Dossier Export Test Case",
            description="Testing complete forensic report generation",
            target_database_name=db_name,
            priority="P1_CRITICAL",
            incident_category="PRIVILEGE_ESCALATION",
            created_by="lead_investigator"
        )
    )

    dossier = DossierService.generate_dossier(db=db_session, case_id=case.id)

    assert dossier["case_id"] == case.id
    assert dossier["case_number"] == case.case_number
    assert "executive_summary" in dossier
    assert "mitre_matrix" in dossier
    assert "evidence_inventory" in dossier
    assert "timeline" in dossier
    assert "audit_trail_summary" in dossier
    assert dossier["audit_trail_summary"]["chain_integrity_verified"] is True

    # Test Markdown rendering
    md = DossierService.export_markdown(dossier)
    assert f"**Case Reference:** `{case.case_number}`" in md
    assert "## 1. Executive Incident Summary" in md
    assert "## 2. MITRE ATT&CK for Enterprise Matrix Mapping" in md
    assert "## 4. Chronological Incident Timeline" in md
    assert "## 6. Chain of Custody & Audit Integrity" in md


def test_case_close_and_ed25519_signing(db_session: Session, setup_timeline_context: dict):
    """Verifies that closing a case verifies audit integrity, generates manifest, and signs with Ed25519."""
    db_name = setup_timeline_context["db_name"]

    case = CaseService.create_case(
        db=db_session,
        req=CaseCreateRequest(
            title="Closure and Signing Test",
            target_database_name=db_name,
            priority="P2_HIGH",
            incident_category="SUSPICIOUS_ACTIVITY",
            created_by="secops"
        )
    )

    # Close and sign case
    close_res = DossierService.close_and_sign_case(
        db=db_session,
        case_id=case.id,
        closed_by="secops_lead",
        closure_reason="Incident resolved; unauthorized login revoked and verified.",
        closure_notes="Full forensic verification completed."
    )

    assert close_res["status"] == "CLOSED"
    assert close_res["closed_by"] == "secops_lead"
    assert close_res["signature"] is not None
    assert close_res["signature_valid"] is True
    assert close_res["audit_chain_verified"] is True
    assert len(close_res["closure_manifest_hash"]) == 64

    # Verify database state
    db_session.refresh(case)
    assert case.status == "CLOSED"
    assert case.closed_at is not None


def test_case_close_blocks_on_tampered_audit_chain(db_session: Session, setup_timeline_context: dict):
    """Verifies that case closure strictly blocks if any audit log entry was tampered with."""
    db_name = setup_timeline_context["db_name"]

    case = CaseService.create_case(
        db=db_session,
        req=CaseCreateRequest(
            title="Tampered Audit Chain Test",
            target_database_name=db_name,
            priority="P3_MEDIUM",
            incident_category="SUSPICIOUS_ACTIVITY",
            created_by="attacker_detector"
        )
    )

    # Maliciously tamper with the audit log hash in the DB
    audit_entry = db_session.query(CaseAuditLog).filter(CaseAuditLog.case_id == case.id).first()
    assert audit_entry is not None
    audit_entry.current_hash = "tampered_fake_hash_12345"
    db_session.commit()

    # Attempting to close must fail with ValueError
    with pytest.raises(ValueError, match="Audit chain verification failed"):
        DossierService.close_and_sign_case(
            db=db_session,
            case_id=case.id,
            closed_by="fraud_analyst",
            closure_reason="Attempting closure on tampered audit trail"
        )


def test_phase4_api_endpoints(db_session: Session, setup_timeline_context: dict):
    """Verifies REST API endpoints for timeline, correlation, dossier, and closure."""
    db_name = setup_timeline_context["db_name"]

    case = CaseService.create_case(
        db=db_session,
        req=CaseCreateRequest(
            title="Phase 4 API Endpoint Test",
            target_database_name=db_name,
            priority="P2_HIGH",
            incident_category="SUSPICIOUS_ACTIVITY",
            created_by="api_tester"
        )
    )

    # 1. GET /api/v1/investigations/{id}/timeline
    res_timeline = client.get(f"/api/v1/investigations/{case.id}/timeline")
    assert res_timeline.status_code == 200, res_timeline.text
    timeline_data = res_timeline.json()
    assert isinstance(timeline_data, list)
    assert len(timeline_data) >= 1
    assert timeline_data[0]["event_type"] == "CASE_OPENED"

    # 2. POST /api/v1/investigations/{id}/correlate
    res_corr = client.post(
        f"/api/v1/investigations/{case.id}/correlate",
        json={"sliding_window_minutes": 60, "auto_link": True, "actor": "api_correlator"}
    )
    assert res_corr.status_code == 200, res_corr.text
    corr_data = res_corr.json()
    assert "candidates_found" in corr_data
    assert "correlation_summary" in corr_data

    # 3. GET /api/v1/investigations/{id}/dossier (JSON)
    res_dossier_json = client.get(f"/api/v1/investigations/{case.id}/dossier?format=json")
    assert res_dossier_json.status_code == 200, res_dossier_json.text
    dossier_json = res_dossier_json.json()
    assert dossier_json["case_id"] == case.id
    assert "executive_summary" in dossier_json

    # 4. GET /api/v1/investigations/{id}/dossier (Markdown)
    res_dossier_md = client.get(f"/api/v1/investigations/{case.id}/dossier?format=markdown")
    assert res_dossier_md.status_code == 200, res_dossier_md.text
    assert "SQL-TRUST Cyber Incident Investigation Dossier" in res_dossier_md.text
    assert "text/markdown" in res_dossier_md.headers.get("content-type", "")

    # 5. POST /api/v1/investigations/{id}/close
    res_close = client.post(
        f"/api/v1/investigations/{case.id}/close",
        json={
            "closed_by": "api_closer",
            "closure_reason": "Case successfully resolved and signed via API",
            "closure_notes": "API test complete"
        }
    )
    assert res_close.status_code == 200, res_close.text
    close_data = res_close.json()
    assert close_data["status"] == "CLOSED"
    assert close_data["signature_valid"] is True
    assert close_data["audit_chain_verified"] is True
