"""
SQL-TRUST Complete Demo Data Seeder
Populates realistic, interconnected synthetic demo data across all 6 modules:
- Module 1: Backup Manager (Protected DB, Full, Diff, Log Backups, Manifests)
- Module 2: Security Monitoring Engine (Sources, Events, Rules, Alerts)
- Module 3: Database Forensics Engine (Baselines, Items, Investigation, Findings)
- Module 4: Cyber Recovery & State Reconstruction (Recovery Points, Assessments, Chains, Recommendations)
- Module 5: Restore & Cyber Recovery Validation Engine (Recovery Jobs, Staging Records, Sandboxes, Validations)
- Module 6: Cyber Investigation & Response Orchestration (Cases, Evidence Links, Workflows, Tasks, Response Plans, Notes)
"""
import sys
import os
import json
import uuid
import hashlib
from datetime import datetime, timezone, timedelta

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.database import SessionLocal, init_db
from backend.services.auth_service import AuthService
from backend.models.backup import (
    ProtectedDatabase,
    BackupRecord,
    BackupManifest,
    BackupOperationLog
)
from backend.models.security import (
    SecuritySource,
    SecurityEvent,
    DetectionRule,
    SecurityAlert,
    AlertStatusHistory
)
from backend.models.forensics import (
    ForensicBaseline,
    ForensicBaselineItem,
    ForensicInvestigation,
    ForensicFinding
)
from backend.models.recovery import (
    RecoveryPoint,
    RecoveryChain,
    RecoveryChainSegment,
    RecoveryAssessment,
    RecoveryEligibility,
    RecoveryRecommendation
)
from backend.models.restore import (
    RecoveryJob,
    RecoveryJobHistory,
    BackupStagingRecord,
    RecoverySandbox,
    RecoveryValidation
)
from backend.models.investigation import (
    InvestigationCase,
    CaseStatusHistory,
    CaseNote,
    CaseEvidenceLink,
    InvestigationWorkflowTemplate,
    InvestigationWorkflow,
    InvestigationWorkflowHistory,
    InvestigationTask,
    IncidentResponsePlan,
    ResponsePlanAction,
    AnalystCollaborationComment
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def seed_demo_data():
    print("=" * 70)
    print("SQL-TRUST COMPLETE DEMO DATA SEEDER")
    print("=" * 70)

    # 1. Initialize Tables
    print("[1/8] Ensuring database tables are created...")
    init_db()

    db = SessionLocal()
    try:
        # 2. Seed Demo Accounts
        print("[2/8] Seeding/verifying local demo accounts...")
        account_res = AuthService.seed_demo_accounts(db)
        print(f"      Demo accounts status: {account_res}")

        now = utc_now()
        t_minus_24h = now - timedelta(hours=24)
        t_minus_12h = now - timedelta(hours=12)
        t_minus_6h = now - timedelta(hours=6)
        t_minus_4h = now - timedelta(hours=4)
        t_minus_3h = now - timedelta(hours=3)
        t_minus_2h = now - timedelta(hours=2)
        t_minus_1h = now - timedelta(hours=1)

        # 3. Module 1: Protected Database & Backups
        print("[3/8] Seeding Module 1 (Protected Databases & Immutable Backups)...")
        demo_db_name = "SQLTrust_DemoEnterprise_ERP"
        db_record = db.query(ProtectedDatabase).filter_by(database_name=demo_db_name).first()
        if not db_record:
            db_record = ProtectedDatabase(
                id=str(uuid.uuid4()),
                server_name="localhost\\SQLEXPRESS",
                database_name=demo_db_name,
                database_identifier="101",
                recovery_model="FULL",
                registration_status="REGISTERED",
                created_at=t_minus_24h
            )
            db.add(db_record)
            db.flush()
            print(f"      Created Protected Database: {demo_db_name}")
        else:
            print(f"      Protected Database exists: {demo_db_name}")

        # Seed Backups (Full, Diff, Log 1, Log 2)
        backup_defs = [
            {
                "type": "FULL",
                "filename": f"{demo_db_name}_FULL_20261114_000000.bak",
                "start": t_minus_24h,
                "finish": t_minus_24h + timedelta(minutes=15),
                "size": 1548290124,
                "first_lsn": "00000120:00000100:0001",
                "last_lsn": "00000120:00000250:0001",
                "checkpoint_lsn": "00000120:00000100:0001",
                "db_backup_lsn": "00000120:00000100:0001"
            },
            {
                "type": "DIFFERENTIAL",
                "filename": f"{demo_db_name}_DIFF_20261114_120000.bak",
                "start": t_minus_12h,
                "finish": t_minus_12h + timedelta(minutes=4),
                "size": 314572800,
                "first_lsn": "00000120:00000250:0001",
                "last_lsn": "00000120:00000450:0001",
                "checkpoint_lsn": "00000120:00000250:0001",
                "db_backup_lsn": "00000120:00000100:0001"
            },
            {
                "type": "LOG",
                "filename": f"{demo_db_name}_LOG_20261114_180000.trn",
                "start": t_minus_6h,
                "finish": t_minus_6h + timedelta(minutes=1),
                "size": 41943040,
                "first_lsn": "00000120:00000450:0001",
                "last_lsn": "00000120:00000600:0001",
                "checkpoint_lsn": "00000120:00000450:0001",
                "db_backup_lsn": "00000120:00000100:0001"
            },
            {
                "type": "LOG",
                "filename": f"{demo_db_name}_LOG_20261114_220000.trn",
                "start": t_minus_2h,
                "finish": t_minus_2h + timedelta(minutes=1),
                "size": 67108864,
                "first_lsn": "00000120:00000600:0001",
                "last_lsn": "00000120:00000800:0001",
                "checkpoint_lsn": "00000120:00000600:0001",
                "db_backup_lsn": "00000120:00000100:0001"
            }
        ]

        saved_backups = []
        for b_def in backup_defs:
            b_rec = db.query(BackupRecord).filter_by(backup_filename=b_def["filename"]).first()
            if not b_rec:
                b_hash = hashlib.sha256(b_def["filename"].encode()).hexdigest()
                b_rec = BackupRecord(
                    id=str(uuid.uuid4()),
                    database_id=db_record.id,
                    backup_type=b_def["type"],
                    backup_filename=b_def["filename"],
                    backup_path=f"D:\\SQLTrust_Storage\\backups\\{b_def['filename']}",
                    backup_size_bytes=b_def["size"],
                    start_time=b_def["start"],
                    finish_time=b_def["finish"],
                    first_lsn=b_def["first_lsn"],
                    last_lsn=b_def["last_lsn"],
                    checkpoint_lsn=b_def["checkpoint_lsn"],
                    database_backup_lsn=b_def["db_backup_lsn"],
                    sha256=b_hash,
                    sql_verification_status="PASSED",
                    storage_upload_status="COMPLETED",
                    storage_object_key=f"backups/{demo_db_name}/{b_def['filename']}",
                    storage_object_version_id="v1-demo-locked",
                    retention_mode="COMPLIANCE",
                    retention_until=now + timedelta(days=30),
                    backup_status="COMPLETED",
                    created_at=b_def["start"]
                )
                db.add(b_rec)
                db.flush()

                # Add immutable manifest
                manifest_payload = {
                    "database_name": demo_db_name,
                    "backup_filename": b_def["filename"],
                    "backup_type": b_def["type"],
                    "sha256": b_hash,
                    "lsn_range": f"{b_def['first_lsn']} - {b_def['last_lsn']}",
                    "worm_compliance": True,
                    "verified_by": "SQL-TRUST Backup Engine"
                }
                manifest_json = json.dumps(manifest_payload, indent=2)
                manifest_rec = BackupManifest(
                    id=str(uuid.uuid4()),
                    backup_id=b_rec.id,
                    manifest_version="1.0",
                    manifest_json=manifest_json,
                    manifest_hash=hashlib.sha256(manifest_json.encode()).hexdigest(),
                    created_at=b_def["finish"]
                )
                db.add(manifest_rec)
                print(f"      Created Backup & Manifest: {b_def['filename']}")
            saved_backups.append(b_rec)

        db.commit()

        # 4. Module 2: Security Telemetry, Rules & Alerts
        print("[4/8] Seeding Module 2 (Security Sources, Rules & Attack Alerts)...")
        audit_dir = os.path.abspath("data/audit")
        xe_dir = os.path.abspath("data/extended_events")
        os.makedirs(audit_dir, exist_ok=True)
        os.makedirs(xe_dir, exist_ok=True)

        sec_source = db.query(SecuritySource).filter_by(source_name="SQLTrust_Local_Telemetry").first()
        if not sec_source:
            sec_source = SecuritySource(
                id=str(uuid.uuid4()),
                source_name="SQLTrust_Local_Telemetry",
                server_name="localhost\\SQLEXPRESS",
                source_type="HYBRID",
                audit_target_path=audit_dir,
                xe_target_path=xe_dir,
                is_active=True,
                created_at=t_minus_24h
            )
            db.add(sec_source)
            db.flush()
        else:
            sec_source.audit_target_path = audit_dir
            sec_source.xe_target_path = xe_dir
            db.flush()

        # Rules
        rules = [
            ("RULE_001_FAILED_LOGINS", "Brute Force Authentication Spike", "Detects repeated failed logins from suspicious IP.", "THRESHOLD", 5, "HIGH"),
            ("RULE_002_PRIVILEGE_ESCALATION", "Unauthorized Sysadmin Role Escalation", "Detects principal membership changes to sysadmin or securityadmin.", "STATE_CHANGE", 1, "CRITICAL"),
            ("RULE_005_RANSOMWARE_CANARY", "Ransomware Mass DDL / Schema Corruption", "Detects rapid schema dropping, table renaming or unobservable encrypted tables.", "SEQUENCE", 3, "CRITICAL")
        ]
        saved_rules = {}
        for r_id, r_name, r_desc, r_cond, r_thresh, r_sev in rules:
            rule_obj = db.query(DetectionRule).filter_by(rule_id=r_id).first()
            if not rule_obj:
                rule_obj = DetectionRule(
                    id=str(uuid.uuid4()),
                    rule_id=r_id,
                    rule_name=r_name,
                    description=r_desc,
                    condition_type=r_cond,
                    threshold_value=r_thresh,
                    time_window_seconds=300,
                    severity=r_sev,
                    is_enabled=True,
                    created_at=t_minus_24h
                )
                db.add(rule_obj)
                db.flush()
            saved_rules[r_id] = rule_obj

        # Attack Events
        fp1 = hashlib.sha256(b"event_attack_login_fail_01").hexdigest()
        ev1 = db.query(SecurityEvent).filter_by(event_fingerprint=fp1).first()
        if not ev1:
            ev1 = SecurityEvent(
                id=str(uuid.uuid4()),
                source_id=sec_source.id,
                event_source="SQL_AUDIT",
                source_file="SQLAudit_20261114.sqlaudit",
                event_type="LOGIN_FAILED",
                event_timestamp=t_minus_4h,
                server_name="localhost\\SQLEXPRESS",
                database_name="master",
                principal_name="sa_attacker",
                client_ip="192.168.1.189",
                client_app="sqlcmd / python-tds exploit tool",
                action="LGFL",
                success=False,
                severity="HIGH",
                event_fingerprint=fp1,
                raw_payload=json.dumps({"ip": "192.168.1.189", "reason": "Password mismatch burst"}),
                integrity_status="VERIFIED",
                created_at=t_minus_4h
            )
            db.add(ev1)
            db.flush()

        fp2 = hashlib.sha256(b"event_attack_privilege_escalation_02").hexdigest()
        ev2 = db.query(SecurityEvent).filter_by(event_fingerprint=fp2).first()
        if not ev2:
            ev2 = SecurityEvent(
                id=str(uuid.uuid4()),
                source_id=sec_source.id,
                event_source="SQL_AUDIT",
                source_file="SQLAudit_20261114.sqlaudit",
                event_type="ROLE_MEMBER_CHANGE",
                event_timestamp=t_minus_3h,
                server_name="localhost\\SQLEXPRESS",
                database_name="master",
                principal_name="sa",
                client_ip="192.168.1.189",
                client_app="sqlcmd",
                action="AL",
                target_object="sysadmin -> [db_compromised_app]",
                success=True,
                severity="CRITICAL",
                event_fingerprint=fp2,
                raw_payload=json.dumps({"command": "ALTER SERVER ROLE sysadmin ADD MEMBER [db_compromised_app]"}),
                integrity_status="VERIFIED",
                created_at=t_minus_3h
            )
            db.add(ev2)
            db.flush()

        # Security Alerts
        alert1 = db.query(SecurityAlert).filter_by(title="Critical: Unauthorized Sysadmin Escalation Detected").first()
        if not alert1:
            alert1 = SecurityAlert(
                id=str(uuid.uuid4()),
                source_id=sec_source.id,
                rule_id=saved_rules["RULE_002_PRIVILEGE_ESCALATION"].id,
                title="Critical: Unauthorized Sysadmin Escalation Detected",
                description="Principal [db_compromised_app] was added to the sysadmin server role outside change control window.",
                severity="CRITICAL",
                status="INVESTIGATING",
                detection_timestamp=t_minus_3h,
                principal_name="db_compromised_app",
                target_object="sysadmin",
                explanation="Detection Rule RULE_002 triggered due to ALTER SERVER ROLE sysadmin event.",
                confidence_score=0.99,
                related_event_count=1,
                created_at=t_minus_3h
            )
            alert1.related_events.append(ev2)
            db.add(alert1)
            db.flush()

        alert2 = db.query(SecurityAlert).filter_by(title="High: Potential Ransomware / DDL Tampering Spike").first()
        if not alert2:
            alert2 = SecurityAlert(
                id=str(uuid.uuid4()),
                source_id=sec_source.id,
                rule_id=saved_rules["RULE_005_RANSOMWARE_CANARY"].id,
                title="High: Potential Ransomware / DDL Tampering Spike",
                description="Corrupted schema definitions and dropped index alerts recorded on ERP orders schema.",
                severity="HIGH",
                status="NEW",
                detection_timestamp=t_minus_2h,
                principal_name="db_compromised_app",
                target_object=f"{demo_db_name}.dbo.CustomerOrders",
                explanation="Detection Rule RULE_005 triggered due to mass ALTER TABLE operations.",
                confidence_score=0.95,
                related_event_count=1,
                created_at=t_minus_2h
            )
            db.add(alert2)
            db.flush()

        db.commit()

        # 5. Module 3: Database Forensics Engine (Baselines & Investigations)
        print("[5/8] Seeding Module 3 (Forensic Baselines & Schema Drift Findings)...")
        baseline = db.query(ForensicBaseline).filter_by(baseline_name="ERP_Production_Golden_v1").first()
        if not baseline:
            b_manifest_hash = hashlib.sha256(b"manifest_golden_baseline_erp_v1").hexdigest()
            baseline = ForensicBaseline(
                id=str(uuid.uuid4()),
                database_id=db_record.id,
                server_name="localhost\\SQLEXPRESS",
                database_name=demo_db_name,
                baseline_name="ERP_Production_Golden_v1",
                baseline_type="FULL",
                status="COMPLETED",
                captured_at=t_minus_24h,
                total_objects=148,
                total_principals=12,
                total_permissions=64,
                sha256_manifest=b_manifest_hash,
                storage_object_key=f"forensics/baselines/{demo_db_name}_golden_v1.json",
                storage_version_id="v1-demo-baseline",
                signature="ed25519:demo_valid_signature_golden_state",
                notes="Authorized reference state baseline captured during pre-incident maintenance.",
                created_at=t_minus_24h
            )
            db.add(baseline)
            db.flush()

            # Baseline Items
            item1 = ForensicBaselineItem(
                id=str(uuid.uuid4()),
                baseline_id=baseline.id,
                item_type="TABLE",
                schema_name="dbo",
                item_name="CustomerOrders",
                raw_definition="CREATE TABLE [dbo].[CustomerOrders] (OrderID INT PRIMARY KEY, OrderTotal DECIMAL(18,2)...)",
                definition_hash=hashlib.sha256(b"CustomerOrders_clean").hexdigest(),
                properties_json=json.dumps({"columns": ["OrderID", "OrderTotal"], "indexes": ["PK_Orders"]}),
                created_at=t_minus_24h
            )
            item2 = ForensicBaselineItem(
                id=str(uuid.uuid4()),
                baseline_id=baseline.id,
                item_type="USER",
                schema_name="dbo",
                item_name="db_compromised_app",
                raw_definition="USER [db_compromised_app] ROLE db_datareader",
                definition_hash=hashlib.sha256(b"db_compromised_app_clean").hexdigest(),
                properties_json=json.dumps({"roles": ["db_datareader"]}),
                created_at=t_minus_24h
            )
            db.add(item1)
            db.add(item2)
            db.flush()

        # Forensic Investigation & Findings
        f_inv = db.query(ForensicInvestigation).filter_by(investigation_name="INV-FORENSIC-ERP-ATTACK").first()
        if not f_inv:
            f_inv = ForensicInvestigation(
                id=str(uuid.uuid4()),
                investigation_name="INV-FORENSIC-ERP-ATTACK",
                server_name="localhost\\SQLEXPRESS",
                database_name=demo_db_name,
                ref_baseline_id=baseline.id,
                status="COMPLETED",
                findings_count=2,
                critical_findings_count=1,
                high_findings_count=1,
                started_at=t_minus_2h,
                completed_at=t_minus_1h,
                summary_notes="Forensic drift detected: sysadmin privilege grant and modified stored procedures.",
                manifest_sha256=hashlib.sha256(b"forensic_investigation_erp").hexdigest()
            )
            db.add(f_inv)
            db.flush()

            find1 = ForensicFinding(
                id=str(uuid.uuid4()),
                investigation_id=f_inv.id,
                category="ROLE_MEMBERSHIP",
                finding_type="ROLE_ESCALATION",
                severity="CRITICAL",
                entity_name="sysadmin",
                schema_name="server_role",
                before_state_json=json.dumps({"member": "db_compromised_app", "role": "db_datareader"}),
                after_state_json=json.dumps({"member": "db_compromised_app", "role": "sysadmin"}),
                explanation="Direct elevation to sysadmin bypasses all column level security.",
                confidence_score=1.0,
                detected_at=t_minus_2h
            )
            find2 = ForensicFinding(
                id=str(uuid.uuid4()),
                investigation_id=f_inv.id,
                category="SCHEMA",
                finding_type="OBJECT_MODIFIED",
                severity="HIGH",
                entity_name="CustomerOrders",
                schema_name="dbo",
                before_state_json=json.dumps({"triggers": []}),
                after_state_json=json.dumps({"triggers": ["trg_encrypt_payload"]}),
                explanation="Suspicious trigger trg_encrypt_payload injected on sensitive table.",
                confidence_score=0.98,
                detected_at=t_minus_2h
            )
            db.add(find1)
            db.add(find2)
            db.flush()

        db.commit()

        # 6. Module 4: Cyber Recovery & Trust Assessments
        print("[6/8] Seeding Module 4 (Recovery Points & Explainable Trust Scores)...")
        # Candidate 1: Clean pre-attack recovery point (Diff Backup @ t-12h)
        rp_clean = db.query(RecoveryPoint).filter_by(
            database_name=demo_db_name,
            recovery_point_type="DIFFERENTIAL"
        ).first()

        if not rp_clean:
            rp_clean = RecoveryPoint(
                id=str(uuid.uuid4()),
                database_id=db_record.id,
                backup_id=saved_backups[1].id,
                server_name="localhost\\SQLEXPRESS",
                database_name=demo_db_name,
                recovery_point_time=t_minus_12h,
                recovery_point_type="DIFFERENTIAL",
                first_lsn="00000120:00000250:0001",
                last_lsn="00000120:00000450:0001",
                checkpoint_lsn="00000120:00000250:0001",
                database_backup_lsn="00000120:00000100:0001",
                integrity_status="VERIFIED",
                sha256=saved_backups[1].sha256,
                storage_object_key=saved_backups[1].storage_object_key,
                retention_mode="COMPLIANCE",
                created_at=t_minus_12h
            )
            db.add(rp_clean)
            db.flush()

        # Candidate 2: Post-attack compromised recovery point (Log Backup @ t-2h)
        rp_infected = db.query(RecoveryPoint).filter_by(
            database_name=demo_db_name,
            recovery_point_type="LOG"
        ).first()

        if not rp_infected:
            rp_infected = RecoveryPoint(
                id=str(uuid.uuid4()),
                database_id=db_record.id,
                backup_id=saved_backups[3].id,
                server_name="localhost\\SQLEXPRESS",
                database_name=demo_db_name,
                recovery_point_time=t_minus_2h,
                recovery_point_type="LOG",
                first_lsn="00000120:00000600:0001",
                last_lsn="00000120:00000800:0001",
                checkpoint_lsn="00000120:00000600:0001",
                database_backup_lsn="00000120:00000100:0001",
                integrity_status="VERIFIED",
                sha256=saved_backups[3].sha256,
                storage_object_key=saved_backups[3].storage_object_key,
                retention_mode="COMPLIANCE",
                created_at=t_minus_2h
            )
            db.add(rp_infected)
            db.flush()

        # Recovery Assessments
        assess_clean = db.query(RecoveryAssessment).filter_by(recovery_point_id=rp_clean.id).first()
        if not assess_clean:
            assess_clean = RecoveryAssessment(
                id=str(uuid.uuid4()),
                recovery_point_id=rp_clean.id,
                assessment_name=f"Trust Assessment - Clean Pre-Attack State ({demo_db_name})",
                model_version="1.0.0",
                trust_classification="HIGH_CONFIDENCE",
                trust_score=94.5,
                has_sufficient_evidence=True,
                confidence_rationale="Captured 8 hours prior to any detected attacker activity. LSN chain continuous from Full backup. WORM compliance retention verified.",
                positive_indicators_json=json.dumps([
                    "Precedes initial attacker failed login sequence by 8 hours",
                    "Cryptographic SHA-256 matches immutable SeaweedFS S3 WORM metadata",
                    "Continuous LSN chain with zero gaps against base FULL backup",
                    "Database baseline comparison matches Golden Baseline v1.0 exactly"
                ]),
                negative_indicators_json=json.dumps([]),
                missing_telemetry_json=json.dumps([]),
                uncertainty_factors_json=json.dumps([]),
                manifest_sha256=hashlib.sha256(b"clean_assessment").hexdigest(),
                signature="ed25519:demo_signature_clean_assessment",
                assessed_at=t_minus_1h
            )
            db.add(assess_clean)
            db.flush()

        assess_infected = db.query(RecoveryAssessment).filter_by(recovery_point_id=rp_infected.id).first()
        if not assess_infected:
            assess_infected = RecoveryAssessment(
                id=str(uuid.uuid4()),
                recovery_point_id=rp_infected.id,
                assessment_name=f"Trust Assessment - Post-Attack Suspect State ({demo_db_name})",
                model_version="1.0.0",
                trust_classification="LOW_CONFIDENCE",
                trust_score=21.0,
                has_sufficient_evidence=True,
                confidence_rationale="Proximity to ransomware canary alerts and unauthorized sysadmin escalation within active attack window.",
                positive_indicators_json=json.dumps([
                    "Backup file physically intact in S3 storage"
                ]),
                negative_indicators_json=json.dumps([
                    "Backup log window overlaps with unauthorized sysadmin privilege escalation",
                    "Schema drift includes unauthorized trigger injections",
                    "Detection Rule RULE_005 canary alert active during log interval"
                ]),
                missing_telemetry_json=json.dumps([]),
                uncertainty_factors_json=json.dumps(["Attacker active during transaction capture"]),
                manifest_sha256=hashlib.sha256(b"infected_assessment").hexdigest(),
                signature="ed25519:demo_signature_infected_assessment",
                assessed_at=t_minus_1h
            )
            db.add(assess_infected)
            db.flush()

        # Eligibility & Recommendation
        elig = db.query(RecoveryEligibility).filter_by(recovery_point_id=rp_clean.id).first()
        if not elig:
            elig = RecoveryEligibility(
                id=str(uuid.uuid4()),
                recovery_point_id=rp_clean.id,
                is_eligible=True,
                eligibility_status="ELIGIBLE",
                requires_offline_sandbox=True,
                chain_usable=True,
                chain_consistent=True,
                logs_available=True,
                identity_matched=True,
                files_accessible=True,
                integrity_verified=True,
                critical_evidence_missing=False,
                evaluated_at=t_minus_1h
            )
            db.add(elig)
            db.flush()

        rec = db.query(RecoveryRecommendation).filter_by(recovery_point_id=rp_clean.id).first()
        if not rec:
            rec = RecoveryRecommendation(
                id=str(uuid.uuid4()),
                database_id=db_record.id,
                recovery_point_id=rp_clean.id,
                assessment_id=assess_clean.id,
                eligibility_id=elig.id,
                rank_order=1,
                trust_classification="HIGH_CONFIDENCE",
                eligibility_status="ELIGIBLE",
                ranking_score=94.5,
                rank_rationale="Precedes initial attacker activity by 8 hours. Continuous LSN verified.",
                tradeoff_analysis="12-hour data recreation window required vs zero risk of backdoor persistence.",
                recommended_next_step="Mount in isolated recovery sandbox and execute Module 3 baseline audit.",
                created_at=t_minus_1h
            )
            db.add(rec)
            db.flush()

        db.commit()

        # 7. Module 5: Restore Validation & Clean-Room Sandbox
        print("[7/8] Seeding Module 5 (Recovery Validation Jobs & Air-Gapped Sandboxes)...")
        recov_job = db.query(RecoveryJob).filter_by(target_database_name=f"{demo_db_name}_Sandbox").first()
        if not recov_job:
            recov_job = RecoveryJob(
                id=str(uuid.uuid4()),
                job_reference="RECOV-20261114-DEMO01",
                candidate_id=rec.id,
                recovery_point_id=rp_clean.id,
                target_database_name=f"{demo_db_name}_Sandbox",
                status="VALIDATED",
                requested_by="demo_investigator",
                approved_by="demo_reviewer",
                requested_at=t_minus_1h,
                approved_at=t_minus_1h + timedelta(minutes=5),
                started_at=t_minus_1h + timedelta(minutes=6),
                completed_at=now - timedelta(minutes=20),
                notes="Automated clean-room dry run restoration and DBCC CHECKDB validation."
            )
            db.add(recov_job)
            db.flush()

            # Job History
            states = [
                ("REQUESTED", "APPROVED", "demo_reviewer", t_minus_1h + timedelta(minutes=5)),
                ("APPROVED", "PREPARING_STAGING", "system_orchestrator", t_minus_1h + timedelta(minutes=6)),
                ("PREPARING_STAGING", "DOWNLOADING_BACKUPS", "system_orchestrator", t_minus_1h + timedelta(minutes=8)),
                ("DOWNLOADING_BACKUPS", "RESTORING_SANDBOX", "system_orchestrator", t_minus_1h + timedelta(minutes=15)),
                ("RESTORING_SANDBOX", "VALIDATING_INTEGRITY", "system_orchestrator", t_minus_1h + timedelta(minutes=25)),
                ("VALIDATING_INTEGRITY", "VALIDATED", "system_orchestrator", now - timedelta(minutes=20)),
            ]
            for f_st, t_st, act, t_dt in states:
                h_rec = RecoveryJobHistory(
                    id=str(uuid.uuid4()),
                    job_id=recov_job.id,
                    from_state=f_st,
                    to_state=t_st,
                    actor=act,
                    reason=f"State transitioned from {f_st} to {t_st}",
                    transitioned_at=t_dt
                )
                db.add(h_rec)

            # Sandbox
            sandbox = RecoverySandbox(
                id=str(uuid.uuid4()),
                job_id=recov_job.id,
                container_id="c_sqltrust_sandbox_demo01",
                container_name="sqltrust-sandbox-demo-erp",
                docker_image="mcr.microsoft.com/mssql/server:2022-latest",
                docker_network="sqltrust_sandbox_net",
                data_volume="sqltrust_sandbox_demo_data",
                log_volume="sqltrust_sandbox_demo_log",
                staging_mount_path="D:\\SQLTrust_Storage\\staging\\",
                host_port=14333,
                sa_password_hash=hashlib.sha256(b"SandboxTempPass!2026").hexdigest(),
                lifecycle_status="HEALTHY",
                is_isolated=True,
                network_isolated=True,
                storage_isolated=True,
                cpu_limit="2.0",
                memory_limit="2048m",
                created_at=t_minus_1h + timedelta(minutes=25)
            )
            db.add(sandbox)
            db.flush()

            # Validation
            val_rec = RecoveryValidation(
                id=str(uuid.uuid4()),
                job_id=recov_job.id,
                sandbox_id=sandbox.id,
                target_database_name=f"{demo_db_name}_Sandbox",
                dbcc_status="PASSED",
                dbcc_errors_count=0,
                dbcc_output_json=json.dumps({
                    "allocation_errors": 0,
                    "consistency_errors": 0,
                    "tables_checked": 148,
                    "status": "DBCC CHECKDB executed cleanly"
                }),
                schema_validation_status="PASSED",
                baseline_id=baseline.id,
                baseline_comparison_status="MATCHED",
                security_inspection_status="PASSED",
                unauthorized_principals_count=0,
                suspicious_objects_count=0,
                overall_assessment="VALIDATED",
                assessment_rationale="Clean pre-attack snapshot validated in isolated container. 0 DBCC CHECKDB errors. Golden baseline match 100%.",
                validated_at=now - timedelta(minutes=20),
                created_at=now - timedelta(minutes=20)
            )
            db.add(val_rec)
            db.flush()

        db.commit()

        # 8. Module 6: Cyber Investigation & Orchestration
        print("[8/8] Seeding Module 6 (Investigation Cases, Workflows, Tasks & Plans)...")
        case = db.query(InvestigationCase).filter_by(title="ERP Ransomware & Unauthorized Privilege Escalation Incident").first()
        if not case:
            case = InvestigationCase(
                id=str(uuid.uuid4()),
                case_number="INV-20261114-001",
                title="ERP Ransomware & Unauthorized Privilege Escalation Incident",
                description="Comprehensive cyber investigation into unauthorized sysadmin role escalation on db_compromised_app, trigger-based schema disruption, and clean-room recovery orchestration.",
                target_database_id=db_record.id,
                target_database_name=demo_db_name,
                priority="P1_CRITICAL",
                status="IN_PROGRESS",
                incident_category="RANSOMWARE_SUSPECTED",
                lead_investigator="demo_investigator",
                assigned_team="Tier 3 DFIR & Database Security",
                created_by="demo_admin",
                severity_score=9.2,
                blast_radius_summary="ERP Database instance, 148 tables, 1 unauthorized sysadmin role membership.",
                containment_status="CONTAINED",
                opened_at=t_minus_2h,
                created_at=t_minus_2h
            )
            db.add(case)
            db.flush()

            # Status history
            sh1 = CaseStatusHistory(
                id=str(uuid.uuid4()),
                case_id=case.id,
                from_status="NEW",
                to_status="TRIAGED",
                changed_by="demo_investigator",
                transition_reason="Initial triage confirmed anomalous sysadmin addition and correlation with telemetry.",
                transitioned_at=t_minus_2h + timedelta(minutes=5)
            )
            sh2 = CaseStatusHistory(
                id=str(uuid.uuid4()),
                case_id=case.id,
                from_status="TRIAGED",
                to_status="IN_PROGRESS",
                changed_by="demo_investigator",
                transition_reason="Playbook initiated; active containment and sandbox staging executed.",
                transitioned_at=t_minus_2h + timedelta(minutes=10)
            )
            db.add(sh1)
            db.add(sh2)

            # Link Evidence
            ev_links = [
                ("SECURITY", "SecurityAlert", alert1.id, "PRIMARY_INDICATOR", "Primary Privilege Escalation Alert", "demo_investigator"),
                ("SECURITY", "SecurityAlert", alert2.id, "CORROBORATING", "Ransomware Schema Canary Alert", "demo_investigator"),
                ("FORENSICS", "ForensicBaseline", baseline.id, "CORROBORATING", "Golden Reference Baseline v1", "demo_analyst"),
                ("RECOVERY", "RecoveryPoint", rp_clean.id, "CORROBORATING", "Clean Pre-Attack Recovery Point (94.5% Trust)", "demo_investigator"),
                ("RESTORE", "RecoveryJob", recov_job.id, "CORROBORATING", "Validated Air-Gapped Sandbox Restore Job", "demo_reviewer")
            ]
            for s_mod, s_ent, s_id, e_role, e_desc, l_by in ev_links:
                lnk = CaseEvidenceLink(
                    id=str(uuid.uuid4()),
                    case_id=case.id,
                    source_module=s_mod,
                    source_entity=s_ent,
                    source_id=s_id,
                    evidence_role=e_role,
                    sha256_hash=hashlib.sha256(e_desc.encode()).hexdigest(),
                    tamper_status="VERIFIED",
                    metadata_snapshot=json.dumps({"title": e_desc, "linked_by": l_by}),
                    linked_by=l_by,
                    linked_at=t_minus_2h + timedelta(minutes=15)
                )
                db.add(lnk)

            # Case Notes
            n1 = CaseNote(
                id=str(uuid.uuid4()),
                case_id=case.id,
                author="demo_investigator",
                note_type="HYPOTHESIS",
                content="Attacker gained initial foothold via brute-force against external interface, utilized compromised account to alter sysadmin role membership, and attempted to inject encryption triggers.",
                is_pinned=True,
                created_at=t_minus_2h + timedelta(minutes=20)
            )
            n2 = CaseNote(
                id=str(uuid.uuid4()),
                case_id=case.id,
                author="demo_analyst",
                note_type="ANALYST_NOTE",
                content="Drift analysis against ERP_Production_Golden_v1 confirmed 1 rogue trigger 'trg_encrypt_payload' and 1 sysadmin membership anomaly. All other database schemas remain unaltered.",
                is_pinned=False,
                created_at=t_minus_1h + timedelta(minutes=10)
            )
            db.add(n1)
            db.add(n2)

            # Investigation Workflow
            wf = InvestigationWorkflow(
                id=str(uuid.uuid4()),
                case_id=case.id,
                name="Ransomware Containment & Clean-Room Recovery Playbook",
                current_stage="RECOVERY_VALIDATION",
                status="IN_PROGRESS",
                owner="demo_investigator",
                created_by="demo_investigator",
                created_at=t_minus_2h + timedelta(minutes=12)
            )
            db.add(wf)
            db.flush()

            # Tasks
            task1 = InvestigationTask(
                id=str(uuid.uuid4()),
                workflow_id=wf.id,
                case_id=case.id,
                stage_name="CONTAINMENT",
                title="Isolate Database Instance Network & Revoke Rogue Privileges",
                description="Immediately disable [db_compromised_app] login and firewall untrusted traffic.",
                task_type="MANUAL",
                status="COMPLETED",
                priority="P1_CRITICAL",
                assigned_to="demo_admin",
                assigned_team="Infrastructure Security",
                is_mandatory=True,
                order_index=1,
                completed_at=t_minus_1h + timedelta(minutes=30),
                completed_by="demo_admin",
                completion_notes="Login disabled. Network firewalled to management VLAN only.",
                created_at=t_minus_2h + timedelta(minutes=15)
            )
            task2 = InvestigationTask(
                id=str(uuid.uuid4()),
                workflow_id=wf.id,
                case_id=case.id,
                stage_name="EVIDENCE_PRESERVATION",
                title="Verify S3 Object Lock & Audit Log Cryptographic Integrity",
                description="Validate SeaweedFS WORM compliance lock on candidate backup files and export tamper-evident receipts.",
                task_type="AUTOMATED_CHECK",
                status="COMPLETED",
                priority="P2_HIGH",
                assigned_to="demo_analyst",
                assigned_team="Digital Forensics",
                is_mandatory=True,
                order_index=2,
                completed_at=t_minus_1h + timedelta(minutes=45),
                completed_by="demo_analyst",
                completion_notes="All backup manifests SHA-256 hashes verified against immutable storage object locks.",
                created_at=t_minus_2h + timedelta(minutes=15)
            )
            task3 = InvestigationTask(
                id=str(uuid.uuid4()),
                workflow_id=wf.id,
                case_id=case.id,
                stage_name="RECOVERY_VALIDATION",
                title="Deploy Pre-Attack State in Air-Gapped Clean-Room Sandbox",
                description="Execute dry-run restore of recommended candidate in isolated sandbox and run DBCC CHECKDB.",
                task_type="MANUAL",
                status="COMPLETED",
                priority="P1_CRITICAL",
                assigned_to="demo_investigator",
                assigned_team="Tier 3 DFIR",
                is_mandatory=True,
                order_index=3,
                completed_at=now - timedelta(minutes=20),
                completed_by="demo_investigator",
                completion_notes="Sandbox restored cleanly. DBCC CHECKDB reported 0 errors across 148 tables.",
                created_at=t_minus_2h + timedelta(minutes=15)
            )
            task4 = InvestigationTask(
                id=str(uuid.uuid4()),
                workflow_id=wf.id,
                case_id=case.id,
                stage_name="RECOVERY_VALIDATION",
                title="Reviewer & CISO Sign-Off for Production Cutover",
                description="Review recovery trust score (94.5%), sandbox report, and sign off for primary ERP cutover.",
                task_type="APPROVAL",
                status="IN_PROGRESS",
                priority="P1_CRITICAL",
                assigned_to="demo_reviewer",
                assigned_team="Security Leadership",
                is_mandatory=True,
                order_index=4,
                created_at=t_minus_2h + timedelta(minutes=15)
            )
            db.add(task1)
            db.add(task2)
            db.add(task3)
            db.add(task4)

            # Response Plan
            resp_plan = IncidentResponsePlan(
                id=str(uuid.uuid4()),
                case_id=case.id,
                title="ERP Ransomware Remediation & Production Recovery Plan",
                summary="Coordinated incident response plan addressing immediate containment, forensic evidence preservation, clean-room sandbox validation, and controlled production recovery.",
                plan_type="CONTAINMENT_AND_RECOVERY",
                status="ACTIVE",
                version=1,
                created_by="demo_investigator",
                approved_by="demo_reviewer",
                approved_at=t_minus_1h,
                approval_notes="Approved for air-gapped staging and evidence preservation. Production cutover pending final check.",
                created_at=t_minus_1h + timedelta(minutes=10)
            )
            db.add(resp_plan)
            db.flush()

            # Response Plan Actions
            act1 = ResponsePlanAction(
                id=str(uuid.uuid4()),
                plan_id=resp_plan.id,
                case_id=case.id,
                title="Revoke Compromised Principal Credentials",
                action_category="CONTAINMENT",
                target_type="LOGIN",
                target_identifier="db_compromised_app",
                risk_level="HIGH",
                proposed_script="ALTER LOGIN [db_compromised_app] DISABLE; REVOKE CONNECT SQL FROM [db_compromised_app];",
                rollback_script="ALTER LOGIN [db_compromised_app] ENABLE;",
                execution_order=1,
                requires_multi_party_approval=True,
                approval_status="APPROVED",
                proposed_by="demo_investigator",
                approved_by="demo_reviewer",
                approved_at=t_minus_1h + timedelta(minutes=20),
                execution_status="EXECUTED_SUCCESS",
                executed_by="demo_admin",
                executed_at=t_minus_1h + timedelta(minutes=30),
                execution_notes="Login disabled. All active SPIDs killed.",
                created_at=t_minus_1h + timedelta(minutes=10)
            )
            act2 = ResponsePlanAction(
                id=str(uuid.uuid4()),
                plan_id=resp_plan.id,
                case_id=case.id,
                title="Validate Immutable Backup Chain in Sandbox",
                action_category="RECOVERY_PREPARATION",
                target_type="DATABASE",
                target_identifier=f"{demo_db_name}_Sandbox",
                risk_level="MEDIUM",
                proposed_script="RESTORE DATABASE SQLTrust_DemoEnterprise_ERP_Sandbox FROM DISK=... WITH NORECOVERY;",
                rollback_script="DROP DATABASE SQLTrust_DemoEnterprise_ERP_Sandbox;",
                execution_order=2,
                requires_multi_party_approval=True,
                approval_status="APPROVED",
                proposed_by="demo_investigator",
                approved_by="demo_reviewer",
                approved_at=t_minus_1h + timedelta(minutes=20),
                execution_status="EXECUTED_SUCCESS",
                executed_by="demo_investigator",
                executed_at=now - timedelta(minutes=20),
                execution_notes="Sandbox restored cleanly. DBCC CHECKDB reported 0 errors.",
                created_at=t_minus_1h + timedelta(minutes=10)
            )
            act3 = ResponsePlanAction(
                id=str(uuid.uuid4()),
                plan_id=resp_plan.id,
                case_id=case.id,
                title="Authorize Production Database Cutover",
                action_category="POST_INCIDENT",
                target_type="DATABASE",
                target_identifier=demo_db_name,
                risk_level="CRITICAL",
                proposed_script="-- Production cutover script awaiting final dual-control approval",
                rollback_script="-- Rollback to maintenance mode",
                execution_order=3,
                requires_multi_party_approval=True,
                approval_status="PENDING_APPROVAL",
                proposed_by="demo_investigator",
                execution_status="NOT_EXECUTED",
                created_at=t_minus_1h + timedelta(minutes=10)
            )
            db.add(act1)
            db.add(act2)
            db.add(act3)

            # Collaboration Comments
            c1 = AnalystCollaborationComment(
                id=str(uuid.uuid4()),
                case_id=case.id,
                plan_id=resp_plan.id,
                author="demo_investigator",
                comment_type="COMMENT",
                content="Sandbox verification completed with 0 errors. Trust score of 94.5% is supported by full LSN continuity and pre-attack timestamp. Requesting final sign-off.",
                created_at=now - timedelta(minutes=15)
            )
            c2 = AnalystCollaborationComment(
                id=str(uuid.uuid4()),
                case_id=case.id,
                plan_id=resp_plan.id,
                author="demo_reviewer",
                comment_type="PEER_REVIEW",
                content="Reviewing DBCC CHECKDB reports and audit logs now. Evidence is clean. Ready to approve final action step.",
                created_at=now - timedelta(minutes=5)
            )
            db.add(c1)
            db.add(c2)

        db.commit()
        print("=" * 70)
        print("DEMO DATA SEEDING COMPLETED SUCCESSFULLY!")
        print("Summary of Seeded Data:")
        print(f"  - Protected Database: {demo_db_name}")
        print(f"  - Backups & Manifests: 4 (Full, Diff, 2x Logs)")
        print(f"  - Telemetry Sources & Rules: 1 Source, 3 Rules, 2 Events, 2 Security Alerts")
        print(f"  - Forensics: 1 Golden Baseline, 2 Items, 1 Investigation, 2 Findings")
        print(f"  - Recovery: 2 Recovery Points (Clean 94.5% vs Infected 21%), 1 Recommendation")
        print(f"  - Restore: 1 Recovery Validation Job (VALIDATED), 1 Sandbox, 1 DBCC Report")
        print(f"  - Investigation: 1 Case (INV-20261114-001), 5 Evidence Links, 4 Tasks, 1 Active Plan")
        print("=" * 70)
        return True

    except Exception as e:
        db.rollback()
        print(f"ERROR: Seeding failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()


if __name__ == "__main__":
    success = seed_demo_data()
    sys.exit(0 if success else 1)
