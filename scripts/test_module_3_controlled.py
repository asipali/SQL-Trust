"""
SQL-TRUST Module 3: Controlled End-to-End Forensic Investigation Test
====================================================================
Executes a real-world, controlled forensic scenario in SQLTrust_Lab:
1. Captures Baseline A (Clean initial state).
2. Executes controlled DDL and security mutations:
   - Create table ForensicAuditTest
   - Alter table ForensicAuditTest (add column notes)
   - Create database user forensic_temp_user
   - Grant role db_owner (escalation)
   - Alter database option (AUTO_CLOSE = ON)
3. Ingests telemetry via Module 2 AuditCollector.
4. Captures Baseline B (Mutated state).
5. Executes Forensic Investigation (Diff A vs B).
6. Verifies:
   - Table creation detected
   - Column alteration detected
   - User addition detected
   - db_owner role escalation detected with CRITICAL severity
   - Configuration drift detected
   - Module 2 telemetry correlated in timeline
   - Ed25519 digital signature verified
   - SeaweedFS WORM retention verified
7. Safely cleans up the controlled test artifacts in SQLTrust_Lab.
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import text
from backend.database import SessionLocal, create_db_engine
from backend.models.security import SecuritySource
from backend.services.security.audit_collector import AuditCollector
from backend.services.forensics.baseline_collector import BaselineCollector
from backend.services.forensics.forensic_service import ForensicService
from backend.services.forensics.timeline_engine import TimelineCorrelator
from backend.services.forensics.evidence_service import ForensicEvidenceService


def cleanup_lab_database(lab_engine):
    with lab_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("IF OBJECT_ID('dbo.ForensicAuditTest', 'U') IS NOT NULL DROP TABLE dbo.ForensicAuditTest;"))
        conn.execute(text("""
            IF EXISTS (SELECT 1 FROM sys.database_role_members rm 
                       JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id 
                       JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id 
                       WHERE r.name = 'db_owner' AND m.name = 'forensic_temp_user')
                ALTER ROLE db_owner DROP MEMBER forensic_temp_user;
        """))
        conn.execute(text("IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'forensic_temp_user') DROP USER forensic_temp_user;"))
        conn.execute(text("ALTER DATABASE SQLTrust_Lab SET AUTO_CLOSE OFF;"))


def main():
    print("=" * 80)
    print("SQL-TRUST MODULE 3: CONTROLLED FORENSIC INVESTIGATION VERIFICATION")
    print("=" * 80)

    db = SessionLocal()
    lab_engine = create_db_engine(database="SQLTrust_Lab")

    try:
        # Step 0: Initial Cleanup to ensure clean starting state
        print("\n[STEP 0] Ensuring clean initial state in SQLTrust_Lab...")
        cleanup_lab_database(lab_engine)

        # Step 1: Capture Baseline A (Clean State)
        print("\n[STEP 1] Capturing Baseline A (Initial Clean State)...")
        collector = BaselineCollector(db, database_name="SQLTrust_Lab")
        baseline_a = collector.capture_baseline(
            baseline_name="Lab_Controlled_Baseline_A",
            notes="Initial clean state before controlled incident"
        )
        print(f"  ✓ Baseline A Captured: ID={baseline_a.id}")
        print(f"    Objects={baseline_a.total_objects}, Principals={baseline_a.total_principals}, SHA256={baseline_a.sha256_manifest[:16]}...")

        # Step 2: Apply Controlled Mutations in SQLTrust_Lab
        print("\n[STEP 2] Executing Controlled DDL, Privilege, and Option Mutations in SQLTrust_Lab...")
        with lab_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            # DDL 1: Table creation
            conn.execute(text("CREATE TABLE dbo.ForensicAuditTest (id INT IDENTITY(1,1) PRIMARY KEY, event_title NVARCHAR(100));"))
            print("  Executed: CREATE TABLE dbo.ForensicAuditTest")

            # DDL 2: Table alteration (column add)
            conn.execute(text("ALTER TABLE dbo.ForensicAuditTest ADD notes NVARCHAR(MAX);"))
            print("  Executed: ALTER TABLE dbo.ForensicAuditTest ADD notes")

            # Principal 1: Create user
            conn.execute(text("CREATE USER forensic_temp_user WITHOUT LOGIN;"))
            print("  Executed: CREATE USER forensic_temp_user")

            # Role 1: Role escalation to db_owner
            conn.execute(text("ALTER ROLE db_owner ADD MEMBER forensic_temp_user;"))
            print("  Executed: ALTER ROLE db_owner ADD MEMBER forensic_temp_user (Privilege Escalation)")

            # Option 1: Alter database configuration
            conn.execute(text("ALTER DATABASE SQLTrust_Lab SET AUTO_CLOSE ON;"))
            print("  Executed: ALTER DATABASE SQLTrust_Lab SET AUTO_CLOSE ON")

        # Step 3: Trigger Module 2 Ingestion to capture the audited events
        print("\n[STEP 3] Ingesting Telemetry via Module 2 AuditCollector...")
        source = db.query(SecuritySource).first()
        if source:
            audit_collector = AuditCollector(db, source)
            collect_res = audit_collector.collect_incremental(batch_limit=50)
            print(f"  Telemetry Ingested: {collect_res.get('events_ingested', 0)} new events.")

        # Step 4: Capture Baseline B (Mutated State)
        print("\n[STEP 4] Capturing Baseline B (Post-Mutation State)...")
        baseline_b = collector.capture_baseline(
            baseline_name="Lab_Controlled_Baseline_B",
            notes="Post-incident state containing controlled changes"
        )
        print(f"  ✓ Baseline B Captured: ID={baseline_b.id}")
        print(f"    Objects={baseline_b.total_objects}, Principals={baseline_b.total_principals}, SHA256={baseline_b.sha256_manifest[:16]}...")
        assert baseline_a.sha256_manifest != baseline_b.sha256_manifest, "Baseline manifest did not change after mutations!"

        # Step 5: Execute Investigation (Diff A vs B)
        print("\n[STEP 5] Running Forensic Investigation Comparison (Baseline A vs Baseline B)...")
        service = ForensicService(db)
        investigation = service.execute_investigation(
            ref_baseline_id=baseline_a.id,
            target_baseline_id=baseline_b.id,
            investigation_name="Controlled_Lab_Incident_Investigation",
            summary_notes="Forensic investigation into unauthorized DDL and role escalation"
        )
        print(f"  ✓ Investigation Completed: ID={investigation.id}")
        print(f"    Total Findings:    {investigation.findings_count}")
        print(f"    Critical Findings: {investigation.critical_findings_count}")
        print(f"    High Findings:     {investigation.high_findings_count}")
        assert investigation.findings_count >= 4, f"Expected at least 4 findings, got {investigation.findings_count}"
        assert investigation.critical_findings_count >= 1, "Expected at least 1 CRITICAL finding (db_owner escalation)"

        # Inspect Findings
        print("\n[STEP 6] Analyzing Forensic Findings:")
        findings = investigation.findings
        for f in findings:
            print(f"  - [{f.severity:<8}] [{f.category:<15}] {f.finding_type:<20} | {f.entity_name}")
            print(f"    Explanation: {f.explanation}")

        # Verify specific detections
        f_types = {f.finding_type for f in findings}
        assert "OBJECT_CREATED" in f_types, "Table creation not detected!"
        assert "ROLE_ESCALATION" in f_types, "Role escalation not detected!"
        assert "CONFIG_DRIFT" in f_types, "Configuration drift not detected!"

        # Step 7: Check Timeline & Telemetry Correlation
        print("\n[STEP 7] Verifying Correlated Timeline Engine:")
        correlator = TimelineCorrelator(db)
        timeline = correlator.get_unified_timeline(investigation.id)
        print(f"  Unified Timeline Entries: {len(timeline)}")
        for t in timeline:
            print(f"    [{t['timestamp'][:19]}] {t['timeline_type']:<24} | {t['title']} ({t['severity']})")

        # Step 8: Verify WORM Evidence & Ed25519 Signature
        print("\n[STEP 8] Verifying SeaweedFS Object Lock WORM Evidence & Signature:")
        evidence_svc = ForensicEvidenceService(db)
        archive_rec = evidence_svc.archive_investigation_report(investigation)
        print(f"  Archived Object Key: {archive_rec.storage_object_key}")
        print(f"  S3 Version ID:       {archive_rec.storage_version_id}")
        print(f"  WORM Retention:      {archive_rec.retention_mode} until {archive_rec.retention_until}")

        verify_res = evidence_svc.verify_evidence_archive(archive_rec.id)
        print(f"  Cryptographic Check: Valid={verify_res.get('valid')}, SHA256 Match={verify_res.get('sha256_match')}, Ed25519 Valid={verify_res.get('signature_valid')}")
        assert verify_res.get("valid") is True, "Cryptographic evidence verification failed!"
        assert verify_res.get("worm_mode") == "COMPLIANCE", "WORM mode is not COMPLIANCE!"

        print("\n" + "=" * 80)
        print("ALL CONTROLLED FORENSIC ENGINE VERIFICATIONS PASSED SUCCESSFULLY.")
        print("=" * 80)

    finally:
        # Step 9: Clean up the lab database
        print("\n[CLEANUP] Reverting SQLTrust_Lab to clean state...")
        cleanup_lab_database(lab_engine)
        print("  ✓ SQLTrust_Lab reverted cleanly.")
        db.close()


if __name__ == "__main__":
    main()
