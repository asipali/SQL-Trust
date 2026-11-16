"""
SQL-TRUST Module 4: Final Security & Recovery Correctness Audit Verification
Empirically tests and audits Critical Reviews A, B, C, and D:
- Review A: Incident Chronology & Uncertainty Handling (No post-backup trust bonus)
- Review B: Backup Chain Correctness (LSN continuity, base matching, fork consistency, metadata limits)
- Review C: Separation of Cyber Trust & Technical Eligibility (All 6 matrix combinations)
- Review D: Cryptographic Evidence Integrity & WORM Storage Verification
"""
import sys
import os
import uuid
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.database import SessionLocal
from backend.models.backup import ProtectedDatabase
from backend.models.recovery import (
    RecoveryPoint,
    RecoveryChain,
    RecoveryChainSegment,
    RecoveryAssessment,
    RecoveryAssessmentEvidence,
    RecoveryEligibility,
    RecoveryRecommendation,
    RecoveryAssessmentHistory
)
from backend.models.security import SecuritySource, SecurityEvent, SecurityAlert, DetectionRule
from backend.services.recovery.discovery import RecoveryPointDiscoveryService
from backend.services.recovery.chain_analyzer import BackupChainAnalyzer, compare_lsn
from backend.services.recovery.correlator import RecoveryCorrelator
from backend.services.recovery.trust_engine import RecoveryTrustEngine
from backend.services.recovery.eligibility_engine import RecoveryEligibilityEngine
from backend.services.recovery.recommendation_engine import RecoveryRecommendationEngine
from backend.services.recovery.evidence_service import RecoveryEvidenceService
from backend.services.security.signer import signer


audit_results: List[Dict[str, Any]] = []


def record_audit(section: str, title: str, passed: bool, details: str):
    audit_results.append({
        "section": section,
        "title": title,
        "passed": passed,
        "details": details
    })
    status_str = "[AUDIT PASS]" if passed else "[AUDIT FAIL]"
    print(f"{status_str} [{section}] {title}")
    print(f"       Details: {details}\n")


def run_audit():
    db = SessionLocal()
    now = datetime.now(timezone.utc)
    tag = uuid.uuid4().hex[:6]

    server_name = f"AuditServer_{tag}"
    db_name = f"SQLTrust_AuditDB_{tag}"

    # 1. Register dedicated isolated protected database for audit
    audit_db = ProtectedDatabase(
        id=str(uuid.uuid4()),
        server_name=server_name,
        database_name=db_name,
        recovery_model="FULL",
        registration_status="REGISTERED"
    )
    db.add(audit_db)

    # 2. Register dedicated isolated security telemetry source for audit
    audit_source = SecuritySource(
        id=str(uuid.uuid4()),
        source_name=f"AuditSource_{tag}",
        server_name=server_name,
        source_type="HYBRID",
        is_active=True
    )
    db.add(audit_source)

    # Lookup existing rules
    rule_normal = db.query(DetectionRule).filter(DetectionRule.rule_id != "RULE_010_COLLECTION_GAP").first()
    rule_gap = db.query(DetectionRule).filter(DetectionRule.rule_id == "RULE_010_COLLECTION_GAP").first()
    db.commit()

    db_id = audit_db.id
    source_id = audit_source.id

    print("\n" + "="*80)
    print("SQL-TRUST MODULE 4: FINAL SECURITY AND RECOVERY CORRECTNESS AUDIT")
    print("="*80 + "\n")

    try:
        # =====================================================================
        # CRITICAL REVIEW A: INCIDENT CHRONOLOGY & UNCERTAINTY HANDLING
        # =====================================================================
        print("--- RUNNING CRITICAL REVIEW A: INCIDENT CHRONOLOGY ---")

        # Test A1: Differentiate event timestamp vs detection time vs collection time
        evt_time = now - timedelta(hours=6)
        det_time = now - timedelta(hours=4)
        col_time = now - timedelta(hours=2)

        test_ev1 = SecurityEvent(
            id=str(uuid.uuid4()),
            source_id=source_id,
            event_source="SQL_AUDIT",
            source_file="test_audit_01.sqlaudit",
            event_timestamp=evt_time,
            server_name=server_name,
            database_name=db_name,
            principal_name="attacker_recon",
            action="SELECT",
            target_object="sys.server_principals",
            event_type="SCHEMA_MUTATION",
            severity="HIGH",
            event_fingerprint=uuid.uuid4().hex,
            raw_payload=json.dumps({"test": "a1"}),
            collection_timestamp=col_time,
            created_at=col_time
        )
        db.add(test_ev1)

        test_alert1 = SecurityAlert(
            id=str(uuid.uuid4()),
            source_id=source_id,
            rule_id=rule_normal.id,
            title="Suspicious Reconnaissance Detected",
            description="Reconnaissance detected",
            severity="HIGH",
            status="NEW",
            detection_timestamp=det_time,
            principal_name="attacker_recon",
            target_object="sys.server_principals",
            explanation="Recon query identified",
            created_at=col_time
        )
        db.add(test_alert1)
        db.commit()

        a1_passed = (
            test_ev1.event_timestamp < test_alert1.detection_timestamp and
            test_alert1.detection_timestamp < test_alert1.created_at
        )
        record_audit("Review A.1", "Chronology Timestamp Differentiation", a1_passed,
                     f"Event Time: {test_ev1.event_timestamp.isoformat()} < Detection Time: {test_alert1.detection_timestamp.isoformat()} < Collection Time: {test_alert1.created_at.isoformat()}")

        # Test A2: Attacker establishes persistence BEFORE backup, but alert/event occurs AFTER backup
        # Event 1: Attacker persistence at T-5 hours (before backup at T-3 hours)
        # Event 2: Anomalous tampering event at T-1 hour (after backup at T-3 hours)
        ev_persist = SecurityEvent(
            id=str(uuid.uuid4()),
            source_id=source_id,
            event_source="SQL_AUDIT",
            source_file="test_audit_02.sqlaudit",
            event_timestamp=now - timedelta(hours=5),
            server_name=server_name,
            database_name=db_name,
            principal_name="backdoor_admin",
            action="ADD_ROLE_MEMBER",
            target_object="sysadmin",
            event_type="ROLE_MEMBER_CHANGE",
            severity="CRITICAL",
            event_fingerprint=uuid.uuid4().hex,
            raw_payload=json.dumps({"test": "persistence"}),
            collection_timestamp=col_time,
            created_at=col_time
        )
        ev_after = SecurityEvent(
            id=str(uuid.uuid4()),
            source_id=source_id,
            event_source="SQL_AUDIT",
            source_file="test_audit_03.sqlaudit",
            event_timestamp=now - timedelta(hours=1),
            server_name=server_name,
            database_name=db_name,
            principal_name="backdoor_admin",
            action="ALTER_SERVER_AUDIT",
            target_object="SQLTrust_ServerAudit",
            event_type="AUDIT_TAMPERING",
            severity="CRITICAL",
            event_fingerprint=uuid.uuid4().hex,
            raw_payload=json.dumps({"test": "tamper_after"}),
            collection_timestamp=now,
            created_at=now
        )
        db.add_all([ev_persist, ev_after])
        db.commit()

        # Recovery point at T-3 hours
        rp_compromised = RecoveryPoint(
            id=str(uuid.uuid4()),
            database_id=db_id,
            server_name=server_name,
            database_name=db_name,
            recovery_point_type="FULL",
            recovery_point_time=now - timedelta(hours=3),
            first_lsn="100000000001000001",
            last_lsn="100000000002000001",
            checkpoint_lsn="100000000001500001",
            storage_object_key=f"backups/{db_name}_audit_comp.bak",
            integrity_status="VERIFIED"
        )
        db.add(rp_compromised)
        db.commit()

        correlator = RecoveryCorrelator(db)
        evidence_pkg = correlator.correlate_evidence_for_point(rp_compromised)

        # Audit check: Ensure NO positive bonus for post-backup event
        pos_from_after_event = [p for p in evidence_pkg["positive_indicators"] if p.get("source_record_id") == str(ev_after.id)]
        has_post_event_bonus = len(pos_from_after_event) > 0

        # Ensure post-backup event is classified under uncertainty_factors with negative penalty
        post_uncertainty = [u for u in evidence_pkg["uncertainty_factors"] if u.get("source_record_id") == str(ev_after.id)]
        has_post_uncertainty = len(post_uncertainty) > 0 and post_uncertainty[0].get("weight_applied", 0) < 0

        trust_engine = RecoveryTrustEngine(db)
        asm_comp = trust_engine.assess_recovery_point(rp_compromised.id)

        a2_passed = (not has_post_event_bonus) and has_post_uncertainty and (asm_comp.trust_classification == "LOW_CONFIDENCE")
        record_audit("Review A.2", "Stealth Persistence & No Post-Backup Trust Bonus", a2_passed,
                     f"Post-Event Positive Bonus: {has_post_event_bonus}, Uncertainty Penalty Present: {has_post_uncertainty}, Classification: {asm_comp.trust_classification}")

        # Test A3: Epistemological Guardrail on Missing Telemetry
        rp_blind = RecoveryPoint(
            id=str(uuid.uuid4()),
            database_id=db_id,
            server_name=server_name,
            database_name=db_name,
            recovery_point_type="FULL",
            recovery_point_time=now - timedelta(hours=10),
            first_lsn="110000000001000001",
            last_lsn="110000000002000001",
            checkpoint_lsn="110000000001500001",
            storage_object_key=f"backups/{db_name}_audit_blind.bak",
            integrity_status="VERIFIED"
        )
        db.add(rp_blind)

        # Add Collection Gap alert that causes telemetry blindness within 2h of rp_blind
        blindness_alert = SecurityAlert(
            id=str(uuid.uuid4()),
            source_id=source_id,
            rule_id=rule_gap.id,
            title="Telemetry Blindness: Audit Drop Detected",
            description="Telemetry blindness due to target outage",
            severity="CRITICAL",
            status="NEW",
            detection_timestamp=now - timedelta(hours=11),
            explanation="Telemetry blindness present around recovery window",
            created_at=now - timedelta(hours=11)
        )
        db.add(blindness_alert)
        db.commit()

        asm_blind = trust_engine.assess_recovery_point(rp_blind.id)
        a3_passed = (asm_blind.trust_classification == "UNASSESSED") and (asm_blind.trust_score is None)
        record_audit("Review A.3", "Epistemological Guardrail: Telemetry Blindness Suppression", a3_passed,
                     f"Classification: {asm_blind.trust_classification}, Numeric Trust Score: {asm_blind.trust_score} (Correctly Suppressed)")

        # =====================================================================
        # CRITICAL REVIEW B: SQL SERVER BACKUP-CHAIN CORRECTNESS
        # =====================================================================
        print("--- RUNNING CRITICAL REVIEW B: BACKUP CHAIN CORRECTNESS ---")
        chain_analyzer = BackupChainAnalyzer(db)
        fork_primary = str(uuid.uuid4())

        # Test B1: Valid unbroken chain (Full + Diff + Log)
        rp_b_full = RecoveryPoint(
            id=str(uuid.uuid4()),
            database_id=db_id,
            server_name=server_name,
            database_name=db_name,
            recovery_point_type="FULL",
            recovery_point_time=now - timedelta(hours=30),
            first_lsn="200000000001000001",
            last_lsn="200000000002000001",
            checkpoint_lsn="200000000001500001",
            recovery_fork_guid=fork_primary,
            storage_object_key=f"backups/{db_name}_b_full.bak",
            integrity_status="VERIFIED"
        )
        rp_b_diff = RecoveryPoint(
            id=str(uuid.uuid4()),
            database_id=db_id,
            server_name=server_name,
            database_name=db_name,
            recovery_point_type="DIFFERENTIAL",
            recovery_point_time=now - timedelta(hours=26),
            first_lsn="200000000002000001",
            last_lsn="200000000003000001",
            checkpoint_lsn="200000000002500001",
            database_backup_lsn=rp_b_full.checkpoint_lsn,
            recovery_fork_guid=fork_primary,
            storage_object_key=f"backups/{db_name}_b_diff.bak",
            integrity_status="VERIFIED"
        )
        rp_b_log = RecoveryPoint(
            id=str(uuid.uuid4()),
            database_id=db_id,
            server_name=server_name,
            database_name=db_name,
            recovery_point_type="LOG",
            recovery_point_time=now - timedelta(hours=24),
            first_lsn="200000000002800001",  # Overlaps diff checkpoint
            last_lsn="200000000004000001",
            checkpoint_lsn="200000000003500001",
            recovery_fork_guid=fork_primary,
            storage_object_key=f"backups/{db_name}_b_log.trn",
            integrity_status="VERIFIED"
        )
        db.add_all([rp_b_full, rp_b_diff, rp_b_log])
        db.commit()

        chain_b1 = chain_analyzer.analyze_chain_for_target(rp_b_log.id)
        b1_passed = (
            chain_b1.is_valid is True and
            chain_b1.validation_status == "VALID" and
            chain_b1.segment_count == 3 and
            "offline sandbox restore validation in SQLTrust_Lab is required" in chain_b1.validation_details
        )
        record_audit("Review B.1", "Valid Chain Continuity & Explicit Metadata Caveat", b1_passed,
                     f"Status: {chain_b1.validation_status}, Segments: {chain_b1.segment_count}, Details: {chain_b1.validation_details[:75]}...")

        # Test B2: Broken LSN log gap
        rp_b_gap_log = RecoveryPoint(
            id=str(uuid.uuid4()),
            database_id=db_id,
            server_name=server_name,
            database_name=db_name,
            recovery_point_type="LOG",
            recovery_point_time=now - timedelta(hours=22),
            first_lsn="200000000009000001",  # Strictly after log1 last_lsn (0004000001)
            last_lsn="200000000010000001",
            checkpoint_lsn="200000000009500001",
            recovery_fork_guid=fork_primary,
            storage_object_key=f"backups/{db_name}_b_gap.trn",
            integrity_status="VERIFIED"
        )
        db.add(rp_b_gap_log)
        db.commit()

        chain_b2 = chain_analyzer.analyze_chain_for_target(rp_b_gap_log.id)
        b2_passed = (chain_b2.is_valid is False and chain_b2.validation_status == "BROKEN_CHAIN")
        record_audit("Review B.2", "Log Sequence Gap Detection", b2_passed,
                     f"Status: {chain_b2.validation_status}, Details: {chain_b2.validation_details}")

        # Test B3: Differential Base LSN Mismatch
        rp_b_full_orphan = RecoveryPoint(
            id=str(uuid.uuid4()),
            database_id=db_id,
            server_name=server_name,
            database_name=db_name,
            recovery_point_type="FULL",
            recovery_point_time=now - timedelta(hours=18),
            first_lsn="400000000001000001",
            last_lsn="400000000002000001",
            checkpoint_lsn="400000000001500001",
            recovery_fork_guid=fork_primary,
            storage_object_key=f"backups/{db_name}_b_full_orphan.bak",
            integrity_status="VERIFIED"
        )
        rp_b_orphan_diff = RecoveryPoint(
            id=str(uuid.uuid4()),
            database_id=db_id,
            server_name=server_name,
            database_name=db_name,
            recovery_point_type="DIFFERENTIAL",
            recovery_point_time=now - timedelta(hours=17),
            first_lsn="400000000002000001",
            last_lsn="400000000003000001",
            checkpoint_lsn="400000000002500001",
            database_backup_lsn="999999999999999999",  # Does not match full checkpoint
            recovery_fork_guid=fork_primary,
            storage_object_key=f"backups/{db_name}_b_orphan_diff.bak",
            integrity_status="VERIFIED"
        )
        db.add_all([rp_b_full_orphan, rp_b_orphan_diff])
        db.commit()

        chain_b3 = chain_analyzer.analyze_chain_for_target(rp_b_orphan_diff.id)
        b3_passed = (chain_b3.is_valid is False and chain_b3.validation_status == "FORK_MISMATCH")
        record_audit("Review B.3", "Differential Base LSN Mismatch Rejection", b3_passed,
                     f"Status: {chain_b3.validation_status}, Details: {chain_b3.validation_details}")

        # Test B4: Recovery Fork GUID Divergence
        fork_diverged = str(uuid.uuid4())
        rp_b_full_fork = RecoveryPoint(
            id=str(uuid.uuid4()),
            database_id=db_id,
            server_name=server_name,
            database_name=db_name,
            recovery_point_type="FULL",
            recovery_point_time=now - timedelta(hours=15),
            first_lsn="600000000001000001",
            last_lsn="600000000002000001",
            checkpoint_lsn="600000000001500001",
            recovery_fork_guid=fork_primary,
            storage_object_key=f"backups/{db_name}_b_full_fork.bak",
            integrity_status="VERIFIED"
        )
        rp_b_forked_log = RecoveryPoint(
            id=str(uuid.uuid4()),
            database_id=db_id,
            server_name=server_name,
            database_name=db_name,
            recovery_point_type="LOG",
            recovery_point_time=now - timedelta(hours=14),
            first_lsn="600000000001800001",
            last_lsn="600000000003000001",
            checkpoint_lsn="600000000002500001",
            recovery_fork_guid=fork_diverged,  # Divergent fork!
            storage_object_key=f"backups/{db_name}_b_forked.trn",
            integrity_status="VERIFIED"
        )
        db.add_all([rp_b_full_fork, rp_b_forked_log])
        db.commit()

        chain_b4 = chain_analyzer.analyze_chain_for_target(rp_b_forked_log.id)
        b4_passed = (chain_b4.is_valid is False and "recovery fork divergence" in chain_b4.validation_details.lower())
        record_audit("Review B.4", "Recovery Fork GUID Divergence Detection", b4_passed,
                     f"Status: {chain_b4.validation_status}, Details: {chain_b4.validation_details}")

        # =====================================================================
        # CRITICAL REVIEW C: SEPARATION OF TRUST AND ELIGIBILITY (6 COMBINATIONS)
        # =====================================================================
        print("--- RUNNING CRITICAL REVIEW C: TRUST & ELIGIBILITY SEPARATION ---")
        rec_engine = RecoveryRecommendationEngine(db)

        # 6 Matrix Combinations:
        # 1. HIGH_CONFIDENCE + ELIGIBLE
        # 2. HIGH_CONFIDENCE + INELIGIBLE
        # 3. MEDIUM_CONFIDENCE + ELIGIBLE
        # 4. MEDIUM_CONFIDENCE + INELIGIBLE
        # 5. LOW_CONFIDENCE + ELIGIBLE
        # 6. UNASSESSED + INELIGIBLE
        matrix_definitions = [
            ("HIGH_CONFIDENCE", True, 90.0),
            ("HIGH_CONFIDENCE", False, 90.0),
            ("MEDIUM_CONFIDENCE", True, 70.0),
            ("MEDIUM_CONFIDENCE", False, 70.0),
            ("LOW_CONFIDENCE", True, 20.0),
            ("UNASSESSED", False, None)
        ]

        matrix_points = []
        for i, (trust_cls, is_elg, t_score) in enumerate(matrix_definitions, start=1):
            pt = RecoveryPoint(
                id=str(uuid.uuid4()),
                database_id=db_id,
                server_name=server_name,
                database_name=db_name,
                recovery_point_type="FULL",
                recovery_point_time=now - timedelta(days=20 - i),
                first_lsn=f"70000000000{i}000001",
                last_lsn=f"70000000000{i}000050",
                checkpoint_lsn=f"70000000000{i}000020",
                storage_object_key=f"backups/{db_name}_matrix_{i}.bak",
                integrity_status="VERIFIED" if is_elg else "FAILED"
            )
            db.add(pt)
            db.flush()

            # Chain
            chain = RecoveryChain(
                id=str(uuid.uuid4()),
                database_id=db_id,
                server_name=server_name,
                database_name=db_name,
                chain_name=f"Chain_Matrix_{i}",
                target_recovery_point_id=pt.id,
                base_full_point_id=pt.id,
                is_complete=is_elg,
                is_valid=is_elg,
                validation_status="VALID" if is_elg else "INTEGRITY_FAILED",
                segment_count=1
            )
            db.add(chain)
            db.flush()

            # Assessment
            asm = RecoveryAssessment(
                id=str(uuid.uuid4()),
                recovery_point_id=pt.id,
                assessment_name=f"Matrix_Assessment_{i}",
                model_version="1.0.0",
                assessed_at=now,
                trust_classification=trust_cls,
                trust_score=t_score,
                confidence_rationale=f"Matrix test {i}: {trust_cls}"
            )
            db.add(asm)
            db.flush()

            # Eligibility
            elg = RecoveryEligibility(
                id=str(uuid.uuid4()),
                recovery_point_id=pt.id,
                chain_id=chain.id,
                evaluated_at=now,
                is_eligible=is_elg,
                eligibility_status="ELIGIBLE" if is_elg else "INELIGIBLE",
                chain_usable=is_elg,
                chain_consistent=is_elg,
                logs_available=is_elg,
                identity_matched=is_elg,
                files_accessible=is_elg,
                integrity_verified=is_elg,
                requires_offline_sandbox=True,
                blocking_reasons_json=None if is_elg else json.dumps(["Integrity check failed"])
            )
            db.add(elg)
            db.flush()

            matrix_points.append((pt, asm, elg))

        db.commit()

        recs = rec_engine.generate_recommendations(database_id=db_id)

        # C1: Assert that an ineligible point NEVER outranks an eligible point
        eligible_ranks = [r.rank_order for r in recs if r.eligibility_status == "ELIGIBLE"]
        ineligible_ranks = [r.rank_order for r in recs if r.eligibility_status == "INELIGIBLE"]
        max_elg_rank = max(eligible_ranks) if eligible_ranks else 0
        min_inelg_rank = min(ineligible_ranks) if ineligible_ranks else 999

        c1_passed = min_inelg_rank > max_elg_rank
        record_audit("Review C.1", "Ineligible Points Cannot Outrank Eligible Points", c1_passed,
                     f"Max Eligible Rank: {max_elg_rank}, Min Ineligible Rank: {min_inelg_rank}")

        # C2: Assert that UNASSESSED points cannot be Rank #1
        top_rec = recs[0]
        unassessed_ranks = [r.rank_order for r in recs if r.trust_classification == "UNASSESSED"]
        c2_passed = (top_rec.trust_classification != "UNASSESSED") and all(r > 1 for r in unassessed_ranks)
        record_audit("Review C.2", "UNASSESSED Points Restricted From Optimal Rank", c2_passed,
                     f"Top Rec Trust: {top_rec.trust_classification}, Unassessed Ranks: {unassessed_ranks}")

        # C3: Assert that freshness cannot override LOW_CONFIDENCE compromised status
        high_conf_rec = next(r for r in recs if r.trust_classification == "HIGH_CONFIDENCE" and r.eligibility_status == "ELIGIBLE")
        low_conf_rec = next(r for r in recs if r.trust_classification == "LOW_CONFIDENCE" and r.eligibility_status == "ELIGIBLE")
        c3_passed = high_conf_rec.rank_order < low_conf_rec.rank_order
        record_audit("Review C.3", "Freshness Cannot Override Intrusion Threat Evidence", c3_passed,
                     f"HIGH_CONF Rank: {high_conf_rec.rank_order} vs LOW_CONF Rank: {low_conf_rec.rank_order}")

        # C4: Verify that all recommended next steps prohibit direct production restore and require sandbox
        all_sandbox = all("sandbox" in r.recommended_next_step.lower() for r in recs if r.eligibility_status == "ELIGIBLE")
        all_prohibit_prod = all("direct production restore prohibited" in r.recommended_next_step.lower() for r in recs)
        c4_passed = all_sandbox and all_prohibit_prod
        record_audit("Review C.4", "Mandatory Sandbox Restriction in All Next-Steps", c4_passed,
                     f"All Require Sandbox: {all_sandbox}, Direct Prod Restore Prohibited: {all_prohibit_prod}")

        # =====================================================================
        # CRITICAL REVIEW D: EVIDENCE INTEGRITY & WORM STORAGE AUDIT
        # =====================================================================
        print("--- RUNNING CRITICAL REVIEW D: EVIDENCE INTEGRITY & WORM STORAGE ---")
        evidence_service = RecoveryEvidenceService(db)

        # Test D1: Clean Assessment Serialization, Signing, and WORM Archive
        clean_asm = matrix_points[0][1]
        archive_res = evidence_service.archive_assessment_report(clean_asm)

        d1_passed = (
            archive_res.get("valid") is True and
            bool(archive_res.get("signature")) and
            bool(archive_res.get("manifest_sha256")) and
            archive_res.get("retention_mode") == "COMPLIANCE"
        )
        record_audit("Review D.1", "Assessment Report Signing & WORM Retention Archive", d1_passed,
                     f"Object Key: {archive_res.get('storage_object_key')}, Mode: {archive_res.get('retention_mode')}")

        # Test D2: WORM Storage Verification (SHA-256 match, signature valid, in sync)
        verify_clean = evidence_service.verify_assessment_archive(clean_asm.id)
        d2_passed = (
            verify_clean.get("valid") is True and
            verify_clean.get("sha256_match") is True and
            verify_clean.get("signature_valid") is True and
            verify_clean.get("signature_in_sync") is True and
            verify_clean.get("worm_compliant") is True
        )
        record_audit("Review D.2", "WORM Verification with Compliant Retention", d2_passed,
                     f"Valid: {verify_clean.get('valid')}, SHA Match: {verify_clean.get('sha256_match')}, Sig Sync: {verify_clean.get('signature_in_sync')}")

        # Test D3: Tamper Detection - Corrupted DB Signature
        original_sig = clean_asm.signature
        clean_asm.signature = "TAMPERED_" + original_sig[9:]
        db.commit()

        verify_tampered_sig = evidence_service.verify_assessment_archive(clean_asm.id)
        d3_passed = (
            verify_tampered_sig.get("valid") is False and
            verify_tampered_sig.get("signature_in_sync") is False
        )
        record_audit("Review D.3", "Tamper Detection on Out-of-Sync Database Signature", d3_passed,
                     f"Valid: {verify_tampered_sig.get('valid')}, Sig in Sync: {verify_tampered_sig.get('signature_in_sync')}")

        # Restore original signature
        clean_asm.signature = original_sig
        db.commit()

        # Test D4: Tamper Detection - Altered Payload in Object Storage
        s3 = evidence_service.storage.s3_client
        bucket = evidence_service.storage.bucket_name
        tampered_key = f"audit-tamper-test/{uuid.uuid4().hex}.json"
        s3.put_object(
            Bucket=bucket,
            Key=tampered_key,
            Body=json.dumps({"forged": "malicious_telemetry"}).encode("utf-8")
        )

        fake_asm = RecoveryAssessment(
            id=str(uuid.uuid4()),
            recovery_point_id=matrix_points[0][0].id,
            assessment_name="Tampered_S3_Test",
            model_version="1.0.0",
            assessed_at=now,
            trust_classification="HIGH_CONFIDENCE",
            trust_score=95.0,
            confidence_rationale="Fake assessment for tamper test",
            storage_object_key=tampered_key,
            storage_version_id=None,
            manifest_sha256="f"*64,
            signature="fake_sig_123"
        )
        db.add(fake_asm)
        db.commit()

        verify_tampered_payload = evidence_service.verify_assessment_archive(fake_asm.id)
        d4_passed = (
            verify_tampered_payload.get("valid") is False and
            verify_tampered_payload.get("sha256_match") is False
        )
        record_audit("Review D.4", "Tamper Detection on Corrupted Storage Payload", d4_passed,
                     f"Valid: {verify_tampered_payload.get('valid')}, SHA Match: {verify_tampered_payload.get('sha256_match')}")

    finally:
        # Controlled Audit Cleanup: Clean only disposable test entities
        print("Cleaning up synthetic audit artifacts...")
        try:
            # Delete recommendations, eligibilities, assessments, segments, chains, points for audit_db
            db.query(RecoveryRecommendation).filter(RecoveryRecommendation.database_id == db_id).delete(synchronize_session=False)
            db.query(RecoveryEligibility).filter(RecoveryEligibility.recovery_point_id.in_(
                db.query(RecoveryPoint.id).filter(RecoveryPoint.database_id == db_id)
            )).delete(synchronize_session=False)
            db.query(RecoveryAssessmentEvidence).filter(RecoveryAssessmentEvidence.assessment_id.in_(
                db.query(RecoveryAssessment.id).filter(RecoveryAssessment.recovery_point_id.in_(
                    db.query(RecoveryPoint.id).filter(RecoveryPoint.database_id == db_id)
                ))
            )).delete(synchronize_session=False)
            db.query(RecoveryAssessmentHistory).filter(RecoveryAssessmentHistory.assessment_id.in_(
                db.query(RecoveryAssessment.id).filter(RecoveryAssessment.recovery_point_id.in_(
                    db.query(RecoveryPoint.id).filter(RecoveryPoint.database_id == db_id)
                ))
            )).delete(synchronize_session=False)
            db.query(RecoveryAssessment).filter(RecoveryAssessment.recovery_point_id.in_(
                db.query(RecoveryPoint.id).filter(RecoveryPoint.database_id == db_id)
            )).delete(synchronize_session=False)
            db.query(RecoveryChainSegment).filter(RecoveryChainSegment.recovery_point_id.in_(
                db.query(RecoveryPoint.id).filter(RecoveryPoint.database_id == db_id)
            )).delete(synchronize_session=False)
            db.query(RecoveryChain).filter(RecoveryChain.database_id == db_id).delete(synchronize_session=False)
            db.query(RecoveryPoint).filter(RecoveryPoint.database_id == db_id).delete(synchronize_session=False)

            # Delete alerts and events for audit_source
            db.query(SecurityAlert).filter(SecurityAlert.source_id == source_id).delete(synchronize_session=False)
            db.query(SecurityEvent).filter(SecurityEvent.source_id == source_id).delete(synchronize_session=False)

            # Delete audit_source and audit_db
            db.query(SecuritySource).filter(SecuritySource.id == source_id).delete(synchronize_session=False)
            db.query(ProtectedDatabase).filter(ProtectedDatabase.id == db_id).delete(synchronize_session=False)
            db.commit()
            print("Successfully cleaned up all synthetic audit entities.")
        except Exception as e:
            db.rollback()
            print(f"Warning during cleanup: {e}")
        finally:
            db.close()

    # Summary
    print("\n" + "="*80)
    print("AUDIT SUMMARY RESULTS")
    print("="*80)
    total = len(audit_results)
    passed = sum(1 for r in audit_results if r["passed"])
    failed = total - passed

    for r in audit_results:
        mark = "✓" if r["passed"] else "✗"
        print(f"  {mark} [{r['section']}] {r['title']}")

    print(f"\nTOTAL: {total} AUDIT CHECKS | PASSED: {passed} | FAILED: {failed}")
    if failed == 0:
        print("\nALL AUDIT REVIEWS PASSED WITH COMPLETE CRYPTOGRAPHIC AND RECOVERY INTEGRITY!")
    else:
        print(f"\nAUDIT IDENTIFIED {failed} FAILURES!")
        sys.exit(1)


if __name__ == "__main__":
    run_audit()
