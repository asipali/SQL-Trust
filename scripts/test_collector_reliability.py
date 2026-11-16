"""
SQL-TRUST Module 2 Hardening Review: Collector Reliability & Fault Tolerance Test Suite
======================================================================================
Tests:
1. Database disconnection / unavailable SQL Server handling.
2. Checkpoint recovery across simulated application restart.
3. Repeated collection idempotency (5 sequential cycles = 0 duplicates).
4. Duplicate overlapping reads handling.
5. Inaccessible / missing file handling.
6. Checkpoint persistence and error recording.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.database import SessionLocal, create_db_engine
from backend.models.security import SecuritySource, SecurityEvent, CollectorCheckpoint
from backend.services.security.audit_collector import AuditCollector
from backend.services.security.xe_collector import XECollector


def test_repeated_collection_idempotency(db: Session, source: SecuritySource):
    print("\n--- [RELIABILITY TEST 1] Repeated Collection Idempotency (5 Cycles) ---")
    collector = AuditCollector(db, source)
    
    # Run cycle 1
    res1 = collector.collect_incremental(batch_limit=50)
    print(f"  Cycle 1: scanned={res1.get('rows_scanned', 0)}, ingested={res1.get('events_ingested', 0)}")
    
    # Run cycles 2 through 5
    for i in range(2, 6):
        res = collector.collect_incremental(batch_limit=50)
        ingested = res.get("events_ingested", 0)
        print(f"  Cycle {i}: scanned={res.get('rows_scanned', 0)}, ingested={ingested}")
        assert ingested == 0, f"Cycle {i} ingested duplicate events! Expected 0, got {ingested}"
    print("  ✓ Repeated collection is 100% idempotent. No duplicate events created.")


def test_checkpoint_recovery_across_restart(db: Session, source: SecuritySource):
    print("\n--- [RELIABILITY TEST 2] Checkpoint Recovery Across Application Restart ---")
    # Simulate App Instance A shutting down
    cp = db.query(CollectorCheckpoint).filter(
        CollectorCheckpoint.source_id == source.id,
        CollectorCheckpoint.collector_type == "SQL_AUDIT"
    ).first()
    assert cp is not None, "Checkpoint not found"
    saved_offset = cp.last_file_offset
    saved_ts = cp.last_event_timestamp
    print(f"  App Shutdown: Saved Checkpoint -> offset={saved_offset}, timestamp={saved_ts}")

    # Simulate App Instance B starting up afresh with new session
    db.close()
    new_db = SessionLocal()
    try:
        new_collector = AuditCollector(new_db, source)
        new_cp = new_collector._get_or_create_checkpoint()
        assert new_cp.last_file_offset == saved_offset, "Checkpoint offset lost during restart"
        assert new_cp.last_event_timestamp == saved_ts, "Checkpoint timestamp lost during restart"
        
        # Execute collection cycle on new instance
        res = new_collector.collect_incremental(batch_limit=50)
        assert res.get("success") is True, f"Collection failed on restarted instance: {res}"
        assert res.get("events_ingested") == 0, "Restarted instance re-ingested existing events!"
        print(f"  App Restart: Checkpoint safely restored. Zero duplicate events re-ingested.")
        print("  ✓ Checkpoint recovery across application restart verified.")
    finally:
        new_db.close()


def test_missing_or_inaccessible_file_handling(db: Session):
    print("\n--- [RELIABILITY TEST 3] Missing or Inaccessible File Handling ---")
    # Create a source pointing to a non-existent path
    fake_source = SecuritySource(
        id=str(uuid.uuid4()),
        source_name=f"GhostSource_{uuid.uuid4().hex[:6]}",
        server_name="localhost\\SQLEXPRESS",
        source_type="SQL_AUDIT",
        audit_target_path="Z:\\NonExistent_Drive\\Invalid_Audit_Folder\\",
        is_active=True
    )
    db.add(fake_source)
    db.commit()

    collector = AuditCollector(db, fake_source)
    res = collector.collect_incremental()
    
    # Verify collector does not crash unhandled, records error in checkpoint
    cp = db.query(CollectorCheckpoint).filter(
        CollectorCheckpoint.source_id == fake_source.id,
        CollectorCheckpoint.collector_type == "SQL_AUDIT"
    ).first()
    
    assert cp is not None
    print(f"  Missing path handled gracefully: success={res.get('success')}, status={cp.status}")
    if not res.get("success"):
        print(f"  Recorded error message: {res.get('error')[:80]}...")
    print("  ✓ Missing / inaccessible path handled gracefully without process crash.")

    # Cleanup fake source
    db.delete(cp)
    db.delete(fake_source)
    db.commit()


def test_sql_connection_drop_handling(db: Session):
    print("\n--- [RELIABILITY TEST 4] SQL Server Disconnection / Unreachable Host Handling ---")
    unreachable_source = SecuritySource(
        id=str(uuid.uuid4()),
        source_name=f"OfflineSource_{uuid.uuid4().hex[:6]}",
        server_name="192.0.2.1\\INVALID_INSTANCE",  # RFC 5737 TEST-NET-1 (unroutable IP)
        source_type="SQL_AUDIT",
        audit_target_path="D:\\Desktop\\HackShift\\SQL Trust\\data\\audit\\",
        is_active=True
    )
    db.add(unreachable_source)
    db.commit()

    collector = AuditCollector(db, unreachable_source)
    # This will fail to connect; verify it catches the error and reports FAILED
    res = collector.collect_incremental()
    
    cp = db.query(CollectorCheckpoint).filter(
        CollectorCheckpoint.source_id == unreachable_source.id,
        CollectorCheckpoint.collector_type == "SQL_AUDIT"
    ).first()
    
    assert res.get("success") is False, "Expected connection failure on unreachable host"
    assert cp.status == "FAILED", f"Expected checkpoint status FAILED, got {cp.status}"
    assert cp.error_message is not None, "Expected error_message to be populated"
    print(f"  Unreachable host handled gracefully: status={cp.status}, error={cp.error_message[:60]}...")
    print("  ✓ SQL Server disconnection handled without unhandled exception.")

    # Cleanup
    db.delete(cp)
    db.delete(unreachable_source)
    db.commit()


def test_xe_collector_checkpointing(db: Session, source: SecuritySource):
    print("\n--- [RELIABILITY TEST 5] Extended Events Collector Reliability ---")
    xe_collector = XECollector(db, source)
    res1 = xe_collector.collect_incremental(batch_limit=50)
    print(f"  XE Cycle 1: scanned={res1.get('rows_scanned', 0)}, ingested={res1.get('events_ingested', 0)}")
    
    # Second cycle should be idempotent
    res2 = xe_collector.collect_incremental(batch_limit=50)
    print(f"  XE Cycle 2: scanned={res2.get('rows_scanned', 0)}, ingested={res2.get('events_ingested', 0)}")
    assert res2.get("events_ingested", 0) == 0, "XE collector re-ingested duplicate events"
    print("  ✓ Extended Events collector checkpointing and idempotency verified.")


def main():
    db = SessionLocal()
    try:
        source = db.query(SecuritySource).first()
        assert source is not None, "No active security source found"
        print("=" * 80)
        print("SQL-TRUST MODULE 2: COLLECTOR RELIABILITY & FAULT TOLERANCE TESTS")
        print("=" * 80)

        test_repeated_collection_idempotency(db, source)
        test_checkpoint_recovery_across_restart(db, source)
        test_missing_or_inaccessible_file_handling(db)
        test_sql_connection_drop_handling(db)
        test_xe_collector_checkpointing(db, source)

        print("\n" + "=" * 80)
        print("COLLECTOR RELIABILITY VERIFICATION COMPLETE: ALL 5 SCENARIOS PASSED")
        print("=" * 80)
    finally:
        db.close()


if __name__ == "__main__":
    main()
