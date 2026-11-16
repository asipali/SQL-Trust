"""
SQL-TRUST Module 1 — Failure and Security Tests
Tests negative execution paths, security controls, and error handling.
"""
import pytest
import os
from sqlalchemy import text
from backend.database import SessionLocal, init_db
from backend.services.database_service import DatabaseService
from backend.services.backup.engine import BackupEngine
from backend.models.backup import ProtectedDatabase, BackupRecord


@pytest.fixture(scope="module")
def db_session():
    init_db()
    db = SessionLocal()
    yield db
    db.close()


def test_system_database_rejection(db_session):
    """Verify system databases cannot be registered without explicit override."""
    service = DatabaseService(db_session)
    for sys_db in ["master", "model", "msdb", "tempdb"]:
        with pytest.raises(ValueError, match="protected SQL Server system database"):
            service.register_database(sys_db, allow_system_override=False)


def test_non_existent_database_rejection(db_session):
    """Verify attempting to register a non-existent database is rejected."""
    service = DatabaseService(db_session)
    with pytest.raises(ValueError, match="does not exist on SQL Server instance"):
        service.register_database("NonExistentDatabase_XYZ123")


def test_sql_injection_identifier_rejection(db_session):
    """Verify SQL injection payloads in identifiers are blocked."""
    service = DatabaseService(db_session)
    payloads = [
        "DB'; DROP TABLE users;--",
        "DB' OR '1'='1",
        "DB\x00NULLBYTE",
        "../../path/traversal",
        "DB && calc.exe"
    ]
    for p in payloads:
        with pytest.raises(ValueError, match="Invalid database name"):
            service.register_database(p)


def test_simple_recovery_log_backup_rejection(db_session):
    """Verify transaction log backups on SIMPLE recovery model databases are blocked with clear explanation."""
    service = DatabaseService(db_session)
    # ProtectedBusinessDB is in SIMPLE recovery model on this instance
    reg = service.register_database("ProtectedBusinessDB", allow_system_override=True)

    engine = BackupEngine(db_session)
    with pytest.raises(ValueError, match="configured in SIMPLE recovery model"):
        engine.execute_backup(reg.id, "LOG")


def test_differential_without_full_backup_rejection(db_session):
    """Verify differential backup fails gracefully if no prior full backup exists."""
    service = DatabaseService(db_session)
    # Register real existing database ProtectedBusinessDB which has no prior full backups
    reg = service.register_database("ProtectedBusinessDB", allow_system_override=True)

    engine = BackupEngine(db_session)
    with pytest.raises(ValueError, match="no prior successful base FULL backup exists"):
        engine.execute_backup(reg.id, "DIFFERENTIAL")


def test_tampered_file_detection(db_session):
    """Verify re-verification flags SHA-256 mismatch if a file is tampered."""
    service = DatabaseService(db_session)
    reg = service.register_database("SQLTrust_TestDB")

    engine = BackupEngine(db_session)
    backup = engine.execute_backup(reg.id, "FULL", operator_notes="Tamper test")
    
    local_file = os.path.join("data", "backups", backup.backup_filename)
    original_sha256 = backup.sha256

    # Temporarily append a tamper byte to the end of the file
    with open(local_file, "ab") as f:
        f.write(b"\x00")

    try:
        verify_res = engine.verify_existing_backup(backup.id)
        assert verify_res["sha256_match"] is False
        assert verify_res["file_integrity"] == "INTEGRITY_MISMATCH"
    finally:
        # Re-download original untampered file from SeaweedFS
        if backup.storage_object_key:
            engine.storage.download_file(backup.storage_object_key, local_file)
            verify_restored = engine.verify_existing_backup(backup.id)
            assert verify_restored["sha256_match"] is True
            assert verify_restored["file_integrity"] == "PASSED"
