"""
SQL-TRUST Module 1 — Integration Tests
Tests real operations against SQL Server 2022 and SeaweedFS using dedicated test database.
"""
import os
import pytest
from sqlalchemy import text
from backend.database import SessionLocal, init_db
from backend.services.database_service import DatabaseService
from backend.services.backup.engine import BackupEngine
from backend.services.storage.seaweedfs import SeaweedFSStorageProvider
from backend.models.backup import BackupRecord, BackupManifest


@pytest.fixture(scope="module")
def setup_environment():
    """Ensure control database tables and test database exist."""
    init_db()
    db = SessionLocal()
    db_service = DatabaseService(db)

    # Ensure dedicated test database SQLTrust_TestDB exists with FULL recovery
    with db_service.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        exists = conn.execute(text("SELECT database_id FROM sys.databases WHERE name = 'SQLTrust_TestDB'")).scalar()
        if not exists:
            conn.execute(text("CREATE DATABASE SQLTrust_TestDB"))
            conn.execute(text("ALTER DATABASE SQLTrust_TestDB SET RECOVERY FULL"))
            conn.execute(text("CREATE TABLE [SQLTrust_TestDB].dbo.AuditLogs (id INT IDENTITY PRIMARY KEY, event_name VARCHAR(100))"))
            conn.execute(text("INSERT INTO [SQLTrust_TestDB].dbo.AuditLogs (event_name) VALUES ('Init Integration Test')"))

    yield db
    db.close()


def test_sql_server_connection(setup_environment):
    """Verify live SQL Server 2022 connection."""
    db = setup_environment
    service = DatabaseService(db)
    res = service.test_connection()
    assert res["connected"] is True
    assert "SQL Server 2022" in res["version"]


def test_database_discovery(setup_environment):
    """Verify discovery of SQL Server databases and system flag."""
    db = setup_environment
    service = DatabaseService(db)
    discovered = service.discover_databases()
    assert len(discovered) > 0
    names = [d["name"].lower() for d in discovered]
    assert "master" in names
    assert "sqltrust_testdb" in names

    master_meta = next(d for d in discovered if d["name"].lower() == "master")
    assert master_meta["is_system"] is True


def test_database_registration(setup_environment):
    """Verify explicit registration of SQLTrust_TestDB."""
    db = setup_environment
    service = DatabaseService(db)
    reg = service.register_database("SQLTrust_TestDB")
    assert reg is not None
    assert reg.database_name == "SQLTrust_TestDB"
    assert reg.recovery_model == "FULL"
    assert reg.registration_status == "REGISTERED"


def test_end_to_end_full_backup(setup_environment):
    """Verify FULL backup execution, LSN extraction, checksum, SHA-256, SeaweedFS upload, and manifest creation."""
    db = setup_environment
    service = DatabaseService(db)
    reg = service.register_database("SQLTrust_TestDB")

    engine = BackupEngine(db)
    backup = engine.execute_backup(reg.id, "FULL", operator_notes="Integration Test Full Backup")

    assert backup.backup_status == "COMPLETED"
    assert backup.sql_verification_status == "PASSED"
    assert backup.storage_upload_status == "COMPLETED"
    assert backup.backup_size_bytes > 0
    assert backup.sha256 is not None
    assert backup.first_lsn is not None
    assert backup.storage_object_key.startswith("backups/SQLTrust_TestDB/FULL/")

    # Verify manifest in control database
    manifest = db.query(BackupManifest).filter(BackupManifest.backup_id == backup.id).first()
    assert manifest is not None
    assert manifest.manifest_hash is not None
    assert "SQLTrust_TestDB" in manifest.manifest_json

    # Verify SeaweedFS upload and download
    storage = SeaweedFSStorageProvider()
    meta = storage.get_object_metadata(backup.storage_object_key)
    assert meta["content_length"] == backup.backup_size_bytes

    # Test download verification
    download_dest = os.path.join("data", "backups", "download_test_" + backup.backup_filename)
    try:
        storage.download_file(backup.storage_object_key, download_dest)
        assert os.path.exists(download_dest)
        assert os.path.getsize(download_dest) == backup.backup_size_bytes
    finally:
        if os.path.exists(download_dest):
            os.remove(download_dest)


def test_differential_and_log_backup(setup_environment):
    """Verify DIFFERENTIAL and LOG backup workflows in sequence."""
    db = setup_environment
    service = DatabaseService(db)
    reg = service.register_database("SQLTrust_TestDB")
    engine = BackupEngine(db)

    # Advance database transaction state
    with service.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("INSERT INTO [SQLTrust_TestDB].dbo.AuditLogs (event_name) VALUES ('Advance Differential LSN')"))

    diff = engine.execute_backup(reg.id, "DIFFERENTIAL", operator_notes="Integration Differential")
    assert diff.backup_status == "COMPLETED"
    assert diff.backup_type == "DIFFERENTIAL"
    assert diff.sql_verification_status == "PASSED"

    with service.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("INSERT INTO [SQLTrust_TestDB].dbo.AuditLogs (event_name) VALUES ('Advance Log LSN')"))

    log = engine.execute_backup(reg.id, "LOG", operator_notes="Integration Log")
    assert log.backup_status == "COMPLETED"
    assert log.backup_type == "LOG"
    assert log.sql_verification_status == "PASSED"
    assert log.storage_upload_status == "COMPLETED"


def test_re_verification(setup_environment):
    """Verify on-demand two-stage verification on existing backup."""
    db = setup_environment
    service = DatabaseService(db)
    reg = service.register_database("SQLTrust_TestDB")

    last_backup = db.query(BackupRecord).filter(
        BackupRecord.database_id == reg.id,
        BackupRecord.backup_status == "COMPLETED"
    ).order_by(BackupRecord.start_time.desc()).first()

    assert last_backup is not None
    engine = BackupEngine(db)
    verify_res = engine.verify_existing_backup(last_backup.id)

    assert verify_res["sql_verification"] == "PASSED"
    assert verify_res["file_integrity"] == "PASSED"
    assert verify_res["sha256_match"] is True
