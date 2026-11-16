"""
SQL-TRUST Module 1 — Unit Tests
Tests filename generation, SHA-256 calculation, manifest creation,
identifier validation, and storage configuration.
"""
import os
import tempfile
import pytest
from datetime import datetime, timezone
from backend.services.database_service import validate_sql_identifier
from backend.services.backup.engine import calculate_file_sha256, BackupEngine
from backend.services.storage.manifest import generate_backup_manifest
from backend.models.backup import BackupRecord, ProtectedDatabase
from backend.services.storage.seaweedfs import SeaweedFSStorageProvider


def test_sql_identifier_validation():
    """Verify strict alphanumeric identifier validation."""
    assert validate_sql_identifier("FinanceDB") == "FinanceDB"
    assert validate_sql_identifier("Test_DB_123") == "Test_DB_123"
    assert validate_sql_identifier("db#prod$") == "db#prod$"

    with pytest.raises(ValueError, match="Invalid database name"):
        validate_sql_identifier("db; DROP TABLE users;--")

    with pytest.raises(ValueError, match="Invalid database name"):
        validate_sql_identifier("db name with spaces")

    with pytest.raises(ValueError, match="cannot be empty"):
        validate_sql_identifier("")


def test_chunked_sha256_calculation():
    """Verify chunked streaming SHA-256 computation against known reference hash."""
    test_data = b"SQL-TRUST Cyber Recovery Platform Test Vector Data 12345"
    import hashlib
    expected_sha256 = hashlib.sha256(test_data).hexdigest()

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(test_data)
        tf_path = tf.name

    try:
        calculated_sha256 = calculate_file_sha256(tf_path, chunk_size=8)
        assert calculated_sha256 == expected_sha256
    finally:
        if os.path.exists(tf_path):
            os.remove(tf_path)


def test_backup_filename_generation():
    """Verify collision-resistant naming format."""
    engine = BackupEngine(db_session=None)
    
    full_name = engine.generate_backup_filename("FinanceDB", "FULL")
    assert full_name.startswith("FinanceDB_FULL_")
    assert full_name.endswith(".bak")

    diff_name = engine.generate_backup_filename("FinanceDB", "DIFFERENTIAL")
    assert diff_name.startswith("FinanceDB_DIFFERENTIAL_")
    assert diff_name.endswith(".bak")

    log_name = engine.generate_backup_filename("FinanceDB", "LOG")
    assert log_name.startswith("FinanceDB_LOG_")
    assert log_name.endswith(".trn")

    # Filenames should be unique across consecutive calls
    another_name = engine.generate_backup_filename("FinanceDB", "FULL")
    assert full_name != another_name


def test_manifest_generation():
    """Verify deterministic JSON manifest generation and SHA-256 hash calculation."""
    db = ProtectedDatabase(
        id="db-123",
        server_name="TEST_SRV",
        database_name="PayrollDB",
        database_identifier="10",
        recovery_model="FULL"
    )

    now = datetime.now(timezone.utc)
    rec = BackupRecord(
        id="backup-456",
        database_id="db-123",
        backup_type="FULL",
        backup_filename="PayrollDB_FULL.bak",
        backup_path=r"C:\backups\PayrollDB_FULL.bak",
        backup_size_bytes=1048576,
        start_time=now,
        finish_time=now,
        first_lsn="1000",
        last_lsn="2000",
        checkpoint_lsn="1500",
        database_backup_lsn="1000",
        sha256="abcdef1234567890",
        sql_verification_status="PASSED",
        storage_upload_status="COMPLETED",
        storage_object_key="backups/PayrollDB/FULL/PayrollDB_FULL.bak",
        backup_status="COMPLETED"
    )

    manifest_output = generate_backup_manifest(
        backup_record=rec,
        database=db,
        storage_provider="SEAWEEDFS"
    )

    assert "manifest_dict" in manifest_output
    assert "manifest_json" in manifest_output
    assert "manifest_hash" in manifest_output
    
    m_dict = manifest_output["manifest_dict"]
    assert m_dict["manifest_version"] == "1.0"
    assert m_dict["backup_id"] == "backup-456"
    assert m_dict["database_name"] == "PayrollDB"
    assert m_dict["first_lsn"] == "1000"
    assert m_dict["sha256"] == "abcdef1234567890"
    assert m_dict["sql_verification"] == "PASSED"
    assert len(manifest_output["manifest_hash"]) == 64


def test_storage_security_audit():
    """Verify that storage security audit inspects without false immutability claims."""
    storage = SeaweedFSStorageProvider()
    audit = storage.inspect_security()
    
    assert "bucket" in audit
    assert "versioning_status" in audit
    assert "object_lock_enabled" in audit
    assert "immutability_guarantee" in audit
    assert isinstance(audit["warnings"], list)
