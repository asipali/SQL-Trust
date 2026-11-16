"""
SQL-TRUST Control Database Models
Module 1: Backup Manager
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    DateTime,
    BigInteger,
    Text,
    ForeignKey,
    Index,
    Enum as SQLEnum
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ProtectedDatabase(Base):
    """
    Databases explicitly registered by administrators for backup protection.
    System databases are excluded by default.
    """
    __tablename__ = "protected_databases"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    server_name = Column(String(255), nullable=False)
    database_name = Column(String(128), nullable=False, unique=True, index=True)
    database_identifier = Column(String(64), nullable=True)  # SQL Server database_id
    recovery_model = Column(String(32), nullable=False, default="SIMPLE")  # FULL, SIMPLE, BULK_LOGGED
    registration_status = Column(String(32), nullable=False, default="REGISTERED")  # REGISTERED, PAUSED, ARCHIVED
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    backups = relationship("BackupRecord", back_populates="database", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ProtectedDatabase {self.database_name} ({self.recovery_model})>"


class BackupRecord(Base):
    """
    Tracks each backup execution (FULL, DIFFERENTIAL, LOG) and its lifecycle.
    """
    __tablename__ = "backup_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    database_id = Column(String(36), ForeignKey("protected_databases.id", ondelete="CASCADE"), nullable=False, index=True)
    backup_type = Column(String(16), nullable=False)  # FULL, DIFFERENTIAL, LOG
    backup_filename = Column(String(255), nullable=False, unique=True, index=True)
    backup_path = Column(String(512), nullable=False)
    backup_size_bytes = Column(BigInteger, default=0, nullable=False)
    
    start_time = Column(DateTime, nullable=False, default=utc_now)
    finish_time = Column(DateTime, nullable=True)
    
    # SQL Server LSN metadata
    first_lsn = Column(String(64), nullable=True)
    last_lsn = Column(String(64), nullable=True)
    checkpoint_lsn = Column(String(64), nullable=True)
    database_backup_lsn = Column(String(64), nullable=True)

    # Verification and Storage Integrity Evidence
    sha256 = Column(String(64), nullable=True)  # Cryptographic checksum
    sql_verification_status = Column(String(32), default="PENDING", nullable=False)  # PENDING, PASSED, FAILED, SKIPPED
    storage_upload_status = Column(String(32), default="PENDING", nullable=False)    # PENDING, COMPLETED, FAILED
    storage_object_key = Column(String(512), nullable=True)
    storage_object_version_id = Column(String(128), nullable=True)
    retention_mode = Column(String(32), nullable=True)  # COMPLIANCE, GOVERNANCE, NONE
    retention_until = Column(DateTime, nullable=True)

    # Execution State
    # PENDING, RUNNING, VERIFYING, UPLOADING, COMPLETED, FAILED
    backup_status = Column(String(32), default="PENDING", nullable=False, index=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    database = relationship("ProtectedDatabase", back_populates="backups")
    manifest = relationship("BackupManifest", back_populates="backup", uselist=False, cascade="all, delete-orphan")
    operation_logs = relationship("BackupOperationLog", back_populates="backup", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<BackupRecord {self.backup_filename} ({self.backup_type}) - {self.backup_status}>"


class BackupManifest(Base):
    """
    Immutable JSON manifest generated for every successfully verified and stored backup.
    """
    __tablename__ = "backup_manifests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    backup_id = Column(String(36), ForeignKey("backup_records.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    manifest_version = Column(String(16), default="1.0", nullable=False)
    manifest_json = Column(Text, nullable=False)
    manifest_hash = Column(String(64), nullable=False)  # SHA-256 of the manifest JSON text
    created_at = Column(DateTime, default=utc_now, nullable=False)

    backup = relationship("BackupRecord", back_populates="manifest")

    def __repr__(self):
        return f"<BackupManifest {self.backup_id} (v{self.manifest_version})>"


class BackupOperationLog(Base):
    """
    Detailed audit and diagnostic log of each discrete step in the backup pipeline.
    """
    __tablename__ = "backup_operation_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    backup_id = Column(String(36), ForeignKey("backup_records.id", ondelete="CASCADE"), nullable=True, index=True)
    operation = Column(String(64), nullable=False)  # VALIDATE_ENV, SQL_BACKUP, SQL_VERIFYONLY, CALCULATE_SHA256, STORAGE_UPLOAD, GENERATE_MANIFEST
    status = Column(String(32), nullable=False)     # RUNNING, COMPLETED, FAILED
    started_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    error_details = Column(Text, nullable=True)

    backup = relationship("BackupRecord", back_populates="operation_logs")

    def __repr__(self):
        return f"<BackupOperationLog {self.operation} - {self.status}>"
