"""
SQL-TRUST Control Database Models
Module 5: Restore & Cyber Recovery Validation Engine
Defines persistent recovery jobs, state transition history, and staging metadata.
Enforces ondelete="RESTRICT" on all foreign keys to prevent cascading forensic deletion.
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
    Boolean,
    Integer,
    Float,
    text
)
from sqlalchemy.orm import relationship
from backend.models.backup import Base, generate_uuid, utc_now


def generate_job_reference() -> str:
    """Generates a human-readable unique reference for a recovery validation job."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_suffix = uuid.uuid4().hex[:6].upper()
    return f"RECOV-{date_str}-{short_suffix}"


class RecoveryJob(Base):
    """
    Primary orchestration record tracking the complete validation lifecycle
    of a designated cyber recovery candidate.
    """
    __tablename__ = "recovery_jobs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    job_reference = Column(String(64), nullable=False, unique=True, index=True, default=generate_job_reference)
    candidate_id = Column(
        String(36),
        ForeignKey("recovery_recommendations.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    recovery_point_id = Column(
        String(36),
        ForeignKey("recovery_points.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    target_database_name = Column(String(128), nullable=False, index=True)
    status = Column(String(32), default="REQUESTED", nullable=False, index=True)
    
    requested_by = Column(String(128), nullable=False)
    approved_by = Column(String(128), nullable=True)
    
    requested_at = Column(DateTime, default=utc_now, nullable=False)
    approved_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    failure_code = Column(String(64), nullable=True)
    failure_reason = Column(Text, nullable=True)
    idempotency_key = Column(String(128), nullable=True)

    __table_args__ = (
        Index(
            "ix_recovery_jobs_idempotency_key",
            "idempotency_key",
            unique=True,
            mssql_where=text("idempotency_key IS NOT NULL")
        ),
    )
    
    target_recovery_time = Column(DateTime, nullable=True)
    target_time_basis = Column(String(32), default="UTC", nullable=False)
    notes = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    candidate = relationship("RecoveryRecommendation", foreign_keys=[candidate_id])
    recovery_point = relationship("RecoveryPoint", foreign_keys=[recovery_point_id])
    history = relationship(
        "RecoveryJobHistory",
        back_populates="job",
        order_by="RecoveryJobHistory.transitioned_at.asc()"
    )
    staging_records = relationship(
        "BackupStagingRecord",
        back_populates="job",
        order_by="BackupStagingRecord.sequence_order.asc()"
    )
    sandbox = relationship("RecoverySandbox", back_populates="job", uselist=False)
    restore_plan = relationship("RestorePlan", back_populates="job", uselist=False)
    validation = relationship("RecoveryValidation", back_populates="job", uselist=False)
    final_report = relationship("RecoveryFinalReport", back_populates="job", uselist=False)


class RecoveryJobHistory(Base):
    """
    Immutable audit log preserving all state transitions throughout the recovery job lifecycle.
    Guarantees non-repudiation and forensic accountability.
    """
    __tablename__ = "recovery_job_history"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    job_id = Column(
        String(36),
        ForeignKey("recovery_jobs.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    from_state = Column(String(32), nullable=False)
    to_state = Column(String(32), nullable=False)
    actor = Column(String(128), nullable=False)
    reason = Column(Text, nullable=True)
    evidence_reference = Column(String(512), nullable=True)
    transitioned_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    job = relationship("RecoveryJob", back_populates="history")


class BackupStagingRecord(Base):
    """
    Tracks local disk staging, download progress, and cryptographic SHA-256 verification
    of individual backup files (Full, Diff, Log) for a recovery job prior to sandbox attachment.
    Enforces strict foreign key integrity with ondelete="NO ACTION".
    """
    __tablename__ = "backup_staging_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    job_id = Column(
        String(36),
        ForeignKey("recovery_jobs.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    recovery_point_id = Column(
        String(36),
        ForeignKey("recovery_points.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    sequence_order = Column(Integer, nullable=False, default=1)
    backup_type = Column(String(32), nullable=False)  # FULL, DIFFERENTIAL, LOG
    storage_object_key = Column(String(512), nullable=False)
    staged_file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(BigInteger, nullable=False, default=0)
    expected_sha256 = Column(String(64), nullable=False)
    computed_sha256 = Column(String(64), nullable=True)
    verification_status = Column(String(32), default="PENDING", nullable=False, index=True)  # PENDING, IN_PROGRESS, VERIFIED, MISMATCH, FAILED
    error_message = Column(Text, nullable=True)
    staged_at = Column(DateTime, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    # Relationships
    job = relationship("RecoveryJob", back_populates="staging_records")
    recovery_point = relationship("RecoveryPoint", foreign_keys=[recovery_point_id])


class RecoverySandbox(Base):
    """
    Tracks the isolated, disposable SQL Server Docker recovery sandbox instance
    created specifically for validating a recovery job without risk to production.
    Enforces strict foreign key integrity with ondelete="NO ACTION".
    """
    __tablename__ = "recovery_sandboxes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    job_id = Column(
        String(36),
        ForeignKey("recovery_jobs.id", ondelete="NO ACTION"),
        nullable=False,
        unique=True,
        index=True
    )
    container_id = Column(String(128), nullable=True, index=True)
    container_name = Column(String(128), nullable=False, unique=True, index=True)
    docker_image = Column(String(255), default="mcr.microsoft.com/mssql/server:2022-latest", nullable=False)
    docker_network = Column(String(128), nullable=False)
    data_volume = Column(String(128), nullable=False)
    log_volume = Column(String(128), nullable=False)
    staging_mount_path = Column(String(512), nullable=False)
    host_port = Column(Integer, nullable=False)
    sa_password_hash = Column(String(128), nullable=False)
    
    lifecycle_status = Column(String(32), default="CREATED", nullable=False, index=True)
    # CREATED, INITIALIZING, HEALTHY, UNHEALTHY, QUARANTINED, CLEANUP_PENDING, CLEANED
    
    is_isolated = Column(Boolean, default=True, nullable=False)
    network_isolated = Column(Boolean, default=True, nullable=False)
    storage_isolated = Column(Boolean, default=True, nullable=False)
    cpu_limit = Column(String(32), default="2.0", nullable=False)
    memory_limit = Column(String(32), default="2048m", nullable=False)
    
    health_checked_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    isolation_evidence_json = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)
    cleaned_at = Column(DateTime, nullable=True)

    # Relationships
    job = relationship("RecoveryJob", back_populates="sandbox")


class RestorePlan(Base):
    """
    Persistent, auditable execution plan for restoring full, differential, and log
    backups into the isolated recovery sandbox with explicit LSN and STOPAT boundaries.
    """
    __tablename__ = "restore_plans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    job_id = Column(
        String(36),
        ForeignKey("recovery_jobs.id", ondelete="NO ACTION"),
        nullable=False,
        unique=True,
        index=True
    )
    sandbox_id = Column(
        String(36),
        ForeignKey("recovery_sandboxes.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    target_database_name = Column(String(128), nullable=False)
    
    full_artifact_id = Column(String(36), ForeignKey("backup_staging_records.id", ondelete="NO ACTION"), nullable=False)
    differential_artifact_id = Column(String(36), ForeignKey("backup_staging_records.id", ondelete="NO ACTION"), nullable=True)
    
    total_operations = Column(Integer, default=1, nullable=False)
    plan_steps_json = Column(Text, nullable=False)  # Ordered JSON array of operations
    
    target_stopat_utc = Column(DateTime, nullable=True)
    target_stopat_local = Column(DateTime, nullable=True)
    status = Column(String(32), default="DRAFT", nullable=False, index=True)  # DRAFT, APPROVED, IN_PROGRESS, COMPLETED, FAILED
    
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    job = relationship("RecoveryJob", back_populates="restore_plan")
    sandbox = relationship("RecoverySandbox")
    operations = relationship("RestoreOperation", back_populates="plan", order_by="RestoreOperation.sequence_number.asc()")


class RestoreOperation(Base):
    """
    Records every individual physical restore step executed against the recovery sandbox.
    """
    __tablename__ = "restore_operations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    plan_id = Column(
        String(36),
        ForeignKey("restore_plans.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    job_id = Column(
        String(36),
        ForeignKey("recovery_jobs.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    sequence_number = Column(Integer, nullable=False)
    operation_type = Column(String(32), nullable=False)  # HEADER_VERIFY, FILELIST_VERIFY, RESTORE_FULL, RESTORE_DIFF, RESTORE_LOG, RESTORE_RECOVERY
    
    backup_file_path = Column(String(512), nullable=False)
    t_sql_command = Column(Text, nullable=False)
    status = Column(String(32), default="PENDING", nullable=False, index=True)  # PENDING, EXECUTING, COMPLETED, FAILED
    
    sql_server_messages = Column(Text, nullable=True)
    error_details = Column(Text, nullable=True)
    execution_duration_ms = Column(Integer, default=0, nullable=False)
    
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    plan = relationship("RestorePlan", back_populates="operations")
    job = relationship("RecoveryJob")


class RecoveryValidation(Base):
    """
    Central record for post-restore forensic inspection, database integrity (DBCC CHECKDB),
    schema analysis, and baseline comparison.
    """
    __tablename__ = "recovery_validations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    job_id = Column(
        String(36),
        ForeignKey("recovery_jobs.id", ondelete="NO ACTION"),
        nullable=False,
        unique=True,
        index=True
    )
    sandbox_id = Column(
        String(36),
        ForeignKey("recovery_sandboxes.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    target_database_name = Column(String(128), nullable=False)
    
    # DBCC CHECKDB Results
    dbcc_status = Column(String(32), default="PENDING", nullable=False)  # PASSED, FAILED, PENDING
    dbcc_errors_count = Column(Integer, default=0, nullable=False)
    dbcc_output_json = Column(Text, nullable=True)
    
    # Schema & Baseline Comparison
    schema_validation_status = Column(String(32), default="PENDING", nullable=False)
    baseline_id = Column(String(36), ForeignKey("forensic_baselines.id", ondelete="NO ACTION"), nullable=True)
    baseline_comparison_status = Column(String(32), default="PENDING", nullable=False)  # MATCHED, DRIFT_DETECTED, NO_BASELINE
    
    # Security Inspection
    security_inspection_status = Column(String(32), default="PENDING", nullable=False)
    unauthorized_principals_count = Column(Integer, default=0, nullable=False)
    suspicious_objects_count = Column(Integer, default=0, nullable=False)
    
    # Final 4-Tier Assessment
    overall_assessment = Column(String(32), default="INCONCLUSIVE", nullable=False, index=True)
    # VALIDATED, FAILED, INCONCLUSIVE, REQUIRES_INVESTIGATION
    
    assessment_rationale = Column(Text, nullable=False)
    validated_at = Column(DateTime, default=utc_now, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    job = relationship("RecoveryJob", back_populates="validation")
    sandbox = relationship("RecoverySandbox")
    baseline = relationship("ForensicBaseline")
    findings = relationship("RecoveryFinding", back_populates="validation", cascade="all, delete-orphan")


class RecoveryFinding(Base):
    """
    Granular security or consistency finding discovered during sandbox recovery validation.
    """
    __tablename__ = "recovery_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    validation_id = Column(
        String(36),
        ForeignKey("recovery_validations.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    job_id = Column(
        String(36),
        ForeignKey("recovery_jobs.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    category = Column(String(32), nullable=False, index=True)  # INTEGRITY, SCHEMA, PRINCIPAL, PERMISSION, PERSISTENCE, RECOVERY_POINT
    severity = Column(String(16), nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    finding_type = Column(String(64), nullable=False)  # DBCC_ALLOCATION_FAULT, UNEXPECTED_SYSADMIN, MALICIOUS_TRIGGER, SCHEMA_MUTATION, LSN_GAP
    entity_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    evidence_reference = Column(String(512), nullable=True)
    recommended_action = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    validation = relationship("RecoveryValidation", back_populates="findings")
    job = relationship("RecoveryJob")


class RecoveryEvidenceItem(Base):
    """
    Cryptographically tracked evidence item generated across the recovery lifecycle.
    """
    __tablename__ = "recovery_evidence_items"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    job_id = Column(
        String(36),
        ForeignKey("recovery_jobs.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    evidence_category = Column(String(64), nullable=False, index=True)
    # JOB_CREATION, BACKUP_STAGING, SANDBOX_PROVISIONING, RESTORE_EXECUTION, DBCC_INTEGRITY, SECURITY_INSPECTION, BASELINE_COMPARISON, FINAL_REPORT
    
    source_artifact = Column(String(255), nullable=False)
    original_sha256 = Column(String(64), nullable=False)
    verified_sha256 = Column(String(64), nullable=True)
    storage_object_key = Column(String(512), nullable=True)
    evidence_metadata_json = Column(Text, nullable=True)
    collected_by = Column(String(128), nullable=False)
    collected_at = Column(DateTime, default=utc_now, nullable=False)
    integrity_status = Column(String(32), default="VERIFIED", nullable=False)

    # Relationships
    job = relationship("RecoveryJob")
    custody_events = relationship("RecoveryChainOfCustody", back_populates="evidence", cascade="all, delete-orphan")


class RecoveryChainOfCustody(Base):
    """
    Immutable audit log for each evidence accession, verification, and inspection event.
    """
    __tablename__ = "recovery_chain_of_custody"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    evidence_id = Column(
        String(36),
        ForeignKey("recovery_evidence_items.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    job_id = Column(
        String(36),
        ForeignKey("recovery_jobs.id", ondelete="NO ACTION"),
        nullable=False,
        index=True
    )
    action = Column(String(64), nullable=False)  # COLLECTED, VERIFIED, EXPORTED, ARCHIVED
    actor = Column(String(128), nullable=False)
    action_details = Column(Text, nullable=True)
    recorded_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    evidence = relationship("RecoveryEvidenceItem", back_populates="custody_events")
    job = relationship("RecoveryJob")


class RecoveryFinalReport(Base):
    """
    Authoritative final recovery validation report containing executive summary,
    full audit trail, cryptographic signatures, and final outcome determination.
    """
    __tablename__ = "recovery_final_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    job_id = Column(
        String(36),
        ForeignKey("recovery_jobs.id", ondelete="NO ACTION"),
        nullable=False,
        unique=True,
        index=True
    )
    report_reference = Column(String(64), nullable=False, unique=True, index=True)
    overall_assessment = Column(String(32), nullable=False, index=True)
    assessment_reason = Column(Text, nullable=False)
    
    report_json = Column(Text, nullable=False)
    report_sha256 = Column(String(64), nullable=False)
    signature = Column(Text, nullable=True)  # Ed25519 signature of canonical report JSON
    signing_key_id = Column(String(64), nullable=True)
    pdf_path = Column(String(512), nullable=True)
    
    generated_by = Column(String(128), nullable=False)
    generated_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    job = relationship("RecoveryJob", back_populates="final_report")
