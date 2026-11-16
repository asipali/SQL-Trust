"""
SQL-TRUST Control Database Models
Module 3: Database Forensics Engine
Provides persistent tracking for database baselines, granular entity snapshots,
forensic investigations, drift findings, telemetry correlations, and signed WORM evidence.
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    DateTime,
    BigInteger,
    Integer,
    Float,
    Boolean,
    Text,
    ForeignKey,
    Index
)
from sqlalchemy.orm import relationship
from backend.models.backup import Base, generate_uuid, utc_now


class ForensicBaseline(Base):
    """
    Metadata record for a complete captured database state baseline.
    """
    __tablename__ = "forensic_baselines"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    database_id = Column(String(36), ForeignKey("protected_databases.id", ondelete="SET NULL"), nullable=True, index=True)
    server_name = Column(String(255), nullable=False)
    database_name = Column(String(128), nullable=False, index=True)
    baseline_name = Column(String(255), nullable=False)
    baseline_type = Column(String(32), default="FULL", nullable=False)  # FULL, SCHEMA_ONLY, SECURITY_ONLY
    status = Column(String(32), default="COMPLETED", nullable=False)     # PENDING, CAPTURING, COMPLETED, FAILED
    
    captured_at = Column(DateTime, default=utc_now, nullable=False, index=True)
    total_objects = Column(Integer, default=0, nullable=False)
    total_principals = Column(Integer, default=0, nullable=False)
    total_permissions = Column(Integer, default=0, nullable=False)
    sha256_manifest = Column(String(64), nullable=False, index=True)
    
    storage_object_key = Column(String(512), nullable=True)
    storage_version_id = Column(String(128), nullable=True)
    signature = Column(Text, nullable=True)  # Ed25519 digital signature of canonical baseline JSON
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    items = relationship("ForensicBaselineItem", back_populates="baseline", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ForensicBaseline {self.baseline_name} - {self.database_name} ({self.total_objects} objs)>"


class ForensicBaselineItem(Base):
    """
    Granular database entity captured within a baseline snapshot.
    Stores schema definitions, permissions, principals, and options with SHA-256 hashes.
    """
    __tablename__ = "forensic_baseline_items"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    baseline_id = Column(String(36), ForeignKey("forensic_baselines.id", ondelete="CASCADE"), nullable=False, index=True)
    
    item_type = Column(String(32), nullable=False, index=True)
    # TABLE, VIEW, PROCEDURE, FUNCTION, TRIGGER, USER, LOGIN, ROLE_MEMBER, PERMISSION, DATABASE_OPTION
    
    schema_name = Column(String(128), nullable=True)
    item_name = Column(String(255), nullable=False, index=True)
    sql_object_id = Column(BigInteger, nullable=True)
    
    definition_hash = Column(String(64), nullable=True, index=True)  # SHA-256 of DDL text / structure
    raw_definition = Column(Text, nullable=True)                     # Full T-SQL DDL where unencrypted
    properties_json = Column(Text, nullable=False)                   # JSON of columns, types, flags, options
    
    is_encrypted = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    baseline = relationship("ForensicBaseline", back_populates="items")

    def __repr__(self):
        return f"<ForensicBaselineItem {self.item_type} - {self.schema_name or 'dbo'}.{self.item_name}>"


class ForensicInvestigation(Base):
    """
    Encapsulates a forensic comparison session between two baselines or a baseline and current state.
    """
    __tablename__ = "forensic_investigations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_name = Column(String(255), nullable=False)
    server_name = Column(String(255), nullable=False)
    database_name = Column(String(128), nullable=False, index=True)
    
    ref_baseline_id = Column(String(36), ForeignKey("forensic_baselines.id", ondelete="NO ACTION"), nullable=False, index=True)
    target_baseline_id = Column(String(36), ForeignKey("forensic_baselines.id", ondelete="NO ACTION"), nullable=True, index=True)
    
    status = Column(String(32), default="COMPLETED", nullable=False)  # IN_PROGRESS, COMPLETED, FAILED
    findings_count = Column(Integer, default=0, nullable=False)
    critical_findings_count = Column(Integer, default=0, nullable=False)
    high_findings_count = Column(Integer, default=0, nullable=False)
    
    started_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    summary_notes = Column(Text, nullable=True)
    
    manifest_sha256 = Column(String(64), nullable=True)
    signature = Column(Text, nullable=True)  # Ed25519 digital signature of investigation report
    storage_object_key = Column(String(512), nullable=True)
    storage_version_id = Column(String(128), nullable=True)

    # Relationships
    ref_baseline = relationship("ForensicBaseline", foreign_keys=[ref_baseline_id])
    target_baseline = relationship("ForensicBaseline", foreign_keys=[target_baseline_id])
    findings = relationship("ForensicFinding", back_populates="investigation", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ForensicInvestigation {self.investigation_name} ({self.findings_count} findings)>"


class ForensicFinding(Base):
    """
    Granular change, mutation, or configuration drift discovered during an investigation.
    """
    __tablename__ = "forensic_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("forensic_investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    
    category = Column(String(32), nullable=False, index=True)
    # SCHEMA, PRINCIPAL, ROLE_MEMBERSHIP, PERMISSION, CONFIGURATION
    
    finding_type = Column(String(64), nullable=False, index=True)
    # OBJECT_CREATED, OBJECT_DROPPED, OBJECT_MODIFIED,
    # USER_ADDED, USER_REMOVED, ROLE_ESCALATION, PERMISSION_MUTATED,
    # CONFIG_DRIFT, UNOBSERVABLE_ENCRYPTED
    
    severity = Column(String(16), default="HIGH", nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    entity_name = Column(String(255), nullable=False)
    schema_name = Column(String(128), nullable=True)
    
    before_state_json = Column(Text, nullable=True)
    after_state_json = Column(Text, nullable=True)
    explanation = Column(Text, nullable=False)
    confidence_score = Column(Float, default=1.0, nullable=False)
    
    detected_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    investigation = relationship("ForensicInvestigation", back_populates="findings")
    correlations = relationship("ForensicCorrelation", back_populates="finding", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ForensicFinding {self.finding_type} - {self.entity_name} ({self.severity})>"


class ForensicCorrelation(Base):
    """
    Correlates a Module 3 state drift finding with a Module 2 telemetry event.
    Enforces epistemological caution: proximity does not equal causation.
    """
    __tablename__ = "forensic_correlations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("forensic_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(String(36), ForeignKey("security_events.id", ondelete="NO ACTION"), nullable=False, index=True)
    
    correlation_type = Column(String(64), nullable=False)  # EXACT_OBJECT_MATCH, ACTION_PATTERN_MATCH, TEMPORAL_WINDOW
    time_delta_seconds = Column(Integer, nullable=False)   # Difference in seconds between telemetry and baseline
    confidence_score = Column(Float, default=0.9, nullable=False)
    correlation_notes = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    finding = relationship("ForensicFinding", back_populates="correlations")
    event = relationship("SecurityEvent")

    def __repr__(self):
        return f"<ForensicCorrelation Finding={self.finding_id[:8]} Event={self.event_id[:8]} ({self.confidence_score})>"


class ForensicEvidenceArchive(Base):
    """
    Tracks forensic evidence bundles and investigation reports uploaded to SeaweedFS Object Lock WORM storage.
    """
    __tablename__ = "forensic_evidence_archives"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("forensic_investigations.id", ondelete="SET NULL"), nullable=True, index=True)
    baseline_id = Column(String(36), ForeignKey("forensic_baselines.id", ondelete="SET NULL"), nullable=True, index=True)
    
    evidence_type = Column(String(32), nullable=False)  # BASELINE_DUMP, INVESTIGATION_REPORT, CORRELATION_MANIFEST
    storage_bucket = Column(String(128), nullable=False)
    storage_object_key = Column(String(512), nullable=False)
    storage_version_id = Column(String(128), nullable=True)
    
    sha256 = Column(String(64), nullable=False, index=True)
    file_size_bytes = Column(BigInteger, default=0, nullable=False)
    signature = Column(Text, nullable=False)
    
    retention_mode = Column(String(32), default="COMPLIANCE", nullable=False)
    retention_until = Column(DateTime, nullable=True)
    verification_status = Column(String(32), default="VERIFIED", nullable=False)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)

    def __repr__(self):
        return f"<ForensicEvidenceArchive {self.storage_object_key} ({self.retention_mode})>"
