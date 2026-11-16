"""
SQL-TRUST Control Database Models
Module 2: Security Monitoring Engine
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
    Index,
    Table
)
from sqlalchemy.orm import relationship
from backend.models.backup import Base, generate_uuid, utc_now

# Association table for Many-to-Many relationship between Alerts and Events
# Uses NO ACTION on one foreign key to satisfy SQL Server multiple cascade path rules
alert_event_associations = Table(
    "alert_event_associations",
    Base.metadata,
    Column("alert_id", String(36), ForeignKey("security_alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", String(36), ForeignKey("security_events.id", ondelete="NO ACTION"), primary_key=True)
)


class SecuritySource(Base):
    """
    Monitored SQL Server instances and telemetry sources.
    """
    __tablename__ = "security_sources"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_name = Column(String(128), nullable=False, unique=True, index=True)
    server_name = Column(String(255), nullable=False)
    source_type = Column(String(32), default="HYBRID", nullable=False)  # SQL_AUDIT, EXTENDED_EVENTS, HYBRID
    audit_target_path = Column(String(512), nullable=True)
    xe_target_path = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    events = relationship("SecurityEvent", back_populates="source", cascade="all, delete-orphan")
    alerts = relationship("SecurityAlert", back_populates="source", cascade="all, delete-orphan")
    checkpoints = relationship("CollectorCheckpoint", back_populates="source", cascade="all, delete-orphan")
    evidence_archives = relationship("EvidenceArchive", back_populates="source", cascade="all, delete-orphan")
    health_snapshots = relationship("MonitoringHealth", back_populates="source", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<SecuritySource {self.source_name} ({self.server_name})>"


class SecurityEvent(Base):
    """
    Normalized and deduplicated security telemetry events from SQL Server Audit and Extended Events.
    """
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_id = Column(String(36), ForeignKey("security_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    event_source = Column(String(32), nullable=False)  # SQL_AUDIT, EXTENDED_EVENTS
    source_file = Column(String(512), nullable=False)
    source_event_id = Column(String(128), nullable=True)
    
    event_type = Column(String(64), nullable=False, index=True)  # LOGIN_FAILED, LOGIN_SUCCESS, ROLE_MEMBER_CHANGE, etc.
    event_timestamp = Column(DateTime, nullable=False, index=True)
    collection_timestamp = Column(DateTime, default=utc_now, nullable=False)
    
    server_name = Column(String(255), nullable=False)
    database_name = Column(String(128), nullable=True, index=True)
    principal_name = Column(String(128), nullable=True, index=True)
    session_id = Column(Integer, nullable=True)
    client_ip = Column(String(64), nullable=True)
    client_app = Column(String(255), nullable=True)
    
    action = Column(String(64), nullable=False)  # Raw action code (e.g. LGFL, LGSU, CR, AL, DR, G, R, D)
    target_object = Column(String(255), nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    severity = Column(String(16), default="INFO", nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    
    event_fingerprint = Column(String(64), nullable=False, unique=True, index=True)  # SHA-256 deduplication key
    raw_payload = Column(Text, nullable=False)  # Complete JSON payload
    evidence_reference = Column(String(512), nullable=True)
    integrity_status = Column(String(32), default="VERIFIED", nullable=False)  # VERIFIED, UNVERIFIED, TAMPERED
    
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    source = relationship("SecuritySource", back_populates="events")
    alerts = relationship("SecurityAlert", secondary=alert_event_associations, back_populates="related_events")

    def __repr__(self):
        return f"<SecurityEvent {self.event_type} - {self.principal_name} ({self.severity})>"


class DetectionRule(Base):
    """
    Explainable detection rules evaluated against normalized event streams.
    """
    __tablename__ = "detection_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    rule_id = Column(String(64), nullable=False, unique=True, index=True)  # RULE_001_FAILED_LOGINS, etc.
    rule_name = Column(String(128), nullable=False)
    description = Column(Text, nullable=False)
    condition_type = Column(String(64), nullable=False)  # THRESHOLD, SEQUENCE, STATE_CHANGE, GAP
    threshold_value = Column(Integer, default=1, nullable=False)
    time_window_seconds = Column(Integer, default=300, nullable=False)
    severity = Column(String(16), default="HIGH", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    is_enabled = Column(Boolean, default=True, nullable=False)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    alerts = relationship("SecurityAlert", back_populates="rule")

    def __repr__(self):
        return f"<DetectionRule {self.rule_id} ({self.severity})>"


class SecurityAlert(Base):
    """
    Security incidents and threat detections generated by the rule engine.
    """
    __tablename__ = "security_alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_id = Column(String(36), ForeignKey("security_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(String(36), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(16), default="HIGH", nullable=False, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(32), default="NEW", nullable=False, index=True)      # NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    
    detection_timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)
    principal_name = Column(String(128), nullable=True)
    target_object = Column(String(255), nullable=True)
    explanation = Column(Text, nullable=False)
    confidence_score = Column(Float, default=1.0, nullable=False)
    evidence_reference = Column(String(512), nullable=True)
    related_event_count = Column(Integer, default=1, nullable=False)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    source = relationship("SecuritySource", back_populates="alerts")
    rule = relationship("DetectionRule", back_populates="alerts")
    related_events = relationship("SecurityEvent", secondary=alert_event_associations, back_populates="alerts")
    status_history = relationship("AlertStatusHistory", back_populates="alert", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<SecurityAlert {self.title} ({self.severity}) - {self.status}>"


class AlertStatusHistory(Base):
    """
    Audit log of alert lifecycle transitions.
    """
    __tablename__ = "alert_status_history"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    alert_id = Column(String(36), ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    previous_status = Column(String(32), nullable=False)
    new_status = Column(String(32), nullable=False)
    changed_by = Column(String(128), default="system", nullable=False)
    comment = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False)

    alert = relationship("SecurityAlert", back_populates="status_history")

    def __repr__(self):
        return f"<AlertStatusHistory {self.previous_status} -> {self.new_status}>"


class CollectorCheckpoint(Base):
    """
    Persistent watermark / checkpoint tracking for incremental file reading.
    Survives application and service restarts.
    """
    __tablename__ = "collector_checkpoints"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_id = Column(String(36), ForeignKey("security_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    collector_type = Column(String(32), nullable=False)  # SQL_AUDIT, EXTENDED_EVENTS
    last_file_name = Column(String(512), nullable=True)
    last_file_offset = Column(BigInteger, default=0, nullable=False)
    last_event_timestamp = Column(DateTime, nullable=True)
    last_run_timestamp = Column(DateTime, default=utc_now, nullable=False)
    records_collected = Column(BigInteger, default=0, nullable=False)
    status = Column(String(32), default="IDLE", nullable=False)  # IDLE, RUNNING, COMPLETED, FAILED
    error_message = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    source = relationship("SecuritySource", back_populates="checkpoints")

    def __repr__(self):
        return f"<CollectorCheckpoint {self.collector_type} - {self.last_file_name}>"


class EvidenceArchive(Base):
    """
    Cryptographically preserved forensic evidence archived in SeaweedFS Object Lock storage.
    """
    __tablename__ = "evidence_archives"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_id = Column(String(36), ForeignKey("security_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(32), nullable=False)  # SQL_AUDIT_FILE, EXTENDED_EVENTS_FILE, NORMALIZED_EXPORT, ALERT_PACKAGE
    source_file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(BigInteger, default=0, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    
    storage_bucket = Column(String(128), nullable=False)
    storage_object_key = Column(String(512), nullable=False)
    storage_version_id = Column(String(128), nullable=True)
    retention_mode = Column(String(32), default="COMPLIANCE", nullable=False)
    retention_until = Column(DateTime, nullable=True)
    
    manifest_id = Column(String(64), nullable=False, index=True)
    signature = Column(Text, nullable=True)  # Base64 encoded Ed25519 digital signature
    collection_timestamp = Column(DateTime, default=utc_now, nullable=False)
    verification_status = Column(String(32), default="VERIFIED", nullable=False)  # PENDING, VERIFIED, FAILED
    
    created_at = Column(DateTime, default=utc_now, nullable=False)

    source = relationship("SecuritySource", back_populates="evidence_archives")

    def __repr__(self):
        return f"<EvidenceArchive {self.storage_object_key} ({self.sha256[:8]}...)>"


class MonitoringHealth(Base):
    """
    Comprehensive monitoring health snapshot.
    Evaluates SQL connectivity, Audit status, XE status, collection lag, and storage health.
    """
    __tablename__ = "monitoring_health"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_id = Column(String(36), ForeignKey("security_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    overall_status = Column(String(32), default="UNASSESSED", nullable=False)  # HEALTHY, DEGRADED, UNAVAILABLE, UNASSESSED
    sql_connectivity = Column(Boolean, default=False, nullable=False)
    audit_enabled = Column(Boolean, default=False, nullable=False)
    audit_target_available = Column(Boolean, default=False, nullable=False)
    audit_collection_lag_seconds = Column(Integer, default=0, nullable=False)
    xe_session_running = Column(Boolean, default=False, nullable=False)
    xe_target_available = Column(Boolean, default=False, nullable=False)
    last_successful_run = Column(DateTime, nullable=True)
    last_event_timestamp = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    storage_connectivity = Column(Boolean, default=False, nullable=False)
    details_json = Column(Text, nullable=True)
    checked_at = Column(DateTime, default=utc_now, nullable=False)

    source = relationship("SecuritySource", back_populates="health_snapshots")

    def __repr__(self):
        return f"<MonitoringHealth {self.overall_status} at {self.checked_at}>"
