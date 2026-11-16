"""
SQL-TRUST Control Database Models
Module 4: Cyber Recovery & State Reconstruction
Provides persistent tracking for recovery points, backup chains, chain segments,
cyber trust assessments, recovery eligibility, ranked recommendations, and assessment history.
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


class RecoveryPoint(Base):
    """
    Metadata record for a discovered or reconstructed point-in-time recovery candidate.
    Extracted from backup headers, LSN metadata, and storage objects.
    """
    __tablename__ = "recovery_points"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    database_id = Column(String(36), ForeignKey("protected_databases.id", ondelete="CASCADE"), nullable=False, index=True)
    backup_id = Column(String(36), ForeignKey("backup_records.id", ondelete="NO ACTION"), nullable=True, index=True)
    server_name = Column(String(255), nullable=False)
    database_name = Column(String(128), nullable=False, index=True)

    recovery_point_time = Column(DateTime, nullable=False, index=True)
    recovery_point_type = Column(String(32), nullable=False)  # FULL, DIFFERENTIAL, LOG, POINT_IN_TIME

    # LSN Chains and Recovery Forks
    first_lsn = Column(String(64), nullable=True)
    last_lsn = Column(String(64), nullable=True)
    checkpoint_lsn = Column(String(64), nullable=True)
    database_backup_lsn = Column(String(64), nullable=True)  # Base checkpoint for differential/log
    differential_base_guid = Column(String(64), nullable=True)
    recovery_fork_guid = Column(String(64), nullable=True)

    # Verification & Storage Status
    integrity_status = Column(String(32), default="PENDING", nullable=False)  # VERIFIED, FAILED, PENDING, UNVERIFIED
    sha256 = Column(String(64), nullable=True)
    storage_object_key = Column(String(512), nullable=True)
    storage_version_id = Column(String(128), nullable=True)
    retention_mode = Column(String(32), nullable=True)
    retention_until = Column(DateTime, nullable=True)

    metadata_json = Column(Text, nullable=True)  # Raw backup header data, size, page checksum state
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    backup_record = relationship("BackupRecord")
    chains_as_target = relationship("RecoveryChain", foreign_keys="RecoveryChain.target_recovery_point_id", back_populates="target_recovery_point")
    assessments = relationship("RecoveryAssessment", back_populates="recovery_point", cascade="all, delete-orphan")
    eligibility = relationship("RecoveryEligibility", back_populates="recovery_point", uselist=False, cascade="all, delete-orphan")
    recommendations = relationship("RecoveryRecommendation", back_populates="recovery_point", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<RecoveryPoint {self.database_name} - {self.recovery_point_type} ({self.recovery_point_time.isoformat()})>"


class RecoveryChain(Base):
    """
    Evaluated sequence of backups (Full -> Differential -> Logs) leading to a specific recovery point.
    """
    __tablename__ = "recovery_chains"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    database_id = Column(String(36), ForeignKey("protected_databases.id", ondelete="NO ACTION"), nullable=False, index=True)
    server_name = Column(String(255), nullable=False)
    database_name = Column(String(128), nullable=False, index=True)
    chain_name = Column(String(255), nullable=False)

    target_recovery_point_id = Column(String(36), ForeignKey("recovery_points.id", ondelete="NO ACTION"), nullable=False, index=True)
    base_full_point_id = Column(String(36), ForeignKey("recovery_points.id", ondelete="NO ACTION"), nullable=False)
    differential_point_id = Column(String(36), ForeignKey("recovery_points.id", ondelete="NO ACTION"), nullable=True)

    is_complete = Column(Boolean, default=False, nullable=False)  # Full + optional Diff + all intervening Logs exist
    is_valid = Column(Boolean, default=False, nullable=False)     # LSN continuity confirmed, verification passed
    validation_status = Column(String(64), nullable=False)        # VALID, BROKEN_CHAIN, MISSING_LOGS, FORK_MISMATCH, INTEGRITY_FAILED, INCOMPLETE
    validation_details = Column(Text, nullable=True)              # Step-by-step diagnostic reasoning

    first_lsn = Column(String(64), nullable=True)
    last_lsn = Column(String(64), nullable=True)
    segment_count = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    target_recovery_point = relationship("RecoveryPoint", foreign_keys=[target_recovery_point_id], back_populates="chains_as_target")
    base_full_point = relationship("RecoveryPoint", foreign_keys=[base_full_point_id])
    differential_point = relationship("RecoveryPoint", foreign_keys=[differential_point_id])
    segments = relationship("RecoveryChainSegment", back_populates="chain", cascade="all, delete-orphan", order_by="RecoveryChainSegment.sequence_order")
    assessments = relationship("RecoveryAssessment", back_populates="chain")

    def __repr__(self):
        return f"<RecoveryChain {self.chain_name} ({self.validation_status}) - Segments: {self.segment_count}>"


class RecoveryChainSegment(Base):
    """
    Maintains the strictly ordered list of backups comprising a chain, tracking segment-to-segment LSN continuity.
    """
    __tablename__ = "recovery_chain_segments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    chain_id = Column(String(36), ForeignKey("recovery_chains.id", ondelete="CASCADE"), nullable=False, index=True)
    recovery_point_id = Column(String(36), ForeignKey("recovery_points.id", ondelete="NO ACTION"), nullable=False, index=True)

    sequence_order = Column(Integer, nullable=False)             # 1 for Full, 2 for Diff, 3..N for Logs
    segment_type = Column(String(32), nullable=False)            # FULL, DIFFERENTIAL, LOG
    first_lsn = Column(String(64), nullable=True)
    last_lsn = Column(String(64), nullable=True)
    checkpoint_lsn = Column(String(64), nullable=True)

    is_continuous = Column(Boolean, default=True, nullable=False)
    continuity_gap_lsn = Column(String(255), nullable=True)       # Non-null if an LSN gap exists between segments
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    chain = relationship("RecoveryChain", back_populates="segments")
    recovery_point = relationship("RecoveryPoint")

    def __repr__(self):
        return f"<RecoveryChainSegment #{self.sequence_order} ({self.segment_type}) - Continuous: {self.is_continuous}>"


class RecoveryAssessment(Base):
    """
    Records the explainable cyber trust assessment for a candidate recovery point.
    """
    __tablename__ = "recovery_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    recovery_point_id = Column(String(36), ForeignKey("recovery_points.id", ondelete="CASCADE"), nullable=False, index=True)
    chain_id = Column(String(36), ForeignKey("recovery_chains.id", ondelete="SET NULL"), nullable=True, index=True)
    assessment_name = Column(String(255), nullable=False)
    model_version = Column(String(32), default="1.0.0", nullable=False)

    # Trust Classification
    trust_classification = Column(String(32), nullable=False, index=True)  # HIGH_CONFIDENCE, MEDIUM_CONFIDENCE, LOW_CONFIDENCE, UNASSESSED
    trust_score = Column(Float, nullable=True)                             # 0.0 to 100.0 (Strictly NULL if UNASSESSED)
    has_sufficient_evidence = Column(Boolean, default=False, nullable=False)
    confidence_rationale = Column(Text, nullable=False)                    # Human-readable explanation of confidence rating

    # Structured Assessment Rubric Factors
    positive_indicators_json = Column(Text, nullable=True)   # JSON array of supporting safety evidence
    negative_indicators_json = Column(Text, nullable=True)   # JSON array of detected threat proximity indicators
    missing_telemetry_json = Column(Text, nullable=True)     # JSON array of unmonitored windows, audit gaps
    uncertainty_factors_json = Column(Text, nullable=True)   # JSON array of clock drift, encrypted objects, unverified LSNs

    # Cryptographic Evidence Preservation
    manifest_sha256 = Column(String(64), nullable=True)
    signature = Column(Text, nullable=True)                  # Ed25519 digital signature
    storage_object_key = Column(String(512), nullable=True)
    storage_version_id = Column(String(128), nullable=True)

    assessed_at = Column(DateTime, default=utc_now, nullable=False, index=True)

    # Relationships
    recovery_point = relationship("RecoveryPoint", back_populates="assessments")
    chain = relationship("RecoveryChain", back_populates="assessments")
    evidence_items = relationship("RecoveryAssessmentEvidence", back_populates="assessment", cascade="all, delete-orphan")
    recommendations = relationship("RecoveryRecommendation", back_populates="assessment", cascade="all, delete-orphan")
    history_entries = relationship("RecoveryAssessmentHistory", back_populates="assessment", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<RecoveryAssessment {self.assessment_name} ({self.trust_classification}) - Score: {self.trust_score}>"


class RecoveryAssessmentEvidence(Base):
    """
    Maintains discrete traceable links between a recovery assessment and observed Module 1, 2, and 3 records.
    """
    __tablename__ = "recovery_assessment_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("recovery_assessments.id", ondelete="CASCADE"), nullable=False, index=True)

    evidence_source = Column(String(64), nullable=False)  # MODULE_1_BACKUP, MODULE_2_EVENT, MODULE_2_ALERT, MODULE_3_BASELINE, MODULE_3_FINDING, MONITORING_HEALTH
    source_record_id = Column(String(64), nullable=False) # ID of underlying backup, event, alert, baseline, or finding
    relationship_type = Column(String(32), nullable=False)# CONFIRMED, PROBABLE, POSSIBLE, UNKNOWN

    time_delta_seconds = Column(Integer, nullable=False)  # Offset between recovery point and evidence
    impact_direction = Column(String(32), nullable=False) # POSITIVE, NEGATIVE, NEUTRAL, UNCERTAINTY
    weight_applied = Column(Float, default=1.0, nullable=False)
    description = Column(Text, nullable=False)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    assessment = relationship("RecoveryAssessment", back_populates="evidence_items")

    def __repr__(self):
        return f"<RecoveryAssessmentEvidence [{self.relationship_type}] {self.evidence_source} -> {self.impact_direction}>"


class RecoveryEligibility(Base):
    """
    Separates technical restore feasibility from trust confidence.
    """
    __tablename__ = "recovery_eligibility"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    recovery_point_id = Column(String(36), ForeignKey("recovery_points.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    chain_id = Column(String(36), ForeignKey("recovery_chains.id", ondelete="SET NULL"), nullable=True)

    is_eligible = Column(Boolean, default=False, nullable=False)
    eligibility_status = Column(String(32), nullable=False, index=True)  # ELIGIBLE, INELIGIBLE, REQUIRES_VALIDATION, BLOCKED
    requires_offline_sandbox = Column(Boolean, default=True, nullable=False)  # Always True for production cyber recovery

    # Technical Checklist
    chain_usable = Column(Boolean, default=False, nullable=False)
    chain_consistent = Column(Boolean, default=False, nullable=False)
    logs_available = Column(Boolean, default=False, nullable=False)
    identity_matched = Column(Boolean, default=False, nullable=False)
    files_accessible = Column(Boolean, default=False, nullable=False)
    integrity_verified = Column(Boolean, default=False, nullable=False)
    critical_evidence_missing = Column(Boolean, default=False, nullable=False)

    blocking_reasons_json = Column(Text, nullable=True)     # JSON array of reasons why restore is blocked
    validation_checklist_json = Column(Text, nullable=True) # Step-by-step verification checklist
    evaluated_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    recovery_point = relationship("RecoveryPoint", back_populates="eligibility")
    chain = relationship("RecoveryChain")
    recommendations = relationship("RecoveryRecommendation", back_populates="eligibility", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<RecoveryEligibility ({self.eligibility_status}) - Eligible: {self.is_eligible}>"


class RecoveryRecommendation(Base):
    """
    Stores ranked candidate recovery points with explainable tradeoffs and next-step actions.
    """
    __tablename__ = "recovery_recommendations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    database_id = Column(String(36), ForeignKey("protected_databases.id", ondelete="NO ACTION"), nullable=False, index=True)
    recovery_point_id = Column(String(36), ForeignKey("recovery_points.id", ondelete="NO ACTION"), nullable=False)
    assessment_id = Column(String(36), ForeignKey("recovery_assessments.id", ondelete="NO ACTION"), nullable=False)
    eligibility_id = Column(String(36), ForeignKey("recovery_eligibility.id", ondelete="NO ACTION"), nullable=False)

    rank_order = Column(Integer, nullable=False)  # 1 (Top Recommended), 2, 3...
    trust_classification = Column(String(32), nullable=False)
    eligibility_status = Column(String(32), nullable=False)
    ranking_score = Column(Float, nullable=False)

    rank_rationale = Column(Text, nullable=False)       # Why this point occupies its rank
    tradeoff_analysis = Column(Text, nullable=False)    # Data loss vs threat risk tradeoff
    recommended_next_step = Column(Text, nullable=False)# e.g. "Mount in isolated SQLTrust_Lab sandbox and execute Module 3 baseline audit"
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    recovery_point = relationship("RecoveryPoint", back_populates="recommendations")
    assessment = relationship("RecoveryAssessment", back_populates="recommendations")
    eligibility = relationship("RecoveryEligibility", back_populates="recommendations")

    def __repr__(self):
        return f"<RecoveryRecommendation #{self.rank_order} ({self.trust_classification} / {self.eligibility_status})>"


class RecoveryAssessmentHistory(Base):
    """
    Maintains an immutable lifecycle audit log of assessment transitions, recalculations, and verifications.
    """
    __tablename__ = "recovery_assessment_history"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("recovery_assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)  # CREATED, REASSESSED, SIGNED, ARCHIVED, VERIFIED, EXPORTED
    actor = Column(String(128), default="SYSTEM", nullable=False)
    notes = Column(Text, nullable=True)
    previous_state_json = Column(Text, nullable=True)
    new_state_json = Column(Text, nullable=False)
    recorded_at = Column(DateTime, default=utc_now, nullable=False)

    # Relationships
    assessment = relationship("RecoveryAssessment", back_populates="history_entries")

    def __repr__(self):
        return f"<RecoveryAssessmentHistory {self.event_type} at {self.recorded_at.isoformat()}>"
