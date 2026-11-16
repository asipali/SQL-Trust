"""
SQL-TRUST Recovery Job State Machine
Module 5: Restore & Cyber Recovery Validation
Enforces deterministic, non-reversible lifecycle state transitions across the 17 defined states.
Prevents unearned state jumps, records immutable transition audits, and supports crash recovery.
"""
from typing import Set, Dict, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.models.restore import RecoveryJob, RecoveryJobHistory


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal or premature lifecycle state transition is attempted."""
    pass


# Full set of 17 lifecycle states
ALL_STATES: Set[str] = {
    "REQUESTED",
    "PREFLIGHT",
    "IMAGE_VERIFIED",
    "ENVIRONMENT_CREATED",
    "BACKUP_STAGING",
    "BACKUP_VERIFIED",
    "RESTORE_IN_PROGRESS",
    "RESTORE_COMPLETED",
    "VALIDATION_IN_PROGRESS",
    "VALIDATION_COMPLETED",
    "EVIDENCE_ARCHIVED",
    "REPORT_GENERATED",
    "FAILED",
    "INTERRUPTED",
    "MANUAL_REVIEW_REQUIRED",
    "CLEANUP_PENDING",
    "CLEANED",
}

# Explicit permitted transitions matrix
PERMITTED_TRANSITIONS: Dict[str, Set[str]] = {
    "REQUESTED": {"PREFLIGHT", "FAILED", "INTERRUPTED"},
    "PREFLIGHT": {"IMAGE_VERIFIED", "ENVIRONMENT_CREATED", "BACKUP_STAGING", "FAILED", "INTERRUPTED", "MANUAL_REVIEW_REQUIRED"},
    "IMAGE_VERIFIED": {"ENVIRONMENT_CREATED", "BACKUP_STAGING", "FAILED", "INTERRUPTED"},
    "ENVIRONMENT_CREATED": {"BACKUP_STAGING", "RESTORE_IN_PROGRESS", "FAILED", "INTERRUPTED"},
    "BACKUP_STAGING": {"BACKUP_VERIFIED", "FAILED", "INTERRUPTED", "MANUAL_REVIEW_REQUIRED"},
    "BACKUP_VERIFIED": {"ENVIRONMENT_CREATED", "RESTORE_IN_PROGRESS", "FAILED", "INTERRUPTED", "MANUAL_REVIEW_REQUIRED"},
    "RESTORE_IN_PROGRESS": {"RESTORE_COMPLETED", "FAILED", "INTERRUPTED"},
    "RESTORE_COMPLETED": {"VALIDATION_IN_PROGRESS", "FAILED", "INTERRUPTED"},
    "VALIDATION_IN_PROGRESS": {"VALIDATION_COMPLETED", "FAILED", "INTERRUPTED"},
    "VALIDATION_COMPLETED": {"EVIDENCE_ARCHIVED", "FAILED", "INTERRUPTED"},
    "EVIDENCE_ARCHIVED": {"REPORT_GENERATED", "FAILED", "INTERRUPTED"},
    "REPORT_GENERATED": {"CLEANUP_PENDING", "FAILED"},
    "FAILED": {"MANUAL_REVIEW_REQUIRED", "CLEANUP_PENDING"},
    "INTERRUPTED": {"MANUAL_REVIEW_REQUIRED"},
    "MANUAL_REVIEW_REQUIRED": {"PREFLIGHT", "BACKUP_STAGING", "CLEANUP_PENDING", "FAILED"},
    "CLEANUP_PENDING": {"CLEANED", "FAILED"},
    "CLEANED": set(),  # Terminal state
}

# Unimplemented states restriction (cleared as Phases 4-7 are implemented)
UNIMPLEMENTED_TARGET_STATES: Set[str] = set()


class RecoveryJobStateMachine:
    """
    Validates and executes atomic state transitions for recovery jobs.
    Guarantees that state history is immutably appended to recovery_job_history.
    """

    @staticmethod
    def is_valid_transition(current_state: str, target_state: str) -> bool:
        """Checks if a transition between two states is structurally permitted."""
        if current_state not in ALL_STATES or target_state not in ALL_STATES:
            return False
        return target_state in PERMITTED_TRANSITIONS.get(current_state, set())

    @classmethod
    def transition(
        cls,
        db: Session,
        job: RecoveryJob,
        target_state: str,
        actor: str,
        reason: Optional[str] = None,
        evidence_reference: Optional[str] = None,
        failure_code: Optional[str] = None
    ) -> RecoveryJob:
        """
        Executes a validated state transition, updates the job record,
        and appends an immutable history entry.
        """
        current_state = job.status

        # 1. Reject self-transitions (idempotency guard)
        if current_state == target_state:
            return job

        # 2. Check permitted transition graph
        if not cls.is_valid_transition(current_state, target_state):
            raise InvalidStateTransitionError(
                f"Illegal transition from state '{current_state}' to '{target_state}'."
            )

        # 3. Reject claiming unimplemented milestones in Phases 2 & 3
        if target_state in UNIMPLEMENTED_TARGET_STATES:
            raise InvalidStateTransitionError(
                f"Target state '{target_state}' cannot be transitioned to because its operational engine is deferred to Phase 4+."
            )

        now = datetime.now(timezone.utc)

        # 4. Update job fields based on target state
        job.status = target_state
        job.updated_at = now

        if target_state == "PREFLIGHT" and not job.started_at:
            job.started_at = now

        if target_state == "FAILED":
            job.completed_at = now
            if failure_code:
                job.failure_code = failure_code
            if reason:
                job.failure_reason = reason

        # 5. Persist immutable history record
        history_entry = RecoveryJobHistory(
            job_id=job.id,
            from_state=current_state,
            to_state=target_state,
            actor=actor,
            reason=reason,
            evidence_reference=evidence_reference,
            transitioned_at=now
        )
        db.add(history_entry)
        db.flush()

        return job
