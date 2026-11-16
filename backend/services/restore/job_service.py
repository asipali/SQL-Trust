"""
SQL-TRUST Recovery Job Management Service
Module 5: Restore & Cyber Recovery Validation
Handles recovery candidate intake, preflight gating, idempotency,
job lifecycle tracking, and state transitions.
"""
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_
from fastapi import HTTPException, status

from backend.models.restore import RecoveryJob, RecoveryJobHistory, generate_job_reference
from backend.models.recovery import (
    RecoveryRecommendation,
    RecoveryPoint,
    RecoveryAssessment,
    RecoveryEligibility
)
from backend.models.backup import ProtectedDatabase
from backend.services.restore.state_machine import RecoveryJobStateMachine, InvalidStateTransitionError


class RecoveryJobService:
    """
    Manages the lifecycle of recovery validation jobs from candidate intake
    through preflight, staging, and state transitions.
    """

    def __init__(self, db: Session):
        self.db = db

    def create_job(
        self,
        candidate_id: str,
        idempotency_key: Optional[str] = None,
        requested_by: Optional[str] = None,
        notes: Optional[str] = None
    ) -> Tuple[RecoveryJob, bool]:
        """
        Ingests a Module 4 recovery candidate and initializes a new recovery validation job.
        Returns a tuple of (RecoveryJob, is_newly_created).
        Supports strict idempotency: if an identical idempotency_key exists, returns the existing job.
        """
        # 1. Idempotency Check
        if idempotency_key:
            existing = self.db.query(RecoveryJob).filter(
                RecoveryJob.idempotency_key == idempotency_key
            ).first()
            if existing:
                return existing, False

        # 2. Fetch Module 4 Recommendation
        recommendation = self.db.query(RecoveryRecommendation).filter(
            RecoveryRecommendation.id == candidate_id
        ).first()
        if not recommendation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Recovery recommendation '{candidate_id}' not found."
            )

        # 3. Retrieve Candidate Recovery Point
        recovery_point = self.db.query(RecoveryPoint).filter(
            RecoveryPoint.id == recommendation.recovery_point_id
        ).first()
        if not recovery_point:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Associated recovery point '{recommendation.recovery_point_id}' not found."
            )

        # 4. Enforce Technical Eligibility Gate
        eligibility = self.db.query(RecoveryEligibility).filter(
            RecoveryEligibility.id == recommendation.eligibility_id
        ).first()
        if not eligibility or not eligibility.is_eligible:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Recovery candidate is technically INELIGIBLE for restore."
            )

        # 5. Enforce Trust Assessment Gate (UNASSESSED prohibited)
        assessment = self.db.query(RecoveryAssessment).filter(
            RecoveryAssessment.id == recommendation.assessment_id
        ).first()
        if not assessment or assessment.trust_classification == "UNASSESSED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Recovery candidate has UNASSESSED trust risk. Complete Module 4 trust assessment first."
            )

        # 6. Resolve Target Database Name
        target_db_name = recovery_point.database_name
        if not target_db_name and recommendation.database_id:
            protected_db = self.db.query(ProtectedDatabase).filter(
                ProtectedDatabase.id == recommendation.database_id
            ).first()
            if protected_db:
                target_db_name = protected_db.database_name
        if not target_db_name:
            target_db_name = "Unknown_Database"

        actor = requested_by or "Operator"
        now = datetime.now(timezone.utc)

        # 7. Create Job Record
        new_job = RecoveryJob(
            job_reference=generate_job_reference(),
            candidate_id=candidate_id,
            recovery_point_id=recommendation.recovery_point_id,
            target_database_name=target_db_name,
            status="REQUESTED",
            requested_by=actor,
            requested_at=now,
            idempotency_key=idempotency_key,
            target_recovery_time=recovery_point.recovery_point_time,
            target_time_basis="UTC",
            notes=notes,
            created_at=now,
            updated_at=now
        )
        self.db.add(new_job)
        self.db.flush()

        # 8. Add Initial History Entry
        initial_history = RecoveryJobHistory(
            job_id=new_job.id,
            from_state="NONE",
            to_state="REQUESTED",
            actor=actor,
            reason="Job requested and intake gates verified",
            transitioned_at=now
        )
        self.db.add(initial_history)
        self.db.commit()
        self.db.refresh(new_job)

        return new_job, True

    def get_job(self, job_id: str) -> RecoveryJob:
        """Retrieves a recovery job by UUID or job_reference."""
        job = self.db.query(RecoveryJob).filter(
            or_(RecoveryJob.id == job_id, RecoveryJob.job_reference == job_id)
        ).first()
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Recovery job '{job_id}' not found."
            )
        return job

    def list_jobs(
        self,
        status_filter: Optional[str] = None,
        candidate_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[RecoveryJob]:
        """Lists recovery validation jobs with optional filtering."""
        query = self.db.query(RecoveryJob)
        if status_filter:
            query = query.filter(RecoveryJob.status == status_filter)
        if candidate_id:
            query = query.filter(RecoveryJob.candidate_id == candidate_id)
        return query.order_by(RecoveryJob.created_at.desc()).offset(offset).limit(limit).all()

    def get_job_history(self, job_id: str) -> List[RecoveryJobHistory]:
        """Retrieves immutable transition history for a recovery job."""
        job = self.get_job(job_id)
        return self.db.query(RecoveryJobHistory).filter(
            RecoveryJobHistory.job_id == job.id
        ).order_by(RecoveryJobHistory.transitioned_at.asc()).all()

    def approve_job(
        self,
        job_id: str,
        approved_by: Optional[str] = None,
        approver_notes: Optional[str] = None
    ) -> RecoveryJob:
        """
        Approves an active recovery job for execution, transitioning it to PREFLIGHT.
        Enforces idempotency: if already in PREFLIGHT, returns current state.
        """
        job = self.get_job(job_id)
        if job.status == "PREFLIGHT":
            return job

        if job.status != "REQUESTED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot approve job in state '{job.status}'. Only jobs in 'REQUESTED' state can be approved."
            )

        actor = approved_by or "Lead_Admin"
        now = datetime.now(timezone.utc)
        job.approved_by = actor
        job.approved_at = now

        try:
            RecoveryJobStateMachine.transition(
                db=self.db,
                job=job,
                target_state="PREFLIGHT",
                actor=actor,
                reason=approver_notes or "Administrative approval granted for preflight execution"
            )
            self.db.commit()
            self.db.refresh(job)
            return job
        except InvalidStateTransitionError as e:
            self.db.rollback()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    def cancel_job(
        self,
        job_id: str,
        cancellation_reason: str,
        cancelled_by: Optional[str] = None
    ) -> RecoveryJob:
        """
        Cancels an active recovery job, marking it as FAILED with code USER_CANCELLED.
        Never deletes forensic history or existing evidence records.
        """
        job = self.get_job(job_id)
        if job.status in ("FAILED", "CLEANED"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel job in terminal state '{job.status}'."
            )

        actor = cancelled_by or "Operator"
        try:
            RecoveryJobStateMachine.transition(
                db=self.db,
                job=job,
                target_state="FAILED",
                actor=actor,
                reason=cancellation_reason,
                failure_code="USER_CANCELLED"
            )
            self.db.commit()
            self.db.refresh(job)
            return job
        except InvalidStateTransitionError as e:
            self.db.rollback()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
