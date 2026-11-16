"""
SQL-TRUST Module 5: Recovery Staging & Verification Service
Implements isolated backup artifact retrieval from SeaweedFS S3 using dedicated
read-only credentials, preflight storage capacity validation, multi-layer path
traversal containment, and chunked streaming SHA-256 cryptographic verification.
"""
import os
import re
import shutil
import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError
import boto3

from backend.config import settings
from backend.models.restore import RecoveryJob, BackupStagingRecord
from backend.models.recovery import (
    RecoveryRecommendation,
    RecoveryPoint,
    RecoveryChain,
    RecoveryChainSegment,
    RecoveryEligibility
)
from backend.models.backup import BackupRecord
from backend.services.restore.state_machine import RecoveryJobStateMachine, InvalidStateTransitionError


class StagingError(Exception):
    """Base exception for staging operations."""
    pass


class InsufficientStorageError(StagingError):
    """Raised when available disk space is insufficient for backup staging."""
    pass


class PathTraversalAttackError(StagingError):
    """Raised when a directory traversal or unsafe path manipulation is detected."""
    pass


class IntegrityMismatchError(StagingError):
    """Raised when the computed SHA-256 hash does not match the expected recovery point hash."""
    pass


class ArtifactDownloadError(StagingError):
    """Raised when downloading a backup artifact from S3 storage fails."""
    pass


class RecoveryStagingService:
    """
    Orchestrates backup staging, cryptographic verification, and lifecycle progression
    for cyber recovery jobs.
    """

    def __init__(self, db: Session, s3_client=None, staging_dir: Optional[str] = None):
        self.db = db
        self.staging_dir = os.path.realpath(staging_dir or settings.RECOVERY_STAGING_DIR)
        self._custom_s3_client = s3_client
        self._s3_client = None

    @property
    def s3_client(self):
        """
        Initializes or returns a dedicated read-only S3 client using sqltrust-recovery-reader credentials.
        Guarantees that the recovery engine has zero permissions to mutate or delete S3 backup objects.
        """
        if self._custom_s3_client is not None:
            return self._custom_s3_client

        if self._s3_client is None:
            self._s3_client = boto3.client(
                "s3",
                endpoint_url=settings.effective_s3_endpoint,
                aws_access_key_id=settings.effective_recovery_s3_access_key,
                aws_secret_access_key=settings.effective_recovery_s3_secret_key,
                region_name=settings.effective_s3_region,
                config=Config(
                    connect_timeout=10,
                    read_timeout=60,
                    retries={"max_attempts": 3}
                )
            )
        return self._s3_client

    def check_storage_capacity(self, total_required_bytes: int) -> bool:
        """
        Validates available disk space on the staging volume.
        Enforces a 1.5x multiplier safety margin over total uncompressed/archive backup size.
        """
        os.makedirs(self.staging_dir, exist_ok=True)
        usage = shutil.disk_usage(self.staging_dir)
        free_bytes = usage.free
        required_safety_bytes = int(total_required_bytes * 1.5)

        if free_bytes < required_safety_bytes:
            free_gb = free_bytes / (1024 ** 3)
            req_gb = required_safety_bytes / (1024 ** 3)
            raise InsufficientStorageError(
                f"Insufficient disk space in staging root '{self.staging_dir}'. "
                f"Available: {free_gb:.2f} GB, Required: {req_gb:.2f} GB (includes 1.5x safety multiplier)."
            )
        return True

    def sanitize_and_resolve_staging_path(self, job_id: str, raw_filename: str) -> str:
        """
        Multi-layer path traversal containment:
        1. Strips dangerous directory prefixes and backslashes.
        2. Validates against a strict alphanumeric, dot, hyphen, and underscore whitelist.
        3. Canonicalizes target path and verifies containment inside the designated job staging subfolder.
        """
        if not raw_filename or not isinstance(raw_filename, str):
            raise PathTraversalAttackError("Filename must be a non-empty string.")

        # Disallow explicit traversal sequences or alternate data stream colons
        if ".." in raw_filename or ":" in raw_filename or raw_filename.startswith(("/", "\\")):
            raise PathTraversalAttackError(f"Security Alert: Directory traversal detected in filename: '{raw_filename}'")

        # Extract pure basename
        clean_name = os.path.basename(raw_filename.replace("\\", "/"))

        # Enforce strict regex whitelist
        if not re.match(r"^[a-zA-Z0-9_.-]+$", clean_name):
            raise PathTraversalAttackError(f"Security Alert: Filename '{clean_name}' contains illegal characters.")

        # Construct destination paths
        job_dir = os.path.realpath(os.path.join(self.staging_dir, job_id))
        resolved_candidate = os.path.realpath(os.path.join(job_dir, clean_name))

        # Containment verification
        base_canonical = self.staging_dir
        if os.path.commonpath([base_canonical, resolved_candidate]) != base_canonical:
            raise PathTraversalAttackError(f"Security Alert: Path escapes staging root: '{raw_filename}'")

        if os.path.commonpath([job_dir, resolved_candidate]) != job_dir:
            raise PathTraversalAttackError(f"Security Alert: Path escapes job staging directory: '{raw_filename}'")

        return resolved_candidate

    def calculate_file_sha256(self, file_path: str, chunk_size: int = 1024 * 1024) -> str:
        """Computes SHA-256 checksum of a file in streaming chunks."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest().lower()

    def download_and_verify_artifact(
        self,
        staging_record: BackupStagingRecord
    ) -> BackupStagingRecord:
        """
        Downloads a backup file from SeaweedFS S3 into an atomic partial file,
        calculates SHA-256 during stream write, validates against expected hash,
        and atomically promotes verified file into place.
        """
        staging_record.verification_status = "IN_PROGRESS"
        self.db.commit()

        destination_path = staging_record.staged_file_path
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        part_path = f"{destination_path}.part"

        hasher = hashlib.sha256()
        bytes_downloaded = 0

        try:
            # 1. Attempt S3 Download via Read-Only Client
            bucket_name = settings.effective_s3_bucket
            object_key = staging_record.storage_object_key

            downloaded_from_s3 = False
            try:
                s3_resp = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
                body = s3_resp["Body"]
                with open(part_path, "wb") as out_f:
                    while chunk := body.read(1024 * 1024):  # 1 MB chunk
                        out_f.write(chunk)
                        hasher.update(chunk)
                        bytes_downloaded += len(chunk)
                downloaded_from_s3 = True
            except (ClientError, EndpointConnectionError, Exception) as s3_err:
                # Fallback check for local development/test environments where backup exists on local disk
                local_candidate = os.path.join(settings.BACKUP_LOCAL_DIR, os.path.basename(object_key))
                if not downloaded_from_s3 and os.path.isfile(local_candidate):
                    with open(local_candidate, "rb") as in_f, open(part_path, "wb") as out_f:
                        while chunk := in_f.read(1024 * 1024):
                            out_f.write(chunk)
                            hasher.update(chunk)
                            bytes_downloaded += len(chunk)
                else:
                    raise ArtifactDownloadError(f"Failed to retrieve object '{object_key}' from S3: {s3_err}")

            computed_sha256 = hasher.hexdigest().lower()
            expected_sha256 = staging_record.expected_sha256.strip().lower()

            # 2. Cryptographic Checksum Verification
            if computed_sha256 != expected_sha256:
                if os.path.exists(part_path):
                    os.remove(part_path)
                staging_record.computed_sha256 = computed_sha256
                staging_record.verification_status = "MISMATCH"
                staging_record.error_message = (
                    f"Cryptographic SHA-256 mismatch! "
                    f"Expected: '{expected_sha256}', Computed: '{computed_sha256}'."
                )
                self.db.commit()
                raise IntegrityMismatchError(staging_record.error_message)

            # 3. Promote Atomic File
            if os.path.exists(destination_path):
                os.remove(destination_path)
            os.replace(part_path, destination_path)

            now_utc = datetime.now(timezone.utc)
            staging_record.computed_sha256 = computed_sha256
            staging_record.file_size_bytes = bytes_downloaded
            staging_record.verification_status = "VERIFIED"
            staging_record.error_message = None
            staging_record.staged_at = now_utc
            staging_record.verified_at = now_utc
            self.db.commit()

            return staging_record

        except Exception as e:
            if os.path.exists(part_path):
                try:
                    os.remove(part_path)
                except Exception:
                    pass
            if not isinstance(e, IntegrityMismatchError):
                staging_record.verification_status = "FAILED"
                staging_record.error_message = str(e)
                self.db.commit()
            raise

    def stage_job_backups(
        self,
        job_id: str,
        actor: str = "Recovery_Staging_Engine"
    ) -> List[BackupStagingRecord]:
        """
        Executes end-to-end backup staging and cryptographic verification for a recovery job:
        1. Validates job lifecycle state (PREFLIGHT or BACKUP_STAGING).
        2. Transitions job state from PREFLIGHT to BACKUP_STAGING.
        3. Identifies all ordered chain segments or standalone recovery point.
        4. Conducts preflight disk space validation.
        5. Downloads and verifies each artifact sequentially.
        6. On total success, transitions job state from BACKUP_STAGING to BACKUP_VERIFIED.
        7. On any failure, transitions job state to FAILED with forensic explanation.
        """
        job = self.db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
        if not job:
            raise StagingError(f"Recovery job '{job_id}' not found.")

        # State Guard: Job must be in PREFLIGHT or already in BACKUP_STAGING
        if job.status not in ("PREFLIGHT", "BACKUP_STAGING"):
            raise InvalidStateTransitionError(
                f"Job '{job_id}' is in state '{job.status}'. Staging requires 'PREFLIGHT' or 'BACKUP_STAGING'."
            )

        # Transition PREFLIGHT -> BACKUP_STAGING if needed
        if job.status == "PREFLIGHT":
            RecoveryJobStateMachine.transition(
                db=self.db,
                job=job,
                target_state="BACKUP_STAGING",
                actor=actor,
                reason="Preflight checks passed. Initiating backup staging and cryptographic verification."
            )

        # 1. Resolve Chain / Artifacts to Stage
        artifacts_to_stage: List[Tuple[int, str, RecoveryPoint]] = []

        recommendation = self.db.query(RecoveryRecommendation).filter(
            RecoveryRecommendation.id == job.candidate_id
        ).first()

        chain_id = None
        if recommendation and recommendation.assessment_id:
            from backend.models.recovery import RecoveryAssessment
            assess = self.db.query(RecoveryAssessment).filter(
                RecoveryAssessment.id == recommendation.assessment_id
            ).first()
            if assess and assess.chain_id:
                chain_id = assess.chain_id

        if chain_id:
            segments = self.db.query(RecoveryChainSegment).filter(
                RecoveryChainSegment.chain_id == chain_id
            ).order_by(RecoveryChainSegment.sequence_order.asc()).all()

            for seg in segments:
                rp = self.db.query(RecoveryPoint).filter(RecoveryPoint.id == seg.recovery_point_id).first()
                if rp:
                    artifacts_to_stage.append((seg.sequence_order, seg.segment_type, rp))

        # Fallback to single recovery point if no chain segments found
        if not artifacts_to_stage:
            rp = self.db.query(RecoveryPoint).filter(RecoveryPoint.id == job.recovery_point_id).first()
            if not rp:
                raise StagingError(f"Target recovery point '{job.recovery_point_id}' not found.")
            artifacts_to_stage.append((1, rp.recovery_point_type, rp))

        # 2. Preflight Storage Capacity Check
        total_estimated_bytes = 0
        for seq, b_type, rp in artifacts_to_stage:
            # Query associated BackupRecord size if present
            if rp.backup_id:
                brec = self.db.query(BackupRecord).filter(BackupRecord.id == rp.backup_id).first()
                if brec and brec.backup_size_bytes:
                    total_estimated_bytes += brec.backup_size_bytes
                    continue
            total_estimated_bytes += 50 * 1024 * 1024  # Default 50MB estimate if unknown

        try:
            self.check_storage_capacity(total_estimated_bytes)
        except InsufficientStorageError as err:
            RecoveryJobStateMachine.transition(
                db=self.db,
                job=job,
                target_state="FAILED",
                actor=actor,
                reason=str(err),
                failure_code="INSUFFICIENT_STORAGE"
            )
            raise

        # 3. Stage & Verify Artifacts Sequentially
        staged_records: List[BackupStagingRecord] = []

        for seq, b_type, rp in artifacts_to_stage:
            # Check for existing staging record
            record = self.db.query(BackupStagingRecord).filter(
                BackupStagingRecord.job_id == job.id,
                BackupStagingRecord.recovery_point_id == rp.id
            ).first()

            raw_filename = os.path.basename(rp.storage_object_key or f"backup_{rp.id}.bak")
            safe_dest_path = self.sanitize_and_resolve_staging_path(job.id, raw_filename)

            if not record:
                record = BackupStagingRecord(
                    job_id=job.id,
                    recovery_point_id=rp.id,
                    sequence_order=seq,
                    backup_type=b_type,
                    storage_object_key=rp.storage_object_key or f"backups/{raw_filename}",
                    staged_file_path=safe_dest_path,
                    expected_sha256=rp.sha256 or "",
                    verification_status="PENDING"
                )
                self.db.add(record)
                self.db.commit()
                self.db.refresh(record)

            # Skip download if already verified and local file exists
            if record.verification_status == "VERIFIED" and os.path.isfile(record.staged_file_path):
                staged_records.append(record)
                continue

            try:
                self.download_and_verify_artifact(record)
                staged_records.append(record)
            except IntegrityMismatchError as imm_err:
                RecoveryJobStateMachine.transition(
                    db=self.db,
                    job=job,
                    target_state="FAILED",
                    actor=actor,
                    reason=f"Artifact #{seq} ({b_type}) failed integrity check: {imm_err}",
                    failure_code="INTEGRITY_MISMATCH"
                )
                raise
            except Exception as dl_err:
                RecoveryJobStateMachine.transition(
                    db=self.db,
                    job=job,
                    target_state="FAILED",
                    actor=actor,
                    reason=f"Artifact #{seq} ({b_type}) download failed: {dl_err}",
                    failure_code="STAGING_DOWNLOAD_FAILED"
                )
                raise

        # 4. Promote Job State to BACKUP_VERIFIED
        all_verified = all(r.verification_status == "VERIFIED" for r in staged_records)
        if all_verified and staged_records:
            RecoveryJobStateMachine.transition(
                db=self.db,
                job=job,
                target_state="BACKUP_VERIFIED",
                actor=actor,
                reason=f"All {len(staged_records)} backup artifacts staged and cryptographically verified."
            )

        return staged_records

    def retry_artifact(
        self,
        record_id: str,
        actor: str = "Operator"
    ) -> BackupStagingRecord:
        """
        Retries staging and verification for a single failed or mismatched backup artifact.
        """
        record = self.db.query(BackupStagingRecord).filter(
            BackupStagingRecord.id == record_id
        ).first()
        if not record:
            raise StagingError(f"Backup staging record '{record_id}' not found.")

        record.verification_status = "PENDING"
        record.error_message = None
        self.db.commit()

        return self.download_and_verify_artifact(record)

    def get_staging_status(self, job_id: str) -> Dict[str, Any]:
        """
        Retrieves aggregated staging and integrity verification status for a job.
        """
        job = self.db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
        if not job:
            raise StagingError(f"Recovery job '{job_id}' not found.")

        records = self.db.query(BackupStagingRecord).filter(
            BackupStagingRecord.job_id == job_id
        ).order_by(BackupStagingRecord.sequence_order.asc()).all()

        total_artifacts = len(records)
        staged_count = sum(1 for r in records if r.verification_status in ("VERIFIED", "IN_PROGRESS"))
        verified_count = sum(1 for r in records if r.verification_status == "VERIFIED")
        total_bytes = sum(r.file_size_bytes or 0 for r in records)

        if not records:
            overall = "PENDING"
        elif any(r.verification_status == "MISMATCH" for r in records):
            overall = "MISMATCH"
        elif any(r.verification_status == "FAILED" for r in records):
            overall = "FAILED"
        elif all(r.verification_status == "VERIFIED" for r in records):
            overall = "VERIFIED"
        else:
            overall = "IN_PROGRESS"

        return {
            "job_id": job.id,
            "job_reference": job.job_reference,
            "overall_status": overall,
            "total_artifacts": total_artifacts,
            "staged_count": staged_count,
            "verified_count": verified_count,
            "total_bytes": total_bytes,
            "artifacts": records
        }
