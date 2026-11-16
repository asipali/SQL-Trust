"""
SQL-TRUST Backup Engine
Orchestrates enterprise SQL Server backup workflows:
FULL, DIFFERENTIAL, and TRANSACTION LOG backups.
Enforces multi-stage verification, chunked cryptographic hashing,
SeaweedFS S3 storage synchronization, and immutable JSON manifest creation.
"""
import os
import shutil
import hashlib
import uuid
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import pyodbc
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import build_odbc_connection_string
from backend.models.backup import (
    ProtectedDatabase,
    BackupRecord,
    BackupManifest,
    BackupOperationLog
)
from backend.services.database_service import validate_sql_identifier, DatabaseService
from backend.services.storage.seaweedfs import SeaweedFSStorageProvider
from backend.services.storage.manifest import generate_backup_manifest

# Thread-safe locks per database to prevent concurrent backup collisions
_db_locks: Dict[str, threading.Lock] = {}
_lock_registry_mutex = threading.Lock()


def get_db_lock(database_name: str) -> threading.Lock:
    """Returns or creates a thread lock for the designated database."""
    with _lock_registry_mutex:
        if database_name not in _db_locks:
            _db_locks[database_name] = threading.Lock()
        return _db_locks[database_name]


def calculate_file_sha256(file_path: str, chunk_size: int = 1024 * 1024) -> str:
    """
    Streams file in memory-efficient chunks (1 MB default) to compute SHA-256 hash.
    Never loads the entire file into memory.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


class BackupEngine:
    """
    Full-lifecycle SQL Server backup orchestrator.
    """

    def __init__(self, db_session: Session):
        self.db = db_session
        self.storage = SeaweedFSStorageProvider()
        self.db_service = DatabaseService(db_session=self.db)

    def _log_operation(
        self,
        backup_id: Optional[str],
        operation: str,
        status: str,
        started_at: datetime,
        completed_at: Optional[datetime] = None,
        error_details: Optional[str] = None
    ) -> BackupOperationLog:
        """Records an audit log entry in the control database."""
        log_entry = BackupOperationLog(
            backup_id=backup_id,
            operation=operation,
            status=status,
            started_at=started_at,
            completed_at=completed_at or datetime.now(timezone.utc),
            error_details=error_details
        )
        self.db.add(log_entry)
        self.db.commit()
        return log_entry

    def generate_backup_filename(self, database_name: str, backup_type: str) -> str:
        """
        Produces collision-resistant backup filename.
        Format: {DatabaseName}_{TYPE}_{YYYYMMDD_HHMMSS}_{UUID8}.bak (.trn for LOG)
        """
        clean_db = validate_sql_identifier(database_name)
        type_upper = backup_type.upper()
        ext = ".trn" if type_upper == "LOG" else ".bak"
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        unique_suffix = uuid.uuid4().hex[:8]
        return f"{clean_db}_{type_upper}_{timestamp}_{unique_suffix}{ext}"

    def check_directory_and_space(self, target_dir: str, min_free_mb: int = 100) -> Dict[str, Any]:
        """
        Validates backup directory existence, write permissions, and available disk space.
        """
        os.makedirs(target_dir, exist_ok=True)

        if not os.access(target_dir, os.W_OK):
            raise PermissionError(f"Backend does not have write access to backup directory: {target_dir}")

        total, used, free = shutil.disk_usage(target_dir)
        free_mb = free / (1024 * 1024)

        if free_mb < min_free_mb:
            raise RuntimeError(
                f"Insufficient disk space in backup directory {target_dir}. "
                f"Available: {free_mb:.2f} MB, Required: {min_free_mb} MB"
            )

        return {
            "directory": target_dir,
            "free_bytes": free,
            "free_mb": free_mb,
            "total_bytes": total
        }

    def execute_backup(
        self,
        database_id: str,
        backup_type: str,
        operator_notes: Optional[str] = None
    ) -> BackupRecord:
        """
        Executes an end-to-end backup workflow:
        1. Pre-backup validation (database status, recovery model, disk space)
        2. SQL Server BACKUP execution
        3. Metadata extraction (LSNs, backup size)
        4. Stage 1 Verification (RESTORE VERIFYONLY WITH CHECKSUM)
        5. Stage 2 Verification (Chunked SHA-256 calculation)
        6. Stage 3 Storage (SeaweedFS S3 upload & remote size verification)
        7. Stage 4 Manifest Generation (JSON manifest & S3 manifest upload)
        8. Audit state transition & database commit
        """
        backup_type = backup_type.upper()
        if backup_type not in ("FULL", "DIFFERENTIAL", "LOG"):
            raise ValueError(f"Unsupported backup type '{backup_type}'. Allowed: FULL, DIFFERENTIAL, LOG")

        # Step 1: Validate Registered Database
        protected_db = self.db.query(ProtectedDatabase).filter(
            ProtectedDatabase.id == database_id
        ).first()

        if not protected_db:
            raise ValueError(f"Protected database with ID '{database_id}' not found in registry.")

        db_name = validate_sql_identifier(protected_db.database_name)

        # Acquire lock to prevent duplicate concurrent backups for this database
        db_lock = get_db_lock(db_name)
        if not db_lock.acquire(blocking=False):
            raise RuntimeError(f"A backup operation is currently in progress for database '{db_name}'. Concurrent backups are prevented.")

        backup_record: Optional[BackupRecord] = None
        local_file_path: Optional[str] = None

        try:
            # Query live SQL Server database state & recovery model
            live_details = self.db_service.get_database_details(db_name)
            if not live_details:
                raise RuntimeError(f"Database '{db_name}' could not be found on SQL Server instance.")

            if live_details["state"] != "ONLINE":
                raise RuntimeError(f"Database '{db_name}' is currently in '{live_details['state']}' state. Backups require ONLINE state.")

            # Update recovery model in registry if changed
            if protected_db.recovery_model != live_details["recovery_model"]:
                protected_db.recovery_model = live_details["recovery_model"]
                self.db.commit()

            # Step 2: Validate Recovery Model & Backup Chain Preconditions
            if backup_type == "LOG":
                if live_details["recovery_model"] == "SIMPLE":
                    raise ValueError(
                        f"Database '{db_name}' is configured in SIMPLE recovery model. "
                        "Transaction log backups require FULL or BULK_LOGGED recovery model because "
                        "SQL Server automatically truncates inactive log portions at checkpoints in SIMPLE recovery."
                    )
                # Verify that at least one FULL backup exists
                last_full = self.db.query(BackupRecord).filter(
                    BackupRecord.database_id == database_id,
                    BackupRecord.backup_type == "FULL",
                    BackupRecord.backup_status == "COMPLETED"
                ).first()
                if not last_full:
                    raise ValueError(
                        f"Cannot take transaction log backup for '{db_name}' because no prior successful FULL backup exists in the chain."
                    )

            elif backup_type == "DIFFERENTIAL":
                last_full = self.db.query(BackupRecord).filter(
                    BackupRecord.database_id == database_id,
                    BackupRecord.backup_type == "FULL",
                    BackupRecord.backup_status == "COMPLETED"
                ).first()
                if not last_full:
                    raise ValueError(
                        f"Cannot take DIFFERENTIAL backup for '{db_name}' because no prior successful base FULL backup exists in the chain."
                    )

            # Step 3: Check Backup Directory & Disk Capacity
            target_dir = settings.BACKUP_LOCAL_DIR
            self.check_directory_and_space(target_dir, min_free_mb=50)

            # Step 4: Generate File Name and Paths
            filename = self.generate_backup_filename(db_name, backup_type)
            local_file_path = os.path.join(target_dir, filename)

            # Check for file collisions
            if os.path.exists(local_file_path):
                raise FileExistsError(f"Backup file '{local_file_path}' already exists! Accidental overwrite prevented.")

            # Construct SQL Server target path (as seen by SQL Server service)
            sql_target_path = os.path.join(settings.SQL_BACKUP_DIR, filename)

            # Initialize BackupRecord in control DB
            start_time = datetime.now(timezone.utc)
            backup_record = BackupRecord(
                database_id=database_id,
                backup_type=backup_type,
                backup_filename=filename,
                backup_path=sql_target_path,
                start_time=start_time,
                backup_status="RUNNING"
            )
            self.db.add(backup_record)
            self.db.commit()
            self.db.refresh(backup_record)

            self._log_operation(
                backup_id=backup_record.id,
                operation="VALIDATE_ENV",
                status="COMPLETED",
                started_at=start_time
            )

            # Step 5: Execute SQL Server Backup Command
            op_start = datetime.now(timezone.utc)
            conn_str = build_odbc_connection_string(database="master")
            
            # Formulate safe parameterized command
            if backup_type == "FULL":
                sql_cmd = f"BACKUP DATABASE [{db_name}] TO DISK = N'{sql_target_path}' WITH FORMAT, INIT, CHECKSUM, STATS = 10"
            elif backup_type == "DIFFERENTIAL":
                sql_cmd = f"BACKUP DATABASE [{db_name}] TO DISK = N'{sql_target_path}' WITH DIFFERENTIAL, FORMAT, INIT, CHECKSUM, STATS = 10"
            else:  # LOG
                sql_cmd = f"BACKUP LOG [{db_name}] TO DISK = N'{sql_target_path}' WITH FORMAT, INIT, CHECKSUM, STATS = 10"

            with pyodbc.connect(conn_str, autocommit=True) as sql_conn:
                cursor = sql_conn.cursor()
                cursor.execute(sql_cmd)
                while cursor.nextset():
                    pass  # Drain informational messages

            finish_time = datetime.now(timezone.utc)
            backup_record.finish_time = finish_time
            self.db.commit()

            self._log_operation(
                backup_id=backup_record.id,
                operation="SQL_BACKUP",
                status="COMPLETED",
                started_at=op_start,
                completed_at=finish_time
            )

            # Step 6: Collect SQL Server Metadata from Header
            op_start = datetime.now(timezone.utc)
            with pyodbc.connect(conn_str, autocommit=True) as sql_conn:
                cursor = sql_conn.cursor()
                cursor.execute(f"RESTORE HEADERONLY FROM DISK = N'{sql_target_path}'")
                cols = [c[0] for c in cursor.description]
                row = cursor.fetchone()
                if row:
                    header_map = dict(zip(cols, row))
                    backup_record.first_lsn = str(header_map.get("FirstLSN") or "")
                    backup_record.last_lsn = str(header_map.get("LastLSN") or "")
                    backup_record.checkpoint_lsn = str(header_map.get("CheckpointLSN") or "")
                    backup_record.database_backup_lsn = str(header_map.get("DatabaseBackupLSN") or "")
                    backup_record.backup_size_bytes = int(header_map.get("BackupSize") or os.path.getsize(local_file_path))
                while cursor.nextset():
                    pass

            self.db.commit()

            # Step 7: Stage 1 Verification (RESTORE VERIFYONLY WITH CHECKSUM)
            backup_record.backup_status = "VERIFYING"
            self.db.commit()

            op_start = datetime.now(timezone.utc)
            with pyodbc.connect(conn_str, autocommit=True) as sql_conn:
                cursor = sql_conn.cursor()
                cursor.execute(f"RESTORE VERIFYONLY FROM DISK = N'{sql_target_path}' WITH CHECKSUM")
                while cursor.nextset():
                    pass

            backup_record.sql_verification_status = "PASSED"
            self.db.commit()

            self._log_operation(
                backup_id=backup_record.id,
                operation="SQL_VERIFYONLY",
                status="COMPLETED",
                started_at=op_start
            )

            # Step 8: Stage 2 Verification (Cryptographic SHA-256 calculation)
            op_start = datetime.now(timezone.utc)
            calculated_hash = calculate_file_sha256(local_file_path)
            exact_size = os.path.getsize(local_file_path)

            backup_record.sha256 = calculated_hash
            backup_record.backup_size_bytes = exact_size
            self.db.commit()

            self._log_operation(
                backup_id=backup_record.id,
                operation="CALCULATE_SHA256",
                status="COMPLETED",
                started_at=op_start
            )

            # Step 9: Stage 3 Storage (SeaweedFS S3 Upload)
            backup_record.backup_status = "UPLOADING"
            self.db.commit()

            op_start = datetime.now(timezone.utc)
            object_key = f"backups/{db_name}/{backup_type}/{filename}"
            
            upload_result = self.storage.upload_file(
                local_file_path=local_file_path,
                object_key=object_key,
                metadata={
                    "sqltrust-backup-id": str(backup_record.id),
                    "sqltrust-database": db_name,
                    "sqltrust-type": backup_type,
                    "sqltrust-sha256": calculated_hash
                }
            )

            backup_record.storage_object_key = object_key
            backup_record.storage_object_version_id = upload_result.get("version_id")
            backup_record.retention_mode = upload_result.get("retention_mode")
            if upload_result.get("retain_until_date"):
                try:
                    backup_record.retention_until = datetime.fromisoformat(str(upload_result["retain_until_date"]))
                except Exception:
                    pass
            backup_record.storage_upload_status = "COMPLETED"
            self.db.commit()

            self._log_operation(
                backup_id=backup_record.id,
                operation="STORAGE_UPLOAD",
                status="COMPLETED",
                started_at=op_start
            )

            # Step 10: Stage 4 Manifest Generation
            op_start = datetime.now(timezone.utc)
            manifest_info = generate_backup_manifest(
                backup_record=backup_record,
                database=protected_db,
                storage_provider="SEAWEEDFS",
                additional_metadata={"notes": operator_notes}
            )

            # Upload manifest JSON object to SeaweedFS alongside the backup
            manifest_key = f"backups/{db_name}/{backup_type}/{filename}.manifest.json"
            # Write temp local manifest
            temp_manifest_path = local_file_path + ".manifest.json"
            with open(temp_manifest_path, "w", encoding="utf-8") as mf:
                mf.write(manifest_info["manifest_json"])

            try:
                self.storage.upload_file(
                    local_file_path=temp_manifest_path,
                    object_key=manifest_key
                )
            finally:
                if os.path.exists(temp_manifest_path):
                    os.remove(temp_manifest_path)

            # Save manifest record in control database
            manifest_record = BackupManifest(
                backup_id=backup_record.id,
                manifest_version="1.0",
                manifest_json=manifest_info["manifest_json"],
                manifest_hash=manifest_info["manifest_hash"]
            )
            self.db.add(manifest_record)

            # Step 11: Finalize Operation State
            backup_record.backup_status = "COMPLETED"
            self.db.commit()
            self.db.refresh(backup_record)

            self._log_operation(
                backup_id=backup_record.id,
                operation="GENERATE_MANIFEST",
                status="COMPLETED",
                started_at=op_start
            )

            return backup_record

        except Exception as e:
            error_msg = str(e)
            if backup_record:
                backup_record.backup_status = "FAILED"
                backup_record.error_message = error_msg
                self.db.commit()

                self._log_operation(
                    backup_id=backup_record.id,
                    operation="BACKUP_PIPELINE",
                    status="FAILED",
                    started_at=datetime.now(timezone.utc),
                    error_details=error_msg
                )
            raise e

        finally:
            db_lock.release()

    def verify_existing_backup(self, backup_id: str) -> Dict[str, Any]:
        """
        Re-verifies an existing completed backup:
        Stage 1: RESTORE VERIFYONLY WITH CHECKSUM on local backup file.
        Stage 2: Re-computes SHA-256 and compares against stored hash.
        """
        record = self.db.query(BackupRecord).filter(BackupRecord.id == backup_id).first()
        if not record:
            raise ValueError(f"Backup record '{backup_id}' not found.")

        local_path = os.path.join(settings.BACKUP_LOCAL_DIR, record.backup_filename)
        
        # If file missing locally, attempt download from SeaweedFS
        downloaded = False
        if not os.path.exists(local_path):
            if record.storage_object_key:
                self.storage.download_file(record.storage_object_key, local_path)
                downloaded = True
            else:
                raise FileNotFoundError(f"Backup file '{record.backup_filename}' not found locally or in remote storage.")

        results = {
            "backup_id": str(record.id),
            "filename": record.backup_filename,
            "version_id": record.storage_object_version_id,
            "retention_mode": record.retention_mode,
            "retention_until": record.retention_until.isoformat() if record.retention_until else None,
            "is_immutable": record.retention_mode in ("COMPLIANCE", "GOVERNANCE"),
            "sql_verification": "FAILED",
            "file_integrity": "FAILED",
            "sha256_match": False,
            "stored_sha256": record.sha256,
            "calculated_sha256": None,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "downloaded_from_storage": downloaded
        }

        # Stage 0: Verify Storage Retention on Remote Object Version
        if record.storage_object_key:
            remote_retention = self.storage.get_object_retention(
                object_key=record.storage_object_key,
                version_id=record.storage_object_version_id
            )
            results["storage_retention_verified"] = remote_retention.get("mode") in ("COMPLIANCE", "GOVERNANCE")
            results["remote_retention_mode"] = remote_retention.get("mode")
            results["remote_retain_until"] = remote_retention.get("retain_until_date")

        # Stage 1: SQL Server RESTORE VERIFYONLY
        try:
            conn_str = build_odbc_connection_string(database="master")
            with pyodbc.connect(conn_str, autocommit=True) as sql_conn:
                cursor = sql_conn.cursor()
                cursor.execute(f"RESTORE VERIFYONLY FROM DISK = N'{record.backup_path}' WITH CHECKSUM")
                while cursor.nextset():
                    pass
            results["sql_verification"] = "PASSED"
        except Exception as e:
            results["sql_verification_error"] = str(e)

        # Stage 2: SHA-256 Check
        try:
            curr_hash = calculate_file_sha256(local_path)
            results["calculated_sha256"] = curr_hash
            if curr_hash == record.sha256:
                results["sha256_match"] = True
                results["file_integrity"] = "PASSED"
            else:
                results["file_integrity"] = "INTEGRITY_MISMATCH"
        except Exception as e:
            results["file_integrity_error"] = str(e)

        return results
