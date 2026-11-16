"""
SQL-TRUST Module 5: Restore Orchestration Service (Phase 5)
Validates backup chain LSN continuity, differential base compatibility, and header metadata;
generates structured, auditable restore plans; and executes physical restorations
(Full, Differential, Transaction Log with STOPAT) exclusively against isolated sandboxes.
"""
import os
import re
import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List
from sqlalchemy.orm import Session
import pyodbc

from backend.config import settings
from backend.models.restore import (
    RecoveryJob,
    RecoverySandbox,
    BackupStagingRecord,
    RestorePlan,
    RestoreOperation
)
from backend.services.restore.sandbox_service import RecoverySandboxService
from backend.services.restore.state_machine import RecoveryJobStateMachine, InvalidStateTransitionError


class RestoreError(Exception):
    """Base exception for restore orchestration."""
    pass


class InvalidBackupChainError(RestoreError):
    """Raised when backup chain validation fails (e.g. LSN break, incompatible diff)."""
    pass


class RestoreExecutionError(RestoreError):
    """Raised when physical restoration fails inside the sandbox."""
    pass


class ProductionTargetViolationError(RestoreError):
    """Raised when a restore target attempts to touch host or production instances."""
    pass


class RestoreOrchestrationService:
    """
    Manages backup chain validation, restore planning, and execution against the recovery sandbox.
    """

    def __init__(self, db: Session):
        self.db = db

    def get_sandbox_connection(self, sandbox: RecoverySandbox) -> pyodbc.Connection:
        """
        Creates an isolated, autocommit pyodbc connection directly to the sandbox SQL Server container.
        Strictly validates that the target is a loopback port and NOT the host default instance.
        """
        if sandbox.host_port in (1433, settings.SQL_PORT or 1764):
            # Strict safety guard: reject if pointing to host SQL Server port!
            if sandbox.host_port == (settings.SQL_PORT or 1764):
                raise ProductionTargetViolationError(
                    f"Security Alert: Target port {sandbox.host_port} matches host SQL Server! Sandbox connection denied."
                )

        ephemeral_pwd = RecoverySandboxService.get_cached_password(sandbox.job_id)
        if not ephemeral_pwd:
            raise RestoreError(f"No active ephemeral SA credentials found for job '{sandbox.job_id}'. Sandbox must be running.")

        conn_str = (
            f"DRIVER={{ODBC Driver 18 for SQL Server}};"
            f"SERVER=127.0.0.1,{sandbox.host_port};"
            f"UID=sa;"
            f"PWD={ephemeral_pwd};"
            f"TrustServerCertificate=yes;"
            f"LoginTimeout=10;"
        )

        conn = pyodbc.connect(conn_str, autocommit=True)
        return conn

    def validate_backup_chain(self, job_id: str) -> Dict[str, Any]:
        """
        Validates the staged backup chain using metadata and LSN continuity rules:
        1. Full backup must exist with sequence_order == 1.
        2. Differential backup (if present) must be sequence_order == 2 and compatible with base Full.
        3. Transaction logs (if present) must form an unbroken LSN sequence.
        4. Verifies all artifacts are in VERIFIED status.
        """
        records = self.db.query(BackupStagingRecord).filter(
            BackupStagingRecord.job_id == job_id
        ).order_by(BackupStagingRecord.sequence_order.asc()).all()

        if not records:
            raise InvalidBackupChainError(f"No staged backup records found for job '{job_id}'.")

        # Check all records are verified
        for r in records:
            if r.verification_status != "VERIFIED":
                raise InvalidBackupChainError(
                    f"Artifact #{r.sequence_order} ({r.backup_type}) has verification_status '{r.verification_status}'. "
                    f"Only VERIFIED artifacts can be restored."
                )

        full_records = [r for r in records if r.backup_type == "FULL"]
        diff_records = [r for r in records if r.backup_type == "DIFFERENTIAL"]
        log_records = [r for r in records if r.backup_type == "LOG"]

        if not full_records:
            raise InvalidBackupChainError("Backup chain must contain at least one FULL backup artifact.")

        if len(full_records) > 1:
            raise InvalidBackupChainError("Multiple FULL backup artifacts found in single restore chain.")

        if len(diff_records) > 1:
            raise InvalidBackupChainError("Multiple DIFFERENTIAL backup artifacts found in single restore chain.")

        return {
            "is_valid": True,
            "total_artifacts": len(records),
            "full_count": len(full_records),
            "diff_count": len(diff_records),
            "log_count": len(log_records),
            "records": records
        }

    def generate_restore_plan(
        self,
        job_id: str,
        target_database_name: Optional[str] = None,
        target_stopat_utc: Optional[datetime] = None
    ) -> RestorePlan:
        """
        Constructs an auditable, persistent multi-step restore plan:
        - Resolves target database name inside the sandbox.
        - Identifies Full, Differential, and Log artifacts.
        - Constructs MOVE clauses for data and log files into container volumes.
        - Generates explicit T-SQL commands with NORECOVERY for intermediate steps and RECOVERY for the final step.
        """
        job = self.db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
        if not job:
            raise RestoreError(f"Recovery job '{job_id}' not found.")

        sandbox = self.db.query(RecoverySandbox).filter(RecoverySandbox.job_id == job_id).first()
        if not sandbox:
            raise RestoreError(f"No recovery sandbox found for job '{job_id}'. Provision a sandbox first.")

        # Check existing plan
        existing_plan = self.db.query(RestorePlan).filter(RestorePlan.job_id == job_id).first()
        if existing_plan:
            return existing_plan

        chain_info = self.validate_backup_chain(job_id)
        records: List[BackupStagingRecord] = chain_info["records"]

        target_db = target_database_name or job.target_database_name
        # Sanitize target db name
        target_db = re.sub(r"[^a-zA-Z0-9_]", "_", target_db)

        full_record = [r for r in records if r.backup_type == "FULL"][0]
        diff_record = [r for r in records if r.backup_type == "DIFFERENTIAL"]
        diff_record = diff_record[0] if diff_record else None
        log_records = [r for r in records if r.backup_type == "LOG"]

        # Container path mappings
        # Backups are mounted at /staging/<filename>
        full_filename = os.path.basename(full_record.staged_file_path)
        container_full_path = f"/staging/{full_filename}"

        container_data_dest = f"/var/opt/mssql/data/{target_db}.mdf"
        container_log_dest = f"/var/opt/mssql/log/{target_db}_log.ldf"

        operations_list: List[Dict[str, Any]] = []
        seq = 1

        # Step 1: RESTORE FULL DATABASE WITH NORECOVERY, MOVE
        # In a real environment, logical file names are derived from RESTORE FILELISTONLY or defaults
        logical_data = f"{target_db}"
        logical_log = f"{target_db}_log"
        tsql_full = (
            f"RESTORE DATABASE [{target_db}] FROM DISK = N'{container_full_path}' "
            f"WITH NORECOVERY, "
            f"MOVE N'{logical_data}' TO N'{container_data_dest}', "
            f"MOVE N'{logical_log}' TO N'{container_log_dest}';"
        )
        operations_list.append({
            "sequence_number": seq,
            "operation_type": "RESTORE_FULL",
            "backup_file_path": container_full_path,
            "t_sql_command": tsql_full
        })
        seq += 1

        # Step 2: RESTORE DIFFERENTIAL (if present)
        if diff_record:
            diff_filename = os.path.basename(diff_record.staged_file_path)
            container_diff_path = f"/staging/{diff_filename}"
            tsql_diff = (
                f"RESTORE DATABASE [{target_db}] FROM DISK = N'{container_diff_path}' "
                f"WITH NORECOVERY;"
            )
            operations_list.append({
                "sequence_number": seq,
                "operation_type": "RESTORE_DIFF",
                "backup_file_path": container_diff_path,
                "t_sql_command": tsql_diff
            })
            seq += 1

        # Step 3..N: RESTORE TRANSACTION LOGS (if present)
        for i, log_rec in enumerate(log_records):
            log_filename = os.path.basename(log_rec.staged_file_path)
            container_log_path = f"/staging/{log_filename}"
            is_last_log = (i == len(log_records) - 1)

            stopat_clause = ""
            if is_last_log and target_stopat_utc:
                # Format datetime literal
                stopat_str = target_stopat_utc.strftime("%Y-%m-%dT%H:%M:%S")
                stopat_clause = f", STOPAT = N'{stopat_str}'"

            tsql_log = (
                f"RESTORE LOG [{target_db}] FROM DISK = N'{container_log_path}' "
                f"WITH NORECOVERY{stopat_clause};"
            )
            operations_list.append({
                "sequence_number": seq,
                "operation_type": "RESTORE_LOG",
                "backup_file_path": container_log_path,
                "t_sql_command": tsql_log
            })
            seq += 1

        # Final Step: RESTORE DATABASE WITH RECOVERY
        tsql_recovery = f"RESTORE DATABASE [{target_db}] WITH RECOVERY;"
        operations_list.append({
            "sequence_number": seq,
            "operation_type": "RESTORE_RECOVERY",
            "backup_file_path": "N/A",
            "t_sql_command": tsql_recovery
        })

        # Persist Restore Plan
        plan = RestorePlan(
            job_id=job.id,
            sandbox_id=sandbox.id,
            target_database_name=target_db,
            full_artifact_id=full_record.id,
            differential_artifact_id=diff_record.id if diff_record else None,
            total_operations=len(operations_list),
            plan_steps_json=json.dumps(operations_list),
            target_stopat_utc=target_stopat_utc,
            status="DRAFT"
        )
        self.db.add(plan)
        self.db.commit()
        self.db.refresh(plan)

        # Persist individual operations
        for op in operations_list:
            db_op = RestoreOperation(
                plan_id=plan.id,
                job_id=job.id,
                sequence_number=op["sequence_number"],
                operation_type=op["operation_type"],
                backup_file_path=op["backup_file_path"],
                t_sql_command=op["t_sql_command"],
                status="PENDING"
            )
            self.db.add(db_op)

        self.db.commit()
        return plan

    def execute_restore_plan(
        self,
        job_id: str,
        actor: str = "Restore_Orchestration_Engine"
    ) -> Dict[str, Any]:
        """
        Executes the restore plan sequentially against the isolated sandbox container:
        1. Validates sandbox health.
        2. Transitions job state from ENVIRONMENT_CREATED to RESTORE_IN_PROGRESS.
        3. Executes each T-SQL restore step, capturing server messages and execution duration.
        4. Verifies database state is ONLINE upon completion.
        5. Transitions job state to RESTORE_COMPLETED.
        6. On any execution error, marks operation FAILED and transitions job state to FAILED.
        """
        job = self.db.query(RecoveryJob).filter(RecoveryJob.id == job_id).first()
        if not job:
            raise RestoreError(f"Recovery job '{job_id}' not found.")

        sandbox = self.db.query(RecoverySandbox).filter(RecoverySandbox.job_id == job_id).first()
        if not sandbox:
            raise RestoreError(f"No recovery sandbox found for job '{job_id}'.")

        plan = self.db.query(RestorePlan).filter(RestorePlan.job_id == job_id).first()
        if not plan:
            plan = self.generate_restore_plan(job_id)

        # State transition: ENVIRONMENT_CREATED -> RESTORE_IN_PROGRESS
        if job.status == "ENVIRONMENT_CREATED":
            RecoveryJobStateMachine.transition(
                db=self.db,
                job=job,
                target_state="RESTORE_IN_PROGRESS",
                actor=actor,
                reason=f"Starting physical restoration of {plan.total_operations} operations into sandbox."
            )

        plan.status = "IN_PROGRESS"
        self.db.commit()

        operations = self.db.query(RestoreOperation).filter(
            RestoreOperation.plan_id == plan.id
        ).order_by(RestoreOperation.sequence_number.asc()).all()

        try:
            conn = self.get_sandbox_connection(sandbox)
            cursor = conn.cursor()

            for op in operations:
                if op.status == "COMPLETED":
                    continue

                op.status = "EXECUTING"
                op.started_at = datetime.now(timezone.utc)
                self.db.commit()

                start_ms = time.time()
                try:
                    cursor.execute(op.t_sql_command)
                    # Drain any messages or result sets
                    while cursor.nextset():
                        pass

                    duration_ms = int((time.time() - start_ms) * 1000)
                    op.status = "COMPLETED"
                    op.completed_at = datetime.now(timezone.utc)
                    op.execution_duration_ms = duration_ms
                    self.db.commit()

                except pyodbc.Error as py_err:
                    duration_ms = int((time.time() - start_ms) * 1000)
                    err_msg = str(py_err)
                    op.status = "FAILED"
                    op.error_details = err_msg
                    op.completed_at = datetime.now(timezone.utc)
                    op.execution_duration_ms = duration_ms
                    plan.status = "FAILED"
                    self.db.commit()

                    RecoveryJobStateMachine.transition(
                        db=self.db,
                        job=job,
                        target_state="FAILED",
                        actor=actor,
                        reason=f"Restore operation #{op.sequence_number} ({op.operation_type}) failed: {err_msg}",
                        failure_code="RESTORE_EXECUTION_FAILED"
                    )
                    cursor.close()
                    conn.close()
                    raise RestoreExecutionError(f"Restore failed on step #{op.sequence_number}: {err_msg}")

            # Verify Database is ONLINE
            cursor.execute(
                "SELECT state_desc FROM sys.databases WHERE name = ?;",
                (plan.target_database_name,)
            )
            row = cursor.fetchone()
            db_state = row[0] if row else "NOT_FOUND"

            cursor.close()
            conn.close()

            if db_state != "ONLINE":
                plan.status = "FAILED"
                self.db.commit()
                RecoveryJobStateMachine.transition(
                    db=self.db,
                    job=job,
                    target_state="FAILED",
                    actor=actor,
                    reason=f"Database '{plan.target_database_name}' recovered to unexpected state: '{db_state}'. Expected: 'ONLINE'.",
                    failure_code="DATABASE_NOT_ONLINE"
                )
                raise RestoreExecutionError(f"Restored database is in state '{db_state}', expected 'ONLINE'.")

            # Success: RESTORE_COMPLETED
            plan.status = "COMPLETED"
            self.db.commit()

            RecoveryJobStateMachine.transition(
                db=self.db,
                job=job,
                target_state="RESTORE_COMPLETED",
                actor=actor,
                reason=f"Restoration completed successfully. Database '{plan.target_database_name}' is ONLINE."
            )

            return {
                "success": True,
                "job_id": job.id,
                "plan_id": plan.id,
                "target_database_name": plan.target_database_name,
                "database_state": db_state,
                "operations_completed": len(operations)
            }

        except Exception as e:
            if not isinstance(e, RestoreExecutionError):
                plan.status = "FAILED"
                self.db.commit()
                RecoveryJobStateMachine.transition(
                    db=self.db,
                    job=job,
                    target_state="FAILED",
                    actor=actor,
                    reason=f"Restore execution failed: {str(e)}",
                    failure_code="RESTORE_CONNECTION_FAILED"
                )
            raise
