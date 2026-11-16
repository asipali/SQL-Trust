"""
SQL-TRUST Recovery Point Discovery Service
Module 4: Cyber Recovery & State Reconstruction
Discovers, extracts, and catalogs candidate recovery points from Module 1 backup records,
SQL Server backup headers, and SeaweedFS WORM storage metadata.
"""
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.database import create_db_engine
from backend.models.backup import BackupRecord, ProtectedDatabase
from backend.models.recovery import RecoveryPoint


class RecoveryPointDiscoveryService:
    """
    Scans backup history, inspects physical backup headers, and creates normalized
    RecoveryPoint records for cyber recovery analysis.
    """

    def __init__(self, db: Session):
        self.db = db

    def discover_recovery_points(self, database_name: Optional[str] = None) -> List[RecoveryPoint]:
        """
        Scans all completed BackupRecords for the given database (or all databases),
        reconciles LSNs and headers, and persists up-to-date RecoveryPoint records.
        """
        query = self.db.query(BackupRecord).join(ProtectedDatabase).filter(
            BackupRecord.backup_status == "COMPLETED"
        )
        if database_name:
            query = query.filter(ProtectedDatabase.database_name == database_name)

        backups = query.order_by(BackupRecord.start_time.asc()).all()
        discovered_points: List[RecoveryPoint] = []

        for bkp in backups:
            point = self.db.query(RecoveryPoint).filter(RecoveryPoint.backup_id == bkp.id).first()
            if not point:
                point = self._create_point_from_backup(bkp)
            else:
                point = self._update_point_from_backup(point, bkp)
            discovered_points.append(point)

        self.db.commit()
        return discovered_points

    def _create_point_from_backup(self, bkp: BackupRecord) -> RecoveryPoint:
        """Instantiates and registers a new RecoveryPoint from a BackupRecord."""
        db_record = bkp.database
        header_meta = self._inspect_backup_header(bkp)

        first_lsn = bkp.first_lsn or header_meta.get("FirstLSN")
        last_lsn = bkp.last_lsn or header_meta.get("LastLSN")
        checkpoint_lsn = bkp.checkpoint_lsn or header_meta.get("CheckpointLSN")
        database_backup_lsn = bkp.database_backup_lsn or header_meta.get("DatabaseBackupLSN")
        diff_base_guid = header_meta.get("DifferentialBaseGUID")
        recovery_fork_guid = header_meta.get("RecoveryForkID")

        integrity_status = "VERIFIED" if (bkp.sql_verification_status == "PASSED" and bkp.sha256) else "UNVERIFIED"
        if bkp.sql_verification_status == "FAILED":
            integrity_status = "FAILED"

        rp_time = bkp.finish_time or bkp.start_time
        if rp_time and rp_time.tzinfo is None:
            rp_time = rp_time.replace(tzinfo=timezone.utc)

        metadata = {
            "source_backup_filename": bkp.backup_filename,
            "backup_size_bytes": bkp.backup_size_bytes,
            "sql_verification_status": bkp.sql_verification_status,
            "sha256": bkp.sha256,
            "header_metadata": header_meta
        }

        point = RecoveryPoint(
            database_id=db_record.id,
            backup_id=bkp.id,
            server_name=db_record.server_name,
            database_name=db_record.database_name,
            recovery_point_time=rp_time,
            recovery_point_type=bkp.backup_type,
            first_lsn=first_lsn,
            last_lsn=last_lsn,
            checkpoint_lsn=checkpoint_lsn,
            database_backup_lsn=database_backup_lsn,
            differential_base_guid=diff_base_guid,
            recovery_fork_guid=recovery_fork_guid,
            integrity_status=integrity_status,
            sha256=bkp.sha256,
            storage_object_key=bkp.storage_object_key,
            storage_version_id=bkp.storage_object_version_id,
            retention_mode=bkp.retention_mode,
            retention_until=bkp.retention_until,
            metadata_json=json.dumps(metadata, default=str)
        )
        self.db.add(point)
        return point

    def _update_point_from_backup(self, point: RecoveryPoint, bkp: BackupRecord) -> RecoveryPoint:
        """Updates integrity or storage metadata on an existing RecoveryPoint."""
        if bkp.sql_verification_status == "PASSED" and bkp.sha256:
            point.integrity_status = "VERIFIED"
        elif bkp.sql_verification_status == "FAILED":
            point.integrity_status = "FAILED"

        point.sha256 = bkp.sha256
        point.storage_object_key = bkp.storage_object_key
        point.storage_version_id = bkp.storage_object_version_id
        point.retention_mode = bkp.retention_mode
        point.retention_until = bkp.retention_until
        return point

    def _inspect_backup_header(self, bkp: BackupRecord) -> Dict[str, Any]:
        """
        Safely attempts to query RESTORE HEADERONLY from SQL Server if the local backup file exists.
        Returns empty dict on failure or if file has been moved to remote WORM storage only.
        """
        import os
        if not bkp.backup_path or not os.path.exists(bkp.backup_path):
            return {}

        try:
            engine = create_db_engine(database="master", server=bkp.database.server_name)
            with engine.connect() as conn:
                # Use parameterized query or safe sanitized path
                clean_path = bkp.backup_path.replace("'", "''")
                sql = text(f"RESTORE HEADERONLY FROM DISK = '{clean_path}'")
                row = conn.execute(sql).mappings().first()
                if row:
                    return {
                        "FirstLSN": str(row.get("FirstLSN") or ""),
                        "LastLSN": str(row.get("LastLSN") or ""),
                        "CheckpointLSN": str(row.get("CheckpointLSN") or ""),
                        "DatabaseBackupLSN": str(row.get("DatabaseBackupLSN") or ""),
                        "BackupType": row.get("BackupType"),
                        "DifferentialBaseGUID": str(row.get("DifferentialBaseGUID") or ""),
                        "RecoveryForkID": str(row.get("RecoveryForkID") or ""),
                        "BackupFinishDate": str(row.get("BackupFinishDate") or "")
                    }
        except Exception:
            pass
        return {}
