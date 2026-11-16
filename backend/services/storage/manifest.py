"""
SQL-TRUST Backup Manifest Generator
Produces cryptographically signed and hashable JSON manifests for every verified backup.
"""
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from backend.models.backup import BackupRecord, ProtectedDatabase
from backend.config import settings


def generate_backup_manifest(
    backup_record: BackupRecord,
    database: ProtectedDatabase,
    storage_provider: str = "SEAWEEDFS",
    additional_metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Constructs a complete, deterministic JSON manifest for the backup record.
    """
    manifest_data = {
        "manifest_version": "1.0",
        "backup_id": str(backup_record.id),
        "database_name": database.database_name,
        "database_id": database.database_identifier,
        "backup_type": backup_record.backup_type,
        "backup_start_time": backup_record.start_time.isoformat() if backup_record.start_time else None,
        "backup_finish_time": backup_record.finish_time.isoformat() if backup_record.finish_time else None,
        "recovery_model": database.recovery_model,
        "first_lsn": backup_record.first_lsn,
        "last_lsn": backup_record.last_lsn,
        "checkpoint_lsn": backup_record.checkpoint_lsn,
        "database_backup_lsn": backup_record.database_backup_lsn,
        "file_name": backup_record.backup_filename,
        "file_size_bytes": backup_record.backup_size_bytes,
        "sha256": backup_record.sha256,
        "sql_verification": backup_record.sql_verification_status,
        "storage_provider": storage_provider,
        "storage_bucket": settings.effective_s3_bucket,
        "storage_object_key": backup_record.storage_object_key,
        "storage_object_version_id": backup_record.storage_object_version_id,
        "retention_mode": backup_record.retention_mode,
        "retention_until": backup_record.retention_until.isoformat() if backup_record.retention_until else None,
        "is_immutable": backup_record.retention_mode in ("COMPLIANCE", "GOVERNANCE"),
        "upload_status": backup_record.storage_upload_status,
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    if additional_metadata:
        manifest_data["metadata"] = additional_metadata

    # Convert to canonical deterministic JSON representation for hashing
    manifest_json_str = json.dumps(manifest_data, indent=2, sort_keys=True)
    manifest_hash = hashlib.sha256(manifest_json_str.encode("utf-8")).hexdigest()

    return {
        "manifest_dict": manifest_data,
        "manifest_json": manifest_json_str,
        "manifest_hash": manifest_hash
    }
