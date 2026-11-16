"""
SQL-TRUST Storage API Endpoints
"""
from fastapi import APIRouter, HTTPException, status
from typing import List

from backend.services.storage.seaweedfs import SeaweedFSStorageProvider
from backend.schemas.storage import StorageHealthResponse, StoredBackupObject

router = APIRouter(prefix="/storage")


@router.get("/health", response_model=StorageHealthResponse, summary="Storage connectivity & security audit")
def get_storage_health():
    """
    Checks SeaweedFS connectivity and performs an audit of Versioning,
    Object Lock, and retention policies on the backup bucket.
    """
    storage = SeaweedFSStorageProvider()
    conn = storage.check_connectivity()
    if not conn.get("connected"):
        return {
            "connected": False,
            "endpoint": conn.get("endpoint", ""),
            "bucket": storage.bucket_name,
            "provider": "SeaweedFS (S3-compatible)",
            "versioning_status": "UNREACHABLE",
            "object_lock_enabled": False,
            "immutability_guarantee": "NONE (Storage Offline)",
            "warnings": ["Storage endpoint unreachable"],
            "error": conn.get("error")
        }

    sec = storage.inspect_security()
    return {
        "connected": True,
        "endpoint": storage.endpoint_url,
        "bucket": storage.bucket_name,
        "provider": "SeaweedFS (S3-compatible)",
        "versioning_status": sec.get("versioning_status", "DISABLED"),
        "object_lock_enabled": sec.get("object_lock_enabled", False),
        "retention_mode": sec.get("retention_mode"),
        "retention_period_days": sec.get("retention_period_days"),
        "immutability_guarantee": sec.get("immutability_guarantee", "Standard"),
        "warnings": sec.get("warnings", []),
        "error": None
    }


@router.get("/backups", response_model=List[StoredBackupObject], summary="List stored backup objects in SeaweedFS")
def list_storage_backups():
    """Lists all stored backup artifacts directly from the SeaweedFS S3 bucket."""
    storage = SeaweedFSStorageProvider()
    try:
        objects = storage.list_objects(prefix="backups/")
        return [
            {
                "key": obj["key"],
                "size_bytes": obj["size_bytes"],
                "last_modified": obj["last_modified"],
                "etag": obj["etag"]
            }
            for obj in objects
        ]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query SeaweedFS objects: {str(e)}"
        )
