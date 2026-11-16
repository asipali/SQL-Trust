"""
SQL-TRUST Backup Management Endpoints
"""
import json
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional

from backend.database import get_db
from backend.models.backup import BackupRecord, BackupManifest, ProtectedDatabase
from backend.services.backup.engine import BackupEngine
from backend.schemas.backup import (
    BackupCreateRequest,
    BackupRecordResponse,
    BackupManifestResponse,
    BackupVerificationResponse,
    BackupStatsResponse
)

router = APIRouter(prefix="/backups")


@router.post("/full", response_model=BackupRecordResponse, status_code=status.HTTP_201_CREATED, summary="Create FULL database backup")
def create_full_backup(req: BackupCreateRequest, db: Session = Depends(get_db)):
    """Initiates a FULL database backup with checksum verification and SeaweedFS upload."""
    engine = BackupEngine(db)
    try:
        record = engine.execute_backup(
            database_id=req.database_id,
            backup_type="FULL",
            operator_notes=req.notes
        )
        return record
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"FULL backup failed: {str(e)}")


@router.post("/differential", response_model=BackupRecordResponse, status_code=status.HTTP_201_CREATED, summary="Create DIFFERENTIAL database backup")
def create_differential_backup(req: BackupCreateRequest, db: Session = Depends(get_db)):
    """Initiates a DIFFERENTIAL backup (requires a prior completed FULL backup in chain)."""
    engine = BackupEngine(db)
    try:
        record = engine.execute_backup(
            database_id=req.database_id,
            backup_type="DIFFERENTIAL",
            operator_notes=req.notes
        )
        return record
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"DIFFERENTIAL backup failed: {str(e)}")


@router.post("/log", response_model=BackupRecordResponse, status_code=status.HTTP_201_CREATED, summary="Create TRANSACTION LOG backup")
def create_log_backup(req: BackupCreateRequest, db: Session = Depends(get_db)):
    """Initiates a TRANSACTION LOG backup (requires FULL/BULK_LOGGED recovery model and existing base FULL backup)."""
    engine = BackupEngine(db)
    try:
        record = engine.execute_backup(
            database_id=req.database_id,
            backup_type="LOG",
            operator_notes=req.notes
        )
        return record
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"LOG backup failed: {str(e)}")


@router.get("", response_model=List[BackupRecordResponse], summary="List backup history")
def list_backups(
    database_id: Optional[str] = Query(None, description="Filter by registered database ID"),
    backup_type: Optional[str] = Query(None, description="Filter by backup type (FULL, DIFFERENTIAL, LOG)"),
    status: Optional[str] = Query(None, description="Filter by status (COMPLETED, FAILED, RUNNING)"),
    db: Session = Depends(get_db)
):
    """Retrieves chronological backup history with filtering options."""
    query = db.query(BackupRecord).join(ProtectedDatabase)

    if database_id:
        query = query.filter(BackupRecord.database_id == database_id)
    if backup_type:
        query = query.filter(BackupRecord.backup_type == backup_type.upper())
    if status:
        query = query.filter(BackupRecord.backup_status == status.upper())

    records = query.order_by(BackupRecord.start_time.desc()).all()
    
    # Enrich response with database_name
    output = []
    for r in records:
        resp_item = BackupRecordResponse.model_validate(r)
        resp_item.database_name = r.database.database_name if r.database else None
        output.append(resp_item)

    return output


@router.get("/stats", response_model=BackupStatsResponse, summary="Get aggregate backup statistics")
def get_backup_stats(db: Session = Depends(get_db)):
    """Calculates overall metrics: total backups, success/failure counts, and total storage size."""
    total = db.query(func.count(BackupRecord.id)).scalar() or 0
    success = db.query(func.count(BackupRecord.id)).filter(BackupRecord.backup_status == "COMPLETED").scalar() or 0
    failed = db.query(func.count(BackupRecord.id)).filter(BackupRecord.backup_status == "FAILED").scalar() or 0
    total_size = db.query(func.sum(BackupRecord.backup_size_bytes)).filter(BackupRecord.backup_status == "COMPLETED").scalar() or 0

    latest_record = db.query(BackupRecord).filter(
        BackupRecord.backup_status == "COMPLETED"
    ).order_by(BackupRecord.start_time.desc()).first()

    return {
        "total_backups": total,
        "successful_backups": success,
        "failed_backups": failed,
        "total_size_bytes": total_size,
        "latest_backup_timestamp": latest_record.start_time.isoformat() if latest_record else None
    }


@router.get("/{backup_id}", response_model=BackupRecordResponse, summary="Get single backup details")
def get_backup(backup_id: str, db: Session = Depends(get_db)):
    """Retrieves complete details of a specific backup record."""
    record = db.query(BackupRecord).filter(BackupRecord.id == backup_id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Backup record '{backup_id}' not found.")
    
    resp_item = BackupRecordResponse.model_validate(record)
    resp_item.database_name = record.database.database_name if record.database else None
    return resp_item


@router.get("/{backup_id}/manifest", response_model=BackupManifestResponse, summary="Get backup manifest JSON")
def get_backup_manifest(backup_id: str, db: Session = Depends(get_db)):
    """Fetches the immutable JSON manifest for a specific backup."""
    manifest = db.query(BackupManifest).filter(BackupManifest.backup_id == backup_id).first()
    if not manifest:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Manifest for backup ID '{backup_id}' not found."
        )

    return {
        "id": str(manifest.id),
        "backup_id": str(manifest.backup_id),
        "manifest_version": manifest.manifest_version,
        "manifest_hash": manifest.manifest_hash,
        "manifest_data": json.loads(manifest.manifest_json),
        "created_at": manifest.created_at
    }


@router.post("/{backup_id}/verify", response_model=BackupVerificationResponse, summary="Re-verify backup integrity")
def verify_backup(backup_id: str, db: Session = Depends(get_db)):
    """
    Executes on-demand two-stage verification on an existing backup:
    Stage 1: RESTORE VERIFYONLY WITH CHECKSUM
    Stage 2: Re-computes SHA-256 and compares with stored cryptographic hash
    """
    engine = BackupEngine(db)
    try:
        return engine.verify_existing_backup(backup_id)
    except FileNotFoundError as fnf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(fnf))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Verification failed: {str(e)}")
