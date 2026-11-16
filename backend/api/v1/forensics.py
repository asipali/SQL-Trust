"""
SQL-TRUST Forensics API Endpoints
Module 3: Database Forensics Engine
Provides REST API endpoints for baseline captures, granular item queries,
forensic investigations, chronological timeline correlation, and WORM evidence verification.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models.forensics import (
    ForensicBaseline,
    ForensicBaselineItem,
    ForensicInvestigation,
    ForensicFinding,
    ForensicEvidenceArchive
)
from backend.schemas.forensics import (
    BaselineCaptureRequest,
    BaselineResponse,
    BaselineItemResponse,
    InvestigationCreateRequest,
    InvestigationResponse,
    TimelineEntry,
    EvidenceVerificationResponse
)
from backend.services.forensics.baseline_collector import BaselineCollector
from backend.services.forensics.forensic_service import ForensicService
from backend.services.forensics.timeline_engine import TimelineCorrelator
from backend.services.forensics.evidence_service import ForensicEvidenceService

router = APIRouter(prefix="/forensics")


@router.post("/baselines/capture", response_model=BaselineResponse)
def capture_database_baseline(
    payload: BaselineCaptureRequest,
    db: Session = Depends(get_db)
):
    """
    Captures a read-only metadata baseline of a SQL Server database.
    Optionally signs and archives the baseline to SeaweedFS Object Lock WORM storage.
    """
    try:
        collector = BaselineCollector(
            db=db,
            database_name=payload.database_name,
            server_name=payload.server_name or "localhost\\SQLEXPRESS"
        )
        baseline = collector.capture_baseline(
            baseline_name=payload.baseline_name,
            notes=payload.notes
        )

        if payload.archive_to_worm:
            try:
                evidence_svc = ForensicEvidenceService(db)
                evidence_svc.archive_baseline(baseline)
            except Exception as e:
                baseline.notes = (baseline.notes or "") + f" [WORM Upload Note: {str(e)}]"
                db.commit()

        return baseline
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to capture baseline: {str(e)}")


@router.get("/baselines", response_model=List[BaselineResponse])
def list_baselines(
    database_name: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Lists all captured database baselines, newest first."""
    query = db.query(ForensicBaseline)
    if database_name:
        query = query.filter(ForensicBaseline.database_name.ilike(f"%{database_name}%"))
    return query.order_by(desc(ForensicBaseline.captured_at)).offset(offset).limit(limit).all()


@router.get("/baselines/{baseline_id}", response_model=BaselineResponse)
def get_baseline(baseline_id: str, db: Session = Depends(get_db)):
    """Retrieves baseline metadata by ID."""
    baseline = db.query(ForensicBaseline).filter(ForensicBaseline.id == baseline_id).first()
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found.")
    return baseline


@router.get("/baselines/{baseline_id}/items", response_model=List[BaselineItemResponse])
def list_baseline_items(
    baseline_id: str,
    item_type: Optional[str] = Query(None, description="Filter by item type (TABLE, VIEW, PROCEDURE, USER, etc.)"),
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Retrieves granular captured items within a baseline snapshot."""
    query = db.query(ForensicBaselineItem).filter(ForensicBaselineItem.baseline_id == baseline_id)
    if item_type:
        query = query.filter(ForensicBaselineItem.item_type == item_type.upper())
    return query.order_by(ForensicBaselineItem.item_type.asc(), ForensicBaselineItem.item_name.asc()).offset(offset).limit(limit).all()


@router.post("/investigations/compare", response_model=InvestigationResponse)
def run_investigation_comparison(
    payload: InvestigationCreateRequest,
    db: Session = Depends(get_db)
):
    """
    Executes a forensic diff investigation between a reference baseline and a target baseline.
    Identifies schema changes, user/role mutations, configuration drift, and correlates with Module 2 telemetry.
    """
    try:
        service = ForensicService(db)
        investigation = service.execute_investigation(
            ref_baseline_id=payload.ref_baseline_id,
            target_baseline_id=payload.target_baseline_id,
            investigation_name=payload.investigation_name,
            summary_notes=payload.summary_notes
        )
        return investigation
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Investigation execution failed: {str(e)}")


@router.get("/investigations", response_model=List[InvestigationResponse])
def list_investigations(
    database_name: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Lists completed and active forensic investigations."""
    query = db.query(ForensicInvestigation)
    if database_name:
        query = query.filter(ForensicInvestigation.database_name.ilike(f"%{database_name}%"))
    return query.order_by(desc(ForensicInvestigation.started_at)).offset(offset).limit(limit).all()


@router.get("/investigations/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(investigation_id: str, db: Session = Depends(get_db)):
    """Retrieves full investigation findings, severity breakdown, and correlations."""
    inv = db.query(ForensicInvestigation).filter(ForensicInvestigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return inv


@router.get("/investigations/{investigation_id}/timeline", response_model=List[TimelineEntry])
def get_investigation_timeline(investigation_id: str, db: Session = Depends(get_db)):
    """
    Builds a unified chronological timeline combining reference baseline,
    audited Module 2 telemetry actions, and investigation findings.
    """
    correlator = TimelineCorrelator(db)
    entries = correlator.get_unified_timeline(investigation_id)
    return entries


@router.post("/investigations/{investigation_id}/archive")
def archive_investigation_to_worm(investigation_id: str, db: Session = Depends(get_db)):
    """Manually triggers WORM archiving and Ed25519 signing for an investigation."""
    inv = db.query(ForensicInvestigation).filter(ForensicInvestigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    try:
        evidence_svc = ForensicEvidenceService(db)
        arc = evidence_svc.archive_investigation_report(inv)
        return {
            "success": True,
            "archive_id": arc.id,
            "object_key": arc.storage_object_key,
            "version_id": arc.storage_version_id,
            "sha256": arc.sha256,
            "retention_until": arc.retention_until.isoformat() if arc.retention_until else None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to archive investigation: {str(e)}")


@router.get("/evidence/{archive_id}/verify", response_model=EvidenceVerificationResponse)
def verify_forensic_evidence(archive_id: str, db: Session = Depends(get_db)):
    """
    Cryptographically verifies the Ed25519 signature and SHA-256 payload integrity
    of an archived forensic evidence manifest in SeaweedFS Object Lock.
    """
    evidence_svc = ForensicEvidenceService(db)
    result = evidence_svc.verify_evidence_archive(archive_id)
    if "error" in result and not result.get("valid"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result
