"""
SQL-TRUST Security Monitoring API Endpoints
Module 2: Security Monitoring Engine
"""
import os
import glob
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models.security import (
    SecuritySource,
    SecurityEvent,
    SecurityAlert,
    DetectionRule,
    EvidenceArchive,
    CollectorCheckpoint
)
from backend.schemas.security import (
    SecuritySourceCreate,
    SecuritySourceResponse,
    SecurityEventResponse,
    SecurityAlertResponse,
    SecurityAlertStatusUpdate,
    DetectionRuleResponse,
    EvidenceArchiveResponse,
    CollectionTriggerResponse
)
from backend.services.security.alert_service import AlertService
from backend.services.security.audit_service import AuditService
from backend.services.security.xe_service import ExtendedEventsService
from backend.services.security.audit_collector import AuditCollector
from backend.services.security.xe_collector import XECollector
from backend.services.security.evidence_archiver import EvidenceArchiver
from backend.services.security.health_service import HealthService
from backend.services.security.rule_engine import ensure_default_rules

router = APIRouter(prefix="/security")


@router.get("/sources", response_model=List[SecuritySourceResponse])
def list_security_sources(db: Session = Depends(get_db)):
    """Lists all registered SQL Server security monitoring sources."""
    sources = db.query(SecuritySource).all()
    # If no source exists, auto-provision default localhost source
    if not sources:
        default_source = SecuritySource(
            source_name="SQLServer-LocalHost",
            server_name=r"localhost\SQLEXPRESS",
            source_type="HYBRID",
            audit_target_path=os.path.abspath(r"data\audit"),
            xe_target_path=os.path.abspath(r"data\extended_events"),
            is_active=True
        )
        db.add(default_source)
        db.commit()
        db.refresh(default_source)
        sources = [default_source]
    return sources


@router.post("/sources", response_model=SecuritySourceResponse, status_code=status.HTTP_201_CREATED)
def create_security_source(payload: SecuritySourceCreate, db: Session = Depends(get_db)):
    """Registers a new SQL Server security monitoring source."""
    existing = db.query(SecuritySource).filter(SecuritySource.source_name == payload.source_name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Security source '{payload.source_name}' is already registered."
        )

    source = SecuritySource(
        source_name=payload.source_name,
        server_name=payload.server_name,
        source_type=payload.source_type,
        audit_target_path=payload.audit_target_path or os.path.abspath(r"data\audit"),
        xe_target_path=payload.xe_target_path or os.path.abspath(r"data\extended_events"),
        is_active=payload.is_active
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


@router.get("/events", response_model=List[SecurityEventResponse])
def list_security_events(
    source_id: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    principal: Optional[str] = None,
    database_name: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Lists normalized security events with filtering and pagination."""
    query = db.query(SecurityEvent)
    if source_id:
        query = query.filter(SecurityEvent.source_id == source_id)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type.upper())
    if severity:
        query = query.filter(SecurityEvent.severity == severity.upper())
    if principal:
        query = query.filter(SecurityEvent.principal_name.ilike(f"%{principal}%"))
    if database_name:
        query = query.filter(SecurityEvent.database_name.ilike(f"%{database_name}%"))

    return query.order_by(desc(SecurityEvent.event_timestamp)).offset(offset).limit(limit).all()


@router.get("/events/{event_id}", response_model=SecurityEventResponse)
def get_security_event(event_id: str, db: Session = Depends(get_db)):
    """Retrieves full details for a normalized security event."""
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Security event not found.")
    return event


@router.get("/alerts", response_model=List[SecurityAlertResponse])
def list_security_alerts(
    source_id: Optional[str] = None,
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Queries security alerts with optional severity and status filters."""
    return AlertService.list_alerts(
        db=db,
        source_id=source_id,
        severity=severity,
        status=status_filter,
        limit=limit,
        offset=offset
    )


@router.get("/alerts/{alert_id}", response_model=SecurityAlertResponse)
def get_security_alert(alert_id: str, db: Session = Depends(get_db)):
    """Retrieves alert details including lifecycle history and related events."""
    alert = AlertService.get_alert_by_id(db=db, alert_id=alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Security alert not found.")
    return alert


@router.patch("/alerts/{alert_id}", response_model=SecurityAlertResponse)
def update_security_alert_status(
    alert_id: str,
    payload: SecurityAlertStatusUpdate,
    db: Session = Depends(get_db)
):
    """Updates alert status (NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
    valid_statuses = {"NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
    if payload.status.upper() not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{payload.status}'. Allowed: {list(valid_statuses)}"
        )

    updated = AlertService.update_alert_status(
        db=db,
        alert_id=alert_id,
        new_status=payload.status,
        changed_by=payload.changed_by or "Administrator",
        comment=payload.comment
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Security alert not found.")
    return updated


@router.get("/health")
def get_monitoring_health(source_id: Optional[str] = None, db: Session = Depends(get_db)):
    """Evaluates and returns comprehensive telemetry and storage monitoring health."""
    return HealthService.evaluate_monitoring_health(db=db, source_id=source_id)


@router.get("/sources/{source_id}/audit")
def get_source_audit_config(source_id: str, db: Session = Depends(get_db)):
    """Inspects live SQL Server Audit configuration for the specified source."""
    source = db.query(SecuritySource).filter(SecuritySource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Security source not found.")
    return AuditService.inspect_audit_configuration(server_name=source.server_name)


@router.get("/sources/{source_id}/extended-events")
def get_source_xe_config(source_id: str, db: Session = Depends(get_db)):
    """Inspects live Extended Events session configuration for the specified source."""
    source = db.query(SecuritySource).filter(SecuritySource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Security source not found.")
    return ExtendedEventsService.inspect_xe_configuration(server_name=source.server_name)


@router.post("/sources/{source_id}/collect", response_model=CollectionTriggerResponse)
def trigger_collection(source_id: str, db: Session = Depends(get_db)):
    """
    Manually triggers incremental collection across SQL Server Audit and Extended Events files.
    Pushes events to rule engine, updates checkpoints, and archives evidence to SeaweedFS WORM storage.
    """
    source = db.query(SecuritySource).filter(SecuritySource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Security source not found.")

    # 1. Audit Collection
    audit_collector = AuditCollector(db=db, source=source)
    audit_res = audit_collector.collect_incremental()

    # 2. Extended Events Collection
    xe_collector = XECollector(db=db, source=source)
    xe_res = xe_collector.collect_incremental()

    # 3. Archive raw forensic files to SeaweedFS Object Lock
    archived_list = []
    try:
        archiver = EvidenceArchiver(db=db, source=source)
        # Check for audit files to archive
        audit_pattern = os.path.join(source.audit_target_path or r"data\audit", "*.sqlaudit")
        for f in glob.glob(audit_pattern):
            # Check if already archived
            existing_arc = db.query(EvidenceArchive.id).filter(EvidenceArchive.source_file_path == f).first()
            if not existing_arc:
                res = archiver.archive_file(f, evidence_type="SQL_AUDIT_FILE")
                archived_list.append(res)

        # Check for XE files to archive
        xe_pattern = os.path.join(source.xe_target_path or r"data\extended_events", "*.xel")
        for f in glob.glob(xe_pattern):
            existing_arc = db.query(EvidenceArchive.id).filter(EvidenceArchive.source_file_path == f).first()
            if not existing_arc:
                res = archiver.archive_file(f, evidence_type="EXTENDED_EVENTS_FILE")
                archived_list.append(res)
    except Exception as e:
        # Non-fatal to collection response
        archived_list.append({"error": str(e)})

    return {
        "success": bool(audit_res.get("success") or xe_res.get("success")),
        "source_id": source_id,
        "audit_collection": audit_res,
        "xe_collection": xe_res,
        "evidence_archived": archived_list
    }


@router.get("/evidence/{evidence_id}", response_model=EvidenceArchiveResponse)
def get_evidence_archive(evidence_id: str, db: Session = Depends(get_db)):
    """Retrieves cryptographic evidence archive metadata by archive ID or manifest ID."""
    archive = db.query(EvidenceArchive).filter(
        (EvidenceArchive.id == evidence_id) | (EvidenceArchive.manifest_id == evidence_id)
    ).first()
    if not archive:
        raise HTTPException(status_code=404, detail="Evidence archive not found.")
    return archive


@router.get("/rules", response_model=List[DetectionRuleResponse])
def list_detection_rules(db: Session = Depends(get_db)):
    """Lists all 10 explainable detection rules with thresholds and severity."""
    rules_dict = ensure_default_rules(db)
    return list(rules_dict.values())
