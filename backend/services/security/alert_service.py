"""
SQL-TRUST Alert Management Service
Module 2: Security Monitoring Engine
Manages alert lifecycle, transitions, investigation notes, and related event evidence.
"""
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.models.security import SecurityAlert, AlertStatusHistory, SecurityEvent


class AlertService:
    @staticmethod
    def list_alerts(
        db: Session,
        source_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[SecurityAlert]:
        """Queries security alerts with optional filters and pagination."""
        query = db.query(SecurityAlert)
        if source_id:
            query = query.filter(SecurityAlert.source_id == source_id)
        if severity:
            query = query.filter(SecurityAlert.severity == severity.upper())
        if status:
            query = query.filter(SecurityAlert.status == status.upper())

        return query.order_by(desc(SecurityAlert.detection_timestamp)).offset(offset).limit(limit).all()

    @staticmethod
    def get_alert_by_id(db: Session, alert_id: str) -> Optional[SecurityAlert]:
        """Retrieves alert details including related events and lifecycle history."""
        return db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()

    @staticmethod
    def update_alert_status(
        db: Session,
        alert_id: str,
        new_status: str,
        changed_by: str = "Administrator",
        comment: Optional[str] = None
    ) -> Optional[SecurityAlert]:
        """
        Transitions alert status (NEW -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED -> FALSE_POSITIVE)
        and preserves audit trail in AlertStatusHistory.
        """
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            return None

        previous_status = alert.status
        alert.status = new_status.upper()
        alert.updated_at = datetime.now(timezone.utc)

        # Append status history
        history = AlertStatusHistory(
            alert_id=alert.id,
            previous_status=previous_status,
            new_status=alert.status,
            changed_by=changed_by,
            comment=comment or f"Status transitioned to {alert.status}."
        )
        db.add(history)
        db.commit()
        db.refresh(alert)
        return alert
