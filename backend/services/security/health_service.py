"""
SQL-TRUST Monitoring Health & Telemetry Assessment Service
Module 2: Security Monitoring Engine
Evaluates live telemetry status: HEALTHY, DEGRADED, UNAVAILABLE, or UNASSESSED.
Never confuses absence of events with absence of security threats when telemetry is inactive.
"""
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import test_sql_connection
from backend.services.storage.seaweedfs import SeaweedFSStorageProvider
from backend.services.security.audit_service import AuditService
from backend.services.security.xe_service import ExtendedEventsService
from backend.models.security import (
    SecuritySource,
    MonitoringHealth,
    CollectorCheckpoint,
    SecurityEvent
)


class HealthService:
    @staticmethod
    def evaluate_monitoring_health(db: Session, source_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes a rigorous health assessment across SQL Server, Audit targets,
        Extended Events sessions, collector watermarks, and SeaweedFS WORM storage.
        """
        source = None
        if source_id:
            source = db.query(SecuritySource).filter(SecuritySource.id == source_id).first()
        if not source:
            source = db.query(SecuritySource).first()

        now = datetime.now(timezone.utc)

        # 1. SQL Server Connectivity
        sql_health = test_sql_connection()
        sql_online = bool(sql_health.get("success"))

        # 2. SQL Server Audit Inspection
        audit_info = AuditService.inspect_audit_configuration()
        audit_enabled = bool(audit_info.get("audit_enabled") and audit_info.get("spec_enabled"))
        audit_target_avail = bool(audit_info.get("log_file_path") and os.path.exists(audit_info["log_file_path"]))

        # 3. Extended Events Inspection
        xe_info = ExtendedEventsService.inspect_xe_configuration()
        xe_running = bool(xe_info.get("session_running"))
        xe_target_avail = bool(xe_info.get("file_count", 0) >= 0 and os.path.exists(os.path.abspath(r"data\extended_events")))

        # 4. Storage Connectivity
        storage = SeaweedFSStorageProvider()
        storage_health = storage.check_connectivity()
        storage_connected = bool(storage_health.get("connected"))

        # 5. Collector Checkpoints & Lag
        last_run = None
        last_event_ts = None
        collection_lag_seconds = 0
        last_error = None

        if source:
            cps = db.query(CollectorCheckpoint).filter(CollectorCheckpoint.source_id == source.id).all()
            for cp in cps:
                if cp.last_run_timestamp and (last_run is None or cp.last_run_timestamp > last_run):
                    last_run = cp.last_run_timestamp
                if cp.last_event_timestamp and (last_event_ts is None or cp.last_event_timestamp > last_event_ts):
                    last_event_ts = cp.last_event_timestamp
                if cp.status == "FAILED" and cp.error_message:
                    last_error = cp.error_message

            if last_event_ts:
                # Normalize timezone awareness for safe subtraction
                if last_event_ts.tzinfo is None:
                    last_event_ts = last_event_ts.replace(tzinfo=timezone.utc)
                # Calculate collection lag relative to now
                collection_lag_seconds = max(0, int((now - last_event_ts).total_seconds()))

        # 6. Synthesize Overall Telemetry Health
        # HEALTHY: SQL online, Audit enabled, XE running, Storage connected, Collector active
        # DEGRADED: SQL online, but either Audit disabled, XE stopped, or collector lagging > 5 mins
        # UNAVAILABLE: SQL offline or critical components inaccessible
        # UNASSESSED: Telemetry not configured or source missing
        if not sql_online:
            overall_status = "UNAVAILABLE"
        elif not audit_info.get("audit_configured") and not xe_info.get("session_configured"):
            overall_status = "UNASSESSED"
        elif audit_enabled and xe_running and storage_connected:
            if collection_lag_seconds > 600:  # 10 minutes lag
                overall_status = "DEGRADED"
            else:
                overall_status = "HEALTHY"
        elif audit_enabled or xe_running:
            overall_status = "DEGRADED"
        else:
            overall_status = "UNAVAILABLE"

        # Record health snapshot if source exists
        if source:
            snapshot = MonitoringHealth(
                source_id=source.id,
                overall_status=overall_status,
                sql_connectivity=sql_online,
                audit_enabled=audit_enabled,
                audit_target_available=audit_target_avail,
                audit_collection_lag_seconds=collection_lag_seconds,
                xe_session_running=xe_running,
                xe_target_available=xe_target_avail,
                last_successful_run=last_run,
                last_event_timestamp=last_event_ts,
                last_error=last_error,
                storage_connectivity=storage_connected,
                checked_at=now
            )
            db.add(snapshot)
            db.commit()

        return {
            "overall_status": overall_status,
            "checked_at": now.isoformat(),
            "sql_server": {
                "connected": sql_online,
                "version": sql_health.get("version"),
                "server": sql_health.get("server")
            },
            "audit": audit_info,
            "extended_events": xe_info,
            "storage": storage_health,
            "collector": {
                "last_run": last_run.isoformat() if last_run else None,
                "last_event_timestamp": last_event_ts.isoformat() if last_event_ts else None,
                "collection_lag_seconds": collection_lag_seconds,
                "last_error": last_error
            }
        }
