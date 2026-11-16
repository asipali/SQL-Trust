"""
SQL-TRUST Incremental SQL Server Audit File Collector
Module 2: Security Monitoring Engine
Reads .sqlaudit files incrementally using sys.fn_get_audit_file, maintains persistent watermarks,
and pushes normalized events through the detection rule engine.
"""
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.database import create_db_engine
from backend.models.security import (
    SecuritySource,
    SecurityEvent,
    CollectorCheckpoint
)
from backend.services.security.normalizer import EventNormalizer
from backend.services.security.rule_engine import RuleEngine


class AuditCollector:
    def __init__(self, db: Session, source: SecuritySource):
        self.db = db
        self.source = source
        self.server_name = source.server_name
        self.audit_path = source.audit_target_path or os.path.abspath(r"data\audit")

    def _get_or_create_checkpoint(self) -> CollectorCheckpoint:
        """Retrieves or creates the persistent watermark checkpoint for SQL Server Audit."""
        cp = self.db.query(CollectorCheckpoint).filter(
            CollectorCheckpoint.source_id == self.source.id,
            CollectorCheckpoint.collector_type == "SQL_AUDIT"
        ).first()

        if not cp:
            cp = CollectorCheckpoint(
                source_id=self.source.id,
                collector_type="SQL_AUDIT",
                last_file_name=None,
                last_file_offset=0,
                last_event_timestamp=None,
                records_collected=0,
                status="IDLE"
            )
            self.db.add(cp)
            self.db.commit()
            self.db.refresh(cp)
        return cp

    def collect_incremental(self, batch_limit: int = 500) -> Dict[str, Any]:
        """
        Executes an incremental collection cycle against SQL Server Audit files.
        Guarantees zero duplicate ingestion and updates persistent checkpoints.
        """
        cp = self._get_or_create_checkpoint()
        cp.status = "RUNNING"
        self.db.commit()

        file_pattern = os.path.join(self.audit_path, "*")
        engine = create_db_engine(database="master", server=self.server_name)

        new_events = []
        ingested_count = 0
        latest_file = cp.last_file_name
        latest_offset = cp.last_file_offset
        latest_ts = cp.last_event_timestamp
        if latest_ts and latest_ts.tzinfo is None:
            latest_ts = latest_ts.replace(tzinfo=timezone.utc)

        try:
            with engine.connect() as conn:
                # Query fn_get_audit_file
                # When restarting or resuming, if initial_file_name and offset exist, pass them
                query_sql = """
                    SELECT TOP (:limit)
                        event_time,
                        sequence_number,
                        action_id,
                        succeeded,
                        session_id,
                        server_principal_name,
                        database_principal_name,
                        target_server_principal_name,
                        database_name,
                        schema_name,
                        object_name,
                        statement,
                        file_name,
                        audit_file_offset,
                        client_ip,
                        application_name
                    FROM sys.fn_get_audit_file(:pattern, DEFAULT, DEFAULT)
                """
                if latest_ts:
                    query_sql += " WHERE event_time >= :min_time"
                query_sql += " ORDER BY event_time ASC, audit_file_offset ASC, sequence_number ASC"

                params = {"pattern": file_pattern, "limit": batch_limit}
                if latest_ts:
                    # Pass timezone-naive UTC for pyodbc datetime comparison
                    params["min_time"] = latest_ts.astimezone(timezone.utc).replace(tzinfo=None)

                rows = conn.execute(text(query_sql), params).mappings().all()

                seen_fingerprints = set()
                for row in rows:
                    norm = EventNormalizer.normalize_audit_record(
                        dict(row),
                        source_id=self.source.id,
                        server_name=self.server_name
                    )

                    fp = norm["event_fingerprint"]
                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)

                    # Deduplication check by fingerprint
                    exists = self.db.query(SecurityEvent.id).filter(
                        SecurityEvent.event_fingerprint == fp
                    ).first()

                    if not exists:
                        ev = SecurityEvent(**norm)
                        self.db.add(ev)
                        new_events.append(ev)
                        ingested_count += 1

                    latest_file = row.get("file_name") or latest_file
                    latest_offset = row.get("audit_file_offset") or latest_offset
                    ev_ts = norm.get("event_timestamp")
                    if ev_ts and ev_ts.tzinfo is None:
                        ev_ts = ev_ts.replace(tzinfo=timezone.utc)
                    if latest_ts and latest_ts.tzinfo is None:
                        latest_ts = latest_ts.replace(tzinfo=timezone.utc)

                    if ev_ts and (latest_ts is None or ev_ts > latest_ts):
                        latest_ts = ev_ts

                self.db.commit()

            # Trigger detection rule evaluation on newly ingested events
            alerts_generated = []
            if new_events:
                rule_engine = RuleEngine(self.db)
                alerts_generated = rule_engine.evaluate_events(new_events, self.source.id)

            # Update checkpoint
            cp.last_file_name = latest_file
            cp.last_file_offset = latest_offset or 0
            cp.last_event_timestamp = latest_ts
            cp.records_collected += ingested_count
            cp.status = "COMPLETED"
            cp.last_run_timestamp = datetime.now(timezone.utc)
            cp.error_message = None
            self.db.commit()

            return {
                "success": True,
                "collector": "SQL_AUDIT",
                "rows_scanned": len(rows),
                "events_ingested": ingested_count,
                "alerts_generated": len(alerts_generated),
                "last_file": latest_file,
                "last_offset": latest_offset,
                "last_timestamp": latest_ts.isoformat() if latest_ts else None
            }

        except Exception as e:
            cp.status = "FAILED"
            cp.error_message = str(e)
            cp.last_run_timestamp = datetime.now(timezone.utc)
            self.db.commit()
            return {
                "success": False,
                "collector": "SQL_AUDIT",
                "error": str(e),
                "events_ingested": 0,
                "alerts_generated": 0
            }
