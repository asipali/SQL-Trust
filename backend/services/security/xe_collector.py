"""
SQL-TRUST Incremental Extended Events File Collector
Module 2: Security Monitoring Engine
Reads .xel files incrementally using sys.fn_xe_file_target_read_file, parses XML payloads,
maintains persistent watermarks, and pushes normalized events through the detection rule engine.
"""
import os
import glob
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


class XECollector:
    def __init__(self, db: Session, source: SecuritySource):
        self.db = db
        self.source = source
        self.server_name = source.server_name
        self.xe_path = source.xe_target_path or os.path.abspath(r"data\extended_events")

    def _get_or_create_checkpoint(self) -> CollectorCheckpoint:
        """Retrieves or creates the persistent watermark checkpoint for Extended Events."""
        cp = self.db.query(CollectorCheckpoint).filter(
            CollectorCheckpoint.source_id == self.source.id,
            CollectorCheckpoint.collector_type == "EXTENDED_EVENTS"
        ).first()

        if not cp:
            cp = CollectorCheckpoint(
                source_id=self.source.id,
                collector_type="EXTENDED_EVENTS",
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
        Executes an incremental collection cycle against Extended Events .xel files.
        Guarantees zero duplicate ingestion and updates persistent checkpoints.
        """
        cp = self._get_or_create_checkpoint()
        cp.status = "RUNNING"
        self.db.commit()

        # Check if any .xel files exist
        pattern = os.path.join(self.xe_path, "*.xel")
        files_found = glob.glob(pattern)
        if not files_found:
            cp.status = "COMPLETED"
            cp.last_run_timestamp = datetime.now(timezone.utc)
            self.db.commit()
            return {
                "success": True,
                "collector": "EXTENDED_EVENTS",
                "rows_scanned": 0,
                "events_ingested": 0,
                "alerts_generated": 0,
                "message": "No .xel files found in target directory."
            }

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
                query_sql = """
                    SELECT TOP (:limit)
                        module_guid,
                        package_guid,
                        object_name,
                        event_data,
                        file_name,
                        file_offset
                    FROM sys.fn_xe_file_target_read_file(:pattern, NULL, NULL, NULL)
                """
                rows = conn.execute(text(query_sql), {"pattern": pattern, "limit": batch_limit}).mappings().all()

                seen_fingerprints = set()
                for row in rows:
                    event_xml = row.get("event_data")
                    source_file = row.get("file_name") or "unknown_xe_file"
                    file_offset = row.get("file_offset")

                    norm = EventNormalizer.normalize_xe_record(
                        target_data_xml=event_xml,
                        source_file=source_file,
                        source_id=self.source.id,
                        server_name=self.server_name,
                        file_offset=file_offset
                    )

                    if not norm:
                        continue

                    fp = norm["event_fingerprint"]
                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)

                    # Deduplication check
                    exists = self.db.query(SecurityEvent.id).filter(
                        SecurityEvent.event_fingerprint == fp
                    ).first()

                    if not exists:
                        ev = SecurityEvent(**norm)
                        self.db.add(ev)
                        new_events.append(ev)
                        ingested_count += 1

                    latest_file = source_file
                    latest_offset = file_offset or latest_offset
                    ev_ts = norm.get("event_timestamp")
                    if ev_ts and ev_ts.tzinfo is None:
                        ev_ts = ev_ts.replace(tzinfo=timezone.utc)
                    if ev_ts and (latest_ts is None or ev_ts > latest_ts):
                        latest_ts = ev_ts

                self.db.commit()

            # Trigger detection rule evaluation
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
                "collector": "EXTENDED_EVENTS",
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
                "collector": "EXTENDED_EVENTS",
                "error": str(e),
                "events_ingested": 0,
                "alerts_generated": 0
            }
