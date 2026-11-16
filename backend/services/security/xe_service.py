"""
SQL-TRUST Extended Events Management & Inspection Service
Module 2: Security Monitoring Engine
Inspects and manages the SQLTrust_Security_XE event session on Microsoft SQL Server.
"""
import os
import glob
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.database import create_db_engine
from backend.config import settings


class ExtendedEventsService:
    @staticmethod
    def inspect_xe_configuration(server_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Queries sys.server_event_sessions, sys.dm_xe_sessions, and session targets.
        """
        engine = create_db_engine(database="master")
        with engine.connect() as conn:
            # Query session state
            session_row = conn.execute(text("""
                SELECT 
                    s.event_session_id,
                    s.name AS session_name,
                    CASE WHEN s.startup_state = 1 THEN 'ON' ELSE 'OFF' END AS startup_state_desc,
                    CASE WHEN r.create_time IS NOT NULL THEN 'RUNNING' ELSE 'STOPPED' END AS runtime_status,
                    r.create_time AS started_at,
                    r.total_buffer_size,
                    r.dropped_event_count
                FROM sys.server_event_sessions s
                LEFT JOIN sys.dm_xe_sessions r ON s.name = r.name
                WHERE s.name = 'SQLTrust_Security_XE'
            """)).mappings().first()

            if not session_row:
                return {
                    "session_configured": False,
                    "session_running": False,
                    "session_name": "SQLTrust_Security_XE",
                    "runtime_status": "NOT_CONFIGURED",
                    "events_configured": [],
                    "target_file_path": None,
                    "file_count": 0,
                    "status": "NOT_CONFIGURED"
                }

            # Query configured events
            event_rows = conn.execute(text("""
                SELECT name FROM sys.server_event_session_events
                WHERE event_session_id = :sid
            """), {"sid": session_row["event_session_id"]}).fetchall()
            events_configured = [r[0] for r in event_rows]

            # Query target file path
            target_row = conn.execute(text("""
                SELECT CAST(v.value AS VARCHAR(500)) AS target_path
                FROM sys.server_event_session_targets t
                JOIN sys.server_event_session_fields v 
                    ON t.event_session_id = v.event_session_id AND t.target_id = v.object_id
                WHERE t.event_session_id = :sid AND v.name = 'filename'
            """), {"sid": session_row["event_session_id"]}).first()

            target_path = target_row[0] if target_row else None

            # Local files check
            xe_dir = os.path.abspath(r"data\extended_events")
            files_found = glob.glob(os.path.join(xe_dir, "*.xel"))

            is_running = (session_row["runtime_status"] == "RUNNING")
            return {
                "session_configured": True,
                "session_name": session_row["session_name"],
                "session_running": is_running,
                "runtime_status": session_row["runtime_status"],
                "startup_state": session_row["startup_state_desc"],
                "started_at": session_row["started_at"].isoformat() if session_row.get("started_at") else None,
                "event_loss_count": session_row.get("dropped_event_count", 0),
                "events_configured": events_configured,
                "target_file_path": target_path,
                "file_count": len(files_found),
                "discovered_files": files_found,
                "status": "HEALTHY" if is_running else "STOPPED"
            }
