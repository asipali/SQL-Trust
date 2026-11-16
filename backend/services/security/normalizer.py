"""
SQL-TRUST Event Normalizer & Deduplication Service
Module 2: Security Monitoring Engine
Parses raw SQL Server Audit records and Extended Events XML payloads into a standardized schema.
Computes deterministic cryptographic fingerprints for idempotent event ingestion.
"""
import hashlib
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Any, Optional


def compute_event_fingerprint(
    server_name: str,
    event_source: str,
    source_file: str,
    event_timestamp: datetime,
    action: str,
    principal_name: Optional[str],
    session_id: Optional[int],
    statement: Optional[str],
    source_event_id: Optional[str] = None
) -> str:
    """
    Computes a deterministic SHA-256 fingerprint for a security event.
    Prevents duplicate ingestion across collector restarts or overlapping file reads.
    """
    ts_str = event_timestamp.astimezone(timezone.utc).isoformat() if event_timestamp else ""
    raw_key = (
        f"{server_name or ''}|{event_source or ''}|{source_file or ''}|"
        f"{ts_str}|{action or ''}|{principal_name or ''}|"
        f"{session_id or 0}|{(statement or '').strip()}|{source_event_id or ''}"
    )
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class EventNormalizer:
    """
    Normalizes audit rows and XE XML events into uniform security event dictionaries.
    """

    # Action code to normalized event_type and baseline severity
    AUDIT_ACTION_MAP = {
        "LGFL": ("LOGIN_FAILED", "HIGH"),
        "LGSU": ("LOGIN_SUCCESS", "INFO"),
        "LGO":  ("LOGOUT", "INFO"),
        "CR":   ("SCHEMA_OBJECT_CREATED", "MEDIUM"),
        "AL":   ("SCHEMA_OBJECT_ALTERED", "MEDIUM"),
        "DR":   ("SCHEMA_OBJECT_DROPPED", "HIGH"),
        "G":    ("PERMISSION_GRANTED", "HIGH"),
        "D":    ("PERMISSION_DENIED", "HIGH"),
        "R":    ("PERMISSION_REVOKED", "HIGH"),
        "APRL": ("APPLICATION_ROLE_PASSWORD_CHANGED", "HIGH"),
        "BA":   ("BACKUP_EXECUTED", "INFO"),
        "RE":   ("RESTORE_EXECUTED", "MEDIUM"),
    }

    @classmethod
    def map_audit_action(cls, action_id: str, statement: Optional[str] = None, succeeded: bool = True) -> tuple[str, str]:
        """Maps SQL Server Audit action_id to (event_type, severity)."""
        action = (action_id or "").strip()
        event_type, severity = cls.AUDIT_ACTION_MAP.get(action, ("SECURITY_OPERATION", "INFO"))

        # Refine based on statement context
        stmt = (statement or "").upper()
        if "SYSADMIN" in stmt and ("ADD" in stmt or "DROP" in stmt or "ALTER" in stmt):
            event_type = "SYSADMIN_MEMBERSHIP_CHANGE"
            severity = "CRITICAL"
        elif "AUDIT" in stmt and ("ALTER" in stmt or "DROP" in stmt or "OFF" in stmt):
            event_type = "AUDIT_CONFIGURATION_CHANGE"
            severity = "CRITICAL"
        elif "EVENT SESSION" in stmt and ("STOP" in stmt or "DROP" in stmt):
            event_type = "EXTENDED_EVENTS_INTERRUPTION"
            severity = "CRITICAL"
        elif not succeeded and action == "LGFL":
            severity = "HIGH"

        return event_type, severity

    @classmethod
    def normalize_audit_record(cls, row: Dict[str, Any], source_id: str, server_name: str) -> Dict[str, Any]:
        """Normalizes a dictionary from sys.fn_get_audit_file."""
        event_time = row.get("event_time")
        if isinstance(event_time, str):
            try:
                event_time = datetime.fromisoformat(event_time)
            except Exception:
                event_time = datetime.now(timezone.utc)
        if event_time and event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)

        action_id = (row.get("action_id") or "").strip()
        succeeded = bool(row.get("succeeded", True))
        statement = row.get("statement") or ""
        principal_name = row.get("server_principal_name") or row.get("database_principal_name")
        session_id = row.get("session_id")
        database_name = row.get("database_name")
        target_object = row.get("object_name") or row.get("target_server_principal_name")
        source_file = row.get("file_name") or "unknown_audit_file"
        file_offset = row.get("audit_file_offset") if row.get("audit_file_offset") is not None else row.get("file_offset")
        seq_num = row.get("sequence_number")
        source_ev_id = f"{file_offset}:{seq_num}" if file_offset is not None else None

        event_type, severity = cls.map_audit_action(action_id, statement, succeeded)

        fingerprint = compute_event_fingerprint(
            server_name=server_name,
            event_source="SQL_AUDIT",
            source_file=source_file,
            event_timestamp=event_time,
            action=action_id,
            principal_name=principal_name,
            session_id=session_id,
            statement=statement,
            source_event_id=source_ev_id
        )

        # Build raw payload for forensic preservation
        clean_row = {}
        for k, v in row.items():
            if isinstance(v, datetime):
                clean_row[k] = v.isoformat()
            elif isinstance(v, bytes):
                clean_row[k] = v.hex()
            else:
                clean_row[k] = v

        return {
            "source_id": source_id,
            "event_source": "SQL_AUDIT",
            "source_file": source_file,
            "source_event_id": source_ev_id,
            "event_type": event_type,
            "event_timestamp": event_time,
            "server_name": server_name,
            "database_name": database_name,
            "principal_name": principal_name,
            "session_id": int(session_id) if session_id is not None else None,
            "client_ip": row.get("client_ip"),
            "client_app": row.get("application_name"),
            "action": action_id,
            "target_object": target_object,
            "success": succeeded,
            "severity": severity,
            "event_fingerprint": fingerprint,
            "raw_payload": json.dumps(clean_row, default=str),
            "integrity_status": "VERIFIED"
        }

    @classmethod
    def normalize_xe_record(
        cls,
        target_data_xml: str,
        source_file: str,
        source_id: str,
        server_name: str,
        file_offset: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """Parses and normalizes an Extended Events event XML string."""
        if not target_data_xml:
            return None

        try:
            root = ET.fromstring(target_data_xml)
        except Exception:
            return None

        event_name = root.attrib.get("name", "xe_event")
        ts_str = root.attrib.get("timestamp")
        if ts_str:
            try:
                # XE timestamps are in UTC e.g. 2026-11-14T05:41:00.000Z
                event_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                event_time = datetime.now(timezone.utc)
        else:
            event_time = datetime.now(timezone.utc)

        # Parse actions and fields
        fields = {}
        for child in root:
            name = child.attrib.get("name")
            if not name:
                continue
            val_elem = child.find("value")
            text_elem = child.find("text")
            val = val_elem.text if val_elem is not None else (text_elem.text if text_elem is not None else None)
            fields[name] = val

        principal_name = fields.get("username") or fields.get("server_principal_name")
        session_id = fields.get("session_id")
        database_name = fields.get("database_name")
        client_app = fields.get("client_app_name")
        client_hostname = fields.get("client_hostname")
        statement = fields.get("sql_text") or fields.get("statement")
        error_number = fields.get("error_number")
        severity_val = fields.get("severity")

        # Map event type and severity
        if event_name == "login":
            event_type = "LOGIN_SUCCESS"
            severity = "INFO"
            success = True
        elif event_name == "logout":
            event_type = "LOGOUT"
            severity = "INFO"
            success = True
        elif event_name == "error_reported":
            if error_number == "18456":
                event_type = "LOGIN_FAILED"
                severity = "HIGH"
                success = False
            else:
                event_type = "ERROR_REPORTED"
                severity = "MEDIUM" if int(severity_val or 0) < 16 else "HIGH"
                success = False
        elif event_name in ("object_created", "object_altered", "object_deleted"):
            event_type = f"SCHEMA_{event_name.upper()}"
            severity = "HIGH" if event_name == "object_deleted" else "MEDIUM"
            success = True
        else:
            event_type = event_name.upper()
            severity = "INFO"
            success = True

        activity_id = fields.get("attach_activity_id") or fields.get("attach_activity_id_xfer") or error_number
        source_ev_id = f"{file_offset}:{activity_id}" if file_offset is not None else activity_id

        fingerprint = compute_event_fingerprint(
            server_name=server_name,
            event_source="EXTENDED_EVENTS",
            source_file=source_file,
            event_timestamp=event_time,
            action=event_name,
            principal_name=principal_name,
            session_id=int(session_id) if session_id else None,
            statement=statement,
            source_event_id=source_ev_id
        )

        return {
            "source_id": source_id,
            "event_source": "EXTENDED_EVENTS",
            "source_file": source_file,
            "source_event_id": source_ev_id,
            "event_type": event_type,
            "event_timestamp": event_time,
            "server_name": server_name,
            "database_name": database_name,
            "principal_name": principal_name,
            "session_id": int(session_id) if session_id else None,
            "client_ip": client_hostname,
            "client_app": client_app,
            "action": event_name,
            "target_object": fields.get("object_name"),
            "success": success,
            "severity": severity,
            "event_fingerprint": fingerprint,
            "raw_payload": json.dumps(fields, default=str),
            "integrity_status": "VERIFIED"
        }
