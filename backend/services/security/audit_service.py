"""
SQL-TRUST SQL Server Audit Management & Inspection Service
Module 2: Security Monitoring Engine
Inspects and manages Server Audit and Audit Specification configurations on Microsoft SQL Server.
"""
import os
import glob
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.database import create_db_engine
from backend.config import settings


class AuditService:
    @staticmethod
    def inspect_audit_configuration(server_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Inspects SQL Server catalogs (sys.server_audits, sys.server_file_audits, sys.server_audit_specifications)
        to return live audit health and configuration metrics.
        """
        engine = create_db_engine(database="master")
        with engine.connect() as conn:
            # Query server audit details
            audit_row = conn.execute(text("""
                SELECT 
                    a.audit_id,
                    a.name AS audit_name,
                    CAST(a.is_state_enabled AS BIT) AS is_enabled,
                    a.type_desc AS target_type,
                    a.on_failure_desc AS failure_action,
                    a.queue_delay,
                    f.log_file_path,
                    f.max_file_size,
                    f.max_rollover_files
                FROM sys.server_audits a
                LEFT JOIN sys.server_file_audits f ON a.audit_id = f.audit_id
                WHERE a.name = 'SQLTrust_ServerAudit'
            """)).mappings().first()

            if not audit_row:
                return {
                    "audit_configured": False,
                    "audit_enabled": False,
                    "audit_name": "SQLTrust_ServerAudit",
                    "spec_configured": False,
                    "spec_enabled": False,
                    "action_groups": [],
                    "file_count": 0,
                    "log_file_path": None,
                    "status": "NOT_CONFIGURED"
                }

            # Query specification details
            spec_rows = conn.execute(text("""
                SELECT 
                    s.name AS spec_name,
                    CAST(s.is_state_enabled AS BIT) AS is_enabled,
                    d.audit_action_name
                FROM sys.server_audit_specifications s
                JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                WHERE s.name = 'SQLTrust_ServerAudit_Spec'
            """)).mappings().all()

            action_groups = [r["audit_action_name"] for r in spec_rows]
            spec_enabled = bool(spec_rows and spec_rows[0]["is_enabled"])

            # Discover local files
            audit_dir = audit_row.get("log_file_path") or os.path.abspath(r"data\audit")
            file_pattern = os.path.join(audit_dir, "*.sqlaudit")
            files_found = glob.glob(file_pattern)

            return {
                "audit_configured": True,
                "audit_name": audit_row["audit_name"],
                "audit_enabled": bool(audit_row["is_enabled"]),
                "target_type": audit_row["target_type"],
                "failure_action": audit_row["failure_action"],
                "queue_delay": audit_row["queue_delay"],
                "log_file_path": audit_dir,
                "max_file_size_mb": audit_row.get("max_file_size"),
                "max_rollover_files": audit_row.get("max_rollover_files"),
                "spec_configured": len(spec_rows) > 0,
                "spec_enabled": spec_enabled,
                "action_groups": action_groups,
                "file_count": len(files_found),
                "discovered_files": files_found,
                "status": "HEALTHY" if audit_row["is_enabled"] and spec_enabled else "DEGRADED"
            }
