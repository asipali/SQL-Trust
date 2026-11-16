"""
SQL-TRUST Database Baseline Collector
Module 3: Database Forensics Engine
Captures comprehensive read-only state baselines of SQL Server databases including
schema objects, columns, DDL definitions, principals, role memberships, permissions, and configuration options.
Computes deterministic SHA-256 hashes for all entities.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.database import create_db_engine
from backend.models.forensics import ForensicBaseline, ForensicBaselineItem
from backend.models.backup import ProtectedDatabase


def compute_sha256(data: str) -> str:
    """Computes standard SHA-256 hex digest of UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class BaselineCollector:
    """
    Executes non-destructive, read-only catalog extraction to build comprehensive state baselines.
    """

    def __init__(self, db: Session, database_name: str, server_name: str = "localhost\\SQLEXPRESS"):
        self.db = db
        self.database_name = database_name
        self.server_name = server_name

    def capture_baseline(self, baseline_name: Optional[str] = None, notes: Optional[str] = None) -> ForensicBaseline:
        """
        Extracts full database metadata and persists a ForensicBaseline with all ForensicBaselineItems.
        """
        captured_time = datetime.now(timezone.utc)
        name = baseline_name or f"Baseline_{self.database_name}_{captured_time.strftime('%Y%m%d_%H%M%S')}"

        # Resolve protected database ID if registered
        prot_db = self.db.query(ProtectedDatabase).filter(
            ProtectedDatabase.database_name == self.database_name
        ).first()
        database_id = prot_db.id if prot_db else None

        engine = create_db_engine(database=self.database_name, server=self.server_name)

        with engine.connect() as conn:
            # 1. Capture Database Options
            db_options = self._collect_database_options(conn)
            
            # 2. Capture Schema Objects & Columns
            objects_data = self._collect_objects_and_columns(conn)
            
            # 3. Capture Triggers
            triggers_data = self._collect_triggers(conn)
            
            # 4. Capture Principals (Users)
            principals_data = self._collect_principals(conn)
            
            # 5. Capture Role Memberships
            role_members_data = self._collect_role_members(conn)
            
            # 6. Capture Permissions
            permissions_data = self._collect_permissions(conn)

        # Build ForensicBaseline record
        baseline = ForensicBaseline(
            database_id=database_id,
            server_name=self.server_name,
            database_name=self.database_name,
            baseline_name=name,
            baseline_type="FULL",
            status="CAPTURING",
            captured_at=captured_time,
            notes=notes,
            sha256_manifest="PENDING"
        )
        self.db.add(baseline)
        self.db.commit()
        self.db.refresh(baseline)

        items: List[ForensicBaselineItem] = []

        # Convert Database Options into Item
        items.append(ForensicBaselineItem(
            baseline_id=baseline.id,
            item_type="DATABASE_OPTION",
            schema_name=None,
            item_name="DATABASE_CONFIGURATION",
            sql_object_id=db_options.get("database_id"),
            definition_hash=compute_sha256(json.dumps(db_options, sort_keys=True, default=str)),
            raw_definition=None,
            properties_json=json.dumps(db_options, default=str),
            is_encrypted=False
        ))

        # Convert Objects into Items
        for obj in objects_data:
            items.append(ForensicBaselineItem(
                baseline_id=baseline.id,
                item_type=obj["item_type"],
                schema_name=obj["schema_name"],
                item_name=obj["object_name"],
                sql_object_id=obj["object_id"],
                definition_hash=obj["definition_hash"],
                raw_definition=obj.get("raw_definition"),
                properties_json=json.dumps(obj["properties"], default=str),
                is_encrypted=obj["is_encrypted"]
            ))

        # Convert Triggers into Items
        for trg in triggers_data:
            items.append(ForensicBaselineItem(
                baseline_id=baseline.id,
                item_type="TRIGGER",
                schema_name=trg["schema_name"],
                item_name=trg["trigger_name"],
                sql_object_id=trg["object_id"],
                definition_hash=trg["definition_hash"],
                raw_definition=trg.get("raw_definition"),
                properties_json=json.dumps(trg["properties"], default=str),
                is_encrypted=trg["is_encrypted"]
            ))

        # Convert Principals into Items
        for pr in principals_data:
            items.append(ForensicBaselineItem(
                baseline_id=baseline.id,
                item_type="USER",
                schema_name=None,
                item_name=pr["principal_name"],
                sql_object_id=pr["principal_id"],
                definition_hash=compute_sha256(f"{pr['principal_name']}|{pr.get('sid_hex')}|{pr.get('type_desc')}"),
                raw_definition=None,
                properties_json=json.dumps(pr, default=str),
                is_encrypted=False
            ))

        # Convert Role Memberships into Items
        for rm in role_members_data:
            items.append(ForensicBaselineItem(
                baseline_id=baseline.id,
                item_type="ROLE_MEMBER",
                schema_name=None,
                item_name=f"{rm['role_name']}::{rm['member_name']}",
                sql_object_id=None,
                definition_hash=compute_sha256(f"{rm['role_name']}::{rm['member_name']}"),
                raw_definition=None,
                properties_json=json.dumps(rm, default=str),
                is_encrypted=False
            ))

        # Convert Permissions into Items
        for perm in permissions_data:
            perm_key = f"{perm['grantee_name']}::{perm['permission_name']}::{perm.get('object_schema') or ''}.{perm.get('object_name') or ''}"
            items.append(ForensicBaselineItem(
                baseline_id=baseline.id,
                item_type="PERMISSION",
                schema_name=perm.get("object_schema"),
                item_name=perm_key,
                sql_object_id=None,
                definition_hash=compute_sha256(json.dumps(perm, sort_keys=True, default=str)),
                raw_definition=None,
                properties_json=json.dumps(perm, default=str),
                is_encrypted=False
            ))

        self.db.add_all(items)
        self.db.commit()

        # Compute full baseline manifest SHA-256
        item_fingerprints = sorted([f"{it.item_type}:{it.item_name}:{it.definition_hash}" for it in items])
        manifest_hash = compute_sha256("\n".join(item_fingerprints))

        baseline.total_objects = len(objects_data) + len(triggers_data)
        baseline.total_principals = len(principals_data)
        baseline.total_permissions = len(permissions_data)
        baseline.sha256_manifest = manifest_hash
        baseline.status = "COMPLETED"

        self.db.commit()
        self.db.refresh(baseline)
        return baseline

    def _collect_database_options(self, conn) -> Dict[str, Any]:
        sql = """
            SELECT 
                d.database_id,
                d.name,
                d.create_date,
                d.compatibility_level,
                d.collation_name,
                d.user_access_desc,
                d.is_read_only,
                d.is_auto_close_on,
                d.is_auto_shrink_on,
                d.state_desc,
                d.recovery_model_desc,
                d.page_verify_option_desc,
                d.is_encrypted,
                d.is_trustworthy_on
            FROM sys.databases d
            WHERE d.name = :db_name
        """
        row = conn.execute(text(sql), {"db_name": self.database_name}).mappings().first()
        if not row:
            return {}
        return dict(row)

    def _collect_objects_and_columns(self, conn) -> List[Dict[str, Any]]:
        # Fetch objects (Tables, Views, Procedures, Functions)
        obj_sql = """
            SELECT 
                o.object_id,
                s.name AS schema_name,
                o.name AS object_name,
                o.type AS obj_type,
                o.type_desc,
                o.create_date,
                o.modify_date,
                m.definition,
                CASE WHEN m.definition IS NULL AND o.type IN ('P', 'V', 'FN', 'IF', 'TF') THEN 1 ELSE 0 END AS is_encrypted
            FROM sys.objects o
            INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
            LEFT JOIN sys.sql_modules m ON o.object_id = m.object_id
            WHERE o.is_ms_shipped = 0 
              AND o.type IN ('U', 'V', 'P', 'FN', 'IF', 'TF')
            ORDER BY s.name, o.name
        """
        obj_rows = conn.execute(text(obj_sql)).mappings().all()

        # Fetch columns for tables and views
        col_sql = """
            SELECT 
                c.object_id,
                c.column_id,
                c.name AS column_name,
                t.name AS type_name,
                c.max_length,
                c.precision,
                c.scale,
                c.is_nullable,
                c.is_identity
            FROM sys.columns c
            INNER JOIN sys.types t ON c.user_type_id = t.user_type_id
            INNER JOIN sys.objects o ON c.object_id = o.object_id
            WHERE o.is_ms_shipped = 0
            ORDER BY c.object_id, c.column_id
        """
        col_rows = conn.execute(text(col_sql)).mappings().all()
        cols_by_object: Dict[int, List[Dict[str, Any]]] = {}
        for c in col_rows:
            cols_by_object.setdefault(c["object_id"], []).append(dict(c))

        type_map = {
            "U": "TABLE",
            "V": "VIEW",
            "P": "PROCEDURE",
            "FN": "FUNCTION",
            "IF": "FUNCTION",
            "TF": "FUNCTION"
        }

        results = []
        for o in obj_rows:
            oid = o["object_id"]
            itype = type_map.get(o["obj_type"].strip(), "OBJECT")
            is_enc = bool(o["is_encrypted"])
            raw_def = o["definition"]

            obj_cols = cols_by_object.get(oid, [])

            if itype == "TABLE":
                # Tables have no sql_modules definition; hash is computed over canonical columns definition
                col_repr = "|".join([
                    f"{col['column_id']}:{col['column_name']}:{col['type_name']}:{col['max_length']}:{col['precision']}:{col['scale']}:{col['is_nullable']}:{col['is_identity']}"
                    for col in obj_cols
                ])
                def_hash = compute_sha256(col_repr)
            elif is_enc:
                def_hash = "ENCRYPTED_UNOBSERVABLE"
            else:
                def_hash = compute_sha256(raw_def.strip()) if raw_def else compute_sha256(o["object_name"])

            properties = {
                "type_desc": o["type_desc"],
                "create_date": o["create_date"],
                "modify_date": o["modify_date"],
                "columns": obj_cols
            }

            results.append({
                "item_type": itype,
                "schema_name": o["schema_name"],
                "object_name": o["object_name"],
                "object_id": oid,
                "definition_hash": def_hash,
                "raw_definition": raw_def if not is_enc else None,
                "properties": properties,
                "is_encrypted": is_enc
            })

        return results

    def _collect_triggers(self, conn) -> List[Dict[str, Any]]:
        sql = """
            SELECT 
                t.object_id,
                s.name AS schema_name,
                t.name AS trigger_name,
                OBJECT_NAME(t.parent_id) AS parent_table,
                t.is_disabled,
                t.is_instead_of_trigger,
                m.definition,
                CASE WHEN m.definition IS NULL THEN 1 ELSE 0 END AS is_encrypted
            FROM sys.triggers t
            INNER JOIN sys.objects p ON t.parent_id = p.object_id
            INNER JOIN sys.schemas s ON p.schema_id = s.schema_id
            LEFT JOIN sys.sql_modules m ON t.object_id = m.object_id
            WHERE t.is_ms_shipped = 0
        """
        rows = conn.execute(text(sql)).mappings().all()
        results = []
        for r in rows:
            is_enc = bool(r["is_encrypted"])
            raw_def = r["definition"]
            def_hash = "ENCRYPTED_UNOBSERVABLE" if is_enc else (compute_sha256(raw_def.strip()) if raw_def else compute_sha256(r["trigger_name"]))
            results.append({
                "object_id": r["object_id"],
                "schema_name": r["schema_name"],
                "trigger_name": r["trigger_name"],
                "definition_hash": def_hash,
                "raw_definition": raw_def if not is_enc else None,
                "is_encrypted": is_enc,
                "properties": {
                    "parent_table": r["parent_table"],
                    "is_disabled": bool(r["is_disabled"]),
                    "is_instead_of_trigger": bool(r["is_instead_of_trigger"])
                }
            })
        return results

    def _collect_principals(self, conn) -> List[Dict[str, Any]]:
        sql = """
            SELECT 
                p.principal_id,
                p.name AS principal_name,
                p.type_desc,
                p.default_schema_name,
                p.create_date,
                p.modify_date,
                p.authentication_type_desc,
                CONVERT(VARCHAR(64), p.sid, 1) AS sid_hex
            FROM sys.database_principals p
            WHERE p.principal_id > 4 AND p.name NOT LIKE '##%'
        """
        rows = conn.execute(text(sql)).mappings().all()
        return [dict(r) for r in rows]

    def _collect_role_members(self, conn) -> List[Dict[str, Any]]:
        sql = """
            SELECT 
                r.name AS role_name,
                m.name AS member_name
            FROM sys.database_role_members rm
            INNER JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
            INNER JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id
        """
        rows = conn.execute(text(sql)).mappings().all()
        return [dict(r) for r in rows]

    def _collect_permissions(self, conn) -> List[Dict[str, Any]]:
        sql = """
            SELECT 
                dp.class_desc,
                dp.permission_name,
                dp.state_desc,
                p.name AS grantee_name,
                OBJECT_SCHEMA_NAME(dp.major_id) AS object_schema,
                OBJECT_NAME(dp.major_id) AS object_name,
                c.name AS column_name
            FROM sys.database_permissions dp
            INNER JOIN sys.database_principals p ON dp.grantee_principal_id = p.principal_id
            LEFT JOIN sys.columns c ON dp.major_id = c.object_id AND dp.minor_id = c.column_id
            WHERE p.principal_id > 4 AND p.name NOT LIKE '##%'
        """
        rows = conn.execute(text(sql)).mappings().all()
        return [dict(r) for r in rows]
