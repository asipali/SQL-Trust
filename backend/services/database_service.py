"""
SQL-TRUST Database Service
Manages SQL Server catalog discovery, identifier validation, and explicit database registration.
Protects system databases by default and prevents unauthorized execution.
"""
import re
from typing import List, Dict, Any, Optional
from sqlalchemy import text
from sqlalchemy.orm import Session
from backend.database import create_db_engine
from backend.models.backup import ProtectedDatabase
from backend.config import settings

SYSTEM_DATABASES = {"master", "model", "msdb", "tempdb"}

# Strict SQL identifier regex: letters, numbers, underscores only
SQL_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9_#$]+$")


def validate_sql_identifier(identifier: str) -> str:
    """
    Validates that a database name or identifier conforms to safe alphanumeric SQL conventions.
    Prevents SQL injection or command chaining.
    """
    if not identifier or not isinstance(identifier, str):
        raise ValueError("Database identifier cannot be empty.")
    
    clean_id = identifier.strip()
    if len(clean_id) > 128:
        raise ValueError(f"Identifier '{clean_id}' exceeds maximum length of 128 characters.")

    if not SQL_IDENTIFIER_REGEX.match(clean_id):
        raise ValueError(
            f"Invalid database name '{clean_id}'. Database names must contain only letters, numbers, underscores, and standard characters."
        )
    return clean_id


class DatabaseService:
    """
    Service for discovering SQL Server databases and managing protected registrations.
    """

    def __init__(self, db_session: Optional[Session] = None):
        self.db = db_session
        self.engine = create_db_engine(database="master")

    def test_connection(self) -> Dict[str, Any]:
        """Runs harmless SELECT @@VERSION; on the SQL Server instance."""
        try:
            with self.engine.connect() as conn:
                version = conn.execute(text("SELECT @@VERSION;")).scalar()
                server_name = conn.execute(text("SELECT @@SERVERNAME;")).scalar()
                return {
                    "connected": True,
                    "server_name": server_name or settings.SQL_SERVER,
                    "version": version.strip() if version else "Unknown",
                    "driver": settings.SQL_DRIVER
                }
        except Exception as e:
            return {
                "connected": False,
                "server_name": settings.SQL_SERVER,
                "error": str(e)
            }

    def discover_databases(self) -> List[Dict[str, Any]]:
        """
        Discovers all databases on the connected SQL Server instance using sys.databases.
        Identifies system databases and checks if they are currently registered.
        """
        query = text("""
            SELECT 
                database_id,
                name,
                state_desc,
                recovery_model_desc,
                create_date,
                compatibility_level
            FROM sys.databases
            ORDER BY name ASC;
        """)

        registered_map = {}
        if self.db:
            registered = self.db.query(ProtectedDatabase).all()
            registered_map = {r.database_name.lower(): r for r in registered}

        databases = []
        with self.engine.connect() as conn:
            rows = conn.execute(query).fetchall()
            for row in rows:
                db_name = row.name
                is_system = db_name.lower() in SYSTEM_DATABASES
                reg_record = registered_map.get(db_name.lower())

                databases.append({
                    "database_id": row.database_id,
                    "name": db_name,
                    "state": row.state_desc,
                    "recovery_model": row.recovery_model_desc,
                    "created_at": row.create_date.isoformat() if row.create_date else None,
                    "compatibility_level": row.compatibility_level,
                    "is_system": is_system,
                    "is_registered": reg_record is not None,
                    "registration_id": reg_record.id if reg_record else None,
                    "registration_status": reg_record.registration_status if reg_record else None
                })

        return databases

    def get_database_details(self, database_name: str) -> Optional[Dict[str, Any]]:
        """Queries metadata for a specific database on SQL Server."""
        clean_name = validate_sql_identifier(database_name)
        query = text("""
            SELECT 
                database_id,
                name,
                state_desc,
                recovery_model_desc,
                create_date,
                compatibility_level
            FROM sys.databases
            WHERE name = :db_name;
        """)

        with self.engine.connect() as conn:
            row = conn.execute(query, {"db_name": clean_name}).fetchone()
            if not row:
                return None
            return {
                "database_id": row.database_id,
                "name": row.name,
                "state": row.state_desc,
                "recovery_model": row.recovery_model_desc,
                "create_date": row.create_date.isoformat() if row.create_date else None,
                "compatibility_level": row.compatibility_level,
                "is_system": row.name.lower() in SYSTEM_DATABASES
            }

    def register_database(
        self,
        database_name: str,
        allow_system_override: bool = False
    ) -> ProtectedDatabase:
        """
        Registers a database for backup management in the SQL-TRUST control database.
        Rejects system databases unless allow_system_override is explicitly set to True.
        """
        if not self.db:
            raise RuntimeError("Database session required for registration.")

        clean_name = validate_sql_identifier(database_name)

        if clean_name.lower() in SYSTEM_DATABASES and not allow_system_override:
            raise ValueError(
                f"Database '{clean_name}' is a protected SQL Server system database. "
                "System databases (master, model, msdb, tempdb) cannot be registered without an explicit administrator override."
            )

        # Verify database exists on the SQL Server instance
        details = self.get_database_details(clean_name)
        if not details:
            raise ValueError(f"Database '{clean_name}' does not exist on SQL Server instance.")

        if details["state"] != "ONLINE":
            raise ValueError(f"Database '{clean_name}' is in '{details['state']}' state and cannot be registered.")

        # Check if already registered
        existing = self.db.query(ProtectedDatabase).filter(
            ProtectedDatabase.database_name == clean_name
        ).first()

        if existing:
            # If paused or archived, re-activate
            if existing.registration_status != "REGISTERED":
                existing.registration_status = "REGISTERED"
                self.db.commit()
                self.db.refresh(existing)
            return existing

        # Create new registration
        conn_info = self.test_connection()
        server_name = conn_info.get("server_name", settings.SQL_SERVER)

        new_record = ProtectedDatabase(
            server_name=server_name,
            database_name=clean_name,
            database_identifier=str(details["database_id"]),
            recovery_model=details["recovery_model"],
            registration_status="REGISTERED"
        )
        self.db.add(new_record)
        self.db.commit()
        self.db.refresh(new_record)
        return new_record

    def list_registered_databases(self) -> List[ProtectedDatabase]:
        """Returns all registered databases from the control database."""
        if not self.db:
            raise RuntimeError("Database session required.")
        return self.db.query(ProtectedDatabase).order_by(ProtectedDatabase.database_name).all()

    def get_registered_database(self, database_id: str) -> Optional[ProtectedDatabase]:
        """Fetch a registered database record by ID."""
        if not self.db:
            raise RuntimeError("Database session required.")
        return self.db.query(ProtectedDatabase).filter(ProtectedDatabase.id == database_id).first()
