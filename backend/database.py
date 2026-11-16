"""
SQL-TRUST Database Connectivity Module
Configures SQLAlchemy engines and pyodbc connections to Microsoft SQL Server 2022.
Supports Windows Authentication and SQL Authentication with ODBC Driver 17 and 18.
Manages connection pooling, control database initialization, and session lifetimes.
"""
import urllib.parse
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from backend.config import settings
from backend.models.backup import Base
import pyodbc


def get_available_odbc_drivers() -> list[str]:
    """Return list of installed SQL Server ODBC drivers on the system."""
    return [d for d in pyodbc.drivers() if "SQL Server" in d]


def build_odbc_connection_string(
    server: str = None,
    port: int = None,
    database: str = None,
    driver: str = None,
    trusted_connection: str = None,
    user: str = None,
    password: str = None
) -> str:
    """
    Constructs an ODBC connection string for SQL Server.
    Includes TrustServerCertificate=yes for ODBC Driver 18 compatibility with local certificates.
    """
    srv = server or settings.SQL_SERVER
    db = database or settings.SQL_DATABASE
    drv = driver or settings.SQL_DRIVER
    trusted = trusted_connection or settings.SQL_TRUSTED_CONNECTION
    usr = user or settings.SQL_USER
    pwd = password or settings.SQL_PASSWORD

    # If the requested driver isn't installed, fall back to another installed SQL driver
    installed_drivers = pyodbc.drivers()
    if drv not in installed_drivers:
        for candidate in ["ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server", "SQL Server"]:
            if candidate in installed_drivers:
                drv = candidate
                break

    parts = [
        f"DRIVER={{{drv}}}",
        f"SERVER={srv}",
        f"DATABASE={db}",
        "TrustServerCertificate=yes",
    ]

    if trusted.lower() in ("yes", "true", "1") or not usr:
        parts.append("Trusted_Connection=yes")
    else:
        parts.append(f"UID={usr}")
        parts.append(f"PWD={pwd}")

    return ";".join(parts) + ";"


def create_db_engine(database: str = None, server: str = None) -> Engine:
    """
    Creates a SQLAlchemy engine using pyodbc connection string.
    If database is not specified, uses settings.SQL_DATABASE.
    If server is not specified, uses settings.SQL_SERVER.
    """
    conn_str = build_odbc_connection_string(database=database, server=server)
    encoded_conn_str = urllib.parse.quote_plus(conn_str)
    connection_url = f"mssql+pyodbc:///?odbc_connect={encoded_conn_str}"
    
    return create_engine(
        connection_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10
    )


# Control Database Engine & Session Factory
engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """
    Ensures the control database tables exist without modifying existing data.
    """
    # Import all models so that Base.metadata includes all tables
    import backend.models.auth  # noqa
    import backend.models.backup  # noqa
    import backend.models.security  # noqa
    import backend.models.forensics  # noqa
    import backend.models.recovery  # noqa
    import backend.models.restore  # noqa
    import backend.models.investigation  # noqa

    # First verify if control database exists on instance; if not, create it via master
    try:
        master_engine = create_db_engine(database="master")
        with master_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            exists = conn.execute(
                text("SELECT database_id FROM sys.databases WHERE name = :db_name"),
                {"db_name": settings.SQL_DATABASE}
            ).scalar()
            if not exists:
                conn.execute(text(f"CREATE DATABASE [{settings.SQL_DATABASE}]"))
    except Exception as e:
        # Continue to table creation; database might already exist or connect directly
        pass

    Base.metadata.create_all(bind=engine)

    # Safe additive schema migration for users table (email, is_pending_approval)
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            existing_cols = [
                row[0] for row in conn.execute(
                    text("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'")
                ).fetchall()
            ]
            if "email" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD email VARCHAR(128) NULL;"))
            if "is_pending_approval" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD is_pending_approval BIT DEFAULT 0 NOT NULL;"))
    except Exception:
        pass


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a SQLAlchemy database session and ensures cleanup.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_sql_connection(database: str = None) -> dict:
    """
    Executes a harmless 'SELECT @@VERSION;' query to verify connectivity.
    Never exposes passwords or sensitive credentials.
    """
    driver_list = get_available_odbc_drivers()
    if not driver_list:
        return {
            "success": False,
            "error": "No SQL Server ODBC drivers installed on this machine.",
            "available_drivers": []
        }

    target_db = database or settings.SQL_DATABASE
    try:
        test_engine = create_db_engine(database=target_db)
        with test_engine.connect() as conn:
            result = conn.execute(text("SELECT @@VERSION;")).scalar()
            return {
                "success": True,
                "version": result.strip() if result else "Unknown",
                "driver_used": settings.SQL_DRIVER,
                "server": settings.SQL_SERVER,
                "database": target_db
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "driver_attempted": settings.SQL_DRIVER,
            "server": settings.SQL_SERVER,
            "available_drivers": driver_list
        }
