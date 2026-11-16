"""
SQL-TRUST Database API Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from backend.database import get_db
from backend.services.database_service import DatabaseService
from backend.schemas.database import (
    DatabaseDiscoveredResponse,
    DatabaseRegisterRequest,
    DatabaseRegisteredResponse,
    ConnectionTestResponse
)

router = APIRouter(prefix="/databases")


@router.get("", response_model=List[DatabaseDiscoveredResponse], summary="Discover SQL Server databases")
def list_databases(db: Session = Depends(get_db)):
    """
    Discovers all databases on the connected SQL Server instance using sys.databases.
    Identifies system databases and flags existing registrations.
    """
    try:
        service = DatabaseService(db)
        return service.discover_databases()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query SQL Server catalog: {str(e)}"
        )


@router.get("/registered", response_model=List[DatabaseRegisteredResponse], summary="List registered databases")
def list_registered(db: Session = Depends(get_db)):
    """Lists all databases currently registered for backup management in SQL-TRUST."""
    service = DatabaseService(db)
    return service.list_registered_databases()


@router.post("/register", response_model=DatabaseRegisteredResponse, summary="Register a database for protection")
def register_database(req: DatabaseRegisterRequest, db: Session = Depends(get_db)):
    """
    Registers a target database for backup management.
    Requires explicit administrator consent to protect against unauthorized database targeting.
    """
    service = DatabaseService(db)
    try:
        return service.register_database(
            database_name=req.database_name,
            allow_system_override=req.allow_system_override
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )


@router.get("/{database_id}", response_model=DatabaseRegisteredResponse, summary="Get registered database details")
def get_database(database_id: str, db: Session = Depends(get_db)):
    """Retrieves metadata for a specific registered database by ID."""
    service = DatabaseService(db)
    record = service.get_registered_database(database_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Database with ID '{database_id}' not found in registry."
        )
    return record


@router.post("/test-connection", response_model=ConnectionTestResponse, summary="Test SQL Server connection")
def test_connection(db: Session = Depends(get_db)):
    """Executes a harmless query (SELECT @@VERSION;) to verify SQL Server reachability."""
    service = DatabaseService(db)
    return service.test_connection()
