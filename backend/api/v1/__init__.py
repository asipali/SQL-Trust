"""
SQL-TRUST API v1 Router Configuration
"""
from fastapi import APIRouter
from backend.api.v1.databases import router as databases_router
from backend.api.v1.backups import router as backups_router
from backend.api.v1.storage import router as storage_router
from backend.api.v1.security import router as security_router
from backend.api.v1.forensics import router as forensics_router
from backend.api.v1.recovery import router as recovery_router
from backend.api.v1.restore import router as restore_router
from backend.api.v1.investigations import router as investigations_router
from backend.api.v1.workflows import router as workflows_router
from backend.api.v1.response_plans import router as response_plans_router
from backend.api.v1.auth import router as auth_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(auth_router, tags=["Authentication & Access Control"])
api_v1_router.include_router(databases_router, tags=["Databases"])
api_v1_router.include_router(backups_router, tags=["Backups"])
api_v1_router.include_router(storage_router, tags=["Storage"])
api_v1_router.include_router(security_router, tags=["Security Monitoring"])
api_v1_router.include_router(forensics_router, tags=["Database Forensics"])
api_v1_router.include_router(recovery_router, tags=["Cyber Recovery"])
api_v1_router.include_router(restore_router, tags=["Recovery Validation Jobs"])
api_v1_router.include_router(investigations_router, tags=["Cyber Investigation & Response"])
api_v1_router.include_router(workflows_router, tags=["Investigation Workflows & Tasks"])
api_v1_router.include_router(response_plans_router, tags=["Incident Response Plans & Collaboration"])

__all__ = [
    "api_v1_router",
    "databases_router",
    "backups_router",
    "storage_router",
    "security_router",
    "forensics_router",
    "recovery_router",
    "restore_router",
    "investigations_router",
    "workflows_router",
    "response_plans_router",
    "auth_router",
]
