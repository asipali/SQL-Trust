"""
SQL-TRUST FastAPI Application Entry Point
Cyber Recovery and Forensic Intelligence Platform
Module 1: Backup Manager
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.database import test_sql_connection, init_db
from backend.api.v1 import api_v1_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context: initialize database tables on startup."""
    init_db()
    yield


app = FastAPI(
    title="SQL-TRUST API",
    description="Cyber Recovery and Forensic Intelligence Platform — Module 1: Backup Manager",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Enable CORS for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Module 1 API routes
app.include_router(api_v1_router)


@app.get("/")
def root():
    return {
        "service": "SQL-TRUST Cyber Recovery Platform",
        "version": "0.1.0",
        "status": "operational",
        "module": "Module 1: Backup Manager",
        "docs": "/docs",
        "api_v1": "/api/v1"
    }


@app.get("/health")
def health_check():
    """Basic health check endpoint returning application availability status."""
    return {
        "status": "ok",
        "service": "SQL-TRUST Cyber Recovery Platform",
        "environment": settings.ENVIRONMENT,
        "version": "0.1.0"
    }


@app.get("/health/sql")
def sql_health_check():
    """Executes a non-destructive query (SELECT @@VERSION) to verify SQL Server connectivity."""
    return test_sql_connection()
