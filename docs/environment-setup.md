# SQL-TRUST — Development Environment Setup Guide

This guide details how the development environment for **SQL-TRUST** (Cyber Recovery & Forensic Intelligence Platform) is installed, configured, and operated on Windows 11.

---

## 1. Prerequisites Summary

| Component | Minimum Version | Installed & Verified Version |
| :--- | :--- | :--- |
| **Operating System** | Windows 10/11 64-bit | Windows 11 Home 64-bit (Build 26300) |
| **Python** | 3.12+ | Python 3.12.10 (User scope side-by-side) |
| **Node.js** | 18+ LTS | Node.js 22.20.0 LTS |
| **npm** | 9+ | npm 10.9.3 |
| **Git** | 2.40+ | Git 2.52.0.windows.1 |
| **Target Database** | SQL Server 2022 | SQL Server 2022 Express (`MSSQL$SQLEXPRESS` v16.0.1220.3) |
| **ODBC Drivers** | ODBC Driver 17 / 18 | Microsoft ODBC Driver 18 (v18.7.1.1) & 17 (v17.11.1.1) |
| **Container Engine** | Docker Desktop 24+ | Docker Desktop 28.5.1 / Compose v2.40.3 |
| **Object Storage** | S3-compatible | SeaweedFS (Docker Compose starter configuration) |

---

## 2. Directory Structure

```text
D:\Desktop\HackShift\SQL Trust\
├── .venv/                   # Python 3.12 isolated virtual environment
├── backend/                 # FastAPI application
│   ├── __init__.py
│   ├── config.py            # Pydantic v2 application configuration
│   ├── database.py          # SQLAlchemy + pyodbc connection provider
│   └── main.py              # FastAPI application & /health endpoints
├── deployment/              # Docker & infrastructure configs
│   ├── docker-compose.yml   # SeaweedFS S3-compatible local stack
│   └── seaweedfs-s3.json    # SeaweedFS S3 authentication config
├── docs/                    # Environment reports & documentation
│   ├── environment-audit.md
│   ├── environment-setup.md
│   └── milestone-0-completion.md
├── frontend/                # React + TypeScript + Vite + Tailwind CSS
│   ├── src/
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css
│   ├── package.json
│   ├── tsconfig.json
│   ├── tailwind.config.js
│   └── vite.config.ts
├── scripts/                 # Utility scripts
│   └── check_environment.py # 10-point automated environment validation
├── tests/                   # Pytest automated test suite
│   ├── __init__.py
│   └── test_health.py       # API and SQL Server connectivity tests
├── .env.example             # Safe template for environment variables
├── .gitignore               # Multi-layer git exclusion configuration
├── README.md                # Project architecture & getting started
└── requirements.txt         # Pinned backend dependencies
```

---

## 3. Python Virtual Environment Setup

The project uses an isolated Python 3.12 virtual environment to avoid interfering with any global or side-by-side Python installations.

### Activate the Environment
```powershell
# From project root:
.\.venv\Scripts\Activate.ps1
```

### Install / Update Dependencies
```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

---

## 4. Microsoft SQL Server 2022 Connectivity

### Local Instance Details
- **Instance Name:** `localhost\SQLEXPRESS` or `.\SQLEXPRESS`
- **TCP Dynamic Port:** Dynamic (default active: 1764)
- **ODBC Driver:** `ODBC Driver 18 for SQL Server` (with automatic fallback to `ODBC Driver 17 for SQL Server`)
- **Authentication:** Windows Authentication (Trusted Connection)

### Connection Security
When using ODBC Driver 18, SQL Server defaults to requiring SSL/TLS encryption. For local development where SQL Server uses self-signed certificates, the connection string automatically specifies `TrustServerCertificate=yes`.

### Testing Local SQL Server Connectivity
```powershell
.\.venv\Scripts\python.exe -c "from backend.database import test_sql_connection; print(test_sql_connection())"
```

---

## 5. SeaweedFS Object Storage (Docker)

A dedicated, isolated SeaweedFS stack is configured in `deployment/docker-compose.yml`:
- Master port: `127.0.0.1:9333`
- Volume port: `127.0.0.1:8888`
- S3 endpoint: `127.0.0.1:8333`
- Bound strictly to `127.0.0.1` (never exposed to public networks)
- Uses isolated volume `seaweedfs_data`

### To launch SeaweedFS (after Docker Desktop is started):
```powershell
cd deployment
docker compose up -d
```

### To check SeaweedFS status:
```powershell
docker compose ps
```

---

## 6. Running the Backend (FastAPI)

```powershell
# Run Uvicorn development server
.\.venv\Scripts\uvicorn.exe backend.main:app --host 127.0.0.1 --port 8000 --reload
```

- **Health Endpoint:** `http://127.0.0.1:8000/health`
- **SQL Diagnostic Endpoint:** `http://127.0.0.1:8000/health/sql`
- **Swagger Documentation:** `http://127.0.0.1:8000/docs`

---

## 7. Running the Frontend (React + Vite)

```powershell
cd frontend
npm run dev
```

The frontend will be available at:
- **Local URL:** `http://localhost:5173`

---

## 8. Automated Testing & Validation

### Run Environment Validation Script
```powershell
.\.venv\Scripts\python.exe scripts\check_environment.py
```

### Run Pytest Test Suite
```powershell
.\.venv\Scripts\pytest.exe -v
```

