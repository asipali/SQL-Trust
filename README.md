# SQL-TRUST — Cyber Recovery & Forensic Intelligence Platform 

**Tagline:** Protect · Detect · Investigate · Recover  
SQL-TRUST is an enterprise-grade SQL Server Cyber Recovery and Forensic Intelligence Platform engineered for enterprise resilience, immutable backup storage, continuous security monitoring, post-incident database forensics, isolated sandbox restoration, and collaborative incident response orchestration.

---

## 1. Tech Stack

- **Operating System:** Windows 11 / Windows Server / Linux (Docker)
- **Backend:** Python 3.12, FastAPI, SQLAlchemy 2.0, pyodbc, Pydantic v2
- **Database Engine:** Microsoft SQL Server (2019 / 2022 / Express Edition)
- **Object Storage:** SeaweedFS (S3-compatible, persistent local volumes, Object Lock WORM compliance)
- **Database Drivers:** Microsoft ODBC Driver 18 & 17 for SQL Server
- **Cryptography:** RSA-4096 / Ed25519 (pyca/cryptography) asymmetric signing, streaming SHA-256 chunked hashing
- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Lucide React, Axios
- **Containerization:** Docker Desktop & Docker Compose (ephemeral air-gapped sandboxes)
- **Testing:** Pytest (175 automated unit and integration tests across 28 test suites)

---

## 2. Core Modules

### Module 1: Backup Manager
- **Database Discovery & Registration:** Discovers databases via `sys.databases`; isolates and guards system databases (`master`, `model`, `msdb`, `tempdb`).
- **Backup Types:** FULL, DIFFERENTIAL, and TRANSACTION LOG backups.
- **Recovery Model Enforcement:** Checks recovery models; enforces FULL/BULK_LOGGED requirements for transaction log backups.
- **Two-Stage Verification:** Runs `RESTORE VERIFYONLY WITH CHECKSUM` followed by chunked 1 MB SHA-256 integrity validation.
- **SeaweedFS S3 Storage:** Stores backup payloads and canonical manifests in persistent object storage with WORM compliance.
- **Immutable JSON Manifests:** Generates signed manifests with complete LSN chains (`FirstLSN`, `LastLSN`, `CheckpointLSN`, `DatabaseBackupLSN`).

### Module 2: Security Monitoring Engine
- **Dual Telemetry Ingestion:** Reads SQL Server Audit (`.sqlaudit`) and Extended Events (`.xel`) continuously.
- **Deterministic Event Deduplication:** SHA-256 fingerprinting guarantees zero duplicate events across file rollovers.
- **Built-in Threat Detection Rules:** Mapped to MITRE ATT&CK techniques:
  - `RULE-001`: Failed Login Spikes (Brute-Force Detection)
  - `RULE-002`: New Privileged Principal / Login Created
  - `RULE-003`: Server Role Membership Escalation (`sysadmin`, `securityadmin`)
  - `RULE-004`: Database Role Escalation (`db_owner`, `db_securityadmin`)
  - `RULE-005`: High-Impact Permission Changes (`CONTROL SERVER`, `ALTER ANY LOGIN`)
  - `RULE-006`: Principal Deletion / Account Destruction
  - `RULE-007`: Suspicious Schema & DDL Mutations (`DROP`, `TRUNCATE`)
  - `RULE-008`: Audit Tampering / Disablement Attempts
  - `RULE-009`: Extended Events Session Interruption
  - `RULE-010`: Collection Health Gap / Telemetry Heartbeat Loss
- **Alert Triage & Lifecycle:** Alert state management (`NEW`, `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE`).
- **Cryptographic Evidence Archival:** Bundles audit evidence into canonical JSON with digital signatures.

### Module 3: Database Forensics Engine
- **Granular Baseline Capture:** Read-only extraction of tables, views, stored procedures, functions, triggers, columns, data types, database principals, role memberships, granular permissions, and database configuration options into deterministic catalog baselines.
- **Comparative Forensics:**
  - **Schema Diff Engine:** Detects `OBJECT_CREATED`, `OBJECT_DROPPED`, `OBJECT_MODIFIED` with column-level transition analysis.
  - **Unobservable Object Detection:** Automatically detects objects created `WITH ENCRYPTION` and flags them as unobservable security risks.
  - **Principal & Privilege Analyzer:** Detects `USER_ADDED`, `USER_REMOVED`, and flags `ROLE_ESCALATION` (`db_owner`, `db_securityadmin`) as CRITICAL.
  - **Configuration Drift Analyzer:** Audits changes in `AUTO_CLOSE`, `TRUSTWORTHY`, `PAGE_VERIFY`, and `RECOVERY_MODEL`.
- **Temporal Timeline Correlation:** Correlates state findings with Module 2 security events across a temporal window to generate a unified incident timeline.
- **Cryptographic Evidence Preservation:** Digital signatures and SeaweedFS S3 Object Lock (`COMPLIANCE` mode, 30 days retention).

### Module 4: Cyber Recovery & State Reconstruction
- **Automated Recovery Point Discovery:** Discovers and catalogues candidate recovery points across Full, Differential, and Transaction Log backups with complete LSN metadata.
- **Backup Chain Continuity Analyzer:** Mathematically models and validates LSN continuity across `Full -> [Differential] -> Log` sequences. Detects broken chains, missing intermediate logs, and fork mismatches.
- **Explainable Cyber Trust Assessment Engine:** Evaluates recovery points against multi-source security intelligence (Module 2 telemetry + Module 3 forensics). Produces a four-tier classification (`HIGH_CONFIDENCE`, `MEDIUM_CONFIDENCE`, `LOW_CONFIDENCE`, `UNASSESSED`) with comprehensive confidence rationale.
- **Epistemological Guardrails (Telemetry Blindness):** Enforces that absence of evidence is not evidence of safety. Telemetry heartbeat drops or unobservable encrypted objects immediately suppress numeric scoring and force classification to `UNASSESSED`.
- **Technical Restore Eligibility Engine:** Decouples physical restore readiness from cyber trust confidence via strict 5-rule technical eligibility gates.
- **Multi-Factor Ranked Recommendation Engine:** Balances cyber trust confidence (65%) and data freshness / RPO (35%) while penalizing ineligibility and forensic risk.

### Module 5: Restore & Cyber Recovery Validation
- **17-State Finite State Machine:** Managed by `RecoveryJobService` ensuring fully deterministic, restart-safe recovery execution.
- **Secure Backup Staging:** Pulls backups from SeaweedFS S3 into isolated staging, enforcing path containment and streaming SHA-256 verification against the initial manifest.
- **Air-Gapped Docker Sandboxes:** Spawns ephemeral, network-isolated Docker SQL Server instances (`NetworkMode: none`) to guarantee zero malware spread or host contamination.
- **Automated Restore Sequence:** Constructs and executes full restore chains (`WITH NORECOVERY` up to point-in-time recovery).
- **Physical & Logical Validation:** Executes automated `DBCC CHECKDB` physical and logical consistency checks.
- **Post-Restore Forensics:** Compares restored sandbox state against known clean baselines to verify data integrity and absence of backdoors.
- **Signed Recovery Certificates:** Generates tamper-evident cryptographic recovery reports signed with RSA-4096 / Ed25519.

### Module 6: Cyber Investigation & Incident Response Orchestration
- **Investigation Case Lifecycle:** Centralized incident management (New, Triage, Scoping, Containment, Eradication, Recovery Validation, Closure, Archived).
- **Automated Incident Intake:** Ingests alerts from Module 2, drift from Module 3, and anomalies from Module 4, mapping to MITRE ATT&CK techniques with configurable triage rules.
- **Chronological Timeline Correlation:** Synthesizes security alerts, forensic drift, database audit records, and analyst notes into a single cohesive chronological timeline.
- **Workflow & Response Playbooks:** State machine phase gates, task checklists (containment, eradication, recovery), and role-based assignments.
- **Analyst Collaboration:** Append-only case audit trails, analyst notes, and evidence linking.
- **Canonical Dossier Reporting:** Generates dual-format reports (machine-readable JSON + Canonical 8-Section Markdown) signed cryptographically and archived to SeaweedFS S3 WORM.

---

## 3. Quick Start

### 1. Start Infrastructure (SeaweedFS Object Storage)
```powershell
docker compose -f deployment/docker-compose.yml up -d
```

### 2. Backend (FastAPI)
```powershell
# Activate Python 3.12 virtual environment
.\.venv\Scripts\Activate.ps1

# Initialize Control Database Schema
python -c "from backend.database import init_db; init_db(); print('SQLTrust_Control initialized.')"

# Launch FastAPI development server
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Base: `http://127.0.0.1:8000`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`

### 3. Frontend (React + Vite)
```powershell
cd frontend
npm install
npm run dev
```
- Web Application: `http://localhost:5173`

### 4. Run Test Suite (175 Automated Pytest Tests)
```powershell
# From repository root
.\.venv\Scripts\pytest.exe -v
```

---

## 4. Master Technical Documentation & Audits

- **[SQLTRUST_COMPLETE_APPLICATION_AUDIT.md](SQLTRUST_COMPLETE_APPLICATION_AUDIT.md)** — **Consolidated Master Application Audit & Architectural Reference (Modules 1–6)**
- **[SQLTRUST_DOCUMENTATION_CLEANUP_INVENTORY.md](SQLTRUST_DOCUMENTATION_CLEANUP_INVENTORY.md)** — **Documentation Classification, Justification & Disposition Inventory**
- **[SQLTRUST_POST_CLEANUP_VERIFICATION.md](SQLTRUST_POST_CLEANUP_VERIFICATION.md)** — **Post-Cleanup Verification & Integrity Record**
- [docs/api-documentation.md](docs/api-documentation.md) — Complete REST API reference specification
- [docs/environment-setup.md](docs/environment-setup.md) — Local and production environment setup & deployment manual
- [docs/backup-workflow.md](docs/backup-workflow.md) — Step-by-step backup & verification lifecycle
- [docs/storage-integration.md](docs/storage-integration.md) — SeaweedFS S3 integration & Object Lock WORM setup
- [docs/evidence-preservation.md](docs/evidence-preservation.md) — Cryptographic evidence standards & signing procedures
- [docs/audit-configuration.md](docs/audit-configuration.md) — SQL Server Audit configuration guide
- [docs/extended-events-configuration.md](docs/extended-events-configuration.md) — Extended Events telemetry configuration
- [docs/security-event-schema.md](docs/security-event-schema.md) — Unified normalized security event schema
- [docs/monitoring-rules.md](docs/monitoring-rules.md) — Threat detection rules catalog & MITRE ATT&CK mapping
- [docs/seaweedfs-backup-migration.md](docs/seaweedfs-backup-migration.md) — SeaweedFS backup migration guide
- [docs/seaweedfs-object-lock-setup.md](docs/seaweedfs-object-lock-setup.md) — S3 Object Lock compliance setup guide
