# SQL-TRUST — Local Demo & RBAC Evaluation Guide

**SQL Server Cyber Recovery & Forensic Intelligence Platform**  
*Protect · Detect · Investigate · Recover*

---

## 1. Executive Overview

SQL-TRUST provides enterprise-grade, cryptographically verifiable SQL Server cyber recovery, immutable backups, forensic baselining, and automated incident response investigation orchestration.

To facilitate local testing, evaluation, stakeholder demonstrations, and security audits without exposing production credentials, SQL-TRUST includes pre-configured local demo accounts representing distinct operational personas.

---

## 2. Pre-Configured Demo Accounts & Credentials

Each demo account is pre-provisioned with salted and stretched passwords (PBKDF2-HMAC-SHA256, 100,000 iterations) and assigned a role within the Role-Based Access Control (RBAC) matrix:

| Username | Role | Password | Primary Responsibilities |
| :--- | :--- | :--- | :--- |
| `demo_admin` | **Admin** | `SQLTrustDemo!Admin2026` | Full platform administration, storage configuration, recovery execution, and policy management |
| `demo_investigator` | **Investigator** | `SQLTrustDemo!Investigator2026` | Incident intake, evidence correlation, timeline reconstruction, and playbook execution |
| `demo_analyst` | **Analyst** | `SQLTrustDemo!Analyst2026` | Forensic baseline analysis, telemetry log inspection, anomaly triage, and evidence notes |
| `demo_reviewer` | **Reviewer** | `SQLTrustDemo!Reviewer2026` | Reviewing recovery points, approving clean-room restore plans, peer review of forensic dossiers |
| `demo_auditor` | **Auditor** | `SQLTrustDemo!Auditor2026` | Read-only access to immutable audit trails, WORM backup receipts, chain-of-custody, and compliance reports |

> [!NOTE]
> All demo accounts have `is_demo_account = true` and `is_active = true` in the `SQLTrust_Control.dbo.users` table. They are automatically provisioned idempotently upon startup or via `AuthService.seed_demo_accounts()`.

---

## 3. RBAC Permission Matrix

The platform enforces strict role boundaries across all 6 modules:

| Permission Category | Admin | Investigator | Analyst | Reviewer | Auditor |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Module 1 — Backup Management** |
| View Backups & Manifests | ✅ | ✅ | ✅ | ✅ | ✅ |
| Trigger Backup Jobs | ✅ | ❌ | ❌ | ❌ | ❌ |
| Verify Backup Hashes / WORM | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Module 2 — Security Monitoring** |
| View Security Events & Alerts | ✅ | ✅ | ✅ | ✅ | ✅ |
| Manage Detection Policies & Gaps | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Module 3 — Forensics Engine** |
| View Baselines & Drift Reports | ✅ | ✅ | ✅ | ✅ | ✅ |
| Capture New Forensics Baseline | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Module 4 — Cyber Recovery** |
| Inspect Recovery Points & Trust Scores | ✅ | ✅ | ✅ | ✅ | ✅ |
| Trigger Recovery Point Assessments | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Module 5 — Sandboxed Restore** |
| View Recovery Validation Jobs | ✅ | ✅ | ✅ | ✅ | ✅ |
| Launch Sandbox / Dry-Run Restore | ✅ | ❌ | ❌ | ✅ | ❌ |
| Approve Production Recovery Run | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Module 6 — Cyber Investigation** |
| View Incident Cases & Timelines | ✅ | ✅ | ✅ | ✅ | ✅ |
| Create Cases & Intake Alerts | ✅ | ✅ | ❌ | ❌ | ❌ |
| Execute Playbook Tasks & Workflows | ✅ | ✅ | ✅ | ❌ | ❌ |
| Approve / Sign-Off Response Dossier | ✅ | ✅ | ❌ | ✅ | ❌ |
| **Audit Trails & Evidence Integrity** |
| View Cryptographic Audit Logs | ✅ | ✅ | ✅ | ✅ | ✅ |
| Export Compliance & Chain-of-Custody | ✅ | ✅ | ❌ | ✅ | ✅ |

---

## 4. How to Authenticate

### A. Web User Interface (Frontend)
1. Open the SQL-TRUST UI in your browser at `http://localhost:5173`.
2. In the top navigation bar, you can either:
   - Click **Sign In** and enter any demo credentials from the table above.
   - Or use the **Quick Demo Persona Switcher** dropdown to instantly simulate the application as any of the 5 roles.
3. The UI will reflect the permissions of the selected role:
   - Action buttons (e.g., "Trigger Restore", "Create Case", "Capture Baseline") are conditionally enabled or disabled according to the user's role.

### B. REST API Authentication (`/api/v1/auth/login`)
You can obtain a signed JWT/HMAC token by sending a JSON payload to the auth endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"demo_admin\", \"password\": \"SQLTrustDemo!Admin2026\"}"
```

**Response Example:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1Ni...",
  "token_type": "bearer",
  "expires_in_minutes": 480,
  "user": {
    "id": 1,
    "username": "demo_admin",
    "full_name": "Demo System Administrator",
    "role": "Admin",
    "is_active": true,
    "is_demo_account": true,
    "last_login_at": "2026-11-15T10:24:00Z"
  }
}
```

### C. Using the Bearer Token or Role Header in API Calls
All protected API v1 routes accept either:
1. `Authorization: Bearer <access_token>` header
2. `X-User-Role: <Role>` header (e.g. `X-User-Role: Admin`) for automated integration tests and command-line scripts.

Example request:
```bash
curl -X GET http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer <access_token>"
```

---

## 5. Idempotent Demo Account Reset

If demo accounts are modified or deleted during testing, you can reset or restore them at any time using:

### Via REST API:
```bash
curl -X POST http://localhost:8000/api/v1/auth/seed-demo-accounts
```

### Via CLI Command:
```powershell
.\.venv\Scripts\python.exe -c "from backend.database import SessionLocal; from backend.services.auth_service import AuthService; db=SessionLocal(); print(AuthService.seed_demo_accounts(db)); db.close()"
```

---

## 6. Demo Data Verification

To populate realistic, cross-module interconnected synthetic data for live demonstrations (including mock ERP databases, attack timelines, forensic baselines, ransomware alerts, recovery candidates, and investigation dossiers), execute:

```powershell
.\.venv\Scripts\python.exe backend/scripts/seed_demo_data.py
```

This guarantees an end-to-end demonstration environment ready for immediate evaluation.
