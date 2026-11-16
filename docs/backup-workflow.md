# SQL-TRUST — Backup Workflow & Verification Lifecycle

This document describes the step-by-step lifecycle of a backup execution in SQL-TRUST Module 1.

---

## 1. End-to-End Workflow Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Administrator / API
    participant Engine as BackupEngine
    participant Catalog as DatabaseService
    participant SQL as Microsoft SQL Server 2022
    participant Staging as Local Staging (data/backups)
    participant Storage as SeaweedFS S3
    participant ControlDB as SQLTrust_Control DB

    Admin->>Engine: execute_backup(database_id, backup_type)
    Engine->>Catalog: Validate database state & recovery model
    Catalog-->>Engine: DB is ONLINE, Recovery Model confirmed
    Engine->>Engine: Acquire database thread lock (prevent concurrency)
    Engine->>Staging: Check write permissions & disk space (>50 MB)
    Engine->>ControlDB: Insert BackupRecord (status="RUNNING")

    Engine->>SQL: BACKUP DATABASE / LOG WITH FORMAT, INIT, CHECKSUM
    SQL->>Staging: Write .bak / .trn file
    SQL-->>Engine: Backup stream complete

    Engine->>SQL: RESTORE HEADERONLY FROM DISK
    SQL-->>Engine: Extract FirstLSN, LastLSN, CheckpointLSN, BackupSize
    Engine->>ControlDB: Update BackupRecord (status="VERIFYING", LSNs)

    Engine->>SQL: RESTORE VERIFYONLY FROM DISK WITH CHECKSUM
    SQL-->>Engine: Page checksums valid (PASSED)
    Engine->>Staging: Stream file in 1 MB chunks to compute SHA-256
    Engine->>ControlDB: Update BackupRecord (sha256, sql_verification="PASSED", status="UPLOADING")

    Engine->>Storage: upload_file(local_path, s3_key, metadata)
    Storage-->>Engine: HeadObject confirmation (size match verified)
    Engine->>Engine: generate_backup_manifest()
    Engine->>Storage: upload_file(manifest.json, s3_manifest_key)
    Engine->>ControlDB: Insert BackupManifest & update BackupRecord (status="COMPLETED")
    Engine-->>Admin: Return completed BackupRecord
```

---

## 2. Recovery Model Requirements & Enforcement

| Backup Type | Supported Recovery Models | Chain Preconditions | Rationale |
| :--- | :--- | :--- | :--- |
| **FULL** | `SIMPLE`, `FULL`, `BULK_LOGGED` | None | Establishes the initial baseline for all future differentials and log backups. |
| **DIFFERENTIAL** | `SIMPLE`, `FULL`, `BULK_LOGGED` | Prior completed `FULL` backup | Captures extent changes since the last full baseline. |
| **TRANSACTION LOG** | `FULL`, `BULK_LOGGED` only | Prior completed `FULL` backup | **SIMPLE model blocked:** In SIMPLE recovery, SQL Server automatically truncates inactive log extents during checkpoints. Taking log backups would disrupt recovery chains and is prohibited by the database engine. |

---

## 3. Two-Stage Integrity Verification

### Stage 1: SQL Server Backup Verification
- **Command:** `RESTORE VERIFYONLY FROM DISK = N'{path}' WITH CHECKSUM;`
- **Scope:** Verifies that the backup file is complete, readable by SQL Server, and that all page-level checksums embedded during backup are valid.
- *Caveat:* `RESTORE VERIFYONLY` confirms the physical integrity of the backup media, but does not prove the absence of application-level data corruption or malicious tampering.

### Stage 2: Cryptographic Hash Verification
- **Method:** 1 MB chunked stream using `hashlib.sha256()`.
- **Purpose:** Produces an immutable cryptographic fingerprint of the backup artifact.
- **Protection:** During on-demand re-verification, the hash is recomputed and compared against the original stored value to detect bit-rot or offline file tampering.

---

## 4. State Transitions & Failure Resilience

A backup operation transitions through strict states:

```
PENDING  ──>  RUNNING  ──>  VERIFYING  ──>  UPLOADING  ──>  COMPLETED
   │             │              │              │
   └───► FAILED ◄┴──────────────┴──────────────┘
```

- If an error occurs at any point (e.g., checksum error, S3 network timeout, disk full), the operation transitions immediately to `FAILED`.
- The exact error stack is preserved in `BackupRecord.error_message` and `BackupOperationLog`.
- Partial or corrupt files are never uploaded to remote storage.
