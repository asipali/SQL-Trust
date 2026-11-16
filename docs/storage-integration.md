# SQL-TRUST — Storage Integration & Immutability Architecture

This guide details the object storage architecture of SQL-TRUST, leveraging SeaweedFS and Boto3.

---

## 1. Storage Architecture

SeaweedFS provides high-throughput, self-hosted, S3-compatible object storage for SQL-TRUST backup artifacts.

- **Endpoint:** `http://127.0.0.1:8333` (Bound strictly to local loopback)
- **Master Service:** Port `9333`
- **Volume Service:** Port `8888`
- **Target Bucket:** `sqltrust-backups`
- **Storage Directory Structure:**
  ```text
  sqltrust-backups/
  └── backups/
      └── {database_name}/
          ├── FULL/
          │   ├── {filename}.bak
          │   └── {filename}.bak.manifest.json
          ├── DIFFERENTIAL/
          │   ├── {filename}.bak
          │   └── {filename}.bak.manifest.json
          └── LOG/
              ├── {filename}.trn
              └── {filename}.trn.manifest.json
  ```

---

## 2. Shared Windows / Docker Directory Strategy

Because SQL Server runs natively as a Windows Service (`NT Service\MSSQL$SQLEXPRESS`) while backend services or future workers may execute inside Docker containers:

- **Windows Staging Directory:** `D:\Desktop\HackShift\SQL Trust\data\backups`
- **Docker Mount Target:** `/app/data/backups`
- **Configuration Keys:**
  - `SQL_BACKUP_DIR`: File path provided in T-SQL `BACKUP ... TO DISK` statements.
  - `BACKUP_LOCAL_DIR`: File path used by Python `hashlib` and Boto3 upload routines.
  - In native Windows execution, both point to the same directory (`data/backups/`).
  - In Dockerized backend execution, the Windows directory is mounted as a volume into the container at `/app/data/backups`.

---

## 3. Immutability & Security Audit Posture

SQL-TRUST implements an explicit security audit probe in `SeaweedFSStorageProvider.inspect_security()`:

- **Bucket Versioning:** Tested via `s3.get_bucket_versioning()`.
- **Object Lock (WORM):** Tested via `s3.get_object_lock_configuration()`.
- **Compliance Policy:**
  - SQL-TRUST **never silently assumes** or claims that an S3 bucket is immutable merely because the API responds.
  - If Object Lock is absent, SQL-TRUST explicitly flags:
    `"Object Lock is not configured on this bucket. S3 API is active, but true WORM immutability is not engaged."`
  - This transparent reporting prevents false security claims in enterprise cyber-recovery audits.
