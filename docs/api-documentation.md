# SQL-TRUST — API Documentation (Module 1: Backup Manager)

All endpoints are hosted at `http://127.0.0.1:8000/api/v1` and documented interactively via OpenAPI Swagger at `http://127.0.0.1:8000/docs`.

---

## 1. Database Management Endpoints

### Discover Databases
- **Endpoint:** `GET /api/v1/databases`
- **Description:** Scans the SQL Server system catalog (`sys.databases`). Flags system databases and indicates current registration status.
- **Response `200 OK`:**
  ```json
  [
    {
      "database_id": 1,
      "name": "master",
      "state": "ONLINE",
      "recovery_model": "SIMPLE",
      "is_system": true,
      "is_registered": false
    },
    {
      "database_id": 6,
      "name": "SQLTrust_TestDB",
      "state": "ONLINE",
      "recovery_model": "FULL",
      "is_system": false,
      "is_registered": true,
      "registration_id": "4ddf67af-bfe9-41dd-a813-e87633eda5b6"
    }
  ]
  ```

### Register Database
- **Endpoint:** `POST /api/v1/databases/register`
- **Request Body:**
  ```json
  {
    "database_name": "SQLTrust_TestDB",
    "allow_system_override": false
  }
  ```
- **Response `200 OK`:** Returns `DatabaseRegisteredResponse`.

### List Registered Databases
- **Endpoint:** `GET /api/v1/databases/registered`
- **Description:** Returns all databases currently protected in `SQLTrust_Control`.

### Test SQL Server Connection
- **Endpoint:** `POST /api/v1/databases/test-connection`
- **Description:** Runs `SELECT @@VERSION;` to verify database engine reachability.

---

## 2. Backup Management Endpoints

### Execute FULL Backup
- **Endpoint:** `POST /api/v1/backups/full`
- **Request Body:**
  ```json
  {
    "database_id": "4ddf67af-bfe9-41dd-a813-e87633eda5b6",
    "notes": "Weekly full backup"
  }
  ```
- **Response `201 Created`:** Returns complete `BackupRecordResponse` including LSNs, SHA-256, and storage keys.

### Execute DIFFERENTIAL Backup
- **Endpoint:** `POST /api/v1/backups/differential`
- **Precondition:** Requires an existing successful FULL backup in the database chain.

### Execute TRANSACTION LOG Backup
- **Endpoint:** `POST /api/v1/backups/log`
- **Precondition:** Requires database in `FULL` or `BULK_LOGGED` recovery model and prior FULL backup.

### List Backup History
- **Endpoint:** `GET /api/v1/backups`
- **Query Parameters:** `database_id`, `backup_type`, `status`.

### Get Aggregate Backup Stats
- **Endpoint:** `GET /api/v1/backups/stats`
- **Response `200 OK`:** Total backups, success/failure counts, total bytes, and latest timestamp.

### Get Backup Manifest
- **Endpoint:** `GET /api/v1/backups/{backup_id}/manifest`
- **Description:** Fetches the canonical JSON manifest and its cryptographic SHA-256 hash.

### Re-verify Backup Integrity
- **Endpoint:** `POST /api/v1/backups/{backup_id}/verify`
- **Description:** Executes on-demand Stage 1 (`RESTORE VERIFYONLY WITH CHECKSUM`) and Stage 2 (SHA-256 recalculation).

---

## 3. Storage Endpoints

### Storage Health & Immutability Audit
- **Endpoint:** `GET /api/v1/storage/health`
- **Description:** Checks SeaweedFS connectivity, bucket existence, versioning status, and Object Lock configuration.

### List Stored Backup Artifacts
- **Endpoint:** `GET /api/v1/storage/backups`
- **Description:** Returns live list of backup artifacts in `sqltrust-backups`.
