# SQL-TRUST — SeaweedFS S3 Object Lock Setup & Configuration Guide

**Date & Time:** 2026-11-14T11:15:00+05:30  
**Storage Engine:** SeaweedFS (S3-compatible)  
**Target Bucket:** `sqltrust-backups-locked`  
**Security Standard:** S3 Object Lock / WORM (Write Once Read Many), COMPLIANCE Mode  
**Lead Roles:** Senior DevOps Engineer, SeaweedFS Storage Administrator, Cybersecurity Engineer  

---

## 1. Architecture Overview

SQL-TRUST uses SeaweedFS as its on-premises, self-hosted, S3-compatible object store. To protect Microsoft SQL Server backup archives against ransomware attacks, malicious administrative deletion, tampering, and premature expiration, SQL-TRUST enforces **S3 Object Lock** in **COMPLIANCE mode**.

### Object Lock Protection Mechanics

```
┌────────────────────────────────────────────────────────────────────────┐
│                   SQL Server Backup Generation (.bak)                  │
│                     SHA-256 Checksum Computed Locally                  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              S3 Upload to 'sqltrust-backups-locked' Bucket             │
│        x-amz-object-lock-mode: COMPLIANCE, RetainUntilDate: +30d       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     SeaweedFS S3 Storage Engine                        │
│  ├── Object Version Generated (Immutable VersionId)                    │
│  ├── Retention Rule Enforced (Non-deletable even by Admin)             │
│  └── Overwrite Attempts Create NEW Versions (Old Version Preserved)    │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Bucket Versioning Enabled:** All objects and updates receive unique, monotonically tracked `VersionId` strings.
2. **Default Bucket Retention:** Any uploaded backup `.bak` or manifest `.json` automatically inherits a 30-day `COMPLIANCE` retention window.
3. **Explicit Object Retention:** Backup jobs explicitly attach retention metadata, binding the retention timestamp into both SeaweedFS and SQL-TRUST SQLite/PostgreSQL operational metadata tables.
4. **Non-Bypassable Compliance:** Under `COMPLIANCE` mode, neither the backup writer nor the administrator can delete or overwrite a protected version until `RetainUntilDate` has passed.

---

## 2. Docker Compose Deployment & Storage Topology

SeaweedFS runs in Docker Desktop using the official `chrislusf/seaweedfs:latest` container image.

### `deployment/docker-compose.yml` Configuration

```yaml
version: '3.8'

services:
  seaweedfs:
    image: chrislusf/seaweedfs:latest
    container_name: sqltrust-seaweedfs
    restart: unless-stopped
    command: "server -s3 -s3.config=/etc/seaweedfs/s3.json -dir=/data"
    ports:
      - "127.0.0.1:9333:9333"   # SeaweedFS Master HTTP
      - "127.0.0.1:8888:8080"   # SeaweedFS Filer HTTP
      - "127.0.0.1:8333:8333"   # SeaweedFS S3 API Endpoint
    volumes:
      - seaweedfs_data:/data
      - ./seaweedfs-s3.json:/etc/seaweedfs/s3.json:ro
    environment:
      - WEED_S3_ENABLED=true

volumes:
  seaweedfs_data:
    name: deployment_seaweedfs_data
```

### Key Deployment Settings:
- **Loopback Binding (`127.0.0.1`):** All ports are bound strictly to `127.0.0.1`, guaranteeing that the S3 API endpoint is never exposed to public or external host network interfaces.
- **Persistent Volume (`deployment_seaweedfs_data`):** S3 object data, metadata directories, and version index stores persist across container restarts.
- **Read-Only S3 Identity Mount (`:ro`):** The S3 identity policy file `/etc/seaweedfs/s3.json` is mounted read-only into the container to prevent in-container tampering.

---

## 3. Storage Identity & IAM Privilege Separation

In accordance with least-privilege cybersecurity principles, three distinct identities are configured in `deployment/seaweedfs-s3.json`:

```json
{
  "identities": [
    {
      "name": "sqltrust-admin",
      "credentials": [
        {
          "accessKey": "${ADMIN_ACCESS_KEY}",
          "secretKey": "${ADMIN_SECRET_KEY}"
        }
      ],
      "actions": [
        "Admin",
        "Read",
        "Write",
        "List",
        "Tagging"
      ]
    },
    {
      "name": "sqltrust-backup-writer",
      "credentials": [
        {
          "accessKey": "${BACKUP_ACCESS_KEY}",
          "secretKey": "${BACKUP_SECRET_KEY}"
        }
      ],
      "actions": [
        "Read",
        "Write",
        "List"
      ]
    },
    {
      "name": "sqltrust-recovery-reader",
      "credentials": [
        {
          "accessKey": "${RECOVERY_ACCESS_KEY}",
          "secretKey": "${RECOVERY_SECRET_KEY}"
        }
      ],
      "actions": [
        "Read",
        "List"
      ]
    }
  ]
}
```

### Identity Roles:
1. **`sqltrust-admin`:** Used for provisioning buckets, configuring bucket versioning, defining Object Lock default retention rules, and setting S3 legal holds during forensic incident response.
2. **`sqltrust-backup-writer`:** Used by the SQL-TRUST Backup Manager engine to upload `.bak` archives, generate JSON manifests, and verify SHA-256 checksums. Has no permission to delete or alter administrative configurations.
3. **`sqltrust-recovery-reader`:** Used by recovery and audit jobs. Read-only permissions (`Read`, `List`). Prohibited from modifying or writing to any storage location (`403 AccessDenied` enforced by SeaweedFS).

---

## 4. Bucket Provisioning & Retention Setup

### Step 1: Create Bucket with Object Lock Enabled
Because S3 Object Lock cannot be retroactively enabled on pre-existing standard buckets, the WORM bucket must be created with `ObjectLockEnabledForBucket=True`.

Using Python Boto3:
```python
import boto3

s3 = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:8333",
    aws_access_key_id=ADMIN_KEY,
    aws_secret_access_key=ADMIN_SECRET,
    region_name="us-east-1"
)

# 1. Create Bucket with Object Lock flag
s3.create_bucket(
    Bucket="sqltrust-backups-locked",
    ObjectLockEnabledForBucket=True
)

# 2. Enable Bucket Versioning (Prerequisite for Object Lock)
s3.put_bucket_versioning(
    Bucket="sqltrust-backups-locked",
    VersioningConfiguration={"Status": "Enabled"}
)

# 3. Configure 30-Day Default COMPLIANCE Retention
s3.put_object_lock_configuration(
    Bucket="sqltrust-backups-locked",
    ObjectLockConfiguration={
        "ObjectLockEnabled": "Enabled",
        "Rule": {
            "DefaultRetention": {
                "Mode": "COMPLIANCE",
                "Days": 30
            }
        }
    }
)
```

Using AWS CLI (Equivalent):
```bash
aws --endpoint-url http://127.0.0.1:8333 s3api create-bucket \
    --bucket sqltrust-backups-locked \
    --object-lock-enabled-for-bucket

aws --endpoint-url http://127.0.0.1:8333 s3api put-bucket-versioning \
    --bucket sqltrust-backups-locked \
    --versioning-configuration Status=Enabled

aws --endpoint-url http://127.0.0.1:8333 s3api put-object-lock-configuration \
    --bucket sqltrust-backups-locked \
    --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":30}}}'
```

---

## 5. SQL-TRUST Application Integration

### Backend Configuration (`backend/config.py` & `.env`)
The application configuration reflects the WORM storage setup:
```env
SEAWEEDFS_S3_ENDPOINT=http://127.0.0.1:8333
SEAWEEDFS_S3_BUCKET_NAME=sqltrust-backups-locked
S3_OBJECT_LOCK_ENABLED=true
S3_OBJECT_LOCK_MODE=COMPLIANCE
S3_OBJECT_LOCK_RETENTION_DAYS=30
```

### Database Schema Updates (`backend/models/backup.py`)
To store immutable object versioning and retention data for every backup run:
- `storage_object_version_id`: Monotonically assigned S3 version string.
- `retention_mode`: String (`COMPLIANCE` / `GOVERNANCE`).
- `retention_until`: Exact UTC timestamp (`datetime`) until which the backup is hardware-locked.

### Backup Manifest Integration (`backend/services/storage/manifest.py`)
Every manifest file generated by the engine includes:
```json
{
  "immutability": {
    "object_lock_enabled": true,
    "retention_mode": "COMPLIANCE",
    "retention_until": "2026-12-14T05:41:06Z",
    "s3_version_id": "67182d19064731371f0d4103bfd9ac43"
  }
}
```

### UI Integration (`frontend/src/App.tsx`)
The React + TypeScript dashboard displays:
- Storage Status Banner: Displays `sqltrust-backups-locked` with green `WORM Active (COMPLIANCE)` badge.
- Backup Table: Displays lock icon and exact `Retain Until` UTC date for each backup row.
- Details Modal: Displays S3 Version ID, retention status, and immutable verification flags.

---

## 6. Verification & Health Monitoring

To verify storage health and Object Lock operational status at any time:

1. **Storage Health Endpoint:**
   `GET http://localhost:8000/api/v1/storage/health`
   Returns:
   ```json
   {
     "connected": true,
     "endpoint": "http://127.0.0.1:8333",
     "bucket": "sqltrust-backups-locked",
     "object_lock_enabled": true,
     "versioning_status": "Enabled",
     "retention_mode": "COMPLIANCE",
     "retention_days": 30
   }
   ```

2. **Automated Verification Script:**
   `python scripts/test_seaweedfs_object_lock.py`
   Runs 10 automated compliance tests verifying upload, versioning, retention enforcement, legal hold, and protected deletion rejection.
