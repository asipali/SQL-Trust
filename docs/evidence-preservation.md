# SQL-TRUST — Forensic Evidence Preservation & WORM Archiving

**Date & Time:** 2026-11-14T11:59:00+05:30  
**Storage Engine:** SeaweedFS 4.50 S3 API (`http://127.0.0.1:8333`)  
**Target Bucket:** `sqltrust-backups-locked`  
**Storage Prefix:** `security-evidence/{server}/`  
**Immutability Standard:** S3 Object Lock, COMPLIANCE Mode (30 Days)  
**Cryptographic Standard:** Ed25519 Asymmetric Digital Signatures + SHA-256  

---

## 1. Evidence Vault Storage Topology

Forensic evidence is structured systematically within the immutable bucket:

```
sqltrust-backups-locked/
└── security-evidence/
    └── {server_name}/
        ├── audit/
        │   └── {year}/{month}/{day}/
        │       └── SQLTrust_ServerAudit_*.sqlaudit
        ├── extended-events/
        │   └── {year}/{month}/{day}/
        │       └── SQLTrust_XE_*.xel
        └── manifests/
            └── {year}/{month}/{day}/
                └── MAN-{sha256_prefix}-{timestamp}.json
```

---

## 2. Cryptographic Manifest & Ed25519 Signing

Every evidence package uploaded to SeaweedFS is certified with a deterministic JSON manifest signed with an Ed25519 private key:

### Manifest Schema:
```json
{
  "manifest_version": "1.0",
  "evidence_id": "MAN-2818d4edc71a5e5a-20261114061924",
  "server_name": "localhost\\SQLEXPRESS",
  "evidence_type": "SQL_AUDIT_FILE",
  "source_file": "SQLTrust_ServerAudit_FB547C8B-FE65-4F1C-A346-951888F90D31_0_134391103897590000.sqlaudit",
  "collection_timestamp": "2026-11-14T06:19:24.123456Z",
  "file_size_bytes": 74240,
  "sha256": "2818d4edc71a5e5a...",
  "storage_bucket": "sqltrust-backups-locked",
  "storage_object_key": "security-evidence/localhost_SQLEXPRESS/audit/2026/11/14/SQLTrust_ServerAudit_....sqlaudit",
  "storage_version_id": "67182b01c8e10aaf57ac441b969d6bfa",
  "retention_mode": "COMPLIANCE",
  "retention_until": "2026-12-14T06:19:24Z",
  "collection_status": "VERIFIED",
  "signature": "MEUCIQD...Base64-Encoded-Ed25519-Signature..."
}
```

### Verification Capabilities:
1. **Public-Key Verification:** Manifest signatures can be validated offline by anyone possessing the public key (`data/keys/sqltrust_signing_ed25519.pub`).
2. **Tamper Detection:** Modifying even a single character in the manifest JSON or SHA-256 digest causes `ManifestSigner.verify_manifest` to reject the artifact (`False`).
3. **Key Separation:** Signing keys are stored in `data/keys/` and never commingled with storage credentials or committed to version control.

---

## 3. Object Lock Enforcement Evidence

When an evidence artifact is uploaded:
1. SeaweedFS generates a distinct, immutable `VersionId`.
2. SeaweedFS binds the bucket's 30-day default `COMPLIANCE` retention rule to the object.
3. SeaweedFS rejects any `DeleteObject(VersionId=...)` call with `403 AccessDenied`.
4. Overwriting an existing key creates a new version while preserving the earlier version intact.
