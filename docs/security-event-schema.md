# SQL-TRUST — Normalized Security Event Schema & Deduplication Specification

**Date & Time:** 2026-11-14T11:57:30+05:30  
**Schema Model:** `SecurityEvent` (`backend/models/security.py`)  
**Database Table:** `dbo.security_events` in `SQLTrust_Control`  
**Deduplication Standard:** Deterministic SHA-256 Fingerprint  

---

## 1. Normalized Event Data Fields

Disparate records from SQL Server Audit (`.sqlaudit`) and Extended Events (`.xel`) are parsed into a single, standardized event model:

| Field Name | Data Type | Nullable | Index | Description |
| :--- | :--- | :---: | :---: | :--- |
| `id` | `VARCHAR(36)` | No | PK | Unique UUID identifier for the event. |
| `source_id` | `VARCHAR(36)` | No | Yes | Foreign Key referencing `security_sources.id`. |
| `event_source` | `VARCHAR(32)` | No | No | Originating telemetry feed: `SQL_AUDIT` or `EXTENDED_EVENTS`. |
| `source_file` | `VARCHAR(512)` | No | No | Source file path (`.sqlaudit` or `.xel`). |
| `source_event_id` | `VARCHAR(128)` | Yes | No | File offset and sequence number identifier. |
| `event_type` | `VARCHAR(64)` | No | Yes | Normalized event class (e.g. `LOGIN_FAILED`, `SYSADMIN_MEMBERSHIP_CHANGE`, `SCHEMA_OBJECT_DROPPED`). |
| `event_timestamp` | `DATETIME` | No | Yes | Original event generation timestamp normalized to UTC. |
| `collection_timestamp` | `DATETIME` | No | No | Collector ingestion timestamp in UTC. |
| `server_name` | `VARCHAR(255)` | No | No | Monitored SQL Server instance hostname. |
| `database_name` | `VARCHAR(128)` | Yes | Yes | Target database context. |
| `principal_name` | `VARCHAR(128)` | Yes | Yes | Executing SQL or Windows login/user principal. |
| `session_id` | `INTEGER` | Yes | No | SQL Server SPID (`@@SPID`). |
| `client_ip` | `VARCHAR(64)` | Yes | No | Client IP address or hostname. |
| `client_app` | `VARCHAR(255)` | Yes | No | Client application name (e.g. `sqlcmd`, `.Net SqlClient Data Provider`). |
| `action` | `VARCHAR(64)` | No | No | Raw action code (e.g. `LGFL`, `LGSU`, `CR`, `AL`, `DR`, `G`, `R`, `D`). |
| `target_object` | `VARCHAR(255)` | Yes | No | Target object or principal acted upon. |
| `success` | `BOOLEAN` | No | No | Operation success (`True`) or failure (`False`). |
| `severity` | `VARCHAR(16)` | No | Yes | Severity tier: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `event_fingerprint` | `VARCHAR(64)` | No | **Unique** | Deterministic SHA-256 fingerprint for deduplication. |
| `raw_payload` | `TEXT` | No | No | Full unedited JSON representation of source row/XML. |
| `evidence_reference` | `VARCHAR(512)` | Yes | No | Storage key or manifest ID of archived evidence file. |
| `integrity_status` | `VARCHAR(32)` | No | No | Verification state (`VERIFIED`, `UNVERIFIED`, `TAMPERED`). |
| `created_at` | `DATETIME` | No | No | Record creation timestamp in UTC. |

---

## 2. Deterministic Cryptographic Fingerprint

To achieve idempotent ingestion across collector restarts, file rollover, and overlapping queries, each event is assigned a deterministic SHA-256 fingerprint:

$$\text{Fingerprint} = \text{SHA256}(\text{Server} \parallel \text{Source} \parallel \text{File} \parallel \text{UTC Timestamp} \parallel \text{Action} \parallel \text{Principal} \parallel \text{SessionID} \parallel \text{Statement} \parallel \text{Offset})$$

```python
raw_key = (
    f"{server_name}|{event_source}|{source_file}|"
    f"{ts_str}|{action}|{principal_name}|"
    f"{session_id}|{statement.strip()}|{source_event_id}"
)
fingerprint = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
```

### Deduplication Guarantees:
1. **In-Memory Tracking:** Each collector cycle maintains a local set `seen_fingerprints = set()` to prevent primary key collisions within high-volume batches.
2. **Database Unique Index:** The `dbo.security_events` table enforces a unique index on `event_fingerprint`, strictly prohibiting duplicate rows.
3. **Verified Zero Duplicates:** Empirical testing confirms 0 duplicate rows across repetitive collection cycles.
