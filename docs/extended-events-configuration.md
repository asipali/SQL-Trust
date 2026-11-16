# SQL-TRUST — Extended Events (XE) Configuration & Forensic Guide

**Date & Time:** 2026-11-14T11:56:30+05:30  
**Target:** Microsoft SQL Server 2022 Express Edition  
**Session Name:** `SQLTrust_Security_XE`  
**Target File:** `D:\Desktop\HackShift\SQL Trust\data\extended_events\SQLTrust_XE.xel`  
**Startup Policy:** `STARTUP_STATE = ON` (Automatically restarts with SQL Server service)  

---

## 1. Session Architecture & Captured Events

Extended Events provides low-overhead, high-performance event tracing directly from the SQL Server database engine. To avoid statement chatter and high disk I/O, events are strictly filtered to security-relevant actions:

| Event Name | Configured Actions | Event Filters & Predicates | Security Objective |
| :--- | :--- | :--- | :--- |
| **`sqlserver.login`** | `client_app_name`, `client_hostname`, `database_name`, `session_id`, `username` | Unfiltered baseline login trace | Correlates connection origins and active administrative sessions. |
| **`sqlserver.logout`** | `client_app_name`, `client_hostname`, `database_name`, `session_id`, `username` | Unfiltered baseline logout trace | Identifies session duration and unusual disconnection patterns. |
| **`sqlserver.error_reported`** | `client_app_name`, `client_hostname`, `database_name`, `session_id`, `sql_text`, `username` | `WHERE error_number = 18456 OR severity >= 14` | Captures authentication failures (18456) and critical system errors with executing SQL text. |
| **`sqlserver.object_created`** | `client_app_name`, `client_hostname`, `database_name`, `session_id`, `sql_text`, `username` | Schema creation | Tracks creation of tables, procedures, views, and backdoor objects. |
| **`sqlserver.object_altered`** | `client_app_name`, `client_hostname`, `database_name`, `session_id`, `sql_text`, `username` | Schema alteration | Tracks structural tampering with executing SQL command text. |
| **`sqlserver.object_deleted`** | `client_app_name`, `client_hostname`, `database_name`, `session_id`, `sql_text`, `username` | Schema destruction | Detects destructive DROP statements and ransomware sabotage. |

---

## 2. Event File Target & Buffer Specifications

- **Target File:** `D:\Desktop\HackShift\SQL Trust\data\extended_events\SQLTrust_XE.xel`
- **Max File Size:** `25 MB` per file.
- **Max Rollover Files:** `10 files` (Hard disk capacity bounded to a maximum of 250 MB).
- **Buffer Memory:** `4096 KB` (In-memory ring buffer).
- **Event Retention Mode:** `ALLOW_SINGLE_EVENT_LOSS` (Prevents thread blocks during peak load).
- **Max Dispatch Latency:** `5 SECONDS` (Fast flush to disk for near-real-time alerting).
- **Causality Tracking:** `TRACK_CAUSALITY = ON` (Correlates causal event sequences across threads).

---

## 3. Dedicated Management Scripts

1. **Setup Script:** [scripts/setup_extended_events.sql](file:///D:/Desktop/HackShift/SQL%20Trust/scripts/setup_extended_events.sql)
   - Creates `SQLTrust_Security_XE` and starts the event session.
2. **Verification Script:** [scripts/verify_extended_events.sql](file:///D:/Desktop/HackShift/SQL%20Trust/scripts/verify_extended_events.sql)
   - Inspects `sys.server_event_sessions`, `sys.dm_xe_sessions`, and session targets.
3. **Disable Script:** [scripts/disable_sqltrust_extended_events.sql](file:///D:/Desktop/HackShift/SQL%20Trust/scripts/disable_sqltrust_extended_events.sql)
   - Safety-gated: requires `@CONFIRM_DISABLE = 'YES'` to stop or drop the session.
