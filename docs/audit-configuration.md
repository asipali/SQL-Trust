# SQL-TRUST — SQL Server Audit Configuration & Operational Guide

**Date & Time:** 2026-11-14T11:56:00+05:30  
**Target:** Microsoft SQL Server 2022 Express Edition  
**Audit Object:** `SQLTrust_ServerAudit`  
**Specification Object:** `SQLTrust_ServerAudit_Spec`  
**Target Directory:** `D:\Desktop\HackShift\SQL Trust\data\audit\`  
**Safety Policy:** `ON_FAILURE = CONTINUE`  

---

## 1. Specification & Action Groups

`SQLTrust_ServerAudit` captures 11 critical security action groups:

| Action Group Name | Category | Security Significance |
| :--- | :--- | :--- |
| **`FAILED_LOGIN_GROUP`** | Authentication | Captures brute-force attacks, credential spraying, and invalid account attempts. |
| **`SUCCESSFUL_LOGIN_GROUP`** | Authentication | Records logon patterns, principal identities, client hostnames, and apps. |
| **`SERVER_PRINCIPAL_CHANGE_GROUP`** | Principal Lifecycle | Logs `CREATE LOGIN`, `ALTER LOGIN`, and `DROP LOGIN`. |
| **`SERVER_ROLE_MEMBER_CHANGE_GROUP`** | Privilege Escalation | Logs `sysadmin` and other fixed server role modifications. |
| **`SERVER_PERMISSION_CHANGE_GROUP`** | Privilege Escalation | Logs server-level `GRANT`, `DENY`, and `REVOKE` statements. |
| **`DATABASE_ROLE_MEMBER_CHANGE_GROUP`** | Database Security | Logs assignment of high-privilege roles like `db_owner` or `db_securityadmin`. |
| **`DATABASE_PERMISSION_CHANGE_GROUP`** | Database Security | Logs database-level `GRANT`, `DENY`, and `REVOKE` statements. |
| **`SCHEMA_OBJECT_CHANGE_GROUP`** | Schema Integrity | Captures `CREATE`, `ALTER`, and `DROP` statements on schema objects. |
| **`DATABASE_OBJECT_CHANGE_GROUP`** | Schema Integrity | Logs database object creation, alteration, and destruction. |
| **`DATABASE_CHANGE_GROUP`** | Database Integrity | Logs database-level structural modifications (`CREATE/ALTER/DROP DATABASE`). |
| **`AUDIT_CHANGE_GROUP`** | Defense Evasion | Logs modifications, state toggles, and attempts to disable auditing. |

---

## 2. Storage & Rollover Configuration

- **File Path:** `D:\Desktop\HackShift\SQL Trust\data\audit\`
- **Max File Size:** `25 MB` per file.
- **Max Rollover Files:** `20 files` (Hard disk capacity bounded to a maximum of 500 MB).
- **Queue Delay:** `1000 ms` (1 second batching to eliminate server I/O degradation).
- **Failure Policy:** `ON_FAILURE = CONTINUE` (CRITICAL: prevents database freeze or shutdown if the target disk encounters temporary contention).

---

## 3. Dedicated Management Scripts

All SQL Server Audit configurations are managed deliberately via scripts in `scripts/`:

1. **Setup Script:** [scripts/setup_sql_audit.sql](file:///D:/Desktop/HackShift/SQL%20Trust/scripts/setup_sql_audit.sql)
   - Idempotently recreates `SQLTrust_ServerAudit` and `SQLTrust_ServerAudit_Spec`.
   - Enables both server audit and specification.
2. **Verification Script:** [scripts/verify_audit_configuration.sql](file:///D:/Desktop/HackShift/SQL%20Trust/scripts/verify_audit_configuration.sql)
   - Inspects `sys.server_audits`, `sys.server_file_audits`, and queries live records via `sys.fn_get_audit_file`.
3. **Disable Script:** [scripts/disable_sqltrust_audit.sql](file:///D:/Desktop/HackShift/SQL%20Trust/scripts/disable_sqltrust_audit.sql)
   - Safety-gated: requires `@CONFIRM_DISABLE = 'YES'` to prevent accidental telemetry interruption.
