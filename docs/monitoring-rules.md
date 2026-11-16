# SQL-TRUST — Security Detection Rules Specification

**Date & Time:** 2026-11-14T11:58:30+05:30  
**Detection Engine:** `RuleEngine` (`backend/services/security/rule_engine.py`)  
**Target Architecture:** Microsoft SQL Server 2022  
**Alert Deduplication:** Active window aggregation with confidence scoring  

---

## 1. Detection Rule Catalog

The rule engine evaluates normalized event streams against 10 explainable rules:

### RULE 1 — MULTIPLE FAILED LOGINS (Brute-Force Detection)
- **Rule ID:** `RULE_001_FAILED_LOGINS`
- **Condition:** $\ge 3$ authentication failures for the same principal or client within 300 seconds.
- **Severity:** `HIGH`
- **Confidence Score:** 0.95
- **Explanation:** Repeated failed authentication attempts suggest password guessing, dictionary attacks, or brute-force credential spraying.

### RULE 2 — NEW PRIVILEGED LOGIN CREATION
- **Rule ID:** `RULE_002_NEW_PRIVILEGED_LOGIN`
- **Condition:** `CREATE LOGIN` statement executed followed by grant of `sysadmin`, `securityadmin`, or `serveradmin`.
- **Severity:** `CRITICAL`
- **Confidence Score:** 0.90
- **Explanation:** Creation of an unannounced administrative login is a primary indicator of lateral movement or unauthorized persistence establishment.

### RULE 3 — SYSADMIN MEMBERSHIP CHANGE
- **Rule ID:** `RULE_003_SYSADMIN_CHANGE`
- **Condition:** Modification of the `sysadmin` fixed server role (`ALTER SERVER ROLE [sysadmin] ADD/DROP MEMBER`).
- **Severity:** `CRITICAL`
- **Confidence Score:** 1.00
- **Explanation:** Membership in `sysadmin` confers unrestricted control over the entire SQL Server instance, including xp_cmdshell execution, file tampering, and backup manipulation.

### RULE 4 — DATABASE ROLE ESCALATION
- **Rule ID:** `RULE_004_DATABASE_ROLE_ESCALATION`
- **Condition:** Assignment of high database privileges (`db_owner` or `db_securityadmin`).
- **Severity:** `HIGH`
- **Confidence Score:** 0.85
- **Explanation:** Grants total control over database objects and permissions within a specific database context, potentially bypassing application tier controls.

### RULE 5 — SENSITIVE PERMISSION MUTATION
- **Rule ID:** `RULE_005_PERMISSION_CHANGE`
- **Condition:** Execution of sensitive `GRANT`, `DENY`, or `REVOKE` statements involving `CONTROL`, `ALTER`, or `TAKE OWNERSHIP`.
- **Severity:** `MEDIUM`
- **Confidence Score:** 0.80
- **Explanation:** Explicit permission alterations that change access control boundaries on tables, schemas, or server securables.

### RULE 6 — SECURITY PRINCIPAL DELETION
- **Rule ID:** `RULE_006_PRINCIPAL_DELETION`
- **Condition:** Execution of `DROP LOGIN` or `DROP USER`.
- **Severity:** `HIGH`
- **Confidence Score:** 0.85
- **Explanation:** Deletion of security principals may represent defense evasion (covering tracks after malicious activity) or sabotage against administrative access.

### RULE 7 — SUSPICIOUS SCHEMA MUTATION
- **Rule ID:** `RULE_007_SCHEMA_MUTATION`
- **Condition:** Destructive DDL statements (`DROP TABLE`, `DROP PROCEDURE`, `DROP DATABASE`, or structural `ALTER`).
- **Severity:** `HIGH`
- **Confidence Score:** 0.90
- **Explanation:** Unauthorized destruction of database tables or code objects indicates possible data wiper attacks, database tampering, or ransomware sabotage.

### RULE 8 — AUDIT CONFIGURATION TAMPERING
- **Rule ID:** `RULE_008_AUDIT_TAMPERING`
- **Condition:** Attempt to disable, alter, or drop `SQLTrust_ServerAudit` or `SQLTrust_ServerAudit_Spec`.
- **Severity:** `CRITICAL`
- **Confidence Score:** 1.00
- **Explanation:** Disabling audit telemetry is a classic adversary evasion technique to operate without detection during data exfiltration or ransomware encryption.

### RULE 9 — EXTENDED EVENTS INTERRUPTION
- **Rule ID:** `RULE_009_XE_INTERRUPTION`
- **Condition:** Stopping (`ALTER EVENT SESSION ... STATE = STOP`), altering, or dropping the `SQLTrust_Security_XE` session.
- **Severity:** `CRITICAL`
- **Confidence Score:** 1.00
- **Explanation:** Stopping Extended Events sessions blinds real-time anomaly detection and error tracking.

### RULE 10 — AUDIT COLLECTION GAP DETECTION
- **Rule ID:** `RULE_010_COLLECTION_GAP`
- **Condition:** Collector lag $> 180$ seconds or inaccessible telemetry target files.
- **Severity:** `HIGH`
- **Confidence Score:** 0.90
- **Explanation:** Significant gaps in telemetry ingestion indicate collector disruption, disk exhaustion, or logging failure.

---

## 2. Alert Lifecycle & Deduplication Logic

- **Lifecycle States:** `NEW` &rarr; `ACKNOWLEDGED` &rarr; `INVESTIGATING` &rarr; `RESOLVED` or `FALSE_POSITIVE`.
- **In-Window Deduplication:** If an active alert exists for the same rule and principal within `time_window_seconds`, incoming events are linked to the existing alert rather than generating alert spam.
- **Audit History:** Every status transition is logged in `alert_status_history` with user notes and timestamps. Original security events are **never deleted**.
