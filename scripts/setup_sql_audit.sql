-- ==============================================================================
-- SQL-TRUST — Module 2: Security Monitoring Engine
-- Script: setup_sql_audit.sql
-- Description: Creates and configures the SQL-TRUST Server Audit & Specification
-- Target: Microsoft SQL Server 2022 (Express, Standard, Enterprise)
-- Note: Requires ALTER ANY SERVER AUDIT and CONTROL SERVER permissions.
-- Safe Failure Policy: ON_FAILURE = CONTINUE (Prevents database freeze/shutdown)
-- ==============================================================================

USE [master];
GO

-- 1. Ensure target directory exists in host filesystem before executing:
-- Default: D:\Desktop\HackShift\SQL Trust\data\audit

-- 2. Drop existing specification if present
IF EXISTS (SELECT * FROM sys.server_audit_specifications WHERE name = 'SQLTrust_ServerAudit_Spec')
BEGIN
    ALTER SERVER AUDIT SPECIFICATION [SQLTrust_ServerAudit_Spec] WITH (STATE = OFF);
    DROP SERVER AUDIT SPECIFICATION [SQLTrust_ServerAudit_Spec];
END
GO

-- 3. Drop existing server audit if present
IF EXISTS (SELECT * FROM sys.server_audits WHERE name = 'SQLTrust_ServerAudit')
BEGIN
    ALTER SERVER AUDIT [SQLTrust_ServerAudit] WITH (STATE = OFF);
    DROP SERVER AUDIT [SQLTrust_ServerAudit];
END
GO

-- 4. Create Server Audit with bounded file rollover and safe failure mode
CREATE SERVER AUDIT [SQLTrust_ServerAudit]
TO FILE 
(
    FILEPATH = 'D:\Desktop\HackShift\SQL Trust\data\audit\',
    MAXSIZE = 25 MB,
    MAX_ROLLOVER_FILES = 20,
    RESERVE_DISK_SPACE = OFF
)
WITH 
(
    QUEUE_DELAY = 1000,             -- 1-second batching to minimize I/O overhead
    ON_FAILURE = CONTINUE            -- CRITICAL: Safe non-destructive failure policy
);
GO

-- 5. Create Server Audit Specification covering core security action groups
CREATE SERVER AUDIT SPECIFICATION [SQLTrust_ServerAudit_Spec]
FOR SERVER AUDIT [SQLTrust_ServerAudit]
    -- Authentication & Session
    ADD (FAILED_LOGIN_GROUP),
    ADD (SUCCESSFUL_LOGIN_GROUP),
    
    -- Principal & Login Lifecycle
    ADD (SERVER_PRINCIPAL_CHANGE_GROUP),
    
    -- Role Escalation & Privileges
    ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
    ADD (SERVER_PERMISSION_CHANGE_GROUP),
    ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
    ADD (DATABASE_PERMISSION_CHANGE_GROUP),
    
    -- Schema & Object Alterations
    ADD (SCHEMA_OBJECT_CHANGE_GROUP),
    ADD (DATABASE_OBJECT_CHANGE_GROUP),
    ADD (DATABASE_CHANGE_GROUP),
    
    -- Audit & Security Configuration Integrity
    ADD (AUDIT_CHANGE_GROUP)
WITH (STATE = ON);
GO

-- 6. Enable Server Audit
ALTER SERVER AUDIT [SQLTrust_ServerAudit] WITH (STATE = ON);
GO

PRINT 'SQL-TRUST Server Audit and Specification successfully configured and enabled.';
GO
