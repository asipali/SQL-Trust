-- ==============================================================================
-- SQL-TRUST — Module 2: Security Monitoring Engine
-- Script: disable_sqltrust_audit.sql
-- Description: Disables and cleans up SQL-TRUST Server Audit & Specification
-- SAFETY NOTICE: Requires deliberate administrator execution.
-- To execute, set @CONFIRM_DISABLE = 'YES'.
-- ==============================================================================

USE [master];
GO

DECLARE @CONFIRM_DISABLE VARCHAR(10) = 'NO'; -- Set to 'YES' deliberately to execute

IF @CONFIRM_DISABLE <> 'YES'
BEGIN
    RAISERROR('SAFETY CHECK: You must explicitly set @CONFIRM_DISABLE = ''YES'' to disable SQL-TRUST Server Audit.', 16, 1);
    RETURN;
END;

PRINT 'Proceeding with deliberate disablement of SQL-TRUST Server Audit...';

IF EXISTS (SELECT * FROM sys.server_audit_specifications WHERE name = 'SQLTrust_ServerAudit_Spec')
BEGIN
    ALTER SERVER AUDIT SPECIFICATION [SQLTrust_ServerAudit_Spec] WITH (STATE = OFF);
    DROP SERVER AUDIT SPECIFICATION [SQLTrust_ServerAudit_Spec];
    PRINT 'Dropped [SQLTrust_ServerAudit_Spec].';
END;

IF EXISTS (SELECT * FROM sys.server_audits WHERE name = 'SQLTrust_ServerAudit')
BEGIN
    ALTER SERVER AUDIT [SQLTrust_ServerAudit] WITH (STATE = OFF);
    DROP SERVER AUDIT [SQLTrust_ServerAudit];
    PRINT 'Dropped [SQLTrust_ServerAudit].';
END;

PRINT 'SQL-TRUST Server Audit successfully removed.';
GO
