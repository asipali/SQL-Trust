-- ==============================================================================
-- SQL-TRUST — Module 2: Security Monitoring Engine
-- Script: disable_sqltrust_extended_events.sql
-- Description: Stops and removes SQL-TRUST Extended Events session
-- SAFETY NOTICE: Requires deliberate administrator execution.
-- To execute, set @CONFIRM_DISABLE = 'YES'.
-- ==============================================================================

USE [master];
GO

DECLARE @CONFIRM_DISABLE VARCHAR(10) = 'NO'; -- Set to 'YES' deliberately to execute

IF @CONFIRM_DISABLE <> 'YES'
BEGIN
    RAISERROR('SAFETY CHECK: You must explicitly set @CONFIRM_DISABLE = ''YES'' to disable SQL-TRUST Extended Events session.', 16, 1);
    RETURN;
END;

PRINT 'Proceeding with deliberate disablement of SQL-TRUST Extended Events session...';

IF EXISTS (SELECT * FROM sys.server_event_sessions WHERE name = 'SQLTrust_Security_XE')
BEGIN
    IF EXISTS (SELECT * FROM sys.dm_xe_sessions WHERE name = 'SQLTrust_Security_XE')
    BEGIN
        ALTER EVENT SESSION [SQLTrust_Security_XE] ON SERVER STATE = STOP;
        PRINT 'Stopped running session [SQLTrust_Security_XE].';
    END;

    DROP EVENT SESSION [SQLTrust_Security_XE] ON SERVER;
    PRINT 'Dropped [SQLTrust_Security_XE] event session.';
END;

PRINT 'SQL-TRUST Extended Events session successfully removed.';
GO
