-- ==============================================================================
-- SQL-TRUST — Module 2: Security Monitoring Engine
-- Script: setup_extended_events.sql
-- Description: Creates and starts the SQL-TRUST Extended Events session
-- Target: Microsoft SQL Server 2022
-- ==============================================================================

USE [master];
GO

-- 1. Drop existing session if running/present
IF EXISTS (SELECT * FROM sys.server_event_sessions WHERE name = 'SQLTrust_Security_XE')
BEGIN
    ALTER EVENT SESSION [SQLTrust_Security_XE] ON SERVER STATE = STOP;
    DROP EVENT SESSION [SQLTrust_Security_XE] ON SERVER;
END
GO

-- 2. Create high-fidelity, filtered Extended Events session
CREATE EVENT SESSION [SQLTrust_Security_XE] ON SERVER
    -- Login & Authentication Events
    ADD EVENT sqlserver.login (
        ACTION (
            sqlserver.client_app_name,
            sqlserver.client_hostname,
            sqlserver.database_name,
            sqlserver.session_id,
            sqlserver.username
        )
    ),
    ADD EVENT sqlserver.logout (
        ACTION (
            sqlserver.client_app_name,
            sqlserver.client_hostname,
            sqlserver.database_name,
            sqlserver.session_id,
            sqlserver.username
        )
    ),
    
    -- Error & Anomaly Reporting (Filtered to Severity >= 11 or Auth Errors 18456)
    ADD EVENT sqlserver.error_reported (
        ACTION (
            sqlserver.client_app_name,
            sqlserver.client_hostname,
            sqlserver.database_name,
            sqlserver.session_id,
            sqlserver.sql_text,
            sqlserver.username
        )
        WHERE ([error_number] = (18456) OR [severity] >= (14))
    ),
    
    -- Filtered DDL & Schema Mutation Events (avoiding high-volume DML queries)
    ADD EVENT sqlserver.object_altered (
        ACTION (
            sqlserver.client_app_name,
            sqlserver.client_hostname,
            sqlserver.database_name,
            sqlserver.session_id,
            sqlserver.sql_text,
            sqlserver.username
        )
    ),
    ADD EVENT sqlserver.object_created (
        ACTION (
            sqlserver.client_app_name,
            sqlserver.client_hostname,
            sqlserver.database_name,
            sqlserver.session_id,
            sqlserver.sql_text,
            sqlserver.username
        )
    ),
    ADD EVENT sqlserver.object_deleted (
        ACTION (
            sqlserver.client_app_name,
            sqlserver.client_hostname,
            sqlserver.database_name,
            sqlserver.session_id,
            sqlserver.sql_text,
            sqlserver.username
        )
    )

    -- Event File Target with bounded capacity and rollover
    ADD TARGET package0.event_file (
        SET filename = 'D:\Desktop\HackShift\SQL Trust\data\extended_events\SQLTrust_XE.xel',
            max_file_size = 25,          -- 25 MB per file
            max_rollover_files = 10      -- Max 10 files (250 MB max storage)
    )
    WITH (
        MAX_MEMORY = 4096 KB,
        EVENT_RETENTION_MODE = ALLOW_SINGLE_EVENT_LOSS,
        MAX_DISPATCH_LATENCY = 5 SECONDS,
        MAX_EVENT_SIZE = 0 KB,
        MEMORY_PARTITION_MODE = NONE,
        TRACK_CAUSALITY = ON,
        STARTUP_STATE = ON               -- Automatically restarts with SQL Server service
    );
GO

-- 3. Start the Event Session
ALTER EVENT SESSION [SQLTrust_Security_XE] ON SERVER STATE = START;
GO

PRINT 'SQL-TRUST Extended Events session successfully created and started.';
GO
