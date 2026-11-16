-- ==============================================================================
-- SQL-TRUST — Module 2: Security Monitoring Engine
-- Script: verify_audit_configuration.sql
-- Description: Inspects and verifies SQL Server Audit state and configuration
-- ==============================================================================

USE [master];
GO

SELECT 
    a.audit_id,
    a.name AS audit_name,
    a.is_state_enabled AS audit_enabled,
    a.type_desc AS target_type,
    a.on_failure_desc AS failure_action,
    a.queue_delay,
    f.log_file_path,
    f.max_file_size,
    f.max_rollover_files
FROM sys.server_audits a
LEFT JOIN sys.server_file_audits f ON a.audit_id = f.audit_id
WHERE a.name = 'SQLTrust_ServerAudit';
GO

SELECT 
    s.server_specification_id,
    s.name AS spec_name,
    s.is_state_enabled AS spec_enabled,
    a.name AS audit_name,
    d.audit_action_name
FROM sys.server_audit_specifications s
JOIN sys.server_audits a ON s.audit_id = a.audit_id
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
WHERE s.name = 'SQLTrust_ServerAudit_Spec';
GO

-- Check file generation in target directory
SELECT TOP 5 
    event_time,
    action_id,
    succeeded,
    session_id,
    server_principal_name,
    database_name,
    object_name,
    statement
FROM sys.fn_get_audit_file('D:\Desktop\HackShift\SQL Trust\data\audit\*', DEFAULT, DEFAULT)
ORDER BY event_time DESC;
GO
