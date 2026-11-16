-- ==============================================================================
-- SQL-TRUST — Module 2: Security Monitoring Engine
-- Script: verify_extended_events.sql
-- Description: Inspects and verifies Extended Events session status
-- ==============================================================================

USE [master];
GO

-- 1. Check Session State
SELECT 
    s.name AS session_name,
    CASE WHEN r.create_time IS NOT NULL THEN 'RUNNING' ELSE 'STOPPED' END AS runtime_status,
    CASE WHEN s.startup_state = 1 THEN 'ON' ELSE 'OFF' END AS startup_state,
    r.create_time AS session_started_at,
    r.total_buffer_size,
    r.dropped_event_count
FROM sys.server_event_sessions s
LEFT JOIN sys.dm_xe_sessions r ON s.name = r.name
WHERE s.name = 'SQLTrust_Security_XE';
GO

-- 2. Check Configured Events & Actions
SELECT 
    event_name = e.name,
    predicate = e.predicate,
    actions = STRING_AGG(a.name, ', ')
FROM sys.server_event_session_events e
LEFT JOIN sys.server_event_session_actions a 
    ON e.event_session_id = a.event_session_id AND e.event_id = a.event_id
WHERE e.event_session_id = (SELECT event_session_id FROM sys.server_event_sessions WHERE name = 'SQLTrust_Security_XE')
GROUP BY e.name, e.predicate;
GO

-- 3. Check Target File Configuration & Live Path
SELECT 
    target_name = t.name,
    target_path = CAST(v.value AS VARCHAR(500))
FROM sys.server_event_session_targets t
JOIN sys.server_event_session_fields v 
    ON t.event_session_id = v.event_session_id AND t.target_id = v.object_id
WHERE t.event_session_id = (SELECT event_session_id FROM sys.server_event_sessions WHERE name = 'SQLTrust_Security_XE')
  AND v.name = 'filename';
GO
