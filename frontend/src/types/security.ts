export interface SecuritySource {
  id: string
  source_name: string
  server_name: string
  source_type: string
  audit_target_path?: string
  xe_target_path?: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface SecurityEvent {
  id: string
  source_id: string
  event_source: string
  source_file: string
  source_event_id?: string
  event_type: string
  event_timestamp: string
  collection_timestamp: string
  server_name: string
  database_name?: string
  principal_name?: string
  session_id?: number
  client_ip?: string
  client_app?: string
  action: string
  target_object?: string
  success: boolean
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  event_fingerprint: string
  raw_payload: string
  evidence_reference?: string
  integrity_status: string
  created_at: string
}

export interface AlertStatusHistory {
  id: string
  alert_id: string
  previous_status: string
  new_status: string
  changed_by: string
  comment?: string
  timestamp: string
}

export interface SecurityAlert {
  id: string
  source_id: string
  rule_id: string
  title: string
  description: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  status: 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE'
  detection_timestamp: string
  principal_name?: string
  target_object?: string
  explanation: string
  confidence_score: number
  evidence_reference?: string
  related_event_count: number
  created_at: string
  updated_at: string
  status_history?: AlertStatusHistory[]
}

export interface DetectionRule {
  id: string
  rule_id: string
  rule_name: string
  description: string
  condition_type: string
  threshold_value: number
  time_window_seconds: number
  severity: string
  is_enabled: boolean
  created_at: string
  updated_at: string
}

export interface EvidenceArchive {
  id: string
  source_id: string
  evidence_type: string
  source_file_path: string
  file_size_bytes: number
  sha256: string
  storage_bucket: string
  storage_object_key: string
  storage_version_id?: string
  retention_mode: string
  retention_until?: string
  manifest_id: string
  signature?: string
  collection_timestamp: string
  verification_status: string
  created_at: string
}

export interface MonitoringHealthData {
  overall_status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE' | 'UNASSESSED'
  checked_at: string
  sql_server: {
    connected: boolean
    version?: string
    server?: string
  }
  audit: {
    audit_configured: boolean
    audit_enabled: boolean
    audit_name: string
    spec_configured: boolean
    spec_enabled: boolean
    action_groups: string[]
    file_count: number
    log_file_path?: string
    status: string
  }
  extended_events: {
    session_configured: boolean
    session_running: boolean
    session_name: string
    runtime_status: string
    startup_state?: string
    events_configured: string[]
    target_file_path?: string
    file_count: number
    status: string
  }
  storage: {
    connected: boolean
    endpoint: string
    bucket: string
    object_lock_enabled?: boolean
    immutability_guarantee?: string
  }
  collector: {
    last_run?: string
    last_event_timestamp?: string
    collection_lag_seconds: number
    last_error?: string
  }
}
