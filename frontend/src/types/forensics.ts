export interface BaselineRecord {
  id: string
  database_id?: string
  server_name: string
  database_name: string
  baseline_name: string
  baseline_type: string
  status: string
  captured_at: string
  total_objects: number
  total_principals: number
  total_permissions: number
  sha256_manifest: string
  storage_object_key?: string
  storage_version_id?: string
  signature?: string
  notes?: string
  created_at: string
}

export interface BaselineItem {
  id: string
  baseline_id: string
  item_type: 'TABLE' | 'VIEW' | 'PROCEDURE' | 'FUNCTION' | 'TRIGGER' | 'USER' | 'ROLE_MEMBER' | 'PERMISSION' | 'DATABASE_OPTION'
  schema_name?: string
  item_name: string
  definition_hash?: string
  raw_definition?: string
  properties_json: string
  is_encrypted: boolean
  created_at: string
}

export interface ForensicCorrelation {
  id: string
  finding_id: string
  event_id: string
  correlation_type: string
  time_delta_seconds: number
  confidence_score: number
  correlation_notes?: string
  created_at: string
}

export interface ForensicFinding {
  id: string
  investigation_id: string
  category: 'SCHEMA' | 'PRINCIPAL' | 'ROLE_MEMBERSHIP' | 'PERMISSION' | 'CONFIGURATION'
  finding_type: string
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  entity_name: string
  schema_name?: string
  before_state_json?: string
  after_state_json?: string
  explanation: string
  confidence_score: number
  detected_at: string
  correlations: ForensicCorrelation[]
}

export interface InvestigationRecord {
  id: string
  investigation_name: string
  server_name: string
  database_name: string
  ref_baseline_id: string
  target_baseline_id?: string
  status: string
  findings_count: number
  critical_findings_count: number
  high_findings_count: number
  started_at: string
  completed_at?: string
  summary_notes?: string
  manifest_sha256?: string
  signature?: string
  storage_object_key?: string
  storage_version_id?: string
  findings: ForensicFinding[]
}

export interface TimelineEntry {
  timestamp: string
  timeline_type: 'BASELINE_REFERENCE' | 'SECURITY_TELEMETRY' | 'INVESTIGATION_COMPLETED'
  title: string
  description: string
  severity: string
  metadata: Record<string, any>
}

export interface EvidenceVerificationResult {
  valid: boolean
  archive_id: string
  evidence_type?: string
  sha256_match?: boolean
  signature_valid?: boolean
  worm_mode?: string
  retention_until?: string
  version_id?: string
  storage_object_key?: string
  error?: string
}
