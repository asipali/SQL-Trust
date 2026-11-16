export interface RecoveryValidation {
  id: string
  job_id: string
  sandbox_id: string
  target_database_name: string
  dbcc_status: 'PASSED' | 'FAILED' | 'PENDING' | string
  dbcc_errors_count: number
  dbcc_output_json?: string
  schema_validation_status: string
  baseline_comparison_status: string
  security_inspection_status: string
  overall_assessment: 'VALIDATED' | 'FAILED' | 'INCONCLUSIVE' | 'REQUIRES_INVESTIGATION' | string
  assessment_rationale: string
  validated_at: string
}

export interface RecoverySandbox {
  id: string
  job_id: string
  container_id?: string
  container_name: string
  docker_image: string
  docker_network: string
  host_port: number
  lifecycle_status: 'CREATED' | 'INITIALIZING' | 'HEALTHY' | 'UNHEALTHY' | 'QUARANTINED' | 'CLEANED' | string
  is_isolated: boolean
  network_isolated: boolean
  storage_isolated: boolean
  created_at: string
}

export interface RecoveryJob {
  id: string
  job_reference: string
  candidate_id: string
  recovery_point_id: string
  target_database_name: string
  status:
    | 'REQUESTED'
    | 'APPROVED'
    | 'PREPARING_STAGING'
    | 'DOWNLOADING_BACKUPS'
    | 'RESTORING_SANDBOX'
    | 'VALIDATING_INTEGRITY'
    | 'VALIDATED'
    | 'RECOVERY_COMPLETED'
    | 'FAILED'
    | string
  requested_by: string
  approved_by?: string
  requested_at: string
  approved_at?: string
  started_at?: string
  completed_at?: string
  notes?: string
  sandbox?: RecoverySandbox
  validation?: RecoveryValidation
}
