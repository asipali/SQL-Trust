/**
 * TypeScript Interfaces for SQL-TRUST Module 4: Cyber Recovery & State Reconstruction
 */

export interface RecoveryPointRecord {
  id: string
  database_id: string
  backup_id?: string
  server_name: string
  database_name: string
  recovery_point_time: string
  recovery_point_type: string
  first_lsn?: string
  last_lsn?: string
  checkpoint_lsn?: string
  database_backup_lsn?: string
  differential_base_guid?: string
  recovery_fork_guid?: string
  integrity_status: string
  sha256?: string
  storage_object_key?: string
  storage_version_id?: string
  retention_mode?: string
  retention_until?: string
  metadata_json?: string
  created_at: string
}

export interface RecoveryChainSegmentRecord {
  id: string
  chain_id: string
  recovery_point_id: string
  sequence_order: number
  segment_type: string
  first_lsn?: string
  last_lsn?: string
  checkpoint_lsn?: string
  is_continuous: boolean
  continuity_gap_lsn?: string
  created_at: string
}

export interface RecoveryChainRecord {
  id: string
  database_id: string
  server_name: string
  database_name: string
  chain_name: string
  target_recovery_point_id: string
  base_full_point_id: string
  differential_point_id?: string
  is_complete: boolean
  is_valid: boolean
  validation_status: string
  validation_details?: string
  first_lsn?: string
  last_lsn?: string
  segment_count: number
  created_at: string
  segments?: RecoveryChainSegmentRecord[]
}

export interface RecoveryAssessmentEvidenceRecord {
  id: string
  assessment_id: string
  evidence_source: string
  source_record_id: string
  relationship_type: string
  time_delta_seconds: number
  impact_direction: string
  weight_applied: number
  description: string
  metadata_json?: string
  created_at: string
}

export interface RecoveryAssessmentRecord {
  id: string
  recovery_point_id: string
  chain_id?: string
  assessment_name: string
  model_version: string
  trust_classification: string
  trust_score?: number
  has_sufficient_evidence: boolean
  confidence_rationale: string
  positive_indicators_json?: string
  negative_indicators_json?: string
  missing_telemetry_json?: string
  uncertainty_factors_json?: string
  manifest_sha256?: string
  signature?: string
  storage_object_key?: string
  storage_version_id?: string
  assessed_at: string
  evidence_items?: RecoveryAssessmentEvidenceRecord[]
}

export interface RecoveryEligibilityRecord {
  id: string
  recovery_point_id: string
  chain_id?: string
  is_eligible: boolean
  eligibility_status: string
  requires_offline_sandbox: boolean
  chain_usable: boolean
  chain_consistent: boolean
  logs_available: boolean
  identity_matched: boolean
  files_accessible: boolean
  integrity_verified: boolean
  critical_evidence_missing: boolean
  blocking_reasons_json?: string
  validation_checklist_json?: string
  evaluated_at: string
}

export interface RecoveryRecommendationRecord {
  id: string
  database_id: string
  recovery_point_id: string
  assessment_id: string
  eligibility_id: string
  rank_order: number
  trust_classification: string
  eligibility_status: string
  ranking_score: number
  rank_rationale: string
  tradeoff_analysis: string
  recommended_next_step: string
  created_at: string
}

export interface RecoveryHealthData {
  status: string
  database_connected: boolean
  storage_connected: boolean
  storage_bucket: string
  worm_compliance_active: boolean
  total_recovery_points: number
  total_valid_chains: number
  total_assessments: number
}
