export interface CaseEvidenceLink {
  id: string
  case_id: string
  source_module: string
  source_entity: string
  source_id: string
  evidence_role: string
  sha256_hash?: string
  tamper_status: string
  metadata_snapshot?: string
  linked_by: string
  linked_at: string
}

export interface InvestigationTask {
  id: string
  workflow_id: string
  case_id: string
  stage_name: string
  title: string
  description?: string
  task_type: 'MANUAL' | 'AUTOMATED_CHECK' | 'REVIEW' | 'APPROVAL' | string
  status: 'PENDING' | 'IN_PROGRESS' | 'BLOCKED' | 'COMPLETED' | 'SKIPPED' | 'CANCELLED' | 'FAILED' | string
  priority: 'P1_CRITICAL' | 'P2_HIGH' | 'P3_MEDIUM' | 'P4_LOW' | string
  assigned_to?: string
  assigned_team?: string
  is_mandatory: boolean
  order_index: number
  completed_at?: string
  completed_by?: string
  completion_notes?: string
}

export interface InvestigationWorkflow {
  id: string
  case_id: string
  name: string
  status: string
  current_stage?: string
  owner?: string
  created_by: string
  created_at: string
  tasks: InvestigationTask[]
}

export interface ResponsePlanAction {
  id: string
  plan_id: string
  title: string
  action_category: 'CONTAINMENT' | 'ERADICATION' | 'RECOVERY_PREPARATION' | 'POST_INCIDENT' | string
  target_type: string
  target_identifier?: string
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string
  proposed_script: string
  execution_order: number
  approval_status: 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | string
  approved_by?: string
  execution_status: 'NOT_EXECUTED' | 'EXECUTED_SUCCESS' | 'EXECUTED_FAILED' | string
  executed_by?: string
  execution_notes?: string
}

export interface IncidentResponsePlan {
  id: string
  case_id: string
  title: string
  summary?: string
  plan_type: string
  status: 'DRAFT' | 'IN_REVIEW' | 'APPROVED' | 'ACTIVE' | 'EXECUTED' | string
  version: number
  created_by: string
  approved_by?: string
  approved_at?: string
  actions: ResponsePlanAction[]
}

export interface CaseNote {
  id: string
  case_id: string
  author: string
  note_type: string
  content: string
  is_pinned: boolean
  created_at: string
}

export interface InvestigationCase {
  id: string
  case_number: string
  title: string
  description?: string
  target_database_name: string
  priority: 'P1_CRITICAL' | 'P2_HIGH' | 'P3_MEDIUM' | 'P4_LOW' | string
  status: 'NEW' | 'TRIAGED' | 'IN_PROGRESS' | 'CONTAINMENT_IN_PROGRESS' | 'RECOVERY_IN_PROGRESS' | 'RESOLVED' | 'CLOSED' | string
  incident_category: string
  lead_investigator?: string
  assigned_team?: string
  severity_score: number
  blast_radius_summary?: string
  containment_status: 'NONE' | 'ISOLATED' | 'CONTAINED' | 'ERADICATED' | string
  opened_at: string
  closed_at?: string
  created_at: string
  notes?: CaseNote[]
  evidence_links?: CaseEvidenceLink[]
  workflows?: InvestigationWorkflow[]
  response_plans?: IncidentResponsePlan[]
}

export interface InvestigationCaseListResponse {
  items: InvestigationCase[]
  total: number
  page: number
  page_size: number
}
