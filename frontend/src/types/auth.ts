export interface UserSession {
  id?: string
  username: string
  email?: string
  full_name: string
  role: 'SECURITY_ADMIN' | 'INCIDENT_APPROVER' | 'SENIOR_ANALYST' | 'INVESTIGATION_ANALYST' | 'INCIDENT_REVIEWER' | 'AUDITOR' | 'READ_ONLY_REVIEWER' | string
  is_demo_account: boolean
  access_token: string
  permissions?: string[]
}

export interface DemoAccount {
  username: string
  role: string
  role_title: string
  description: string
  permissions: string[]
}

export interface UserAccountRecord {
  id: string
  username: string
  email?: string
  full_name: string
  role: string
  is_active: boolean
  is_pending_approval: boolean
  is_demo_account: boolean
  created_at?: string
  last_login_at?: string
  permissions: string[]
}

export interface AuthAuditRecord {
  id: string
  timestamp: string
  actor_username: string
  actor_role: string
  action: string
  target_username?: string
  details: string
  ip_address?: string
}
