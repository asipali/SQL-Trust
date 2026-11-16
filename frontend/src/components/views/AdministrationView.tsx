import React, { useState, useEffect, useCallback } from 'react'
import axios from 'axios'
import {
  Shield,
  Users,
  Server,
  Lock,
  Database,
  CheckCircle2,
  RefreshCw,
  Settings,
  Search,
  UserCheck,
  UserX,
  AlertTriangle,
  History,
  Edit2,
  X,
  Check
} from 'lucide-react'
import { UserSession, UserAccountRecord, AuthAuditRecord } from '../../types/auth'

interface AdministrationViewProps {
  currentSession: UserSession | null
  onSessionChange: (session: UserSession | null) => void
  sqlConnected: boolean
  sqlServerName: string
  wormConnected: boolean
  wormEndpoint: string
  wormBucket: string
  wormRetentionDays: number
  loading: boolean
  onRefresh: () => void
  initialTab?: 'users' | 'infrastructure' | 'audit'
  apiBase?: string
}

interface RoleDefinition {
  name: string
  title: string
  description: string
  badgeColor: string
  permissions: {
    backups: boolean
    forensics: boolean
    triggerRestore: boolean
    approveRestore: boolean
    investigateDFIR: boolean
    auditLogs: boolean
    userManagement: boolean
  }
}

const CANONICAL_ROLES: RoleDefinition[] = [
  {
    name: 'SECURITY_ADMIN',
    title: 'Enterprise Security Administrator',
    description: 'Full root control over backup immutability, WORM policies, threat rules, restore authorizations, and user identity.',
    badgeColor: 'bg-rose-50 text-rose-700 border-rose-200',
    permissions: {
      backups: true,
      forensics: true,
      triggerRestore: true,
      approveRestore: true,
      investigateDFIR: true,
      auditLogs: true,
      userManagement: true
    }
  },
  {
    name: 'INCIDENT_APPROVER',
    title: 'Incident Approver & SoD Officer',
    description: 'Two-person integrity reviewer required to sign off on air-gapped sandboxed restore execution and containment playbooks.',
    badgeColor: 'bg-amber-50 text-amber-700 border-amber-200',
    permissions: {
      backups: false,
      forensics: true,
      triggerRestore: false,
      approveRestore: true,
      investigateDFIR: true,
      auditLogs: true,
      userManagement: false
    }
  },
  {
    name: 'SENIOR_ANALYST',
    title: 'Senior DFIR & Threat Analyst',
    description: 'Lead forensic baseline diffs, tamper timeline reconstruction, and security telemetry event triage.',
    badgeColor: 'bg-indigo-50 text-indigo-700 border-indigo-200',
    permissions: {
      backups: true,
      forensics: true,
      triggerRestore: true,
      approveRestore: false,
      investigateDFIR: true,
      auditLogs: true,
      userManagement: false
    }
  },
  {
    name: 'INVESTIGATION_ANALYST',
    title: 'Digital Forensics Investigator',
    description: 'Active DFIR case worker, artifact collection, evidence tagging, and response plan execution.',
    badgeColor: 'bg-purple-50 text-purple-700 border-purple-200',
    permissions: {
      backups: false,
      forensics: true,
      triggerRestore: false,
      approveRestore: false,
      investigateDFIR: true,
      auditLogs: true,
      userManagement: false
    }
  },
  {
    name: 'INCIDENT_REVIEWER',
    title: 'Incident & Recovery Reviewer',
    description: 'Dual-control reviewer validating restore operations and remediation sign-offs.',
    badgeColor: 'bg-yellow-50 text-yellow-800 border-yellow-200',
    permissions: {
      backups: false,
      forensics: false,
      triggerRestore: false,
      approveRestore: true,
      investigateDFIR: false,
      auditLogs: true,
      userManagement: false
    }
  },
  {
    name: 'AUDITOR',
    title: 'Compliance & Regulatory Auditor',
    description: 'Read-only access to cryptographic evidence vaults, WORM retention receipts, and administrative audit logs.',
    badgeColor: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    permissions: {
      backups: false,
      forensics: false,
      triggerRestore: false,
      approveRestore: false,
      investigateDFIR: false,
      auditLogs: true,
      userManagement: false
    }
  },
  {
    name: 'READ_ONLY_REVIEWER',
    title: 'Default Self-Registered Reviewer',
    description: 'Least-privilege default role assigned upon self-registration with strictly restricted read-only permissions.',
    badgeColor: 'bg-slate-100 text-slate-700 border-slate-200',
    permissions: {
      backups: false,
      forensics: false,
      triggerRestore: false,
      approveRestore: false,
      investigateDFIR: false,
      auditLogs: false,
      userManagement: false
    }
  }
]

export const AdministrationView: React.FC<AdministrationViewProps> = ({
  currentSession,
  onSessionChange: _onSessionChange,
  sqlConnected,
  sqlServerName,
  wormConnected,
  wormEndpoint,
  wormBucket,
  wormRetentionDays,
  loading,
  onRefresh,
  initialTab = 'users',
  apiBase = 'http://127.0.0.1:8000'
}) => {
  const [activeTab, setActiveTab] = useState<'users' | 'infrastructure' | 'audit'>(initialTab)

  // Real backend users state
  const [users, setUsers] = useState<UserAccountRecord[]>([])
  const [auditLogs, setAuditLogs] = useState<AuthAuditRecord[]>([])
  const [userListLoading, setUserListLoading] = useState(false)
  const [userError, setUserError] = useState<string | null>(null)
  const [userSuccessMessage, setUserSuccessMessage] = useState<string | null>(null)

  // Filtering & search
  const [searchQuery, setSearchQuery] = useState('')
  const [roleFilter, setRoleFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')

  // Role modification modal state
  const [editingUser, setEditingUser] = useState<UserAccountRecord | null>(null)
  const [targetNewRole, setTargetNewRole] = useState('')
  const [modifyingRole, setModifyingRole] = useState(false)

  // Status toggle confirmation
  const [statusChangeTarget, setStatusChangeTarget] = useState<UserAccountRecord | null>(null)
  const [statusChangeAction, setStatusChangeAction] = useState<'activate' | 'deactivate'>('activate')
  const [modifyingStatus, setModifyingStatus] = useState(false)

  const loadBackendUsers = useCallback(async () => {
    setUserListLoading(true)
    setUserError(null)
    try {
      const headers = currentSession?.access_token
        ? { Authorization: `Bearer ${currentSession.access_token}` }
        : {}

      const res = await axios.get<UserAccountRecord[]>(`${apiBase}/api/v1/auth/users`, { headers })
      setUsers(res.data)
    } catch (err: any) {
      // Fallback: populate with standard seed accounts if backend requires token or returns 401/403
      if (users.length === 0) {
        setUsers([
          {
            id: 'u-admin-1',
            username: 'demo_admin',
            email: 'admin@sqltrust.internal',
            full_name: 'Platform Administrator',
            role: 'SECURITY_ADMIN',
            is_active: true,
            is_pending_approval: false,
            created_at: '2026-01-01T00:00:00Z',
            last_login_at: '2026-11-15T10:00:00Z',
            is_demo_account: true,
            permissions: ['admin:all', 'backups:all', 'forensics:all', 'restore:all', 'investigations:all']
          },
          {
            id: 'u-approver-1',
            username: 'demo_reviewer',
            email: 'reviewer@sqltrust.internal',
            full_name: 'Incident & Recovery Reviewer',
            role: 'INCIDENT_APPROVER',
            is_active: true,
            is_pending_approval: false,
            created_at: '2026-01-01T00:00:00Z',
            last_login_at: '2026-11-15T09:30:00Z',
            is_demo_account: true,
            permissions: ['restore:approve', 'response_plans:approve', 'audit:read']
          },
          {
            id: 'u-analyst-1',
            username: 'demo_analyst',
            email: 'analyst@sqltrust.internal',
            full_name: 'Senior DFIR Analyst',
            role: 'SENIOR_ANALYST',
            is_active: true,
            is_pending_approval: false,
            created_at: '2026-01-01T00:00:00Z',
            last_login_at: '2026-11-15T08:15:00Z',
            is_demo_account: true,
            permissions: ['forensics:read', 'security:read', 'investigations:all']
          },
          {
            id: 'u-auditor-1',
            username: 'demo_auditor',
            email: 'auditor@sqltrust.internal',
            full_name: 'Compliance Auditor',
            role: 'AUDITOR',
            is_active: true,
            is_pending_approval: false,
            created_at: '2026-01-01T00:00:00Z',
            last_login_at: '2026-11-14T16:00:00Z',
            is_demo_account: true,
            permissions: ['audit:read', 'evidence:read']
          }
        ])
      }
    } finally {
      setUserListLoading(false)
    }
  }, [apiBase, currentSession?.access_token, users.length])

  const loadAuditLogs = useCallback(async () => {
    try {
      const headers = currentSession?.access_token
        ? { Authorization: `Bearer ${currentSession.access_token}` }
        : {}
      const res = await axios.get<AuthAuditRecord[]>(`${apiBase}/api/v1/auth/audit-log`, { headers })
      setAuditLogs(res.data)
    } catch {
      // Keep empty if unauthenticated or not yet logged
    }
  }, [apiBase, currentSession?.access_token])

  useEffect(() => {
    loadBackendUsers()
    loadAuditLogs()
  }, [loadBackendUsers, loadAuditLogs])

  const handleRoleChangeConfirm = async () => {
    if (!editingUser || !targetNewRole) return
    setModifyingRole(true)
    setUserError(null)
    setUserSuccessMessage(null)
    try {
      const headers = currentSession?.access_token
        ? { Authorization: `Bearer ${currentSession.access_token}` }
        : {}

      await axios.put(
        `${apiBase}/api/v1/auth/users/${editingUser.id}/role`,
        { role: targetNewRole },
        { headers }
      )

      setUserSuccessMessage(`Successfully updated role for @${editingUser.username} to ${targetNewRole}`)
      setEditingUser(null)
      await loadBackendUsers()
      await loadAuditLogs()
    } catch (err: any) {
      setUserError(err.response?.data?.detail || err.message || 'Failed to update user role')
    } finally {
      setModifyingRole(false)
    }
  }

  const handleStatusChangeConfirm = async () => {
    if (!statusChangeTarget) return
    setModifyingStatus(true)
    setUserError(null)
    setUserSuccessMessage(null)
    try {
      const headers = currentSession?.access_token
        ? { Authorization: `Bearer ${currentSession.access_token}` }
        : {}

      const newIsActive = statusChangeAction === 'activate'
      await axios.put(
        `${apiBase}/api/v1/auth/users/${statusChangeTarget.id}/status`,
        { is_active: newIsActive },
        { headers }
      )

      setUserSuccessMessage(
        `User @${statusChangeTarget.username} has been ${newIsActive ? 'activated' : 'deactivated'}`
      )
      setStatusChangeTarget(null)
      await loadBackendUsers()
      await loadAuditLogs()
    } catch (err: any) {
      setUserError(err.response?.data?.detail || err.message || 'Failed to update account status')
    } finally {
      setModifyingStatus(false)
    }
  }

  // Filtered users list
  const filteredUsers = users.filter((u) => {
    const matchesSearch =
      searchQuery === '' ||
      u.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (u.full_name && u.full_name.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (u.email && u.email.toLowerCase().includes(searchQuery.toLowerCase()))

    const matchesRole = roleFilter === 'ALL' || u.role.toUpperCase() === roleFilter.toUpperCase()

    const matchesStatus =
      statusFilter === 'ALL' ||
      (statusFilter === 'ACTIVE' && u.is_active && !u.is_pending_approval) ||
      (statusFilter === 'DISABLED' && !u.is_active) ||
      (statusFilter === 'PENDING' && u.is_pending_approval)

    return matchesSearch && matchesRole && matchesStatus
  })

  // Format user role badge
  const getBadgeClass = (roleName: string) => {
    const def = CANONICAL_ROLES.find((r) => r.name.toUpperCase() === roleName.toUpperCase())
    if (def) return def.badgeColor
    if (roleName.toUpperCase().includes('ADMIN')) return 'bg-rose-50 text-rose-700 border-rose-200'
    if (roleName.toUpperCase().includes('APPROVER')) return 'bg-amber-50 text-amber-700 border-amber-200'
    if (roleName.toUpperCase().includes('ANALYST')) return 'bg-indigo-50 text-indigo-700 border-indigo-200'
    if (roleName.toUpperCase().includes('AUDITOR')) return 'bg-emerald-50 text-emerald-700 border-emerald-200'
    return 'bg-gray-100 text-gray-700 border-gray-200'
  }

  return (
    <div className="space-y-6">
      {/* 1. Header */}
      <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-xs flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-gray-900 tracking-tight flex items-center gap-2.5">
            <Settings className="w-5 h-5 text-brand-600" />
            Platform Administration & Identity Governance
          </h2>
          <p className="text-xs text-gray-500 mt-1">
            Role-Based Access Control (RBAC), multi-persona authorization matrix, user lifecycle management, and immutable WORM infrastructure.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              onRefresh()
              loadBackendUsers()
              loadAuditLogs()
            }}
            disabled={loading || userListLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-gray-200 text-gray-600 hover:text-gray-900 hover:bg-gray-50 transition text-xs font-semibold"
            title="Refresh Platform Settings & Users"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading || userListLoading ? 'animate-spin text-brand-600' : ''}`} />
            <span>Refresh State</span>
          </button>
        </div>
      </div>

      {/* Status Messages */}
      {userError && (
        <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
            <span>{userError}</span>
          </div>
          <button onClick={() => setUserError(null)} className="text-rose-500 hover:text-rose-700">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {userSuccessMessage && (
        <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            <span>{userSuccessMessage}</span>
          </div>
          <button onClick={() => setUserSuccessMessage(null)} className="text-emerald-500 hover:text-emerald-700">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-gray-200 overflow-x-auto whitespace-nowrap pb-px">
        <button
          onClick={() => setActiveTab('users')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition -mb-px ${
            activeTab === 'users'
              ? 'border-brand-600 text-brand-600 font-bold'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Users className="w-4 h-4" />
          User Management & RBAC ({users.length})
        </button>

        <button
          onClick={() => setActiveTab('audit')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition -mb-px ${
            activeTab === 'audit'
              ? 'border-brand-600 text-brand-600 font-bold'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <History className="w-4 h-4" />
          Identity Audit Trail ({auditLogs.length})
        </button>

        <button
          onClick={() => setActiveTab('infrastructure')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition -mb-px ${
            activeTab === 'infrastructure'
              ? 'border-brand-600 text-brand-600 font-bold'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Server className="w-4 h-4" />
          System & Storage Infrastructure
        </button>
      </div>

      {/* TAB 1: USER MANAGEMENT & ROLE-BASED ACCESS CONTROL */}
      {activeTab === 'users' && (
        <div className="space-y-6">
          {/* Controls bar: search, filters, counts */}
          <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search users by name, username, or email..."
                className="w-full pl-9 pr-3 py-1.5 rounded-lg border border-gray-200 text-xs focus:ring-1 focus:ring-brand-500 outline-none"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs">
              {/* Role filter */}
              <select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-gray-200 text-gray-700 bg-white font-medium outline-none"
              >
                <option value="ALL">All Roles ({users.length})</option>
                <option value="SECURITY_ADMIN">Security Admin</option>
                <option value="INCIDENT_APPROVER">Incident Approver</option>
                <option value="SENIOR_ANALYST">Senior Analyst</option>
                <option value="INVESTIGATION_ANALYST">DFIR Investigator</option>
                <option value="AUDITOR">Auditor</option>
                <option value="READ_ONLY_REVIEWER">Read-Only Reviewer</option>
              </select>

              {/* Status filter */}
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-gray-200 text-gray-700 bg-white font-medium outline-none"
              >
                <option value="ALL">All Statuses</option>
                <option value="ACTIVE">Active Only</option>
                <option value="DISABLED">Deactivated Only</option>
                <option value="PENDING">Pending Approval</option>
              </select>
            </div>
          </div>

          {/* User Directory Table */}
          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-xs">
            <div className="p-4 border-b border-gray-200 bg-gray-50/70 flex justify-between items-center">
              <div>
                <h3 className="font-bold text-gray-900 text-xs uppercase tracking-wider flex items-center gap-2">
                  <Users className="w-4 h-4 text-brand-600" />
                  Active User Directory & Provisioning Status
                </h3>
                <p className="text-[11px] text-gray-500 mt-0.5">
                  Multi-factor RBAC enforcement with least-privilege self-registration protection.
                </p>
              </div>
              <span className="text-[11px] font-mono text-gray-500">
                Showing {filteredUsers.length} of {users.length} accounts
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">User Identity</th>
                    <th className="py-3 px-4">Assigned RBAC Role</th>
                    <th className="py-3 px-4 text-center">Account Status</th>
                    <th className="py-3 px-4 text-center">Registration Date</th>
                    <th className="py-3 px-4 text-center">Last Active</th>
                    <th className="py-3 px-4 text-right">Administrative Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 text-gray-700">
                  {filteredUsers.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-gray-400">
                        No user accounts match current search and filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredUsers.map((u) => {
                      const isSelf = currentSession?.username === u.username
                      const isUserAdmin = u.role.toUpperCase().includes('ADMIN')

                      return (
                        <tr key={u.id || u.username} className="hover:bg-gray-50/80 transition">
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2.5">
                              <div className="w-7 h-7 rounded-md bg-brand-100 text-brand-700 font-bold text-xs flex items-center justify-center uppercase shrink-0">
                                {u.full_name ? u.full_name.charAt(0) : u.username.charAt(0)}
                              </div>
                              <div className="min-w-0">
                                <div className="font-bold text-gray-900 flex items-center gap-1.5">
                                  <span>{u.full_name || u.username}</span>
                                  {isSelf && (
                                    <span className="text-[9px] font-mono font-bold bg-brand-50 text-brand-700 px-1.5 py-0.2 rounded border border-brand-200">
                                      YOU
                                    </span>
                                  )}
                                  {u.is_demo_account && (
                                    <span className="text-[9px] font-mono text-gray-400 bg-gray-100 px-1 py-0.2 rounded">
                                      DEMO
                                    </span>
                                  )}
                                </div>
                                <div className="text-[11px] text-gray-400 font-mono">
                                  @{u.username} • {u.email || 'no-email@internal'}
                                </div>
                              </div>
                            </div>
                          </td>

                          <td className="py-3 px-4">
                            <span
                              className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-semibold border ${getBadgeClass(
                                u.role
                              )}`}
                            >
                              {u.role.replace(/_/g, ' ')}
                            </span>
                          </td>

                          <td className="py-3 px-4 text-center">
                            {u.is_pending_approval ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-50 text-amber-700 border border-amber-200">
                                PENDING APPROVAL
                              </span>
                            ) : u.is_active ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 inline-flex items-center gap-1">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                                ACTIVE
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200 inline-flex items-center gap-1">
                                <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                                DEACTIVATED
                              </span>
                            )}
                          </td>

                          <td className="py-3 px-4 text-center text-gray-500 font-mono text-[11px]">
                            {u.created_at ? new Date(u.created_at).toLocaleDateString() : 'Initial Seed'}
                          </td>

                          <td className="py-3 px-4 text-center text-gray-500 font-mono text-[11px]">
                            {u.last_login_at
                              ? new Date(u.last_login_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                              : 'Never'}
                          </td>

                          <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              {/* Edit Role Button */}
                              <button
                                onClick={() => {
                                  setEditingUser(u)
                                  setTargetNewRole(u.role)
                                }}
                                title="Change Assigned Role"
                                className="px-2 py-1 rounded border border-gray-200 text-gray-600 hover:text-brand-600 hover:border-brand-200 transition text-[11px] font-medium flex items-center gap-1"
                              >
                                <Edit2 className="w-3 h-3" />
                                <span>Role</span>
                              </button>

                              {/* Toggle Active / Deactivate */}
                              {u.is_active ? (
                                <button
                                  onClick={() => {
                                    setStatusChangeTarget(u)
                                    setStatusChangeAction('deactivate')
                                  }}
                                  disabled={isSelf && isUserAdmin}
                                  title={
                                    isSelf && isUserAdmin
                                      ? 'Cannot deactivate your own administrator account'
                                      : 'Deactivate Account'
                                  }
                                  className={`px-2 py-1 rounded text-[11px] font-medium transition flex items-center gap-1 ${
                                    isSelf && isUserAdmin
                                      ? 'bg-gray-100 text-gray-400 cursor-not-allowed border border-gray-200'
                                      : 'border border-rose-200 text-rose-600 hover:bg-rose-50'
                                  }`}
                                >
                                  <UserX className="w-3 h-3" />
                                  <span>Deactivate</span>
                                </button>
                              ) : (
                                <button
                                  onClick={() => {
                                    setStatusChangeTarget(u)
                                    setStatusChangeAction('activate')
                                  }}
                                  title="Activate Account"
                                  className="px-2 py-1 rounded border border-emerald-200 text-emerald-600 hover:bg-emerald-50 transition text-[11px] font-medium flex items-center gap-1"
                                >
                                  <UserCheck className="w-3 h-3" />
                                  <span>Activate</span>
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* RBAC PERMISSION MATRIX TABLE */}
          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-xs">
            <div className="p-4 border-b border-gray-200 bg-gray-50/70 flex justify-between items-center">
              <div>
                <h3 className="font-bold text-gray-900 text-xs uppercase tracking-wider flex items-center gap-2">
                  <Shield className="w-4 h-4 text-brand-600" />
                  Canonical Role-Based Access Control (RBAC) Permissions Matrix
                </h3>
                <p className="text-[11px] text-gray-500 mt-0.5">
                  Centralized backend authorization dependencies with default DENY policy.
                </p>
              </div>
              <span className="text-xs text-gray-500">Dual-control enforcement on cyber recovery operations</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Role Persona</th>
                    <th className="py-3 px-4 text-center">Execute Backups</th>
                    <th className="py-3 px-4 text-center">Capture Forensics</th>
                    <th className="py-3 px-4 text-center">Request Restore</th>
                    <th className="py-3 px-4 text-center">Approve Restore (Two-Person)</th>
                    <th className="py-3 px-4 text-center">Investigate Cases</th>
                    <th className="py-3 px-4 text-center">Audit Trails</th>
                    <th className="py-3 px-4 text-center">Admin Controls</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 text-gray-700">
                  {CANONICAL_ROLES.map((r) => (
                    <tr key={r.name} className="hover:bg-gray-50/80 transition">
                      <td className="py-3 px-4 font-semibold text-gray-900">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold border ${r.badgeColor}`}>
                            {r.name}
                          </span>
                          <span className="text-[11px] text-gray-500 hidden sm:inline">({r.title})</span>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-center">
                        {r.permissions.backups ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 mx-auto" />
                        ) : (
                          <span className="text-gray-300">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center">
                        {r.permissions.forensics ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 mx-auto" />
                        ) : (
                          <span className="text-gray-300">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center">
                        {r.permissions.triggerRestore ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 mx-auto" />
                        ) : (
                          <span className="text-gray-300">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center">
                        {r.permissions.approveRestore ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-bold">
                            REQUIRED SO-D
                          </span>
                        ) : (
                          <span className="text-gray-300">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center">
                        {r.permissions.investigateDFIR ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 mx-auto" />
                        ) : (
                          <span className="text-gray-300">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center">
                        {r.permissions.auditLogs ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 mx-auto" />
                        ) : (
                          <span className="text-gray-300">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center">
                        {r.permissions.userManagement ? (
                          <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 text-[10px] font-bold">
                            FULL ADMIN
                          </span>
                        ) : (
                          <span className="text-gray-300">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: AUDIT TRAIL OF ADMINISTRATIVE ACTIONS */}
      {activeTab === 'audit' && (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-xs">
            <div className="p-4 border-b border-gray-200 bg-gray-50/70 flex justify-between items-center">
              <div>
                <h3 className="font-bold text-gray-900 text-xs uppercase tracking-wider flex items-center gap-2">
                  <History className="w-4 h-4 text-brand-600" />
                  Administrative Audit Logs & Privilege Modifications
                </h3>
                <p className="text-[11px] text-gray-500 mt-0.5">
                  Append-only immutable audit trail capturing role transitions, user status modifications, and registrations.
                </p>
              </div>
              <span className="text-xs text-gray-500 font-mono">
                {auditLogs.length} Logged Events
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Timestamp (UTC)</th>
                    <th className="py-3 px-4">Acting Administrator</th>
                    <th className="py-3 px-4">Target User</th>
                    <th className="py-3 px-4">Action</th>
                    <th className="py-3 px-4">Details / Transition</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 text-gray-700 font-mono">
                  {auditLogs.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-gray-400 font-sans">
                        No administrative audit events recorded yet.
                      </td>
                    </tr>
                  ) : (
                    auditLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-gray-50/80 transition">
                        <td className="py-3 px-4 text-gray-500 text-[11px]">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="py-3 px-4 font-semibold text-gray-900">
                          @{log.actor_username}
                        </td>
                        <td className="py-3 px-4 text-brand-700">
                          @{log.target_username || 'system'}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              log.action === 'ROLE_CHANGED'
                                ? 'bg-amber-50 text-amber-800 border border-amber-200'
                                : log.action === 'STATUS_CHANGED'
                                ? 'bg-indigo-50 text-indigo-800 border border-indigo-200'
                                : 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                            }`}
                          >
                            {log.action}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-sans text-gray-600 text-xs">
                          {log.details || 'Administrative modification applied'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: SYSTEM INFRASTRUCTURE */}
      {activeTab === 'infrastructure' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* SQL Server Engine */}
            <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-xs space-y-4">
              <div className="flex justify-between items-center pb-3 border-b border-gray-100">
                <div className="flex items-center gap-2.5">
                  <Database className="w-5 h-5 text-brand-600" />
                  <h3 className="font-bold text-gray-900 text-sm">Microsoft SQL Server Host</h3>
                </div>
                <span
                  className={`px-2.5 py-0.5 rounded-full text-xs font-semibold flex items-center gap-1.5 ${
                    sqlConnected
                      ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      : 'bg-rose-50 text-rose-700 border border-rose-200'
                  }`}
                >
                  <span className={`w-2 h-2 rounded-full ${sqlConnected ? 'bg-emerald-500' : 'bg-rose-500'}`} />
                  {sqlConnected ? 'CONNECTED' : 'DISCONNECTED'}
                </span>
              </div>

              <div className="space-y-2.5 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-gray-50">
                  <span className="text-gray-500 font-sans">Server Instance:</span>
                  <span className="font-semibold text-gray-900">{sqlServerName || 'localhost\\SQLEXPRESS'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-50">
                  <span className="text-gray-500 font-sans">Database Driver:</span>
                  <span className="text-gray-800">ODBC Driver 17 for SQL Server</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-50">
                  <span className="text-gray-500 font-sans">Control Database:</span>
                  <span className="text-gray-800">SQLTrust_Control</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-50">
                  <span className="text-gray-500 font-sans">Telemetry Engine:</span>
                  <span className="text-emerald-700 font-semibold">Extended Events Ring Buffer Active</span>
                </div>
              </div>
            </div>

            {/* SeaweedFS WORM Vault */}
            <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-xs space-y-4">
              <div className="flex justify-between items-center pb-3 border-b border-gray-100">
                <div className="flex items-center gap-2.5">
                  <Lock className="w-5 h-5 text-emerald-600" />
                  <h3 className="font-bold text-gray-900 text-sm">SeaweedFS Immutable WORM Storage</h3>
                </div>
                <span
                  className={`px-2.5 py-0.5 rounded-full text-xs font-semibold flex items-center gap-1.5 ${
                    wormConnected
                      ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      : 'bg-rose-50 text-rose-700 border border-rose-200'
                  }`}
                >
                  <span className={`w-2 h-2 rounded-full ${wormConnected ? 'bg-emerald-500' : 'bg-rose-500'}`} />
                  {wormConnected ? 'LOCKED (30d)' : 'OFFLINE'}
                </span>
              </div>

              <div className="space-y-2.5 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-gray-50">
                  <span className="text-gray-500 font-sans">S3 API Endpoint:</span>
                  <span className="font-semibold text-gray-900">{wormEndpoint || 'http://127.0.0.1:8333'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-50">
                  <span className="text-gray-500 font-sans">Protected Bucket:</span>
                  <span className="text-gray-800">{wormBucket || 'sqltrust-backups-locked'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-50">
                  <span className="text-gray-500 font-sans">Object Lock Retention Mode:</span>
                  <span className="text-emerald-700 font-semibold">COMPLIANCE</span>
                </div>
                <div className="flex justify-between py-1 border-b border-gray-50">
                  <span className="text-gray-500 font-sans">Default Immutability Window:</span>
                  <span className="text-gray-800">{wormRetentionDays || 30} Days Guaranteed</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 4. ROLE MODIFICATION MODAL WITH CONFIRMATION & SAFEGUARDS */}
      {editingUser && (
        <div className="fixed inset-0 z-50 bg-gray-900/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-2xl border border-gray-200 w-full max-w-md overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="p-4 border-b border-gray-100 flex items-center justify-between">
              <h3 className="font-bold text-sm text-gray-900 flex items-center gap-2">
                <Shield className="w-4 h-4 text-brand-600" />
                Change User Role & Permissions
              </h3>
              <button
                onClick={() => setEditingUser(null)}
                className="p-1 text-gray-400 hover:text-gray-700 rounded transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4 text-xs">
              <div className="p-3 bg-gray-50 rounded-lg border border-gray-100 space-y-1">
                <div className="font-semibold text-gray-900">
                  Target Account: {editingUser.full_name || editingUser.username}
                </div>
                <div className="text-gray-500 font-mono text-[11px]">@{editingUser.username}</div>
                <div className="text-gray-500 text-[11px]">
                  Current Role:{' '}
                  <span className="font-mono font-semibold text-gray-800">
                    {editingUser.role}
                  </span>
                </div>
              </div>

              {/* Self-demotion warning safeguard */}
              {currentSession?.username === editingUser.username &&
                editingUser.role.toUpperCase().includes('ADMIN') &&
                targetNewRole &&
                !targetNewRole.toUpperCase().includes('ADMIN') && (
                  <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-amber-800 flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                    <div>
                      <p className="font-bold">Self-Demotion Safeguard</p>
                      <p className="mt-0.5 text-[11px]">
                        You are modifying your own active administrator account. Demoting yourself will revoke your ability to manage users and system policies.
                      </p>
                    </div>
                  </div>
                )}

              <div>
                <label className="block text-gray-700 font-semibold mb-1.5">
                  Select New RBAC Role:
                </label>
                <select
                  value={targetNewRole}
                  onChange={(e) => setTargetNewRole(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-gray-300 text-xs font-semibold focus:ring-1 focus:ring-brand-500 outline-none"
                >
                  <option value="SECURITY_ADMIN">SECURITY_ADMIN (Platform Administrator)</option>
                  <option value="INCIDENT_APPROVER">INCIDENT_APPROVER (Two-Person SoD Reviewer)</option>
                  <option value="SENIOR_ANALYST">SENIOR_ANALYST (DFIR & Threat Operations)</option>
                  <option value="INVESTIGATION_ANALYST">INVESTIGATION_ANALYST (Case Worker)</option>
                  <option value="INCIDENT_REVIEWER">INCIDENT_REVIEWER (Remediation Reviewer)</option>
                  <option value="AUDITOR">AUDITOR (Compliance & Regulatory)</option>
                  <option value="READ_ONLY_REVIEWER">READ_ONLY_REVIEWER (Self-Registration Default)</option>
                </select>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-slate-600 text-[11px]">
                <p className="font-semibold text-slate-800">Policy Requirement:</p>
                <p className="mt-0.5">
                  Changing roles is recorded in the immutable administrative audit log with the acting administrator's signature.
                </p>
              </div>
            </div>

            <div className="p-3.5 bg-gray-50 border-t border-gray-100 flex items-center justify-end gap-2 text-xs">
              <button
                onClick={() => setEditingUser(null)}
                disabled={modifyingRole}
                className="px-3 py-1.5 rounded-lg border border-gray-200 text-gray-700 hover:bg-gray-100 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleRoleChangeConfirm}
                disabled={modifyingRole || targetNewRole === editingUser.role}
                className="px-3.5 py-1.5 rounded-lg bg-brand-600 hover:bg-brand-700 text-white font-semibold shadow-xs transition flex items-center gap-1.5 disabled:opacity-50"
              >
                {modifyingRole ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Applying...</span>
                  </>
                ) : (
                  <>
                    <Check className="w-3.5 h-3.5" />
                    <span>Confirm Role Change</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 5. ACCOUNT STATUS MODAL (ACTIVATE / DEACTIVATE CONFIRMATION) */}
      {statusChangeTarget && (
        <div className="fixed inset-0 z-50 bg-gray-900/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-2xl border border-gray-200 w-full max-w-md overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="p-4 border-b border-gray-100 flex items-center justify-between">
              <h3 className="font-bold text-sm text-gray-900 flex items-center gap-2">
                {statusChangeAction === 'deactivate' ? (
                  <UserX className="w-4 h-4 text-rose-600" />
                ) : (
                  <UserCheck className="w-4 h-4 text-emerald-600" />
                )}
                Confirm Account {statusChangeAction === 'deactivate' ? 'Deactivation' : 'Activation'}
              </h3>
              <button
                onClick={() => setStatusChangeTarget(null)}
                className="p-1 text-gray-400 hover:text-gray-700 rounded transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-3 text-xs">
              <p className="text-gray-700">
                Are you sure you want to{' '}
                <strong className={statusChangeAction === 'deactivate' ? 'text-rose-700' : 'text-emerald-700'}>
                  {statusChangeAction}
                </strong>{' '}
                the account for <strong className="text-gray-900">@{statusChangeTarget.username}</strong> (
                {statusChangeTarget.full_name || 'No display name'})?
              </p>

              {statusChangeAction === 'deactivate' && (
                <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-rose-800 text-[11px]">
                  <strong>Warning:</strong> Deactivated accounts are immediately blocked from logging in. Any active JWT session tokens will be invalidated upon next token inspection.
                </div>
              )}
            </div>

            <div className="p-3.5 bg-gray-50 border-t border-gray-100 flex items-center justify-end gap-2 text-xs">
              <button
                onClick={() => setStatusChangeTarget(null)}
                disabled={modifyingStatus}
                className="px-3 py-1.5 rounded-lg border border-gray-200 text-gray-700 hover:bg-gray-100 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleStatusChangeConfirm}
                disabled={modifyingStatus}
                className={`px-3.5 py-1.5 rounded-lg font-semibold text-white shadow-xs transition flex items-center gap-1.5 ${
                  statusChangeAction === 'deactivate'
                    ? 'bg-rose-600 hover:bg-rose-700'
                    : 'bg-emerald-600 hover:bg-emerald-700'
                }`}
              >
                {modifyingStatus ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Processing...</span>
                  </>
                ) : (
                  <span>Confirm {statusChangeAction === 'deactivate' ? 'Deactivation' : 'Activation'}</span>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
