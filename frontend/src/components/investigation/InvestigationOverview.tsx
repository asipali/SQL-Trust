import { useState, useMemo, useEffect } from 'react'
import {
  FolderLock,
  ListTodo,
  MessageSquare,
  AlertOctagon,
  CheckCircle2,
  Clock,
  User,
  Link2,
  RefreshCw,
  PlusCircle,
  FileCheck,
  Search,
  AlertCircle
} from 'lucide-react'
import { InvestigationCase } from '../../types/investigation'
import { UserSession } from '../../types/auth'
import { normalizeCasesResponse } from '../../utils/normalizeCases'
import { ScrollReveal } from '../common/ScrollReveal'

interface InvestigationOverviewProps {
  cases: InvestigationCase[] | unknown
  loading: boolean
  error?: string | null
  onRefresh: () => void
  currentSession: UserSession | null
}

type StatusFilterType = 'ALL' | 'NEW' | 'TRIAGED' | 'IN_PROGRESS' | 'RESOLVED' | 'CLOSED'

export function InvestigationOverview({
  cases: rawCases,
  loading,
  error: externalError,
  onRefresh,
  currentSession
}: InvestigationOverviewProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilterType>('ALL')
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'workflow' | 'evidence' | 'response_plan' | 'notes'>('workflow')

  // Safely normalize cases using the normalization layer
  const { cases, normalizationError } = useMemo(() => {
    try {
      if (rawCases === undefined || rawCases === null) {
        return { cases: [] as InvestigationCase[], normalizationError: null }
      }
      const normalized = normalizeCasesResponse(rawCases)
      return { cases: normalized, normalizationError: null }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Invalid investigation cases response structure'
      return { cases: [] as InvestigationCase[], normalizationError: msg }
    }
  }, [rawCases])

  const displayError = externalError || normalizationError

  // Auto-select first case when cases load or change
  useEffect(() => {
    if (cases.length > 0) {
      if (!selectedCaseId || !cases.some((c) => c.id === selectedCaseId)) {
        setSelectedCaseId(cases[0].id)
      }
    } else {
      setSelectedCaseId(null)
    }
  }, [cases, selectedCaseId])

  // Filter cases based on search term and status
  const filteredCases = useMemo(() => {
    return cases.filter((c) => {
      const term = searchTerm.trim().toLowerCase()
      const matchesSearch =
        !term ||
        c.case_number.toLowerCase().includes(term) ||
        c.title.toLowerCase().includes(term) ||
        c.target_database_name.toLowerCase().includes(term) ||
        (c.lead_investigator && c.lead_investigator.toLowerCase().includes(term)) ||
        (c.incident_category && c.incident_category.toLowerCase().includes(term))

      const matchesStatus =
        statusFilter === 'ALL' ||
        (statusFilter === 'IN_PROGRESS'
          ? c.status === 'IN_PROGRESS' || c.status === 'CONTAINMENT_IN_PROGRESS' || c.status === 'RECOVERY_IN_PROGRESS'
          : c.status === statusFilter)

      return matchesSearch && matchesStatus
    })
  }, [cases, searchTerm, statusFilter])

  const activeCase = useMemo(() => {
    if (!selectedCaseId) return filteredCases.length > 0 ? filteredCases[0] : null
    return cases.find((c) => c.id === selectedCaseId) || (filteredCases.length > 0 ? filteredCases[0] : null)
  }, [cases, filteredCases, selectedCaseId])

  const userRole = currentSession?.role || 'Admin'
  const canCreateCase = userRole === 'Admin' || userRole === 'Investigator'
  const canApprovePlan = userRole === 'Admin' || userRole === 'Reviewer'

  const formatPriority = (priority: string) => {
    switch (priority) {
      case 'P1_CRITICAL':
        return 'Critical'
      case 'P2_HIGH':
        return 'High'
      case 'P3_MEDIUM':
        return 'Medium'
      case 'P4_LOW':
        return 'Low'
      default:
        return priority
    }
  }

  const formatStatus = (status: string) => {
    switch (status) {
      case 'NEW':
        return 'New'
      case 'TRIAGED':
        return 'Triaged'
      case 'IN_PROGRESS':
        return 'In Progress'
      case 'CONTAINMENT_IN_PROGRESS':
        return 'Containment'
      case 'RECOVERY_IN_PROGRESS':
        return 'Recovery'
      case 'RESOLVED':
        return 'Resolved'
      case 'CLOSED':
        return 'Closed'
      default:
        return status
    }
  }

  const getPriorityBadgeStyle = (priority: string) => {
    switch (priority) {
      case 'P1_CRITICAL':
        return 'bg-red-50 text-red-700 border-red-200'
      case 'P2_HIGH':
        return 'bg-amber-50 text-amber-700 border-amber-200'
      case 'P3_MEDIUM':
        return 'bg-blue-50 text-blue-700 border-blue-200'
      case 'P4_LOW':
        return 'bg-gray-100 text-gray-700 border-gray-200'
      default:
        return 'bg-gray-100 text-gray-700 border-gray-200'
    }
  }

  const getStatusBadgeStyle = (status: string) => {
    switch (status) {
      case 'RESOLVED':
      case 'CLOSED':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200'
      case 'IN_PROGRESS':
      case 'CONTAINMENT_IN_PROGRESS':
      case 'RECOVERY_IN_PROGRESS':
        return 'bg-orange-50 text-brand border-orange-200 font-semibold'
      case 'TRIAGED':
        return 'bg-amber-50 text-amber-700 border-amber-200'
      case 'NEW':
        return 'bg-blue-50 text-blue-700 border-blue-200'
      default:
        return 'bg-gray-100 text-gray-700 border-gray-200'
    }
  }

  const totalCount = cases.length
  const criticalCount = cases.filter((c) => c.priority === 'P1_CRITICAL').length
  const activeCount = cases.filter(
    (c) => c.status === 'IN_PROGRESS' || c.status === 'CONTAINMENT_IN_PROGRESS' || c.status === 'NEW' || c.status === 'TRIAGED'
  ).length
  const evidenceCount = activeCase?.evidence_links?.length || 5

  return (
    <div className="space-y-6">
      {/* Editorial Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-1">
        <div>
          <h1 className="text-xl font-bold text-gray-900 tracking-tight flex items-center gap-2">
            Incident Investigations
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Active DFIR cases, cross-module evidence correlation, containment playbooks, and multi-party sign-offs.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {canCreateCase && (
            <button
              onClick={() => alert('New investigation creation: initiate from Security Alert triage or DFIR intake.')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand hover:bg-brand-600 text-white text-xs font-semibold shadow-xs transition"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              New Investigation
            </button>
          )}
          <button
            onClick={onRefresh}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-gray-200 hover:bg-gray-50 text-gray-700 text-xs font-medium shadow-xs transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-gray-500 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Error Alert Banner */}
      {displayError && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-700 flex items-start justify-between gap-3 text-xs">
          <div className="flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-red-800">Investigation Service Error</div>
              <p className="text-red-700 mt-0.5 font-mono text-[11px]">{displayError}</p>
            </div>
          </div>
          <button
            onClick={onRefresh}
            className="px-2.5 py-1 rounded-md bg-red-600 hover:bg-red-700 text-white font-medium shrink-0 transition"
          >
            Retry
          </button>
        </div>
      )}

      {/* Posture Metrics Strip */}
      <ScrollReveal direction="up" delay={0.1}>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white p-4 rounded-xl border border-gray-200/90 shadow-card">
            <div className="flex items-center justify-between text-gray-500 text-xs">
              <span className="font-semibold text-gray-700">Total Cases</span>
              <span className="p-1 rounded bg-amber-50 text-amber-700">
                <FolderLock className="w-4 h-4" />
              </span>
            </div>
            <div className="text-2xl font-bold text-gray-900 mt-2">
              {loading && totalCount === 0 ? '...' : totalCount}
            </div>
            <div className="text-[11px] text-amber-700 mt-1 font-medium">
              {activeCount} active incidents
            </div>
          </div>

          <div className="bg-white p-4 rounded-xl border border-gray-200/90 shadow-card">
            <div className="flex items-center justify-between text-gray-500 text-xs">
              <span className="font-semibold text-gray-700">Critical Priority</span>
              <span className="p-1 rounded bg-red-50 text-red-600">
                <AlertOctagon className="w-4 h-4" />
              </span>
            </div>
            <div className="text-2xl font-bold text-red-600 mt-2">
              {loading && totalCount === 0 ? '...' : criticalCount}
            </div>
            <div className="text-[11px] text-red-600 mt-1 font-medium">Immediate containment</div>
          </div>

          <div className="bg-white p-4 rounded-xl border border-gray-200/90 shadow-card">
            <div className="flex items-center justify-between text-gray-500 text-xs">
              <span className="font-semibold text-gray-700">Linked Evidence</span>
              <span className="p-1 rounded bg-orange-50 text-brand">
                <Link2 className="w-4 h-4" />
              </span>
            </div>
            <div className="text-2xl font-bold text-gray-900 mt-2">{evidenceCount}</div>
            <div className="text-[11px] text-gray-500 mt-1">Cross-Module Tamper-Evident</div>
          </div>

          <div className="bg-white p-4 rounded-xl border border-gray-200/90 shadow-card">
            <div className="flex items-center justify-between text-gray-500 text-xs">
              <span className="font-semibold text-gray-700">Assigned Persona</span>
              <span className="p-1 rounded bg-purple-50 text-purple-700">
                <User className="w-4 h-4" />
              </span>
            </div>
            <div className="text-lg font-bold text-purple-700 mt-2">{userRole}</div>
            <div className="text-[11px] text-gray-500 mt-1">
              {canCreateCase ? '✓ Investigation Lead' : canApprovePlan ? '✓ Approver (SoD)' : '✓ Auditor View'}
            </div>
          </div>
        </div>
      </ScrollReveal>

      {/* Main Grid: Cases List and Case Dossier Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Filter Controls and Cases List (5 Cols) */}
        <div className="lg:col-span-5 bg-white rounded-xl border border-gray-200/90 shadow-card p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-gray-900 flex items-center gap-2">
              <FolderLock className="w-4 h-4 text-brand" />
              Incidents ({filteredCases.length})
            </h2>
            {loading && (
              <span className="text-[11px] text-gray-500 flex items-center gap-1">
                <RefreshCw className="w-3 h-3 animate-spin text-brand" />
                Syncing...
              </span>
            )}
          </div>

          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-gray-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search case #, title, database, analyst..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-gray-50 border border-gray-200 text-xs text-gray-900 placeholder-gray-400 focus:outline-none focus:border-brand focus:bg-white transition"
            />
          </div>

          {/* Status Filter Pills */}
          <div className="flex flex-wrap gap-1 pt-0.5">
            {(['ALL', 'IN_PROGRESS', 'NEW', 'TRIAGED', 'RESOLVED', 'CLOSED'] as StatusFilterType[]).map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition ${statusFilter === st
                  ? 'bg-orange-50 text-brand border border-orange-200 font-semibold'
                  : 'bg-gray-100 text-gray-600 hover:text-gray-900 hover:bg-gray-200/70'
                  }`}
              >
                {st === 'ALL' ? 'All' : formatStatus(st)}
              </button>
            ))}
          </div>

          {/* Case List Scroll Area */}
          <div className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
            {loading && cases.length === 0 ? (
              <div className="py-12 text-center text-gray-400 text-xs flex flex-col items-center justify-center gap-2">
                <RefreshCw className="w-5 h-5 animate-spin text-brand" />
                <span>Loading investigation cases from control repository...</span>
              </div>
            ) : filteredCases.length === 0 ? (
              <div className="py-12 px-4 text-center rounded-lg bg-gray-50 border border-gray-200 text-xs text-gray-500 space-y-2">
                <FolderLock className="w-8 h-8 text-gray-300 mx-auto" />
                <div className="font-semibold text-gray-700">
                  {cases.length === 0 ? 'No Investigation Cases' : 'No Matching Cases Found'}
                </div>
                <p className="text-[11px] text-gray-500">
                  {cases.length === 0
                    ? 'No cyber investigation cases exist yet. Security incident alerts or automated intake will trigger new cases.'
                    : `No cases matched search "${searchTerm}" with filter "${statusFilter}".`}
                </p>
                {cases.length > 0 && (
                  <button
                    onClick={() => {
                      setSearchTerm('')
                      setStatusFilter('ALL')
                    }}
                    className="mt-2 text-brand hover:text-brand-600 text-xs font-semibold"
                  >
                    Reset filters
                  </button>
                )}
              </div>
            ) : (
              filteredCases.map((c) => {
                const isSelected = activeCase?.id === c.id
                return (
                  <div
                    key={c.id}
                    onClick={() => setSelectedCaseId(c.id)}
                    className={`p-3.5 rounded-lg border cursor-pointer transition ${isSelected
                      ? 'bg-orange-50/60 border-brand shadow-xs'
                      : 'bg-white border-gray-200 hover:border-gray-300 hover:bg-gray-50/60'
                      }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-gray-900">
                        {c.case_number}
                      </span>
                      <span
                        className={`px-2 py-0.2 rounded text-[10px] font-semibold border ${getPriorityBadgeStyle(
                          c.priority
                        )}`}
                      >
                        {formatPriority(c.priority)}
                      </span>
                    </div>
                    <div className="text-xs font-semibold text-gray-900 mt-1 line-clamp-1">
                      {c.title}
                    </div>
                    <div className="text-[11px] text-gray-500 mt-0.5">
                      Target: <strong className="text-gray-700">{c.target_database_name}</strong>
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-gray-500 mt-2 pt-2 border-t border-gray-100">
                      <span>Lead: {c.lead_investigator || 'Unassigned'}</span>
                      <span
                        className={`px-1.5 py-0.2 rounded text-[10px] border ${getStatusBadgeStyle(
                          c.status
                        )}`}
                      >
                        {formatStatus(c.status)}
                      </span>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </div>

        {/* Right Column: Case Dossier Details (7 Cols) */}
        <div className="lg:col-span-7 bg-white rounded-xl border border-gray-200/90 shadow-card p-5 space-y-4">
          {activeCase ? (
            <>
              {/* Case Header */}
              <div className="border-b border-gray-200 pb-3 flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-gray-900">
                      {activeCase.case_number}
                    </span>
                    <span
                      className={`px-2 py-0.2 rounded text-[10px] font-semibold border ${getPriorityBadgeStyle(
                        activeCase.priority
                      )}`}
                    >
                      {formatPriority(activeCase.priority)}
                    </span>
                    <span
                      className={`px-2 py-0.2 rounded text-[10px] font-semibold border ${getStatusBadgeStyle(
                        activeCase.status
                      )}`}
                    >
                      {formatStatus(activeCase.status)}
                    </span>
                  </div>
                  <h2 className="text-sm font-bold text-gray-900 mt-1">{activeCase.title}</h2>
                  <p className="text-xs text-gray-500 mt-0.5">{activeCase.description || 'No description provided.'}</p>
                </div>

                <div className="text-right text-xs shrink-0">
                  <div className="text-gray-500">Severity Score</div>
                  <div className="text-lg font-bold text-red-600 font-mono">
                    {typeof activeCase.severity_score === 'number'
                      ? activeCase.severity_score.toFixed(1)
                      : activeCase.severity_score || '0.0'}{' '}
                    / 10.0
                  </div>
                </div>
              </div>

              {/* Sub-tab Navigation */}
              <div className="flex items-center gap-1 bg-gray-100 p-1 rounded-lg border border-gray-200 text-xs overflow-x-auto whitespace-nowrap">
                <button
                  onClick={() => setActiveTab('workflow')}
                  className={`px-3 py-1.5 rounded-md transition font-medium flex items-center gap-1.5 ${activeTab === 'workflow'
                    ? 'bg-white text-gray-900 font-semibold shadow-xs'
                    : 'text-gray-600 hover:text-gray-900'
                    }`}
                >
                  <ListTodo className="w-3.5 h-3.5" />
                  Playbook Tasks
                </button>
                <button
                  onClick={() => setActiveTab('evidence')}
                  className={`px-3 py-1.5 rounded-md transition font-medium flex items-center gap-1.5 ${activeTab === 'evidence'
                    ? 'bg-white text-gray-900 font-semibold shadow-xs'
                    : 'text-gray-600 hover:text-gray-900'
                    }`}
                >
                  <Link2 className="w-3.5 h-3.5" />
                  Linked Evidence ({evidenceCount})
                </button>
                <button
                  onClick={() => setActiveTab('response_plan')}
                  className={`px-3 py-1.5 rounded-md transition font-medium flex items-center gap-1.5 ${activeTab === 'response_plan'
                    ? 'bg-white text-gray-900 font-semibold shadow-xs'
                    : 'text-gray-600 hover:text-gray-900'
                    }`}
                >
                  <FileCheck className="w-3.5 h-3.5" />
                  Response Plan & SoD
                </button>
                <button
                  onClick={() => setActiveTab('notes')}
                  className={`px-3 py-1.5 rounded-md transition font-medium flex items-center gap-1.5 ${activeTab === 'notes'
                    ? 'bg-white text-gray-900 font-semibold shadow-xs'
                    : 'text-gray-600 hover:text-gray-900'
                    }`}
                >
                  <MessageSquare className="w-3.5 h-3.5" />
                  Analyst Collaboration
                </button>
              </div>

              {/* Tab 1: Playbook Tasks */}
              {activeTab === 'workflow' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-gray-700">
                    <span className="font-semibold">
                      Playbook: Ransomware Containment & Clean-Room Recovery
                    </span>
                    <span className="text-emerald-700 font-medium text-[11px] bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                      3 of 4 Completed
                    </span>
                  </div>

                  <div className="space-y-2">
                    {[
                      {
                        title: 'Isolate Database Instance Network & Revoke Rogue Privileges',
                        stage: 'CONTAINMENT',
                        status: 'COMPLETED',
                        assigned: 'demo_admin',
                        priority: 'Critical'
                      },
                      {
                        title: 'Verify S3 Object Lock & Audit Log Cryptographic Integrity',
                        stage: 'EVIDENCE_PRESERVATION',
                        status: 'COMPLETED',
                        assigned: 'demo_analyst',
                        priority: 'High'
                      },
                      {
                        title: 'Deploy Pre-Attack State in Air-Gapped Clean-Room Sandbox',
                        stage: 'RECOVERY_VALIDATION',
                        status: 'COMPLETED',
                        assigned: 'demo_investigator',
                        priority: 'Critical'
                      },
                      {
                        title: 'Reviewer & CISO Sign-Off for Production Cutover',
                        stage: 'RECOVERY_VALIDATION',
                        status: 'IN_PROGRESS',
                        assigned: 'demo_reviewer',
                        priority: 'Critical'
                      }
                    ].map((t, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg bg-gray-50 border border-gray-200 flex items-center justify-between text-xs"
                      >
                        <div className="flex items-center gap-2.5">
                          {t.status === 'COMPLETED' ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                          ) : (
                            <Clock className="w-4 h-4 text-amber-600 shrink-0 animate-pulse" />
                          )}
                          <div>
                            <div className="font-semibold text-gray-900">{t.title}</div>
                            <div className="text-[11px] text-gray-500 flex items-center gap-2 mt-0.5">
                              <span>Stage: {t.stage}</span>
                              <span>•</span>
                              <span>Assigned: {t.assigned}</span>
                            </div>
                          </div>
                        </div>

                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${t.status === 'COMPLETED'
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : 'bg-amber-50 text-amber-700 border-amber-200'
                            }`}
                        >
                          {t.status === 'COMPLETED' ? 'Completed' : 'In Progress'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tab 2: Linked Evidence */}
              {activeTab === 'evidence' && (
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-gray-700 mb-2">
                    Polymorphic Cross-Module Evidence Links (Tamper-Evident SHA-256)
                  </div>
                  {activeCase.evidence_links && activeCase.evidence_links.length > 0 ? (
                    activeCase.evidence_links.map((ev, idx) => (
                      <div
                        key={ev.id || idx}
                        className="p-3 rounded-lg bg-gray-50 border border-gray-200 text-xs flex items-center justify-between"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-gray-200 text-gray-700">
                              {ev.source_module}
                            </span>
                            <span className="font-semibold text-gray-900">
                              {ev.source_entity}: {ev.evidence_role}
                            </span>
                          </div>
                          <div className="font-mono text-[10px] text-gray-500 mt-1">
                            SHA-256: {ev.sha256_hash || 'Verified by Storage WORM'}
                          </div>
                        </div>
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          {ev.tamper_status || 'VERIFIED'}
                        </span>
                      </div>
                    ))
                  ) : (
                    [
                      {
                        module: 'SECURITY',
                        type: 'SecurityAlert',
                        title: 'Primary Privilege Escalation Alert (RULE_002)',
                        hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
                      },
                      {
                        module: 'SECURITY',
                        type: 'SecurityAlert',
                        title: 'Ransomware Schema Canary Alert (RULE_005)',
                        hash: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
                      },
                      {
                        module: 'FORENSICS',
                        type: 'ForensicBaseline',
                        title: 'Golden Reference Baseline v1 (148 Objects)',
                        hash: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
                      },
                      {
                        module: 'RECOVERY',
                        type: 'RecoveryPoint',
                        title: 'Clean Pre-Attack Recovery Point (94.5% Trust Score)',
                        hash: 'fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9'
                      },
                      {
                        module: 'RESTORE',
                        type: 'RecoveryJob',
                        title: 'Validated Air-Gapped Sandbox Restore Job (0 DBCC Errors)',
                        hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4'
                      }
                    ].map((ev, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg bg-gray-50 border border-gray-200 text-xs flex items-center justify-between"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-gray-200 text-gray-700">
                              {ev.module}
                            </span>
                            <span className="font-semibold text-gray-900">{ev.title}</span>
                          </div>
                          <div className="font-mono text-[10px] text-gray-500 mt-1">
                            SHA-256: {ev.hash}
                          </div>
                        </div>
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          VERIFIED
                        </span>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab 3: Response Plan & SoD */}
              {activeTab === 'response_plan' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-xs font-bold text-gray-900">
                        Plan: ERP Ransomware Remediation & Production Recovery Plan
                      </div>
                      <div className="text-[11px] text-gray-500 mt-0.5">
                        Status: <strong className="text-emerald-700 font-semibold">ACTIVE (v1)</strong> • Approved by: <strong className="text-gray-800">demo_reviewer</strong>
                      </div>
                    </div>
                    {canApprovePlan && (
                      <button
                        onClick={() => alert('Plan approval confirmed under dual-control separation of duties.')}
                        className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold shadow-xs"
                      >
                        Sign-Off Plan
                      </button>
                    )}
                  </div>

                  <div className="space-y-2">
                    {[
                      {
                        step: '1. Revoke Compromised Principal Credentials',
                        type: 'CONTAINMENT',
                        status: 'EXECUTED_SUCCESS',
                        actor: 'demo_admin',
                        script: 'ALTER LOGIN [db_compromised_app] DISABLE; REVOKE CONNECT SQL...'
                      },
                      {
                        step: '2. Validate Immutable Backup Chain in Sandbox',
                        type: 'RECOVERY_PREPARATION',
                        status: 'EXECUTED_SUCCESS',
                        actor: 'demo_investigator',
                        script: 'RESTORE DATABASE SQLTrust_DemoEnterprise_ERP_Sandbox FROM DISK=...'
                      },
                      {
                        step: '3. Authorize Production Database Cutover',
                        type: 'POST_INCIDENT',
                        status: 'PENDING_APPROVAL',
                        actor: 'demo_reviewer',
                        script: '-- Production cutover script awaiting final dual-control approval'
                      }
                    ].map((act, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 rounded-lg bg-gray-50 border border-gray-200 text-xs space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-gray-900">{act.step}</span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${act.status === 'EXECUTED_SUCCESS'
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                              : 'bg-purple-50 text-purple-700 border-purple-200'
                              }`}
                          >
                            {act.status === 'EXECUTED_SUCCESS' ? 'Executed' : 'Pending Approval'}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-gray-700 bg-white p-2 rounded border border-gray-200">
                          {act.script}
                        </div>
                        <div className="text-[11px] text-gray-500">
                          Operator / Approver: <strong className="text-gray-800">{act.actor}</strong>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tab 4: Analyst Collaboration */}
              {activeTab === 'notes' && (
                <div className="space-y-3">
                  <div className="text-xs font-semibold text-gray-700 mb-2">
                    Analyst Collaboration & Separation of Duties Audit Notes
                  </div>
                  <div className="space-y-2">
                    {activeCase.notes && activeCase.notes.length > 0 ? (
                      activeCase.notes.map((note) => (
                        <div
                          key={note.id}
                          className="p-3.5 rounded-lg bg-gray-50 border border-gray-200 text-xs space-y-1"
                        >
                          <div className="flex items-center justify-between text-gray-500">
                            <strong className="text-gray-900">{note.author} ({note.note_type})</strong>
                            <span className="text-[11px]">
                              {new Date(note.created_at).toLocaleTimeString()}
                            </span>
                          </div>
                          <p className="text-gray-700">{note.content}</p>
                        </div>
                      ))
                    ) : (
                      <>
                        <div className="p-3.5 rounded-lg bg-gray-50 border border-gray-200 text-xs space-y-1">
                          <div className="flex items-center justify-between text-gray-500">
                            <strong className="text-brand">demo_investigator (Lead DFIR)</strong>
                            <span className="text-[11px]">15 mins ago</span>
                          </div>
                          <p className="text-gray-700">
                            Sandbox verification completed with 0 errors. Trust score of 94.5% is supported by full LSN continuity and pre-attack timestamp. Requesting final sign-off.
                          </p>
                        </div>

                        <div className="p-3.5 rounded-lg bg-gray-50 border border-gray-200 text-xs space-y-1">
                          <div className="flex items-center justify-between text-gray-500">
                            <strong className="text-emerald-700">demo_reviewer (Incident Reviewer)</strong>
                            <span className="text-[11px]">5 mins ago</span>
                          </div>
                          <p className="text-gray-700">
                            Reviewing DBCC CHECKDB reports and audit logs now. Evidence is clean. Ready to approve final action step.
                          </p>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-24 text-gray-400 text-xs space-y-2">
              <FolderLock className="w-8 h-8 text-gray-300 mx-auto" />
              <div className="font-semibold text-gray-700">No Investigation Case Selected</div>
              <p className="text-[11px] text-gray-500">
                Select an incident from the list on the left to inspect its timeline, evidence chain, and playbook status.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
