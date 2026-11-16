import React, { useState } from 'react'
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  FileText,
  Lock,
  RefreshCw,
  Search,
  CheckCircle2
} from 'lucide-react'
import {
  MonitoringHealthData,
  SecurityAlert,
  SecurityEvent,
  EvidenceArchive
} from '../../types/security'
import { ScrollReveal } from '../common/ScrollReveal'

interface SecurityOperationsViewProps {
  health: MonitoringHealthData | null
  alerts: SecurityAlert[]
  events: SecurityEvent[]
  evidenceList: EvidenceArchive[]
  loading: boolean
  collecting: boolean
  onTriggerCollect: () => void
  onUpdateAlertStatus: (alertId: string, status: string, comment?: string) => void
  onRefresh: () => void
  initialTab?: 'alerts' | 'events' | 'audit' | 'vault'
}

export const SecurityOperationsView: React.FC<SecurityOperationsViewProps> = ({
  health,
  alerts,
  events,
  evidenceList,
  loading,
  collecting,
  onTriggerCollect,
  onUpdateAlertStatus,
  onRefresh,
  initialTab = 'alerts'
}) => {
  const [activeTab, setActiveTab] = useState<'alerts' | 'events' | 'audit' | 'vault'>(initialTab)
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('ALL')

  const criticalCount = alerts.filter((a) => a.severity === 'CRITICAL' && a.status !== 'RESOLVED').length
  const highCount = alerts.filter((a) => a.severity === 'HIGH' && a.status !== 'RESOLVED').length

  const filteredAlerts = alerts.filter((a) => {
    const matchesSearch =
      a.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.rule_id.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesSeverity = severityFilter === 'ALL' || a.severity === severityFilter
    return matchesSearch && matchesSeverity
  })

  const filteredEvents = events.filter((e) => {
    const matchesSearch =
      e.event_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (e.principal_name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (e.target_object || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (e.action || '').toLowerCase().includes(searchQuery.toLowerCase())
    return matchesSearch
  })

  return (
    <div className="space-y-6">
      {/* Header & Posture Banner */}
      <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-bold text-gray-900 tracking-tight flex items-center gap-2.5">
              <ShieldAlert className="w-5 h-5 text-brand-500" />
              Security Operations & Threat Detection
            </h2>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5" />
              {health?.overall_status || 'HEALTHY'}
            </span>
          </div>
          <p className="text-sm text-gray-500 mt-1">
            Real-time Extended Events telemetry, SQL Server Audit monitoring, automated tamper heuristics, and signed evidence vaults.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onTriggerCollect}
            disabled={collecting}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-500 hover:bg-brand-600 disabled:opacity-50 text-white text-sm font-medium shadow-sm transition"
          >
            <RefreshCw className={`w-4 h-4 ${collecting ? 'animate-spin' : ''}`} />
            {collecting ? 'Polling Telemetry...' : 'Trigger Telemetry Ingestion'}
          </button>
          <button
            onClick={onRefresh}
            disabled={loading}
            className="p-2 rounded-lg border border-gray-200 text-gray-600 hover:text-gray-900 hover:bg-gray-50 transition"
            title="Refresh Security Status"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-brand-500' : ''}`} />
          </button>
        </div>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm">
          <div className="text-xs font-medium text-gray-500 flex justify-between items-center">
            <span>ACTIVE CRITICAL THREATS</span>
            <AlertTriangle className="w-4 h-4 text-rose-500" />
          </div>
          <div className="text-2xl font-bold text-rose-600 mt-2">{criticalCount}</div>
          <p className="text-xs text-gray-400 mt-0.5">Requiring immediate containment</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm">
          <div className="text-xs font-medium text-gray-500 flex justify-between items-center">
            <span>HIGH SEVERITY ALERTS</span>
            <ShieldAlert className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-bold text-amber-600 mt-2">{highCount}</div>
          <p className="text-xs text-gray-400 mt-0.5">Suspicious privilege/schema drift</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm">
          <div className="text-xs font-medium text-gray-500 flex justify-between items-center">
            <span>TELEMETRY EVENTS (24H)</span>
            <Activity className="w-4 h-4 text-brand-500" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mt-2">{events.length}</div>
          <p className="text-xs text-gray-400 mt-0.5">Audit log & XE captured events</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm">
          <div className="text-xs font-medium text-gray-500 flex justify-between items-center">
            <span>EVIDENCE VAULT BUNDLES</span>
            <Lock className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-2xl font-bold text-emerald-700 mt-2">{evidenceList.length}</div>
          <p className="text-xs text-gray-400 mt-0.5">Cryptographically signed & locked</p>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-gray-200 overflow-x-auto whitespace-nowrap pb-px">
        <button
          onClick={() => setActiveTab('alerts')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${
            activeTab === 'alerts'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          Threat Alerts ({alerts.length})
        </button>
        <button
          onClick={() => setActiveTab('events')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${
            activeTab === 'events'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Activity className="w-4 h-4" />
          Security Event Stream ({events.length})
        </button>
        <button
          onClick={() => setActiveTab('audit')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${
            activeTab === 'audit'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <FileText className="w-4 h-4" />
          Audit & Extended Events
        </button>
        <button
          onClick={() => setActiveTab('vault')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${
            activeTab === 'vault'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Lock className="w-4 h-4" />
          Evidence Vault ({evidenceList.length})
        </button>
      </div>

      {/* TAB 1: THREAT ALERTS */}
      {activeTab === 'alerts' && (
        <div className="space-y-4">
          {/* Scroll-Revealed Threat Vector Analysis Matrix */}
          <ScrollReveal direction="up" delay={0.05}>
            <div className="bg-white rounded-xl border border-gray-200 shadow-xs overflow-hidden">
              <div className="px-5 py-3.5 border-b border-gray-100 bg-gray-50/70 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-brand-600" />
                  <span className="text-xs font-bold uppercase tracking-wider text-gray-900">
                    Threat Vector Analysis Matrix & Telemetry Posture
                  </span>
                </div>
                <div className="flex items-center gap-2 text-[11px] font-mono text-gray-500">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  <span>Ring Buffer Engine: ONLINE</span>
                </div>
              </div>

              <div className="p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">P1 Critical Alerts</span>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-2xl font-bold text-rose-600">{criticalCount}</span>
                    <span className="text-[11px] text-gray-400">of {alerts.length} total</span>
                  </div>
                  <div className="mt-2 w-full bg-gray-200 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-rose-500 h-1.5 rounded-full"
                      style={{ width: `${alerts.length > 0 ? (criticalCount / alerts.length) * 100 : 0}%` }}
                    />
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">High Severity Alerts</span>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-2xl font-bold text-amber-600">{highCount}</span>
                    <span className="text-[11px] text-gray-400">triage pending</span>
                  </div>
                  <div className="mt-2 w-full bg-gray-200 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-amber-500 h-1.5 rounded-full"
                      style={{ width: `${alerts.length > 0 ? (highCount / alerts.length) * 100 : 0}%` }}
                    />
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Extended Events Velocity</span>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-2xl font-bold text-gray-900">{events.length}</span>
                    <span className="text-[11px] text-gray-400">events in buffer</span>
                  </div>
                  <div className="mt-2 text-[11px] font-mono text-emerald-700 flex items-center gap-1">
                    <Activity className="w-3 h-3 text-emerald-600" /> Continuous Capture Active
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">MITRE ATT&CK Mapping</span>
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-50 text-rose-700 border border-rose-200">
                      T1485 Data Destruction
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-50 text-amber-700 border border-amber-200">
                      T1565 Data Tamper
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-blue-50 text-blue-700 border border-blue-200">
                      T1078 Valid Accounts
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </ScrollReveal>

          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-4 rounded-xl border border-gray-200 shadow-sm">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search alerts, rules, or details..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-gray-50 border border-gray-200 rounded-lg text-sm text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-brand-500 focus:bg-white transition"
              />
            </div>
            <div className="flex flex-wrap items-center gap-2 self-start sm:self-auto">
              <span className="text-xs font-medium text-gray-500">Severity:</span>
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setSeverityFilter(s)}
                  className={`px-2.5 py-1 rounded-md text-xs font-semibold transition ${
                    severityFilter === s
                      ? 'bg-gray-900 text-white'
                      : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Threat Rule / Title</th>
                    <th className="py-3 px-4">Target / Context</th>
                    <th className="py-3 px-4">Detected Timestamp</th>
                    <th className="py-3 px-4">Triage Status</th>
                    <th className="py-3 px-4 text-right">Triage Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 text-gray-700 font-sans">
                  {filteredAlerts.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-gray-400">
                        No security alerts matching current filter parameters.
                      </td>
                    </tr>
                  ) : (
                    filteredAlerts.map((alert) => (
                      <tr key={alert.id} className="hover:bg-gray-50/80 transition">
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                              alert.severity === 'CRITICAL'
                                ? 'bg-rose-50 text-rose-700 border border-rose-200'
                                : alert.severity === 'HIGH'
                                ? 'bg-amber-50 text-amber-700 border border-amber-200'
                                : alert.severity === 'MEDIUM'
                                ? 'bg-blue-50 text-blue-700 border border-blue-200'
                                : 'bg-gray-100 text-gray-700 border border-gray-200'
                            }`}
                          >
                            {alert.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <div className="font-semibold text-gray-900">{alert.title}</div>
                          <div className="text-gray-500 text-[11px] mt-0.5">{alert.description}</div>
                        </td>
                        <td className="py-3 px-4 font-mono text-gray-600">
                          {alert.principal_name || alert.target_object || 'SQL Server Instance'}
                        </td>
                        <td className="py-3 px-4 font-mono text-gray-500">
                          {new Date(alert.created_at).toISOString().replace('T', ' ').slice(0, 19)}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                              alert.status === 'NEW'
                                ? 'bg-rose-50 text-rose-700 border border-rose-200'
                                : alert.status === 'ACKNOWLEDGED'
                                ? 'bg-amber-50 text-amber-700 border border-amber-200'
                                : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            }`}
                          >
                            {alert.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            {alert.status === 'NEW' && (
                              <button
                                onClick={() => onUpdateAlertStatus(alert.id, 'ACKNOWLEDGED')}
                                className="px-2.5 py-1 rounded bg-amber-50 border border-amber-200 hover:bg-amber-100 text-amber-700 text-xs font-medium transition"
                              >
                                Acknowledge
                              </button>
                            )}
                            {alert.status !== 'RESOLVED' && (
                              <button
                                onClick={() => onUpdateAlertStatus(alert.id, 'RESOLVED')}
                                className="px-2.5 py-1 rounded bg-emerald-50 border border-emerald-200 hover:bg-emerald-100 text-emerald-700 text-xs font-medium transition"
                              >
                                Resolve
                              </button>
                            )}
                          </div>
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

      {/* TAB 2: SECURITY EVENT STREAM */}
      {activeTab === 'events' && (
        <div className="space-y-4">
          <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex items-center justify-between">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search SQL statement, principal, or object..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-gray-50 border border-gray-200 rounded-lg text-sm text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-brand-500 focus:bg-white transition"
              />
            </div>
            <span className="text-xs font-mono text-gray-500">{filteredEvents.length} telemetry records</span>
          </div>

          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Event Type</th>
                    <th className="py-3 px-4">Principal</th>
                    <th className="py-3 px-4">Target Object / Database</th>
                    <th className="py-3 px-4">Executed Statement</th>
                    <th className="py-3 px-4">Timestamp (UTC)</th>
                    <th className="py-3 px-4">Success</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 text-gray-700 font-sans">
                  {filteredEvents.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-gray-400">
                        No telemetry events recorded. Run a query or trigger collection above.
                      </td>
                    </tr>
                  ) : (
                    filteredEvents.map((evt) => (
                      <tr key={evt.id} className="hover:bg-gray-50/80 transition font-mono">
                        <td className="py-3 px-4 font-semibold text-gray-900">{evt.event_type}</td>
                        <td className="py-3 px-4 text-brand-600">{evt.principal_name || 'sa'}</td>
                        <td className="py-3 px-4 text-gray-600">{evt.target_object || 'master'}</td>
                        <td className="py-3 px-4 max-w-xs truncate text-gray-700" title={evt.action}>
                          {evt.action || '—'}
                        </td>
                        <td className="py-3 px-4 text-gray-500">
                          {new Date(evt.event_timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                        </td>
                        <td className="py-3 px-4 font-sans">
                          {evt.success ? (
                            <span className="text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded text-[11px] font-semibold">
                              SUCCESS
                            </span>
                          ) : (
                            <span className="text-rose-700 bg-rose-50 border border-rose-200 px-2 py-0.5 rounded text-[11px] font-semibold">
                              FAILED
                            </span>
                          )}
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

      {/* TAB 3: AUDIT CONFIGURATION */}
      {activeTab === 'audit' && (
        <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm space-y-6">
          <div>
            <h3 className="text-base font-bold text-gray-900 flex items-center gap-2">
              <FileText className="w-5 h-5 text-brand-500" />
              SQL Server Audit & Extended Events Specifications
            </h3>
            <p className="text-sm text-gray-500 mt-1">
              Active server audit specifications and lightweight event capture pipelines configured for threat monitoring.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl border border-gray-200 bg-gray-50 space-y-2">
              <span className="text-xs font-semibold uppercase text-gray-500">Server Audit Specification</span>
              <div className="text-sm font-bold text-gray-900">SQLTrust_ServerAudit_Spec</div>
              <p className="text-xs text-gray-600">
                Captures BACKUP_RESTORE_GROUP, SCHEMA_OBJECT_CHANGE_GROUP, and DATABASE_PRINCIPAL_CHANGE_GROUP.
              </p>
              <div className="pt-2 flex items-center gap-2 text-xs text-emerald-700 font-semibold">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                STATUS: ENABLED & RUNNING
              </div>
            </div>

            <div className="p-4 rounded-xl border border-gray-200 bg-gray-50 space-y-2">
              <span className="text-xs font-semibold uppercase text-gray-500">Extended Events Engine</span>
              <div className="text-sm font-bold text-gray-900">SQLTrust_XE_Session</div>
              <p className="text-xs text-gray-600">
                Zero-overhead ring buffer capturing rpc_completed, sql_statement_completed, and error_reported events.
              </p>
              <div className="pt-2 flex items-center gap-2 text-xs text-emerald-700 font-semibold">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                STATUS: ACTIVE RING BUFFER
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: EVIDENCE VAULT */}
      {activeTab === 'vault' && (
        <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm space-y-6">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-base font-bold text-gray-900 flex items-center gap-2">
                <Lock className="w-5 h-5 text-emerald-600" />
                Forensic Evidence Vault & WORM Archival Records
              </h3>
              <p className="text-sm text-gray-500 mt-1">
                Cryptographically sealed evidence bundles with Ed25519 digital signatures and SeaweedFS Object Lock compliance.
              </p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4">Archive Key</th>
                  <th className="py-3 px-4">Record Count</th>
                  <th className="py-3 px-4">SHA-256 Digest</th>
                  <th className="py-3 px-4">WORM Retention Mode</th>
                  <th className="py-3 px-4">Retain Until</th>
                  <th className="py-3 px-4 text-right">Signature Proof</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 text-gray-700 font-mono">
                {evidenceList.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-gray-400 font-sans">
                      No evidence archive bundles committed to the vault yet.
                    </td>
                  </tr>
                ) : (
                  evidenceList.map((ev) => (
                    <tr key={ev.id} className="hover:bg-gray-50/80 transition">
                      <td className="py-3 px-4 text-gray-900 font-semibold">{ev.storage_object_key}</td>
                      <td className="py-3 px-4 text-gray-600">{(ev.file_size_bytes / 1024).toFixed(1)} KB</td>
                      <td className="py-3 px-4 text-brand-600 truncate max-w-[140px]" title={ev.sha256}>
                        {ev.sha256}
                      </td>
                      <td className="py-3 px-4 text-emerald-700 font-semibold">{ev.retention_mode}</td>
                      <td className="py-3 px-4 text-gray-500">
                        {ev.retention_until ? new Date(ev.retention_until).toLocaleDateString() : 'N/A'}
                      </td>
                      <td className="py-3 px-4 text-right font-sans">
                        <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[11px] font-semibold">
                          VERIFIED
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
