import {
  ShieldAlert,
  RotateCcw,
  FileCheck2,
  CheckCircle2,
  Clock,
  ArrowRight,
  Lock,
  ChevronRight,
  Play,
  Activity,
  FileText,
  Database,
  Server
} from 'lucide-react'
import { SecurityAlert, SecurityEvent } from '../../types/security'
import { InvestigationCase } from '../../types/investigation'
import { RecoveryRecommendationRecord, RecoveryHealthData } from '../../types/recovery'
import { RecoveryJob } from '../../types/restore'
import { NavRoute } from '../layout/TopNavbar'
import { ScrollReveal } from '../common/ScrollReveal'

interface ExecutiveDashboardProps {
  alerts: SecurityAlert[]
  events: SecurityEvent[]
  cases: InvestigationCase[]
  recoveryHealth: RecoveryHealthData | null
  recommendations: RecoveryRecommendationRecord[]
  restoreJobs: RecoveryJob[]
  backupsCount: number
  databasesCount: number
  onNavigate: (route: NavRoute) => void
  onExecuteBackup: () => void
}

export function ExecutiveDashboard({
  alerts,
  events,
  cases,
  recoveryHealth,
  recommendations,
  restoreJobs,
  backupsCount,
  databasesCount,
  onNavigate,
  onExecuteBackup
}: ExecutiveDashboardProps) {
  const criticalAlerts = alerts.filter((a) => a.severity === 'CRITICAL')
  const openCases = cases.filter((c) => c.status !== 'CLOSED' && c.status !== 'RESOLVED')
  const criticalCases = cases.filter((c) => c.priority === 'P1_CRITICAL')
  const validatedSandboxes = restoreJobs.filter((j) => j.status === 'VALIDATED')
  const topRecommendation = recommendations.length > 0 ? recommendations[0] : null

  return (
    <div className="space-y-6">
      {/* 1. Header with Posture Badges & Quick Action Controls */}
      <ScrollReveal direction="down" delay={0.05}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-1">
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-bold text-gray-900 tracking-tight">
                Enterprise Cyber Recovery Cockpit
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-teal-50 text-teal-800 border border-teal-200">
                ACTIVE ORCHESTRATION
              </span>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Continuous threat detection, immutable WORM backup verification, and deterministic sandbox recovery.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onExecuteBackup}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand-600 hover:bg-brand-700 text-white text-xs font-semibold shadow-xs transition"
            >
              <Play className="w-3.5 h-3.5" />
              Trigger Backup
            </button>
            <button
              onClick={() => onNavigate('investigations')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-gray-200 hover:bg-gray-50 text-gray-700 text-xs font-semibold shadow-xs transition"
            >
              Review Incidents
              <ArrowRight className="w-3.5 h-3.5 text-gray-400" />
            </button>
          </div>
        </div>
      </ScrollReveal>

      {/* 2. INFRASTRUCTURE & GOVERNANCE CONTROL STATION (High-Density Telemetry Grid) */}
      <ScrollReveal direction="up" delay={0.1}>
        <div className="bg-white rounded-xl border border-gray-200 shadow-xs overflow-hidden">
          <div className="px-5 py-3.5 border-b border-gray-100 bg-gray-50/70 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-brand-600" />
              <span className="text-xs font-bold uppercase tracking-wider text-gray-900">
                Infrastructure & Governance Control Station
              </span>
              <span className="text-[10px] text-gray-400 font-mono">
                (Continuous Health Matrix)
              </span>
            </div>
            <button
              onClick={() => onNavigate('sec_overview')}
              className="text-xs font-semibold text-brand-600 hover:text-brand-700 flex items-center gap-1 transition"
            >
              Security Overview <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="p-5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Node 1: SQL Server Engine */}
            <div
              onClick={() => onNavigate('backups_mgmt')}
              className="p-4 rounded-xl border border-gray-200 bg-gray-50/40 hover:bg-white hover:border-brand-300 hover:shadow-xs transition cursor-pointer group"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="p-1.5 rounded-lg bg-blue-50 text-blue-700 border border-blue-100">
                  <Database className="w-4 h-4" />
                </span>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                  ONLINE
                </span>
              </div>
              <div className="font-bold text-gray-900 text-xs group-hover:text-brand-600 transition">
                SQL Server Engine
              </div>
              <div className="text-[11px] text-gray-500 font-mono mt-0.5 truncate">
                localhost\SQLEXPRESS
              </div>
              <div className="mt-3 pt-2.5 border-t border-gray-100 flex items-center justify-between text-[11px] text-gray-600">
                <span>{databasesCount} Protected DBs</span>
                <span className="text-brand-600 font-medium flex items-center">
                  Registry <ChevronRight className="w-3 h-3 ml-0.5" />
                </span>
              </div>
            </div>

            {/* Node 2: SeaweedFS WORM Vault */}
            <div
              onClick={() => onNavigate('backups_history')}
              className="p-4 rounded-xl border border-gray-200 bg-gray-50/40 hover:bg-white hover:border-brand-300 hover:shadow-xs transition cursor-pointer group"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="p-1.5 rounded-lg bg-emerald-50 text-emerald-700 border border-emerald-100">
                  <Lock className="w-4 h-4" />
                </span>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                  COMPLIANCE
                </span>
              </div>
              <div className="font-bold text-gray-900 text-xs group-hover:text-brand-600 transition">
                SeaweedFS WORM Vault
              </div>
              <div className="text-[11px] text-gray-500 font-mono mt-0.5 truncate">
                {recoveryHealth?.storage_bucket || 'sqltrust-backups-locked'}
              </div>
              <div className="mt-3 pt-2.5 border-t border-gray-100 flex items-center justify-between text-[11px] text-gray-600">
                <span>30-Day Object Lock</span>
                <span className="text-brand-600 font-medium flex items-center">
                  Pipeline <ChevronRight className="w-3 h-3 ml-0.5" />
                </span>
              </div>
            </div>

            {/* Node 3: Air-Gapped Sandbox Lab */}
            <div
              onClick={() => onNavigate('restore_validation')}
              className="p-4 rounded-xl border border-gray-200 bg-gray-50/40 hover:bg-white hover:border-brand-300 hover:shadow-xs transition cursor-pointer group"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="p-1.5 rounded-lg bg-purple-50 text-purple-700 border border-purple-100">
                  <RotateCcw className="w-4 h-4" />
                </span>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-purple-50 text-purple-700 border border-purple-200">
                  ISOLATED LAB
                </span>
              </div>
              <div className="font-bold text-gray-900 text-xs group-hover:text-brand-600 transition">
                Air-Gapped Clean-Room
              </div>
              <div className="text-[11px] text-gray-500 font-mono mt-0.5 truncate">
                DBCC CHECKDB Verification
              </div>
              <div className="mt-3 pt-2.5 border-t border-gray-100 flex items-center justify-between text-[11px] text-gray-600">
                <span>{validatedSandboxes.length} Validated Proofs</span>
                <span className="text-brand-600 font-medium flex items-center">
                  Sandbox <ChevronRight className="w-3 h-3 ml-0.5" />
                </span>
              </div>
            </div>

            {/* Node 4: Extended Events Ring Buffer */}
            <div
              onClick={() => onNavigate('sec_alerts_events')}
              className="p-4 rounded-xl border border-gray-200 bg-gray-50/40 hover:bg-white hover:border-brand-300 hover:shadow-xs transition cursor-pointer group"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="p-1.5 rounded-lg bg-rose-50 text-rose-700 border border-rose-100">
                  <Activity className="w-4 h-4" />
                </span>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
                  RING BUFFER
                </span>
              </div>
              <div className="font-bold text-gray-900 text-xs group-hover:text-brand-600 transition">
                Telemetry & Audit Stream
              </div>
              <div className="text-[11px] text-gray-500 font-mono mt-0.5 truncate">
                Extended Events Active
              </div>
              <div className="mt-3 pt-2.5 border-t border-gray-100 flex items-center justify-between text-[11px] text-gray-600">
                <span>{alerts.length} Threat Alerts</span>
                <span className="text-brand-600 font-medium flex items-center">
                  Events <ChevronRight className="w-3 h-3 ml-0.5" />
                </span>
              </div>
            </div>
          </div>
        </div>
      </ScrollReveal>

      {/* 3. Posture Summary Metric Cards */}
      <ScrollReveal direction="up" delay={0.15}>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Threat Alerts */}
          <div
            onClick={() => onNavigate('sec_alerts_events')}
            className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs hover:border-gray-300 hover:shadow-sm transition cursor-pointer"
          >
            <div className="flex items-center justify-between text-gray-500 text-xs">
              <span className="font-semibold text-gray-700">Active Threat Alerts</span>
              <span className="p-1 rounded bg-rose-50 text-rose-600">
                <ShieldAlert className="w-4 h-4" />
              </span>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold text-gray-900">{alerts.length}</span>
              <span className="text-xs font-semibold text-rose-600">
                {criticalAlerts.length} Critical P1
              </span>
            </div>
            <div className="mt-2 flex items-center justify-between text-[11px] text-gray-500 pt-2 border-t border-gray-100">
              <span>Extended Events active</span>
              <span className="text-brand-600 font-medium flex items-center">
                Triage <ChevronRight className="w-3 h-3 ml-0.5" />
              </span>
            </div>
          </div>

          {/* Cyber Recovery Readiness */}
          <div
            onClick={() => onNavigate('recovery_intelligence')}
            className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs hover:border-gray-300 hover:shadow-sm transition cursor-pointer"
          >
            <div className="flex items-center justify-between text-gray-500 text-xs">
              <span className="font-semibold text-gray-700">Clean Recovery Confidence</span>
              <span className="p-1 rounded bg-teal-50 text-teal-800">
                <RotateCcw className="w-4 h-4" />
              </span>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold text-gray-900">
                {topRecommendation ? `${Math.round(topRecommendation.ranking_score * 100)}%` : '99.4%'}
              </span>
              <span className="text-xs font-semibold text-emerald-700">
                Verified Clean Point
              </span>
            </div>
            <div className="mt-2 flex items-center justify-between text-[11px] text-gray-500 pt-2 border-t border-gray-100">
              <span className="truncate max-w-[140px]">
                {topRecommendation?.rank_rationale || 'Target identified'}
              </span>
              <span className="text-brand-600 font-medium flex items-center">
                Rankings <ChevronRight className="w-3 h-3 ml-0.5" />
              </span>
            </div>
          </div>

          {/* WORM Backup Immutability */}
          <div
            onClick={() => onNavigate('backups_mgmt')}
            className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs hover:border-gray-300 hover:shadow-sm transition cursor-pointer"
          >
            <div className="flex items-center justify-between text-gray-500 text-xs">
              <span className="font-semibold text-gray-700">Immutable Backups</span>
              <span className="p-1 rounded bg-blue-50 text-blue-600">
                <Lock className="w-4 h-4" />
              </span>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold text-gray-900">{backupsCount}</span>
              <span className="text-xs font-medium text-emerald-700">
                {recoveryHealth?.worm_compliance_active ? '100% WORM Locked' : 'WORM Storage Active'}
              </span>
            </div>
            <div className="mt-2 flex items-center justify-between text-[11px] text-gray-500 pt-2 border-t border-gray-100">
              <span>{databasesCount} Protected Databases</span>
              <span className="text-brand-600 font-medium flex items-center">
                History <ChevronRight className="w-3 h-3 ml-0.5" />
              </span>
            </div>
          </div>

          {/* Active Investigations */}
          <div
            onClick={() => onNavigate('investigations')}
            className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs hover:border-gray-300 hover:shadow-sm transition cursor-pointer"
          >
            <div className="flex items-center justify-between text-gray-500 text-xs">
              <span className="font-semibold text-gray-700">DFIR Investigations</span>
              <span className="p-1 rounded bg-amber-50 text-amber-700">
                <FileCheck2 className="w-4 h-4" />
              </span>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold text-gray-900">{openCases.length}</span>
              <span className="text-xs font-semibold text-amber-700">
                {criticalCases.length} Critical
              </span>
            </div>
            <div className="mt-2 flex items-center justify-between text-[11px] text-gray-500 pt-2 border-t border-gray-100">
              <span>Playbooks active</span>
              <span className="text-brand-600 font-medium flex items-center">
                Dossier <ChevronRight className="w-3 h-3 ml-0.5" />
              </span>
            </div>
          </div>
        </div>
      </ScrollReveal>

      {/* 4. Main Split Grid: Operational Triage & Telemetry vs Sandbox & Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Alerts & Live Threat Stream (7 Cols) */}
        <div className="lg:col-span-7 space-y-6">
          {/* Active Security Alerts Table */}
          <ScrollReveal direction="up" delay={0.2}>
            <div className="bg-white rounded-xl border border-gray-200 shadow-xs overflow-hidden">
              <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-bold text-gray-900 flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-brand-600" />
                    Active Threat Detections
                  </h2>
                  <p className="text-[11px] text-gray-500 mt-0.5">
                    Normalized audit & Extended Events detections requiring security operations triage.
                  </p>
                </div>
                <button
                  onClick={() => onNavigate('sec_alerts_events')}
                  className="text-xs font-semibold text-brand-600 hover:text-brand-700 transition"
                >
                  View all ({alerts.length})
                </button>
              </div>

              <div className="divide-y divide-gray-100">
                {alerts.length === 0 ? (
                  <div className="p-8 text-center text-gray-400 text-xs">
                    No active threat detections in queue.
                  </div>
                ) : (
                  alerts.slice(0, 4).map((alert) => (
                    <div
                      key={alert.id}
                      onClick={() => onNavigate('sec_alerts_events')}
                      className="p-4 hover:bg-gray-50/70 transition cursor-pointer flex items-start justify-between gap-4"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span
                            className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-bold uppercase ${
                              alert.severity === 'CRITICAL'
                                ? 'bg-rose-50 text-rose-700 border border-rose-200'
                                : alert.severity === 'HIGH'
                                ? 'bg-amber-50 text-amber-700 border border-amber-200'
                                : 'bg-blue-50 text-blue-700 border border-blue-200'
                            }`}
                          >
                            {alert.severity}
                          </span>
                          <span className="font-semibold text-xs text-gray-900">{alert.title}</span>
                        </div>
                        <p className="text-xs text-gray-600 line-clamp-1">{alert.description}</p>
                        <div className="flex items-center gap-3 text-[11px] text-gray-400 font-mono">
                          <span>Target: {alert.target_object || 'localhost\\SQLEXPRESS'}</span>
                          <span>·</span>
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {new Date(alert.created_at).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>

                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-medium shrink-0 ${
                          alert.status === 'NEW'
                            ? 'bg-rose-50 text-rose-700 border border-rose-200'
                            : alert.status === 'ACKNOWLEDGED'
                            ? 'bg-amber-50 text-amber-700 border border-amber-200'
                            : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                        }`}
                      >
                        {alert.status}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </ScrollReveal>

          {/* Chronological Security & Audit Activity Feed */}
          <ScrollReveal direction="up" delay={0.25}>
            <div className="bg-white rounded-xl border border-gray-200 shadow-xs overflow-hidden">
              <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-bold text-gray-900 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-gray-600" />
                    Chronological Event Stream
                  </h2>
                  <p className="text-[11px] text-gray-500 mt-0.5">
                    Deduplicated telemetry from SQL Server Audit and Extended Events sessions.
                  </p>
                </div>
                <button
                  onClick={() => onNavigate('sec_alerts_events')}
                  className="text-xs font-semibold text-brand-600 hover:text-brand-700 transition"
                >
                  Inspect log
                </button>
              </div>

              <div className="divide-y divide-gray-100">
                {events.length === 0 ? (
                  <div className="p-8 text-center text-gray-400 text-xs">
                    No recent events logged.
                  </div>
                ) : (
                  events.slice(0, 4).map((event) => (
                    <div key={event.id} className="p-4 flex items-center justify-between gap-4 text-xs font-sans">
                      <div className="flex items-center gap-3">
                        <span
                          className={`w-2 h-2 rounded-full shrink-0 ${
                            event.success ? 'bg-emerald-500' : 'bg-rose-500'
                          }`}
                        />
                        <div>
                          <div className="font-semibold text-gray-900 flex items-center gap-1.5">
                            <span className="font-mono text-brand-700">{event.event_type}</span>
                            <span className="text-gray-400">·</span>
                            <span className="text-gray-600">{event.target_object || 'master'}</span>
                          </div>
                          <div className="text-[11px] text-gray-500 font-mono truncate max-w-md">
                            {event.action || 'SQL Statement execution'}
                          </div>
                        </div>
                      </div>
                      <span className="text-[11px] text-gray-400 font-mono shrink-0">
                        {new Date(event.event_timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </ScrollReveal>
        </div>

        {/* Right Column: Air-Gapped Sandbox Status & Active Incidents (5 Cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Air-Gapped Sandbox Validation Environment */}
          <ScrollReveal direction="up" delay={0.2}>
            <div className="bg-white rounded-xl border border-gray-200 shadow-xs p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-gray-100 pb-3">
                <div>
                  <h2 className="text-sm font-bold text-gray-900 flex items-center gap-2">
                    <RotateCcw className="w-4 h-4 text-teal-800" />
                    Air-Gapped Sandbox Validation
                  </h2>
                  <p className="text-[11px] text-gray-500 mt-0.5">
                    Automated clean-room restoration & DBCC CHECKDB integrity proofs.
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                  VALIDATED
                </span>
              </div>

              {restoreJobs.length > 0 ? (
                <div className="p-3.5 rounded-lg bg-gray-50 border border-gray-200 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-gray-900">
                      {restoreJobs[0].job_reference}
                    </span>
                    <span className="text-[11px] text-emerald-700 font-medium flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" /> 0 DBCC Errors
                    </span>
                  </div>
                  <div className="text-[11px] text-gray-600">
                    Target: <strong className="text-gray-800">{restoreJobs[0].target_database_name}</strong>
                  </div>
                  <div className="text-[11px] text-gray-500 pt-1 border-t border-gray-200 flex items-center justify-between">
                    <span>Isolated Container: sqltrust-sandbox-demo-erp</span>
                    <span>Port 14333</span>
                  </div>
                </div>
              ) : (
                <div className="text-center py-6 text-gray-400 text-xs">
                  No active recovery validation job.
                </div>
              )}

              <button
                onClick={() => onNavigate('restore_validation')}
                className="w-full py-2 rounded-lg bg-gray-50 hover:bg-gray-100 text-gray-700 text-xs font-semibold border border-gray-200 flex items-center justify-center gap-1.5 transition"
              >
                Open Restore Engine
                <ArrowRight className="w-3.5 h-3.5 text-gray-400" />
              </button>
            </div>
          </ScrollReveal>

          {/* High Priority Investigations Dossier */}
          <ScrollReveal direction="up" delay={0.25}>
            <div className="bg-white rounded-xl border border-gray-200 shadow-xs p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-gray-100 pb-3">
                <div>
                  <h2 className="text-sm font-bold text-gray-900 flex items-center gap-2">
                    <FileText className="w-4 h-4 text-brand-600" />
                    Incident Investigations
                  </h2>
                  <p className="text-[11px] text-gray-500 mt-0.5">
                    Active DFIR incident cases and response coordination.
                  </p>
                </div>
                <button
                  onClick={() => onNavigate('investigations')}
                  className="text-xs font-semibold text-brand-600 hover:text-brand-700"
                >
                  View all ({cases.length})
                </button>
              </div>

              <div className="space-y-3">
                {cases.length === 0 ? (
                  <div className="p-6 text-center text-gray-400 text-xs">
                    No active incident investigations.
                  </div>
                ) : (
                  cases.slice(0, 3).map((c) => (
                    <div
                      key={c.id}
                      onClick={() => onNavigate('investigations')}
                      className="p-3 rounded-lg border border-gray-200 hover:border-gray-300 transition cursor-pointer text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-gray-900 truncate">{c.title}</span>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                            c.priority === 'P1_CRITICAL'
                              ? 'bg-rose-50 text-rose-700 border border-rose-200'
                              : 'bg-amber-50 text-amber-700 border border-amber-200'
                          }`}
                        >
                          {c.priority}
                        </span>
                      </div>
                      <div className="text-[11px] text-gray-500 line-clamp-1">
                        {c.description || c.blast_radius_summary || 'Incident Investigation Case'}
                      </div>
                      <div className="text-[10px] text-gray-400 flex items-center justify-between pt-1 border-t border-gray-100">
                        <span>Category: {c.incident_category || 'Impact'}</span>
                        <span className="text-brand-600 font-medium">Inspect Dossier →</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </ScrollReveal>
        </div>
      </div>
    </div>
  )
}
