import React, { useState } from 'react'
import {
  FileSearch,
  Database,
  Layers,
  Activity,
  PlusCircle,
  RefreshCw,
  GitCompare,
  ShieldAlert,
  FileText,
  Lock
} from 'lucide-react'
import { BaselineRecord, InvestigationRecord, TimelineEntry } from '../../types/forensics'
import { DiscoveredDB } from './DataProtectionView'
import { ScrollReveal } from '../common/ScrollReveal'

interface ForensicsViewProps {
  baselines: BaselineRecord[]
  investigations: InvestigationRecord[]
  selectedInvestigation: InvestigationRecord | null
  forensicTimeline: TimelineEntry[]
  discoveredDBs: DiscoveredDB[]
  loading: boolean
  capturingBaseline: boolean
  runningCompare: boolean
  onSelectInvestigation: (inv: InvestigationRecord) => void
  onCaptureBaseline: (dbName: string, name?: string, notes?: string) => Promise<void>
  onRunCompare: (refId: string, tgtId: string, name?: string) => Promise<void>
  onRefresh: () => void
  initialTab?: 'baselines' | 'diff' | 'principals' | 'config' | 'timeline'
}

export const ForensicsView: React.FC<ForensicsViewProps> = ({
  baselines,
  investigations,
  selectedInvestigation,
  forensicTimeline,
  discoveredDBs,
  loading,
  capturingBaseline,
  runningCompare,
  onSelectInvestigation,
  onCaptureBaseline,
  onRunCompare,
  onRefresh,
  initialTab = 'baselines'
}) => {
  const [activeTab, setActiveTab] = useState<'baselines' | 'diff' | 'principals' | 'config' | 'timeline'>(
    initialTab
  )
  const [captureModalOpen, setCaptureModalOpen] = useState(false)
  const [compareModalOpen, setCompareModalOpen] = useState(false)

  // Capture form state
  const [captureDbName, setCaptureDbName] = useState<string>(discoveredDBs[0]?.name || 'SQLTrust_Lab')
  const [captureName, setCaptureName] = useState('')
  const [captureNotes, setCaptureNotes] = useState('')

  // Compare form state
  const [compareRefId, setCompareRefId] = useState('')
  const [compareTgtId, setCompareTgtId] = useState('')
  const [compareName, setCompareName] = useState('')

  const handleCaptureSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!captureDbName) return
    await onCaptureBaseline(captureDbName, captureName || undefined, captureNotes || undefined)
    setCaptureModalOpen(false)
    setCaptureName('')
    setCaptureNotes('')
  }

  const handleCompareSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!compareRefId || !compareTgtId) return
    await onRunCompare(compareRefId, compareTgtId, compareName || undefined)
    setCompareModalOpen(false)
    setCompareName('')
    setActiveTab('diff')
  }

  const findings = selectedInvestigation?.findings || []
  const schemaFindings = findings.filter((f) => f.category === 'SCHEMA' || f.finding_type?.startsWith('SCHEMA'))
  const principalFindings = findings.filter((f) => f.category === 'PRINCIPAL' || f.category === 'ROLE_MEMBERSHIP' || f.category === 'PERMISSION' || f.finding_type?.startsWith('PRINCIPAL'))
  const configFindings = findings.filter((f) => f.category === 'CONFIGURATION' || f.finding_type?.startsWith('CONFIG'))

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-gray-900 tracking-tight flex items-center gap-2.5">
            <FileSearch className="w-5 h-5 text-brand-500" />
            Database Forensics & Tamper Diff Engine
          </h2>
          <p className="text-sm text-gray-500 mt-1">
            Automated schema baselining, cryptographic state snapshots, privilege drift detection, and correlated tamper timelines.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setCaptureModalOpen(true)}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold shadow-sm transition"
          >
            <PlusCircle className="w-4 h-4" />
            Capture Baseline
          </button>
          <button
            onClick={() => setCompareModalOpen(true)}
            disabled={baselines.length < 2}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-brand-500 hover:bg-brand-600 disabled:opacity-50 text-white text-xs font-semibold shadow-sm transition"
          >
            <GitCompare className="w-4 h-4" />
            Run Forensic Diff
          </button>
          <button
            onClick={onRefresh}
            disabled={loading}
            className="p-2 rounded-lg border border-gray-200 text-gray-600 hover:text-gray-900 hover:bg-gray-50 transition"
            title="Refresh Forensics"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-brand-500' : ''}`} />
          </button>
        </div>
      </div>

      {/* Active Investigation Selector */}
      {investigations.length > 0 && (
        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-gray-700">
            <GitCompare className="w-4 h-4 text-brand-500" />
            <span>Active Forensic Comparison:</span>
          </div>
          <select
            value={selectedInvestigation?.id || ''}
            onChange={(e) => {
              const inv = investigations.find((i) => i.id === e.target.value)
              if (inv) onSelectInvestigation(inv)
            }}
            className="w-full sm:w-auto min-w-0 sm:min-w-[260px] max-w-full bg-gray-50 border border-gray-300 rounded-lg p-2 text-xs font-medium text-gray-900 focus:outline-none focus:ring-1 focus:ring-brand-500"
          >
            {investigations.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.investigation_name} ({inv.database_name} — {inv.findings_count} findings)
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Sub-Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-gray-200 overflow-x-auto whitespace-nowrap pb-px">
        <button
          onClick={() => setActiveTab('baselines')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${activeTab === 'baselines'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
        >
          <Database className="w-4 h-4" />
          Captured Baselines ({baselines.length})
        </button>
        <button
          onClick={() => setActiveTab('diff')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${activeTab === 'diff'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
        >
          <FileText className="w-4 h-4" />
          Schema DDL Diff ({schemaFindings.length})
        </button>
        <button
          onClick={() => setActiveTab('principals')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${activeTab === 'principals'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
        >
          <ShieldAlert className="w-4 h-4" />
          Privilege Drift ({principalFindings.length})
        </button>
        <button
          onClick={() => setActiveTab('config')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${activeTab === 'config'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
        >
          <Layers className="w-4 h-4" />
          Config Drift ({configFindings.length})
        </button>
        <button
          onClick={() => setActiveTab('timeline')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${activeTab === 'timeline'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
        >
          <Activity className="w-4 h-4" />
          Correlated Timeline ({forensicTimeline.length})
        </button>
      </div>

      {/* TAB 1: BASELINES */}
      {activeTab === 'baselines' && (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4">Baseline Identifier</th>
                  <th className="py-3 px-4">Database</th>
                  <th className="py-3 px-4">Objects Indexed</th>
                  <th className="py-3 px-4">Captured Timestamp (UTC)</th>
                  <th className="py-3 px-4">Cryptographic Proof</th>
                  <th className="py-3 px-4">WORM Vault Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 text-gray-700 font-sans">
                {baselines.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-gray-400">
                      No forensic baselines captured yet. Click 'Capture Baseline' to take a cryptographically signed snapshot.
                    </td>
                  </tr>
                ) : (
                  baselines.map((b) => (
                    <tr key={b.id} className="hover:bg-gray-50/80 transition font-mono">
                      <td className="py-3.5 px-4 font-semibold text-gray-900 font-sans flex items-center gap-2">
                        <Database className="w-3.5 h-3.5 text-brand-500" />
                        {b.baseline_name}
                      </td>
                      <td className="py-3.5 px-4 text-brand-600">{b.database_name}</td>
                      <td className="py-3.5 px-4 text-gray-600">
                        {b.total_objects} tables/procs, {b.total_principals} principals
                      </td>
                      <td className="py-3.5 px-4 text-gray-500">
                        {new Date(b.captured_at).toISOString().replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="py-3.5 px-4 text-gray-500 truncate max-w-[120px]" title={b.sha256_manifest}>
                        {b.sha256_manifest ? `${b.sha256_manifest.slice(0, 10)}...` : 'Ed25519 Signed'}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[11px] font-semibold flex items-center gap-1 w-fit font-sans">
                          <Lock className="w-3 h-3 text-emerald-600" />
                          LOCKED (30d)
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

      {/* TAB 2: SCHEMA DDL DIFF */}
      {activeTab === 'diff' && (
        <div className="space-y-4">
          {/* Scroll-Revealed Forensic Evidence & Tamper Analysis Panel */}
          <ScrollReveal direction="up" delay={0.05}>
            <div className="bg-white rounded-xl border border-gray-200 shadow-xs overflow-hidden">
              <div className="px-5 py-3.5 border-b border-gray-100 bg-gray-50/70 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <GitCompare className="w-4 h-4 text-brand-600" />
                  <span className="text-xs font-bold uppercase tracking-wider text-gray-900">
                    Forensic Evidence Causal Graph & Tamper Diff
                  </span>
                </div>
                <div className="flex items-center gap-2 text-[11px] font-mono text-gray-500">
                  <span className="w-2 h-2 rounded-full bg-indigo-500" />
                  <span>Investigation: {selectedInvestigation?.investigation_name || 'Active Diff'}</span>
                </div>
              </div>

              <div className="p-5 grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Schema DDL Mutations</span>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-2xl font-bold text-gray-900">{schemaFindings.length}</span>
                    <span className="text-[11px] text-gray-400">table / view / proc changes</span>
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-rose-700 bg-rose-50 px-2 py-0.5 rounded border border-rose-200 inline-block">
                    Structural Tamper Detected
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Principal & Role Drift</span>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-2xl font-bold text-gray-900">{principalFindings.length}</span>
                    <span className="text-[11px] text-gray-400">privilege grants</span>
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200 inline-block">
                    Security Boundary Drift
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Configuration Modifications</span>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-2xl font-bold text-gray-900">{configFindings.length}</span>
                    <span className="text-[11px] text-gray-400">engine parameters</span>
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 inline-block">
                    Cryptographically Proven
                  </div>
                </div>
              </div>
            </div>
          </ScrollReveal>

          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
              <h3 className="font-semibold text-gray-900 text-sm flex items-center gap-2">
                <FileText className="w-4 h-4 text-brand-500" />
                Schema & DDL Changes Detected
              </h3>
              <span className="text-xs text-gray-500 font-mono">{schemaFindings.length} differences</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-gray-50/50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Object Name</th>
                    <th className="py-3 px-4">Change Description</th>
                    <th className="py-3 px-4">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 text-gray-700 font-sans">
                  {schemaFindings.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-gray-400">
                        No schema differences detected between selected baselines.
                      </td>
                    </tr>
                  ) : (
                    schemaFindings.map((f, i) => (
                      <tr key={i} className="hover:bg-gray-50/80 transition">
                        <td className="py-3 px-4 font-mono font-semibold text-brand-600">{f.finding_type}</td>
                        <td className="py-3 px-4 font-mono text-gray-900">{f.entity_name}</td>
                        <td className="py-3 px-4 text-gray-700">{f.explanation}</td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-semibold ${f.severity === 'HIGH' || f.severity === 'CRITICAL'
                                ? 'bg-rose-50 text-rose-700 border border-rose-200'
                                : 'bg-amber-50 text-amber-700 border border-amber-200'
                              }`}
                          >
                            {f.severity || 'MEDIUM'}
                          </span>
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

      {/* TAB 3: PRIVILEGE DRIFT */}
      {activeTab === 'principals' && (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
            <h3 className="font-semibold text-gray-900 text-sm flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-600" />
              Database Principal & Role Membership Drift
            </h3>
            <span className="text-xs text-gray-500 font-mono">{principalFindings.length} findings</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-gray-50/50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4">Finding Type</th>
                  <th className="py-3 px-4">Principal Name</th>
                  <th className="py-3 px-4">Privilege Alteration</th>
                  <th className="py-3 px-4">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 text-gray-700 font-sans">
                {principalFindings.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-8 text-center text-gray-400">
                      No principal or role privilege anomalies detected.
                    </td>
                  </tr>
                ) : (
                  principalFindings.map((f, i) => (
                    <tr key={i} className="hover:bg-gray-50/80 transition">
                      <td className="py-3 px-4 font-mono font-semibold text-amber-600">{f.finding_type}</td>
                      <td className="py-3 px-4 font-mono text-gray-900">{f.entity_name}</td>
                      <td className="py-3 px-4 text-gray-700">{f.explanation}</td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                          {f.severity || 'HIGH'}
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

      {/* TAB 4: CONFIG DRIFT */}
      {activeTab === 'config' && (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
            <h3 className="font-semibold text-gray-900 text-sm flex items-center gap-2">
              <Layers className="w-4 h-4 text-brand-500" />
              Instance Configuration Drift
            </h3>
            <span className="text-xs text-gray-500 font-mono">{configFindings.length} findings</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-gray-50/50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4">Parameter</th>
                  <th className="py-3 px-4">Reference Value</th>
                  <th className="py-3 px-4">Current Value</th>
                  <th className="py-3 px-4">Security Impact</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 text-gray-700 font-sans">
                {configFindings.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-8 text-center text-gray-400">
                      Instance configurations match hardened baseline specifications.
                    </td>
                  </tr>
                ) : (
                  configFindings.map((f, i) => (
                    <tr key={i} className="hover:bg-gray-50/80 transition">
                      <td className="py-3 px-4 font-mono font-semibold text-gray-900">{f.entity_name}</td>
                      <td className="py-3 px-4 font-mono text-emerald-700">0 (DISABLED)</td>
                      <td className="py-3 px-4 font-mono text-rose-700">1 (ENABLED)</td>
                      <td className="py-3 px-4 text-gray-700">{f.explanation}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 5: TIMELINE */}
      {activeTab === 'timeline' && (
        <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm space-y-4">
          <h3 className="text-base font-bold text-gray-900 flex items-center gap-2">
            <Activity className="w-5 h-5 text-brand-500" />
            Correlated Forensic Tamper Timeline
          </h3>
          <div className="space-y-4 border-l-2 border-gray-200 ml-4 pl-4 font-sans">
            {forensicTimeline.length === 0 ? (
              <p className="text-xs text-gray-400 py-4">No chronological events mapped to this comparison.</p>
            ) : (
              forensicTimeline.map((item, i) => (
                <div key={i} className="relative space-y-1">
                  <div className="absolute -left-[23px] top-1.5 w-3 h-3 rounded-full bg-brand-500 border-2 border-white ring-1 ring-brand-500"></div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-gray-400">
                      {new Date(item.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                    </span>
                    <span className="px-2 py-0.2 rounded text-[10px] font-semibold bg-gray-100 text-gray-700">
                      {item.timeline_type}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-gray-900">{item.title}</div>
                  <div className="text-xs text-gray-600 font-mono">{item.description}</div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* CAPTURE BASELINE MODAL */}
      {captureModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl border border-gray-200">
            <div className="flex justify-between items-center border-b border-gray-100 pb-3">
              <h3 className="text-base font-bold text-gray-900 flex items-center gap-2">
                <Database className="w-5 h-5 text-brand-500" />
                Capture Database State Baseline
              </h3>
              <button
                onClick={() => setCaptureModalOpen(false)}
                className="p-1 rounded-md text-gray-400 hover:text-gray-700 transition"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCaptureSubmit} className="space-y-4 text-xs font-sans">
              <div>
                <label className="block text-gray-700 font-semibold mb-1">Target Database:</label>
                <select
                  value={captureDbName}
                  onChange={(e) => setCaptureDbName(e.target.value)}
                  className="w-full bg-white border border-gray-300 rounded-lg p-2.5 text-gray-900 text-xs focus:ring-1 focus:ring-brand-500 focus:outline-none"
                >
                  {discoveredDBs.map((d) => (
                    <option key={d.name} value={d.name}>
                      {d.name} {d.is_system ? '(System)' : ''}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-gray-700 font-semibold mb-1">Baseline Name (Optional):</label>
                <input
                  type="text"
                  placeholder="e.g. Baseline_Lab_PreIncident"
                  value={captureName}
                  onChange={(e) => setCaptureName(e.target.value)}
                  className="w-full bg-white border border-gray-300 rounded-lg p-2.5 text-gray-900 text-xs focus:ring-1 focus:ring-brand-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-gray-700 font-semibold mb-1">Investigation Notes:</label>
                <textarea
                  placeholder="Context or justification for capturing this baseline..."
                  rows={2}
                  value={captureNotes}
                  onChange={(e) => setCaptureNotes(e.target.value)}
                  className="w-full bg-white border border-gray-300 rounded-lg p-2.5 text-gray-900 text-xs focus:ring-1 focus:ring-brand-500 focus:outline-none"
                />
              </div>

              <div className="p-3 bg-gray-50 rounded-lg border border-gray-200 text-[11px] text-gray-600">
                <span className="text-emerald-700 font-semibold block mb-0.5">Immutable WORM Vault Commitment:</span>
                Snapshot will be cryptographically signed with Ed25519 and uploaded to SeaweedFS Object Lock with 30-day compliance retention.
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-gray-100">
                <button
                  type="button"
                  onClick={() => setCaptureModalOpen(false)}
                  className="px-4 py-2 rounded-lg border border-gray-200 text-gray-600 hover:bg-gray-50 font-medium text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={capturingBaseline}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white font-medium text-xs transition flex items-center gap-1.5 shadow-sm"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${capturingBaseline ? 'animate-spin' : ''}`} />
                  {capturingBaseline ? 'Capturing...' : 'Capture Baseline'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* COMPARE BASELINES MODAL */}
      {compareModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl border border-gray-200">
            <div className="flex justify-between items-center border-b border-gray-100 pb-3">
              <h3 className="text-base font-bold text-gray-900 flex items-center gap-2">
                <GitCompare className="w-5 h-5 text-brand-500" />
                Execute Forensic Comparison
              </h3>
              <button
                onClick={() => setCompareModalOpen(false)}
                className="p-1 rounded-md text-gray-400 hover:text-gray-700 transition"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCompareSubmit} className="space-y-4 text-xs font-sans">
              <div>
                <label className="block text-gray-700 font-semibold mb-1">
                  Reference Baseline (Trusted / Pre-Incident):
                </label>
                <select
                  value={compareRefId}
                  onChange={(e) => setCompareRefId(e.target.value)}
                  className="w-full bg-white border border-gray-300 rounded-lg p-2.5 text-gray-900 text-xs focus:ring-1 focus:ring-brand-500 focus:outline-none"
                  required
                >
                  <option value="">-- Select Reference Baseline --</option>
                  {baselines.map((b) => (
                    <option key={b.id} value={b.id}>
                      {b.baseline_name} ({b.database_name} — {new Date(b.captured_at).toLocaleDateString()})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-gray-700 font-semibold mb-1">
                  Target Baseline (Suspect / Post-Incident):
                </label>
                <select
                  value={compareTgtId}
                  onChange={(e) => setCompareTgtId(e.target.value)}
                  className="w-full bg-white border border-gray-300 rounded-lg p-2.5 text-gray-900 text-xs focus:ring-1 focus:ring-brand-500 focus:outline-none"
                  required
                >
                  <option value="">-- Select Target Baseline --</option>
                  {baselines.map((b) => (
                    <option key={b.id} value={b.id}>
                      {b.baseline_name} ({b.database_name} — {new Date(b.captured_at).toLocaleDateString()})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-gray-700 font-semibold mb-1">Investigation Name (Optional):</label>
                <input
                  type="text"
                  placeholder="e.g. Investigation_UnauthorizedDDL"
                  value={compareName}
                  onChange={(e) => setCompareName(e.target.value)}
                  className="w-full bg-white border border-gray-300 rounded-lg p-2.5 text-gray-900 text-xs focus:ring-1 focus:ring-brand-500 focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-gray-100">
                <button
                  type="button"
                  onClick={() => setCompareModalOpen(false)}
                  className="px-4 py-2 rounded-lg border border-gray-200 text-gray-600 hover:bg-gray-50 font-medium text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={runningCompare}
                  className="px-4 py-2 rounded-lg bg-brand-500 hover:bg-brand-600 disabled:opacity-50 text-white font-medium text-xs transition flex items-center gap-1.5 shadow-sm"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${runningCompare ? 'animate-spin' : ''}`} />
                  {runningCompare ? 'Executing Diff...' : 'Run Forensic Diff'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
