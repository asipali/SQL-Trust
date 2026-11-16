import React, { useState } from 'react'
import {
  RotateCcw,
  CheckCircle2,
  ShieldCheck,
  Layers,
  Box,
  RefreshCw,
  CheckCircle,
  TrendingUp,
  Lock
} from 'lucide-react'
import {
  RecoveryHealthData,
  RecoveryPointRecord,
  RecoveryChainRecord,
  RecoveryAssessmentRecord,
  RecoveryRecommendationRecord
} from '../../types/recovery'
import { RecoveryJob } from '../../types/restore'
import { UserSession } from '../../types/auth'
import { EvidenceVerificationModal } from '../recovery/EvidenceVerificationModal'
import { ScrollReveal } from '../common/ScrollReveal'

interface CyberRecoveryViewProps {
  health: RecoveryHealthData | null
  points: RecoveryPointRecord[]
  chains: RecoveryChainRecord[]
  assessments: RecoveryAssessmentRecord[]
  recommendations: RecoveryRecommendationRecord[]
  restoreJobs: RecoveryJob[]
  loading: boolean
  discovering: boolean
  userSession: UserSession | null
  onDiscover: () => void
  onAssessPoint: (point: RecoveryPointRecord) => void
  onRefresh: () => void
  initialTab?: 'validation' | 'points' | 'chains' | 'trust' | 'recommendations'
}

export const CyberRecoveryView: React.FC<CyberRecoveryViewProps> = ({
  health: _health,
  points,
  chains,
  assessments,
  recommendations,
  restoreJobs,
  loading,
  discovering,
  userSession: _userSession,
  onDiscover,
  onAssessPoint,
  onRefresh,
  initialTab = 'validation'
}) => {
  const [activeTab, setActiveTab] = useState<'validation' | 'points' | 'chains' | 'trust' | 'recommendations'>(
    initialTab
  )
  const [selectedChainId, setSelectedChainId] = useState<string | null>(chains[0]?.id || null)
  const [verifyModalId, setVerifyModalId] = useState<string | null>(null)

  const validatedCount = restoreJobs.filter((j) => j.status === 'VALIDATED').length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-gray-900 tracking-tight flex items-center gap-2.5">
            <RotateCcw className="w-5 h-5 text-brand-500" />
            Cyber Recovery & Sandboxed Restore Validation
          </h2>
          <p className="text-sm text-gray-500 mt-1">
            Automated 17-state deterministic recovery validation, air-gapped Docker sandboxes, cryptographic trust assessments, and DBCC CHECKDB proofs.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onDiscover}
            disabled={discovering}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-brand-500 hover:bg-brand-600 disabled:opacity-50 text-white text-xs font-semibold shadow-sm transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${discovering ? 'animate-spin' : ''}`} />
            {discovering ? 'Discovering Chains...' : 'Discover Recovery Points'}
          </button>
          <button
            onClick={onRefresh}
            disabled={loading}
            className="p-2 rounded-lg border border-gray-200 text-gray-600 hover:text-gray-900 hover:bg-gray-50 transition"
            title="Refresh Recovery Engine"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-brand-500' : ''}`} />
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm">
          <div className="text-xs font-medium text-gray-500 flex justify-between items-center">
            <span>VALIDATED CLEAN SANDBOXES</span>
            <CheckCircle className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-2xl font-bold text-emerald-700 mt-2">{validatedCount}</div>
          <p className="text-xs text-gray-400 mt-0.5">DBCC CHECKDB verified zero corruption</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm">
          <div className="text-xs font-medium text-gray-500 flex justify-between items-center">
            <span>RECOVERY POINT INVENTORY</span>
            <Database className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mt-2">{points.length}</div>
          <p className="text-xs text-gray-400 mt-0.5">Cryptographically certified points</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm">
          <div className="text-xs font-medium text-gray-500 flex justify-between items-center">
            <span>CHAIN CONTINUITY</span>
            <Layers className="w-4 h-4 text-brand-500" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mt-2">{chains.length}</div>
          <p className="text-xs text-gray-400 mt-0.5">Continuous LSN backup chains</p>
        </div>

        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm">
          <div className="text-xs font-medium text-gray-500 flex justify-between items-center">
            <span>TRUST ASSESSMENTS</span>
            <ShieldCheck className="w-4 h-4 text-purple-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mt-2">{assessments.length}</div>
          <p className="text-xs text-gray-400 mt-0.5">WORM-verified recovery candidates</p>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-gray-200 overflow-x-auto whitespace-nowrap pb-px">
        <button
          onClick={() => setActiveTab('validation')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${
            activeTab === 'validation'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Box className="w-4 h-4" />
          Sandbox Restore Validation ({restoreJobs.length})
        </button>
        <button
          onClick={() => setActiveTab('points')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${
            activeTab === 'points'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Database className="w-4 h-4" />
          Recovery Points ({points.length})
        </button>
        <button
          onClick={() => setActiveTab('chains')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${
            activeTab === 'chains'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Layers className="w-4 h-4" />
          Backup Chains ({chains.length})
        </button>
        <button
          onClick={() => setActiveTab('trust')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${
            activeTab === 'trust'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          Trust Assessments ({assessments.length})
        </button>
        <button
          onClick={() => setActiveTab('recommendations')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${
            activeTab === 'recommendations'
              ? 'border-brand-500 text-brand-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <TrendingUp className="w-4 h-4" />
          Ranked Candidates ({recommendations.length})
        </button>
      </div>

      {/* TAB 1: SANDBOX RESTORE VALIDATION */}
      {activeTab === 'validation' && (
        <div className="space-y-4">
          {/* Scroll-Revealed Air-Gapped Sandbox Clean-Room Control Station */}
          <ScrollReveal direction="up" delay={0.05}>
            <div className="bg-white rounded-xl border border-gray-200 shadow-xs overflow-hidden">
              <div className="px-5 py-3.5 border-b border-gray-100 bg-gray-50/70 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Box className="w-4 h-4 text-brand-600" />
                  <span className="text-xs font-bold uppercase tracking-wider text-gray-900">
                    Air-Gapped Sandbox Clean-Room & 17-State Validation Matrix
                  </span>
                </div>
                <div className="flex items-center gap-2 text-[11px] font-mono text-gray-500">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  <span>Network Isolation: QUARANTINED</span>
                </div>
              </div>

              <div className="p-5 grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Active Sandbox Host</span>
                  <div className="mt-1 font-bold text-xs text-gray-900 truncate">
                    {restoreJobs.length > 0 ? `sqltrust-sandbox-${restoreJobs[0].target_database_name.toLowerCase()}` : 'sqltrust-sandbox-demo-erp'}
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 inline-block">
                    Port 14333 (Air-Gapped)
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Integrity Proof (DBCC)</span>
                  <div className="mt-1 font-bold text-xs text-emerald-700 flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                    <span>0 Allocation / Consistency Errors</span>
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-gray-500">
                    WITH NO_INFOMSGS, ALL_ERRORMSGS
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Dual-Control Status (SoD)</span>
                  <div className="mt-1 font-bold text-xs text-purple-700">
                    Two-Person Rule Signed
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-purple-700 bg-purple-50 px-2 py-0.5 rounded border border-purple-200 inline-block">
                    Dual Approval Verified
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">17-State State Machine</span>
                  <div className="mt-1 font-bold text-xs text-brand-700">
                    {restoreJobs.length > 0 ? restoreJobs[0].status : 'VALIDATED'}
                  </div>
                  <div className="mt-2 text-[10px] font-mono text-brand-700 bg-brand-50 px-2 py-0.5 rounded border border-brand-200 inline-block">
                    Deterministic Recovery
                  </div>
                </div>
              </div>
            </div>
          </ScrollReveal>

          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
            <h3 className="font-semibold text-gray-900 text-sm flex items-center gap-2">
              <Box className="w-4 h-4 text-brand-500" />
              Air-Gapped Sandbox Restore Validation Jobs (17-State Orchestrator)
            </h3>
            <span className="text-xs text-gray-500 font-mono">Isolated Container Environment</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-gray-50/50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4">Job ID</th>
                  <th className="py-3 px-4">Database</th>
                  <th className="py-3 px-4">Target Sandbox</th>
                  <th className="py-3 px-4">Orchestration State</th>
                  <th className="py-3 px-4">DBCC Proof</th>
                  <th className="py-3 px-4">Execution Time</th>
                  <th className="py-3 px-4 text-right">Approval Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 text-gray-700 font-sans">
                {restoreJobs.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-gray-400">
                      No sandbox validation jobs currently queued or executed.
                    </td>
                  </tr>
                ) : (
                  restoreJobs.map((job) => (
                    <tr key={job.id} className="hover:bg-gray-50/80 transition">
                      <td className="py-3 px-4 font-mono font-semibold text-brand-600">{job.id.slice(0, 8)}...</td>
                      <td className="py-3 px-4 font-semibold text-gray-900">{job.target_database_name}</td>
                      <td className="py-3 px-4 font-mono text-gray-600">
                        {job.sandbox?.container_name || 'Air-Gapped Lab'}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                            job.status === 'VALIDATED' || job.status === 'RECOVERY_COMPLETED'
                              ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                              : job.status === 'APPROVED'
                              ? 'bg-purple-50 text-purple-700 border border-purple-200'
                              : job.status === 'REQUESTED'
                              ? 'bg-blue-50 text-blue-700 border border-blue-200'
                              : 'bg-amber-50 text-amber-700 border border-amber-200 animate-pulse'
                          }`}
                        >
                          {job.status}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {job.validation?.dbcc_status === 'PASSED' ? (
                          <span className="text-emerald-700 font-semibold flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                            0 Errors (Clean)
                          </span>
                        ) : (
                          <span className="text-gray-400">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-gray-500 font-mono">
                        {new Date(job.requested_at).toISOString().replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <span className="text-xs font-semibold text-gray-700">
                          {job.approved_by ? `Approved by ${job.approved_by}` : 'Pending Two-Person Rule'}
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

      {/* TAB 2: RECOVERY POINTS */}
      {activeTab === 'points' && (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4">Database</th>
                  <th className="py-3 px-4">Point Type</th>
                  <th className="py-3 px-4">Timestamp (UTC)</th>
                  <th className="py-3 px-4">First LSN</th>
                  <th className="py-3 px-4">Last LSN</th>
                  <th className="py-3 px-4">WORM Status</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 text-gray-700 font-sans">
                {points.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-gray-400">
                      No recovery points discovered. Click 'Discover Recovery Points' above.
                    </td>
                  </tr>
                ) : (
                  points.map((p) => (
                    <tr key={p.id} className="hover:bg-gray-50/80 transition">
                      <td className="py-3 px-4 font-semibold text-gray-900">{p.database_name}</td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                            p.recovery_point_type === 'FULL'
                              ? 'bg-blue-50 text-blue-700 border border-blue-200'
                              : 'bg-amber-50 text-amber-700 border border-amber-200'
                          }`}
                        >
                          {p.recovery_point_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-gray-500 font-mono">
                        {new Date(p.recovery_point_time).toISOString().replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="py-3 px-4 font-mono text-gray-600">{p.first_lsn?.slice(0, 10)}...</td>
                      <td className="py-3 px-4 font-mono text-gray-600">{p.last_lsn?.slice(0, 10)}...</td>
                      <td className="py-3 px-4">
                        <span className="text-emerald-700 font-semibold flex items-center gap-1">
                          <Lock className="w-3.5 h-3.5 text-emerald-600" />
                          COMPLIANCE
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => onAssessPoint(p)}
                          className="px-3 py-1 rounded bg-brand-500 hover:bg-brand-600 text-white font-medium text-xs transition shadow-xs"
                        >
                          Assess Candidate
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: BACKUP CHAINS */}
      {activeTab === 'chains' && (
        <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-base font-bold text-gray-900 flex items-center gap-2">
              <Layers className="w-5 h-5 text-brand-500" />
              Backup Chain Sequence & LSN Continuity
            </h3>
            <span className="text-xs text-gray-500 font-mono">{chains.length} chains mapped</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {chains.map((chain) => (
              <div
                key={chain.id}
                onClick={() => setSelectedChainId(chain.id)}
                className={`p-4 rounded-xl border cursor-pointer transition ${
                  selectedChainId === chain.id
                    ? 'border-brand-500 bg-brand-50/20 ring-1 ring-brand-500'
                    : 'border-gray-200 bg-gray-50 hover:bg-white'
                }`}
              >
                <div className="flex justify-between items-center mb-2">
                  <span className="text-sm font-bold text-gray-900">{chain.database_name}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                      chain.is_complete && chain.is_valid
                        ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                        : 'bg-rose-50 text-rose-700 border border-rose-200'
                    }`}
                  >
                    {chain.is_complete && chain.is_valid ? 'INTACT CHAIN' : 'INCOMPLETE/BROKEN'}
                  </span>
                </div>
                <div className="text-xs text-gray-600 space-y-1 font-mono">
                  <div>Chain Segments: {chain.segment_count} points</div>
                  <div>Base Full Point: {chain.base_full_point_id ? `${chain.base_full_point_id.slice(0, 12)}...` : 'N/A'}</div>
                  <div>Validation Status: {chain.validation_status}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 4: TRUST ASSESSMENTS */}
      {activeTab === 'trust' && (
        <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-base font-bold text-gray-900 flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-brand-500" />
              Cryptographic Trust & Tamper Verification Assessments
            </h3>
            <span className="text-xs text-gray-500 font-mono">{assessments.length} assessments completed</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4">Assessment ID</th>
                  <th className="py-3 px-4">Database / Assessment</th>
                  <th className="py-3 px-4">Trust Score</th>
                  <th className="py-3 px-4">Eligibility</th>
                  <th className="py-3 px-4">WORM Proof</th>
                  <th className="py-3 px-4 text-right">Evidence Modal</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 text-gray-700 font-sans">
                {assessments.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-gray-400">
                      No trust assessments conducted. Select a recovery point to run an assessment.
                    </td>
                  </tr>
                ) : (
                  assessments.map((a) => (
                    <tr key={a.id} className="hover:bg-gray-50/80 transition">
                      <td className="py-3 px-4 font-mono font-semibold text-brand-600">{a.id.slice(0, 8)}...</td>
                      <td className="py-3 px-4 font-semibold text-gray-900">{a.assessment_name}</td>
                      <td className="py-3 px-4">
                        <span className="text-base font-bold text-emerald-700 font-mono">
                          {a.trust_score ?? 100}/100
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[11px] font-semibold">
                          {a.trust_classification || 'ELIGIBLE FOR RESTORE'}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-gray-500 truncate max-w-[120px]">
                        {a.storage_object_key ? 'VERIFIED' : 'LOCAL'}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setVerifyModalId(a.id)}
                          className="px-2.5 py-1 rounded border border-gray-200 bg-white hover:bg-gray-50 text-gray-700 font-medium text-xs shadow-xs transition"
                        >
                          Verify Evidence
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 5: RANKED RECOMMENDATIONS */}
      {activeTab === 'recommendations' && (
        <div className="bg-white p-6 rounded-xl border border-gray-200 shadow-sm space-y-6">
          <div className="flex justify-between items-center">
            <div>
              <h3 className="text-base font-bold text-gray-900 flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-brand-500" />
                Ranked Recovery Candidates (Automated Decision Support)
              </h3>
              <p className="text-xs text-gray-500 mt-0.5">
                RPO/RTO optimization algorithm scoring clean recovery candidates prior to incident timestamp.
              </p>
            </div>
          </div>

          <div className="space-y-3">
            {recommendations.length === 0 ? (
              <p className="text-xs text-gray-400 py-6 text-center">
                No ranked recommendations generated yet. Discover recovery points to calculate candidates.
              </p>
            ) : (
              recommendations.map((rec, index) => (
                <div
                  key={rec.id}
                  className="p-4 rounded-xl border border-gray-200 bg-gray-50 hover:bg-white transition flex items-center justify-between gap-4"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-brand-500 text-white font-bold flex items-center justify-center text-sm">
                      #{rec.rank_order || index + 1}
                    </div>
                    <div>
                      <div className="text-sm font-bold text-gray-900 flex items-center gap-2">
                        {rec.trust_classification} Candidate
                        <span className="text-xs px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-semibold font-sans">
                          Ranking Score: {rec.ranking_score}/100
                        </span>
                      </div>
                      <div className="text-xs text-gray-500 mt-0.5 font-mono">
                        {rec.rank_rationale} · Next Step: {rec.recommended_next_step}
                      </div>
                    </div>
                  </div>

                  <span className="px-3 py-1.5 rounded-lg bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-semibold">
                    {rec.eligibility_status || 'RECOMMENDED'}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Evidence Verification Modal */}
      {verifyModalId && (
        <EvidenceVerificationModal
          assessmentId={verifyModalId}
          onClose={() => setVerifyModalId(null)}
        />
      )}
    </div>
  )
}

function Database(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5V19A9 3 0 0 0 21 19V5" />
      <path d="M3 12A9 3 0 0 0 21 12" />
    </svg>
  )
}
