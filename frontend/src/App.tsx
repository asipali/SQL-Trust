import { useEffect, useState } from 'react'
import axios from 'axios'
import { motion, AnimatePresence } from 'framer-motion'
import { ShieldAlert, Lock, ArrowLeft } from 'lucide-react'

import { TopNavbar, NavRoute } from './components/layout/TopNavbar'
import { AuthModal } from './components/auth/AuthModal'

import { ExecutiveDashboard } from './components/dashboard/ExecutiveDashboard'
import { DataProtectionView, DiscoveredDB, RegisteredDB, BackupRecord } from './components/views/DataProtectionView'
import { SecurityOperationsView } from './components/views/SecurityOperationsView'
import { ForensicsView } from './components/views/ForensicsView'
import { CyberRecoveryView } from './components/views/CyberRecoveryView'
import { AdministrationView } from './components/views/AdministrationView'
import { InvestigationOverview } from './components/investigation/InvestigationOverview'

import { RecoveryJob } from './types/restore'
import { InvestigationCase } from './types/investigation'
import { UserSession } from './types/auth'
import { InvestigationService } from './services/investigationService'

import { BaselineRecord, InvestigationRecord, TimelineEntry } from './types/forensics'
import {
  SecuritySource,
  SecurityEvent,
  SecurityAlert,
  EvidenceArchive,
  MonitoringHealthData
} from './types/security'
import {
  RecoveryPointRecord,
  RecoveryChainRecord,
  RecoveryAssessmentRecord,
  RecoveryRecommendationRecord,
  RecoveryHealthData
} from './types/recovery'

const API_BASE = 'http://127.0.0.1:8000'

interface ConnectionInfo {
  connected: boolean
  server_name?: string
  version?: string
  driver?: string
  error?: string
}

interface StorageHealth {
  connected: boolean
  endpoint: string
  bucket: string
  provider: string
  versioning_status: string
  object_lock_enabled: boolean
  immutability_guarantee: string
  warnings: string[]
}

export default function App() {
  const [currentRoute, setCurrentRoute] = useState<NavRoute>('dashboard')

  // Auth & Session
  const [userSession, setUserSession] = useState<UserSession | null>(() => {
    try {
      const saved = localStorage.getItem('sqltrust_session')
      return saved ? JSON.parse(saved) : null
    } catch {
      return null
    }
  })
  const [authModalOpen, setAuthModalOpen] = useState(false)
  const [authModalMode, setAuthModalMode] = useState<'login' | 'register'>('login')

  // Connection & Infrastructure
  const [connInfo, setConnInfo] = useState<ConnectionInfo | null>(null)
  const [storageHealth, setStorageHealth] = useState<StorageHealth | null>(null)

  // Data Protection (Module 1)
  const [backups, setBackups] = useState<BackupRecord[]>([])
  const [discoveredDBs, setDiscoveredDBs] = useState<DiscoveredDB[]>([])
  const [registeredDBs, setRegisteredDBs] = useState<RegisteredDB[]>([])

  // Security Operations (Module 2)
  const [secHealth, setSecHealth] = useState<MonitoringHealthData | null>(null)
  const [secAlerts, setSecAlerts] = useState<SecurityAlert[]>([])
  const [secEvents, setSecEvents] = useState<SecurityEvent[]>([])
  const [secEvidence, setSecEvidence] = useState<EvidenceArchive[]>([])
  const [secSources, setSecSources] = useState<SecuritySource[]>([])
  const [collecting, setCollecting] = useState(false)

  // Forensics (Module 3)
  const [baselines, setBaselines] = useState<BaselineRecord[]>([])
  const [investigations, setInvestigations] = useState<InvestigationRecord[]>([])
  const [selectedInvestigation, setSelectedInvestigation] = useState<InvestigationRecord | null>(null)
  const [forensicTimeline, setForensicTimeline] = useState<TimelineEntry[]>([])
  const [capturingBaseline, setCapturingBaseline] = useState(false)
  const [runningCompare, setRunningCompare] = useState(false)

  // Recovery (Module 4)
  const [recoveryHealth, setRecoveryHealth] = useState<RecoveryHealthData | null>(null)
  const [recoveryPoints, setRecoveryPoints] = useState<RecoveryPointRecord[]>([])
  const [recoveryChains, setRecoveryChains] = useState<RecoveryChainRecord[]>([])
  const [recoveryAssessments, setRecoveryAssessments] = useState<RecoveryAssessmentRecord[]>([])
  const [recoveryRecommendations, setRecoveryRecommendations] = useState<RecoveryRecommendationRecord[]>([])
  const [discoveringRecovery, setDiscoveringRecovery] = useState(false)

  // Sandboxed Restore (Module 5)
  const [restoreJobs, setRestoreJobs] = useState<RecoveryJob[]>([])

  // Cyber Investigations (Module 6)
  const [cyberCases, setCyberCases] = useState<InvestigationCase[]>([])
  const [cyberCasesLoading, setCyberCasesLoading] = useState(false)
  const [cyberCasesError, setCyberCasesError] = useState<string | null>(null)

  const [refreshing, setRefreshing] = useState(false)

  // Data Fetching
  const loadData = async () => {
    setRefreshing(true)
    try {
      const [connRes, storageRes, backupsRes, discRes, regRes] = await Promise.all([
        axios.post<ConnectionInfo>(`${API_BASE}/api/v1/databases/test-connection`).catch(e => ({ data: { connected: false, error: e.message } })),
        axios.get<StorageHealth>(`${API_BASE}/api/v1/storage/health`).catch(() => ({ data: null })),
        axios.get<BackupRecord[]>(`${API_BASE}/api/v1/backups`).catch(() => ({ data: [] })),
        axios.get<DiscoveredDB[]>(`${API_BASE}/api/v1/databases`).catch(() => ({ data: [] })),
        axios.get<RegisteredDB[]>(`${API_BASE}/api/v1/databases/registered`).catch(() => ({ data: [] }))
      ])

      setConnInfo(connRes.data)
      setStorageHealth(storageRes.data)
      setBackups(backupsRes.data)
      setDiscoveredDBs(discRes.data)
      setRegisteredDBs(regRes.data)

      await Promise.all([
        loadSecurityData(),
        loadForensicsData(),
        loadRecoveryData(),
        loadRestoreData(),
        loadInvestigationData()
      ])
    } catch (err) {
      console.error('Data loading error:', err)
    } finally {
      setRefreshing(false)
    }
  }

  const loadSecurityData = async () => {
    try {
      const [hRes, aRes, eRes, vRes, sRes] = await Promise.all([
        axios.get<MonitoringHealthData>(`${API_BASE}/api/v1/security/health`).catch(() => ({ data: null })),
        axios.get<SecurityAlert[]>(`${API_BASE}/api/v1/security/alerts`).catch(() => ({ data: [] })),
        axios.get<SecurityEvent[]>(`${API_BASE}/api/v1/security/events?limit=50`).catch(() => ({ data: [] })),
        axios.get<EvidenceArchive[]>(`${API_BASE}/api/v1/security/evidence`).catch(() => ({ data: [] })),
        axios.get<SecuritySource[]>(`${API_BASE}/api/v1/security/sources`).catch(() => ({ data: [] }))
      ])
      setSecHealth(hRes.data)
      setSecAlerts(aRes.data)
      setSecEvents(eRes.data)
      setSecEvidence(vRes.data)
      setSecSources(sRes.data)
    } catch (err) {
      console.error('Security data loading error:', err)
    }
  }

  const loadForensicsData = async () => {
    try {
      const [baseRes, invRes] = await Promise.all([
        axios.get<BaselineRecord[]>(`${API_BASE}/api/v1/forensics/baselines`).catch(() => ({ data: [] })),
        axios.get<InvestigationRecord[]>(`${API_BASE}/api/v1/forensics/investigations`).catch(() => ({ data: [] }))
      ])
      setBaselines(baseRes.data)
      setInvestigations(invRes.data)

      if (invRes.data.length > 0) {
        const cur = selectedInvestigation ? invRes.data.find(i => i.id === selectedInvestigation.id) || invRes.data[0] : invRes.data[0]
        setSelectedInvestigation(cur)
        axios.get<TimelineEntry[]>(`${API_BASE}/api/v1/forensics/investigations/${cur.id}/timeline`)
          .then(tRes => setForensicTimeline(tRes.data))
          .catch(() => setForensicTimeline([]))
      }
    } catch (err) {
      console.error('Forensics data loading error:', err)
    }
  }

  const loadRecoveryData = async () => {
    try {
      const [hRes, pRes, cRes, aRes, rRes] = await Promise.all([
        axios.get<RecoveryHealthData>(`${API_BASE}/api/v1/recovery/health`).catch(() => ({ data: null })),
        axios.get<RecoveryPointRecord[]>(`${API_BASE}/api/v1/recovery/points?discover=true`).catch(() => ({ data: [] })),
        axios.get<RecoveryChainRecord[]>(`${API_BASE}/api/v1/recovery/chains`).catch(() => ({ data: [] })),
        axios.get<RecoveryAssessmentRecord[]>(`${API_BASE}/api/v1/recovery/assessments`).catch(() => ({ data: [] })),
        axios.get<RecoveryRecommendationRecord[]>(`${API_BASE}/api/v1/recovery/recommendations`).catch(() => ({ data: [] }))
      ])
      setRecoveryHealth(hRes.data)
      setRecoveryPoints(pRes.data)
      setRecoveryChains(cRes.data)
      setRecoveryAssessments(aRes.data)
      setRecoveryRecommendations(rRes.data)
    } catch (err) {
      console.error('Recovery data loading error:', err)
    }
  }

  const loadRestoreData = async () => {
    try {
      const res = await axios.get<RecoveryJob[]>(`${API_BASE}/api/v1/recovery/jobs`).catch(() => ({ data: [] }))
      setRestoreJobs(res.data)
    } catch (err) {
      console.error('Restore data loading error:', err)
    }
  }

  const loadInvestigationData = async () => {
    setCyberCasesLoading(true)
    setCyberCasesError(null)
    try {
      const cases = await InvestigationService.fetchCases(API_BASE)
      setCyberCases(cases)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch investigation cases'
      setCyberCasesError(msg)
      setCyberCases([])
    } finally {
      setCyberCasesLoading(false)
    }
  }

  // Action Handlers
  const handleTriggerCollect = async () => {
    if (!secSources || secSources.length === 0) return
    setCollecting(true)
    try {
      await axios.post(`${API_BASE}/api/v1/security/sources/${secSources[0].id}/collect`)
      await loadSecurityData()
    } catch (err: any) {
      alert(err.response?.data?.detail || err.message || 'Collection failed')
    } finally {
      setCollecting(false)
    }
  }

  const handleUpdateAlertStatus = async (alertId: string, status: string, comment?: string) => {
    try {
      await axios.patch(`${API_BASE}/api/v1/security/alerts/${alertId}`, {
        status,
        comment,
        changed_by: userSession?.full_name || 'Administrator'
      })
      await loadSecurityData()
    } catch (err: any) {
      alert(err.response?.data?.detail || err.message || 'Status update failed')
    }
  }

  const handleCaptureBaseline = async (dbName: string, name?: string, notes?: string) => {
    setCapturingBaseline(true)
    try {
      await axios.post(`${API_BASE}/api/v1/forensics/baselines/capture`, {
        database_name: dbName,
        baseline_name: name || undefined,
        notes: notes || undefined,
        archive_to_worm: true
      })
      await loadForensicsData()
    } catch (err: any) {
      alert(err.response?.data?.detail || err.message || 'Capture failed')
    } finally {
      setCapturingBaseline(false)
    }
  }

  const handleRunCompare = async (refId: string, tgtId: string, name?: string) => {
    setRunningCompare(true)
    try {
      const res = await axios.post<InvestigationRecord>(`${API_BASE}/api/v1/forensics/investigations/compare`, {
        ref_baseline_id: refId,
        target_baseline_id: tgtId,
        investigation_name: name || undefined
      })
      await loadForensicsData()
      setSelectedInvestigation(res.data)
    } catch (err: any) {
      alert(err.response?.data?.detail || err.message || 'Comparison failed')
    } finally {
      setRunningCompare(false)
    }
  }

  const handleDiscoverRecovery = async () => {
    setDiscoveringRecovery(true)
    try {
      await axios.get(`${API_BASE}/api/v1/recovery/points?discover=true`)
      await loadRecoveryData()
    } catch (err: any) {
      alert(err.response?.data?.detail || err.message || 'Discovery failed')
    } finally {
      setDiscoveringRecovery(false)
    }
  }

  const handleAssessPoint = async (point: RecoveryPointRecord) => {
    try {
      await axios.post<RecoveryAssessmentRecord>(`${API_BASE}/api/v1/recovery/assessments`, {
        recovery_point_id: point.id,
        assessment_name: `Assessment_${point.database_name}_${point.recovery_point_type}`,
        archive_to_worm: true
      })
      await loadRecoveryData()
      setCurrentRoute('recovery_intelligence')
    } catch (err: any) {
      alert(err.response?.data?.detail || err.message || 'Assessment failed')
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  // Canonical Role & Route Access Validation (Strict Least Privilege)
  const userRole = (userSession?.role || 'READ_ONLY_REVIEWER').toUpperCase()
  const isSecurityAdmin = userRole.includes('ADMIN')
  const isApprover = userRole.includes('APPROVER')
  const isSeniorAnalyst = userRole.includes('SENIOR_ANALYST')
  const isInvestigator = userRole.includes('INVESTIGATION_ANALYST') || userRole.includes('INVESTIGATOR')
  const isReviewer = userRole.includes('INCIDENT_REVIEWER')
  const isAuditor = userRole.includes('AUDITOR')

  const isCurrentRouteAuthorized = (route: NavRoute): boolean => {
    if (isSecurityAdmin) return true
    switch (route) {
      case 'dashboard':
      case 'sec_overview':
      case 'sec_alerts_events':
      case 'sec_audit_activity':
        return true
      case 'backups_mgmt':
      case 'backups_history':
        return isApprover || isSeniorAnalyst || isInvestigator || isAuditor
      case 'forensics_baselines':
      case 'forensics_timeline':
      case 'evidence_vault':
        return isApprover || isSeniorAnalyst || isInvestigator || isReviewer || isAuditor
      case 'recovery_intelligence':
      case 'restore_validation':
      case 'recovery_history':
        return isApprover || isSeniorAnalyst || isInvestigator || isAuditor
      case 'investigations':
      case 'response_plans':
      case 'investigation_reports':
        return isApprover || isSeniorAnalyst || isInvestigator || isReviewer || isAuditor
      case 'admin_users':
      case 'admin_settings':
        return isSecurityAdmin // Strictly SECURITY_ADMIN only
      default:
        return false
    }
  }

  const isAuthorized = isCurrentRouteAuthorized(currentRoute)

  return (
    <div className="min-h-screen bg-canvas text-appText-primary flex flex-col font-sans antialiased w-full max-w-full overflow-x-hidden selection:bg-brand/10 selection:text-brand">
      {/* Direct-Link Horizontal Navigation */}
      <TopNavbar
        currentRoute={currentRoute}
        onNavigate={setCurrentRoute}
        apiBase={API_BASE}
        currentSession={userSession}
        onSessionChange={setUserSession}
        onRefreshAll={loadData}
        isRefreshing={refreshing}
        sqlServerConnected={connInfo?.connected ?? false}
        wormVaultConnected={storageHealth?.connected ?? false}
        alerts={secAlerts}
        counts={{
          alertsCount: secAlerts.filter(a => a.severity === 'CRITICAL' && a.status !== 'RESOLVED').length,
          casesCount: cyberCases.filter(c => c.status !== 'CLOSED' && c.status !== 'RESOLVED').length,
          backupsCount: backups.length,
          validationsCount: restoreJobs.filter(j => j.status === 'VALIDATED').length
        }}
        onOpenAuthModal={(mode) => {
          setAuthModalMode(mode)
          setAuthModalOpen(true)
        }}
      />

      {/* Main Content View Area (Fully responsive, min-w-0, fluid width up to 1720px, no horizontal overflow) */}
      <main className="flex-1 w-full max-w-[1720px] mx-auto px-3 py-4 sm:px-6 sm:py-6 lg:px-8 overflow-x-hidden min-w-0">
          <AnimatePresence mode="wait">
            {!isAuthorized ? (
              <motion.div
                key="access-denied"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                transition={{ duration: 0.2 }}
                className="max-w-2xl mx-auto my-12 bg-white rounded-2xl border border-rose-200/80 shadow-xl p-6 sm:p-10 text-center"
              >
                <div className="w-16 h-16 rounded-2xl bg-rose-50 border border-rose-200 text-rose-600 flex items-center justify-center mx-auto mb-5 shadow-sm">
                  <ShieldAlert className="w-8 h-8" />
                </div>
                <span className="inline-block px-3 py-1 rounded-full text-xs font-mono font-bold bg-rose-100 text-rose-800 mb-3">
                  HTTP 403 · FORBIDDEN
                </span>
                <h2 className="text-xl sm:text-2xl font-bold text-gray-900 tracking-tight">
                  Access Restricted
                </h2>
                <p className="mt-3 text-sm text-gray-600 leading-relaxed">
                  Your assigned role <span className="font-mono font-bold text-gray-800 bg-gray-100 px-1.5 py-0.5 rounded">{userRole}</span> does
                  not possess the required permissions to access the requested module.
                </p>
                <div className="mt-4 p-4 rounded-xl bg-gray-50 border border-gray-200 text-xs text-gray-500 text-left space-y-1.5">
                  <div className="flex justify-between">
                    <span className="font-semibold text-gray-700">Requested Route:</span>
                    <span className="font-mono text-gray-900">{currentRoute}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="font-semibold text-gray-700">Security Requirement:</span>
                    <span className="font-mono text-gray-900">Least-Privilege Role Authorization</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="font-semibold text-gray-700">Authorized Authority:</span>
                    <span className="font-mono text-gray-900">
                      {currentRoute.startsWith('admin') ? 'SECURITY_ADMIN Only' : 'Assigned Incident Role'}
                    </span>
                  </div>
                </div>
                <div className="mt-6 flex flex-col sm:flex-row items-center justify-center gap-3">
                  <button
                    onClick={() => setCurrentRoute('dashboard')}
                    className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-semibold text-sm transition shadow-sm flex items-center justify-center gap-2"
                  >
                    <ArrowLeft className="w-4 h-4" />
                    Return to Dashboard
                  </button>
                  {!userSession && (
                    <button
                      onClick={() => {
                        setAuthModalMode('login')
                        setAuthModalOpen(true)
                      }}
                      className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-gray-100 hover:bg-gray-200 text-gray-800 font-semibold text-sm transition flex items-center justify-center gap-2"
                    >
                      <Lock className="w-4 h-4" />
                      Sign In with Privileged Account
                    </button>
                  )}
                </div>
              </motion.div>
            ) : (
              <motion.div
                key={currentRoute}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.15 }}
              >
                {/* 1. OVERVIEW */}
                {currentRoute === 'dashboard' && (
                  <ExecutiveDashboard
                    alerts={secAlerts}
                    events={secEvents}
                    cases={cyberCases}
                    recoveryHealth={recoveryHealth}
                    recommendations={recoveryRecommendations}
                    restoreJobs={restoreJobs}
                    backupsCount={backups.length}
                    databasesCount={discoveredDBs.length}
                    onNavigate={setCurrentRoute}
                    onExecuteBackup={() => setCurrentRoute('backups_mgmt')}
                  />
                )}

                {/* 2. DATA PROTECTION */}
                {(currentRoute === 'backups_mgmt' || currentRoute === 'backups_history') && (
                  <DataProtectionView
                    apiBase={API_BASE}
                    discoveredDBs={discoveredDBs}
                    registeredDBs={registeredDBs}
                    backups={backups}
                    loading={refreshing}
                    onRefresh={loadData}
                    initialTab={currentRoute === 'backups_mgmt' ? 'registry' : 'history'}
                  />
                )}

                {/* 3. SECURITY OPERATIONS */}
                {(currentRoute === 'sec_overview' || currentRoute === 'sec_alerts_events' || currentRoute === 'sec_audit_activity') && (
                  <SecurityOperationsView
                    health={secHealth}
                    alerts={secAlerts}
                    events={secEvents}
                    evidenceList={secEvidence}
                    loading={refreshing}
                    collecting={collecting}
                    onTriggerCollect={handleTriggerCollect}
                    onUpdateAlertStatus={handleUpdateAlertStatus}
                    onRefresh={loadSecurityData}
                    initialTab={
                      currentRoute === 'sec_overview'
                        ? 'alerts'
                        : currentRoute === 'sec_alerts_events'
                          ? 'events'
                          : 'audit'
                    }
                  />
                )}

                {/* 4. FORENSICS */}
                {(currentRoute === 'forensics_baselines' || currentRoute === 'forensics_timeline' || currentRoute === 'evidence_vault') && (
                  <ForensicsView
                    baselines={baselines}
                    investigations={investigations}
                    selectedInvestigation={selectedInvestigation}
                    forensicTimeline={forensicTimeline}
                    discoveredDBs={discoveredDBs}
                    loading={refreshing}
                    capturingBaseline={capturingBaseline}
                    runningCompare={runningCompare}
                    onSelectInvestigation={setSelectedInvestigation}
                    onCaptureBaseline={handleCaptureBaseline}
                    onRunCompare={handleRunCompare}
                    onRefresh={loadForensicsData}
                    initialTab={
                      currentRoute === 'forensics_baselines'
                        ? 'baselines'
                        : currentRoute === 'forensics_timeline'
                          ? 'timeline'
                          : 'baselines'
                    }
                  />
                )}

                {/* 5. CYBER RECOVERY */}
                {(currentRoute === 'recovery_intelligence' || currentRoute === 'restore_validation' || currentRoute === 'recovery_history') && (
                  <CyberRecoveryView
                    health={recoveryHealth}
                    points={recoveryPoints}
                    chains={recoveryChains}
                    assessments={recoveryAssessments}
                    recommendations={recoveryRecommendations}
                    restoreJobs={restoreJobs}
                    loading={refreshing}
                    discovering={discoveringRecovery}
                    userSession={userSession}
                    onDiscover={handleDiscoverRecovery}
                    onAssessPoint={handleAssessPoint}
                    onRefresh={loadRecoveryData}
                    initialTab={
                      currentRoute === 'restore_validation'
                        ? 'validation'
                        : currentRoute === 'recovery_history'
                          ? 'points'
                          : 'trust'
                    }
                  />
                )}

                {/* 6. INVESTIGATIONS */}
                {(currentRoute === 'investigations' || currentRoute === 'response_plans') && (
                  <InvestigationOverview
                    cases={cyberCases}
                    loading={cyberCasesLoading || refreshing}
                    error={cyberCasesError}
                    onRefresh={loadInvestigationData}
                    currentSession={userSession}
                  />
                )}

                {/* 7. ADMINISTRATION */}
                {(currentRoute === 'admin_users' || currentRoute === 'admin_settings') && (
                  <AdministrationView
                    currentSession={userSession}
                    onSessionChange={setUserSession}
                    sqlConnected={connInfo?.connected ?? false}
                    sqlServerName={connInfo?.server_name || 'localhost\\SQLEXPRESS'}
                    wormConnected={storageHealth?.connected ?? false}
                    wormEndpoint={storageHealth?.endpoint || 'http://127.0.0.1:8333'}
                    wormBucket={storageHealth?.bucket || 'sqltrust-backups-locked'}
                    wormRetentionDays={30}
                    loading={refreshing}
                    onRefresh={loadData}
                    initialTab={currentRoute === 'admin_users' ? 'users' : 'infrastructure'}
                  />
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </main>

        {/* Real Sign In & Sign Up Modal with Least-Privilege Role Provisioning */}
        <AuthModal
          isOpen={authModalOpen}
          onClose={() => setAuthModalOpen(false)}
          apiBase={API_BASE}
          initialMode={authModalMode}
          onSuccess={(session) => {
            setUserSession(session)
            setAuthModalOpen(false)
            loadData()
          }}
        />
    </div>
  )
}
