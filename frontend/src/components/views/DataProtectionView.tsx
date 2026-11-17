import React, { useState } from 'react'
import {
  Database,
  Layers,
  PlusCircle,
  CheckCircle2,
  AlertCircle,
  FileText,
  Lock,
  RefreshCw,
  Search,
  ShieldCheck,
  Check
} from 'lucide-react'
import axios from 'axios'
import { ScrollReveal } from '../common/ScrollReveal'

export interface DiscoveredDB {
  database_id: number
  name: string
  state: string
  recovery_model: string
  created_at?: string
  is_system: boolean
  is_registered: boolean
  registration_id?: string
}

export interface RegisteredDB {
  id: string
  server_name: string
  database_name: string
  recovery_model: string
  registration_status: string
  created_at: string
}

export interface BackupRecord {
  id: string
  database_id: string
  database_name?: string
  backup_type: 'FULL' | 'DIFFERENTIAL' | 'LOG'
  backup_filename: string
  backup_path: string
  backup_size_bytes: number
  start_time: string
  finish_time?: string
  first_lsn?: string
  last_lsn?: string
  checkpoint_lsn?: string
  database_backup_lsn?: string
  sha256?: string
  sql_verification_status: string
  storage_upload_status: string
  storage_object_key?: string
  storage_object_version_id?: string
  retention_mode?: string
  retention_until?: string
  backup_status: string
  error_message?: string
  created_at: string
}

export interface ManifestData {
  backup_id: string
  manifest_version: string
  manifest_hash: string
  manifest_data: any
}

interface DataProtectionViewProps {
  apiBase: string
  discoveredDBs: DiscoveredDB[]
  registeredDBs: RegisteredDB[]
  backups: BackupRecord[]
  loading: boolean
  onRefresh: () => void
  initialTab?: 'registry' | 'history'
}

export const DataProtectionView: React.FC<DataProtectionViewProps> = ({
  apiBase,
  discoveredDBs,
  registeredDBs,
  backups,
  loading,
  onRefresh,
  initialTab = 'history'
}) => {
  const [activeTab, setActiveTab] = useState<'registry' | 'history'>(initialTab)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('ALL')

  // Modals
  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [selectedBackup, setSelectedBackup] = useState<BackupRecord | null>(null)
  const [manifestData, setManifestData] = useState<ManifestData | null>(null)
  const [loadingManifest, setLoadingManifest] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [verificationResult, setVerificationResult] = useState<any | null>(null)

  // Backup Form State
  const [formDbId, setFormDbId] = useState<string>(registeredDBs[0]?.id || '')
  const [formBackupType, setFormBackupType] = useState<'FULL' | 'DIFFERENTIAL' | 'LOG'>('FULL')
  const [formNotes, setFormNotes] = useState('')
  const [submittingBackup, setSubmittingBackup] = useState(false)
  const [backupError, setBackupError] = useState<string | null>(null)
  const [backupSuccess, setBackupSuccess] = useState<string | null>(null)
  const [registering, setRegistering] = useState<string | null>(null)
  const [copiedHash, setCopiedHash] = useState<string | null>(null)

  const formatBytes = (bytes: number) => {
    if (!bytes || bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const handleRegister = async (databaseName: string, isSystem: boolean) => {
    setRegistering(databaseName)
    try {
      await axios.post(`${apiBase}/api/v1/databases/register`, {
        database_name: databaseName,
        is_system: isSystem,
        allow_system_override: isSystem
      })
      onRefresh()
    } catch (err: any) {
      alert(err.response?.data?.detail || err.message || 'Database registration failed')
    } finally {
      setRegistering(null)
    }
  }

  const handleCreateBackup = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!formDbId) return

    setSubmittingBackup(true)
    setBackupError(null)
    setBackupSuccess(null)

    const endpoint =
      formBackupType === 'FULL'
        ? `${apiBase}/api/v1/backups/full`
        : formBackupType === 'DIFFERENTIAL'
          ? `${apiBase}/api/v1/backups/differential`
          : `${apiBase}/api/v1/backups/log`

    try {
      const res = await axios.post<BackupRecord>(endpoint, {
        database_id: formDbId,
        notes: formNotes || undefined
      })
      setBackupSuccess(`Backup executed successfully! Backup ID: ${res.data.id}`)
      setFormNotes('')
      onRefresh()
      setTimeout(() => {
        setCreateModalOpen(false)
        setActiveTab('history')
        setBackupSuccess(null)
      }, 1500)
    } catch (err: any) {
      setBackupError(err.response?.data?.detail || err.message || 'Backup execution failed')
    } finally {
      setSubmittingBackup(false)
    }
  }

  const handleOpenDetails = async (backup: BackupRecord) => {
    setSelectedBackup(backup)
    setVerificationResult(null)
    setLoadingManifest(true)
    try {
      const res = await axios.get<ManifestData>(`${apiBase}/api/v1/backups/${backup.id}/manifest`)
      setManifestData(res.data)
    } catch {
      setManifestData(null)
    } finally {
      setLoadingManifest(false)
    }
  }

  const handleVerifyNow = async (backupId: string) => {
    setVerifying(true)
    try {
      const res = await axios.post(`${apiBase}/api/v1/backups/${backupId}/verify`)
      setVerificationResult(res.data)
      onRefresh()
    } catch (err: any) {
      alert(err.response?.data?.detail || err.message || 'Verification failed')
    } finally {
      setVerifying(false)
    }
  }

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedHash(id)
    setTimeout(() => setCopiedHash(null), 2000)
  }

  const filteredBackups = backups.filter((b) => {
    const matchesSearch =
      (b.database_name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      b.backup_filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (b.sha256 || '').toLowerCase().includes(searchQuery.toLowerCase())
    const matchesType = typeFilter === 'ALL' || b.backup_type === typeFilter
    return matchesSearch && matchesType
  })

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-white p-6 rounded-xl border border-gray-200 shadow-sm">
        <div>
          <h2 className="text-xl font-bold text-gray-900 tracking-tight flex items-center gap-2.5">
            <Database className="w-5 h-5 text-brand-500" />
            Data Protection & Immutable Vault
          </h2>
          <p className="text-sm text-gray-500 mt-1">
            Enterprise SQL Server backup orchestration, cryptographic manifest integrity, and WORM-locked vault storage.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              if (registeredDBs.length > 0 && !formDbId) {
                setFormDbId(registeredDBs[0].id)
              }
              setCreateModalOpen(true)
            }}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-500 hover:bg-brand-600 text-white text-sm font-medium shadow-sm transition-colors"
          >
            <PlusCircle className="w-4 h-4" />
            Execute Backup
          </button>
          <button
            onClick={onRefresh}
            disabled={loading}
            className="p-2 rounded-lg border border-gray-200 text-gray-600 hover:text-gray-900 hover:bg-gray-50 transition"
            title="Refresh Backups"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-brand-500' : ''}`} />
          </button>
        </div>
      </div>

      {/* View Switcher Tabs */}
      <div className="flex items-center gap-2 border-b border-gray-200 overflow-x-auto whitespace-nowrap pb-px">
        <button
          onClick={() => setActiveTab('history')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${activeTab === 'history'
            ? 'border-brand-500 text-brand-600'
            : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
        >
          <Layers className="w-4 h-4" />
          Backup Execution History ({backups.length})
        </button>
        <button
          onClick={() => setActiveTab('registry')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition -mb-px ${activeTab === 'registry'
            ? 'border-brand-500 text-brand-600'
            : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
        >
          <Database className="w-4 h-4" />
          Discovered & Protected Databases ({discoveredDBs.length})
        </button>
      </div>

      {/* TAB 1: BACKUP HISTORY */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          {/* Scroll-Revealed Ingestion Pipeline Architecture Panel */}
          <ScrollReveal direction="up" delay={0.05}>
            <div className="bg-white rounded-xl border border-gray-200 shadow-xs overflow-hidden">
              <div className="px-5 py-3.5 border-b border-gray-100 bg-gray-50/70 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-brand-600" />
                  <span className="text-xs font-bold uppercase tracking-wider text-gray-900">
                    Immutable Backup Ingestion & WORM Storage Pipeline
                  </span>
                </div>
                <div className="flex items-center gap-2 text-[11px] font-mono text-gray-500">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  <span>Object Lock Compliance: ACTIVE</span>
                </div>
              </div>

              <div className="p-5 grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <div className="text-[10px] font-mono font-bold text-gray-400">STAGE 01</div>
                  <div className="font-bold text-xs text-gray-900 mt-1">SQL VDI Stream</div>
                  <div className="text-[11px] text-gray-500 mt-0.5">Native WITH CHECKSUM stream from SQL Server engine.</div>
                  <div className="mt-2 text-[10px] font-mono text-brand-700 bg-brand-50 px-2 py-0.5 rounded border border-brand-200 inline-block">
                    {discoveredDBs.length} DB Sources
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <div className="text-[10px] font-mono font-bold text-gray-400">STAGE 02</div>
                  <div className="font-bold text-xs text-gray-900 mt-1">SHA-256 Digest</div>
                  <div className="text-[11px] text-gray-500 mt-0.5">Streaming cryptographic payload digest calculation.</div>
                  <div className="mt-2 text-[10px] font-mono text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 inline-block">
                    Zero-Trust Verification
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <div className="text-[10px] font-mono font-bold text-gray-400">STAGE 03</div>
                  <div className="font-bold text-xs text-gray-900 mt-1">WORM Object Lock</div>
                  <div className="text-[11px] text-gray-500 mt-0.5">SeaweedFS S3 API with 30-day compliance retention lock.</div>
                  <div className="mt-2 text-[10px] font-mono text-purple-700 bg-purple-50 px-2 py-0.5 rounded border border-purple-200 inline-block">
                    Immutable Storage
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-gray-50/60 border border-gray-100">
                  <div className="text-[10px] font-mono font-bold text-gray-400">STAGE 04</div>
                  <div className="font-bold text-xs text-gray-900 mt-1">Ledger Auditing</div>
                  <div className="text-[11px] text-gray-500 mt-0.5">Cryptographic entry registered in SQLTrust_Control ledger.</div>
                  <div className="mt-2 text-[10px] font-mono text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200 inline-block">
                    {backups.length} Protected Artifacts
                  </div>
                </div>
              </div>
            </div>
          </ScrollReveal>

          {/* Filters Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-4 rounded-xl border border-gray-200 shadow-sm">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search database, filename, or SHA-256..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-gray-50 border border-gray-200 rounded-lg text-sm text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-brand-500 focus:bg-white transition"
              />
            </div>
            <div className="flex items-center gap-2 self-start sm:self-auto">
              <span className="text-xs font-medium text-gray-500">Type:</span>
              {(['ALL', 'FULL', 'DIFFERENTIAL', 'LOG'] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setTypeFilter(t)}
                  className={`px-3 py-1 rounded-md text-xs font-semibold transition ${typeFilter === t
                    ? 'bg-gray-900 text-white'
                    : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                    }`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* Backups Table */}
          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-gray-50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Database</th>
                    <th className="py-3 px-4">Backup Type</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Size</th>
                    <th className="py-3 px-4">Execution Time</th>
                    <th className="py-3 px-4">SHA-256 Integrity</th>
                    <th className="py-3 px-4">WORM Retention</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 text-gray-700 font-sans">
                  {filteredBackups.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-12 text-center text-gray-400">
                        No backup records found matching current criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredBackups.map((b) => (
                      <tr key={b.id} className="hover:bg-gray-50/80 transition">
                        <td className="py-3 px-4 font-semibold text-gray-900 flex items-center gap-2">
                          <Database className="w-3.5 h-3.5 text-gray-400" />
                          {b.database_name || 'Protected DB'}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-semibold ${b.backup_type === 'FULL'
                              ? 'bg-blue-50 text-blue-700 border border-blue-200'
                              : b.backup_type === 'DIFFERENTIAL'
                                ? 'bg-amber-50 text-amber-700 border border-amber-200'
                                : 'bg-purple-50 text-purple-700 border border-purple-200'
                              }`}
                          >
                            {b.backup_type}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-semibold flex items-center gap-1 w-fit ${b.backup_status === 'COMPLETED'
                              ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                              : b.backup_status === 'FAILED'
                                ? 'bg-rose-50 text-rose-700 border border-rose-200'
                                : 'bg-gray-50 text-gray-700 border border-gray-200'
                              }`}
                          >
                            {b.backup_status === 'COMPLETED' ? (
                              <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                            ) : (
                              <AlertCircle className="w-3 h-3 text-rose-600" />
                            )}
                            {b.backup_status}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-gray-600">{formatBytes(b.backup_size_bytes)}</td>
                        <td className="py-3 px-4 text-gray-500 font-mono">
                          {new Date(b.created_at).toISOString().replace('T', ' ').slice(0, 19)}
                        </td>
                        <td className="py-3 px-4">
                          {b.sha256 ? (
                            <div className="flex items-center gap-1 font-mono text-gray-600">
                              <span className="truncate max-w-[110px]" title={b.sha256}>
                                {b.sha256.slice(0, 8)}...{b.sha256.slice(-6)}
                              </span>
                              <button
                                onClick={() => copyToClipboard(b.sha256!, b.id)}
                                className="p-1 text-gray-400 hover:text-gray-700 rounded"
                                title="Copy full SHA-256 hash"
                              >
                                {copiedHash === b.id ? (
                                  <Check className="w-3 h-3 text-emerald-600" />
                                ) : (
                                  <FileText className="w-3 h-3" />
                                )}
                              </button>
                            </div>
                          ) : (
                            <span className="text-gray-400">PENDING</span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          {b.retention_mode ? (
                            <div className="flex items-center gap-1.5 text-emerald-700">
                              <Lock className="w-3.5 h-3.5 text-emerald-600" />
                              <span className="font-semibold text-[11px]">{b.retention_mode}</span>
                              {b.retention_until && (
                                <span className="text-gray-500 text-[10px]">
                                  ({new Date(b.retention_until).toLocaleDateString()})
                                </span>
                              )}
                            </div>
                          ) : (
                            <span className="text-gray-400">—</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => handleOpenDetails(b)}
                            className="px-2.5 py-1 rounded border border-gray-200 bg-white hover:bg-gray-50 text-gray-700 font-medium text-xs shadow-xs transition"
                          >
                            Details & Manifest
                          </button>
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

      {/* TAB 2: DATABASE REGISTRY */}
      {activeTab === 'registry' && (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-gray-200 flex justify-between items-center bg-gray-50">
              <h3 className="font-semibold text-gray-900 text-sm flex items-center gap-2">
                <Database className="w-4 h-4 text-brand-500" />
                Live SQL Server Instance Databases
              </h3>
              <span className="text-xs text-gray-500">Connected via sys.databases catalog view</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-gray-50/50 border-b border-gray-200 text-gray-600 font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Database Name</th>
                    <th className="py-3 px-4">State</th>
                    <th className="py-3 px-4">Recovery Model</th>
                    <th className="py-3 px-4">Scope</th>
                    <th className="py-3 px-4">Protection Status</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 text-gray-700 font-sans">
                  {discoveredDBs.map((db) => (
                    <tr key={db.database_id} className="hover:bg-gray-50/80 transition">
                      <td className="py-3.5 px-4 font-semibold text-gray-900">{db.name}</td>
                      <td className="py-3.5 px-4 font-mono text-gray-600">{db.state}</td>
                      <td className="py-3.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold ${db.recovery_model === 'FULL'
                            ? 'bg-blue-50 text-blue-700 border border-blue-200'
                            : 'bg-gray-100 text-gray-700'
                            }`}
                        >
                          {db.recovery_model}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        {db.is_system ? (
                          <span className="text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded text-[11px] font-semibold">
                            System
                          </span>
                        ) : (
                          <span className="text-gray-600 text-[11px]">User Database</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4">
                        {db.is_registered ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[11px] font-semibold flex items-center gap-1 w-fit">
                            <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                            REGISTERED
                          </span>
                        ) : (
                          <span className="text-gray-400 text-[11px]">Unregistered</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        {!db.is_registered && (
                          <button
                            onClick={() => handleRegister(db.name, db.is_system)}
                            disabled={registering === db.name}
                            className="px-3 py-1 rounded bg-brand-500 hover:bg-brand-600 text-white font-medium text-xs transition shadow-xs disabled:opacity-50"
                          >
                            {registering === db.name ? 'Registering...' : 'Register for Protection'}
                          </button>
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

      {/* CREATE BACKUP MODAL */}
      {createModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 space-y-5 shadow-2xl border border-gray-200">
            <div className="flex justify-between items-center border-b border-gray-100 pb-3">
              <div>
                <h3 className="text-base font-bold text-gray-900 flex items-center gap-2">
                  <PlusCircle className="w-5 h-5 text-brand-500" />
                  Initiate Database Backup
                </h3>
                <p className="text-xs text-gray-500 mt-0.5">
                  Executes a verified SQL Server backup and transfers to WORM immutable storage.
                </p>
              </div>
              <button
                onClick={() => setCreateModalOpen(false)}
                className="p-1 rounded-md text-gray-400 hover:text-gray-700 transition"
              >
                ✕
              </button>
            </div>

            {backupError && (
              <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
                <span>{backupError}</span>
              </div>
            )}

            {backupSuccess && (
              <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>{backupSuccess}</span>
              </div>
            )}

            <form onSubmit={handleCreateBackup} className="space-y-4 text-xs font-sans">
              <div>
                <label className="block text-gray-700 font-semibold mb-1">Target Registered Database:</label>
                <select
                  value={formDbId}
                  onChange={(e) => setFormDbId(e.target.value)}
                  className="w-full bg-white border border-gray-300 rounded-lg p-2.5 text-gray-900 text-xs focus:ring-1 focus:ring-brand-500 focus:outline-none font-mono"
                  required
                >
                  {registeredDBs.length === 0 ? (
                    <option value="">No registered databases available</option>
                  ) : (
                    registeredDBs.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.database_name} ({d.recovery_model} Recovery Model)
                      </option>
                    ))
                  )}
                </select>
              </div>

              <div>
                <label className="block text-gray-700 font-semibold mb-1">Backup Execution Type:</label>
                <div className="grid grid-cols-3 gap-2">
                  {(['FULL', 'DIFFERENTIAL', 'LOG'] as const).map((type) => (
                    <button
                      type="button"
                      key={type}
                      onClick={() => setFormBackupType(type)}
                      className={`p-2.5 rounded-lg border text-center font-semibold text-xs transition ${formBackupType === type
                        ? 'bg-brand-50 border-brand-500 text-brand-600'
                        : 'bg-white border-gray-200 text-gray-600 hover:bg-gray-50'
                        }`}
                    >
                      {type}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-gray-700 font-semibold mb-1">
                  Operator Notes / Change Request (Optional):
                </label>
                <textarea
                  value={formNotes}
                  onChange={(e) => setFormNotes(e.target.value)}
                  placeholder="e.g. Scheduled pre-maintenance backup"
                  className="w-full bg-white border border-gray-300 rounded-lg p-2.5 text-gray-900 text-xs focus:ring-1 focus:ring-brand-500 focus:outline-none h-20"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2 border-t border-gray-100">
                <button
                  type="button"
                  onClick={() => setCreateModalOpen(false)}
                  className="px-4 py-2 rounded-lg border border-gray-200 text-gray-600 hover:bg-gray-50 font-medium text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submittingBackup || registeredDBs.length === 0}
                  className="px-4 py-2 rounded-lg bg-brand-500 hover:bg-brand-600 disabled:opacity-50 text-white font-medium text-xs transition flex items-center gap-1.5 shadow-sm"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${submittingBackup ? 'animate-spin' : ''}`} />
                  {submittingBackup ? 'Executing Two-Stage Backup...' : 'Execute Backup'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* BACKUP DETAILS & MANIFEST MODAL */}
      {selectedBackup && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl border border-gray-200 max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center border-b border-gray-100 pb-3">
              <div>
                <h3 className="text-base font-bold text-gray-900 flex items-center gap-2">
                  <FileText className="w-5 h-5 text-brand-500" />
                  Backup Execution Details & Cryptographic Manifest
                </h3>
                <p className="text-xs text-gray-500 font-mono mt-0.5">{selectedBackup.backup_filename}</p>
              </div>
              <button
                onClick={() => setSelectedBackup(null)}
                className="p-1 rounded-md text-gray-400 hover:text-gray-700 transition"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-3 bg-gray-50 p-4 rounded-xl border border-gray-200 font-mono">
                <div>
                  <span className="text-gray-500">Backup Type:</span>
                  <div className="text-gray-900 font-bold">{selectedBackup.backup_type}</div>
                </div>
                <div>
                  <span className="text-gray-500">Execution Status:</span>
                  <div className="text-emerald-700 font-bold">{selectedBackup.backup_status}</div>
                </div>
                <div>
                  <span className="text-gray-500">File Size:</span>
                  <div className="text-gray-900">{formatBytes(selectedBackup.backup_size_bytes)}</div>
                </div>
                <div>
                  <span className="text-gray-500">SQL Verification:</span>
                  <div className="text-gray-900">{selectedBackup.sql_verification_status}</div>
                </div>
                <div className="col-span-2">
                  <span className="text-gray-500">Cryptographic SHA-256 Digest:</span>
                  <div className="text-brand-600 truncate">{selectedBackup.sha256}</div>
                </div>
                <div className="col-span-2">
                  <span className="text-gray-500">Storage Object Key:</span>
                  <div className="text-gray-800 truncate">{selectedBackup.storage_object_key}</div>
                </div>
                <div className="col-span-2">
                  <span className="text-gray-500">WORM Object Lock:</span>
                  <div className="text-emerald-700 font-semibold">
                    Mode: {selectedBackup.retention_mode || 'NONE'} | Retain Until:{' '}
                    {selectedBackup.retention_until || 'N/A'}
                  </div>
                </div>
              </div>

              {/* Two-Stage Verification Action */}
              <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs space-y-2">
                <div className="flex justify-between items-center">
                  <span className="font-semibold text-gray-900">Re-verify Cryptographic & Physical Integrity:</span>
                  <button
                    onClick={() => handleVerifyNow(selectedBackup.id)}
                    disabled={verifying}
                    className="px-3 py-1.5 rounded-lg bg-brand-500 hover:bg-brand-600 text-white font-medium text-xs transition flex items-center gap-1.5 shadow-sm"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
                    {verifying ? 'Verifying Integrity...' : 'Re-verify Backup Integrity Now'}
                  </button>
                </div>

                {verificationResult && (
                  <div className="mt-3 p-3 rounded-lg bg-gray-50 border border-gray-200 font-mono text-[11px] space-y-1">
                    <div className="text-emerald-700 font-semibold flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                      Integrity Proof:
                    </div>
                    <div>SQL Server Verify: {verificationResult.sql_verification}</div>
                    <div>
                      Cryptographic SHA-256 Match:{' '}
                      <span className="text-emerald-600 font-semibold">
                        {verificationResult.sha256_match ? 'MATCH (100% Intact)' : 'MISMATCH'}
                      </span>
                    </div>
                    <div>
                      Storage Retention Verified:{' '}
                      {verificationResult.storage_retention_verified
                        ? `YES (${verificationResult.remote_retention_mode})`
                        : 'NO'}
                    </div>
                    {verificationResult.remote_retain_until && (
                      <div>Remote Retain Until Date: {verificationResult.remote_retain_until}</div>
                    )}
                  </div>
                )}
              </div>

              {/* JSON Manifest Viewer */}
              <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs space-y-2">
                <h4 className="font-semibold text-gray-900 text-xs flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-brand-500" />
                  Immutable JSON Manifest Evidence
                </h4>
                {loadingManifest ? (
                  <p className="text-gray-400">Loading manifest from database & SeaweedFS...</p>
                ) : manifestData ? (
                  <pre className="bg-gray-50 p-3 rounded-lg text-[11px] font-mono text-gray-800 overflow-x-auto max-h-48 border border-gray-200">
                    {JSON.stringify(manifestData.manifest_data, null, 2)}
                  </pre>
                ) : (
                  <p className="text-gray-400">No manifest found for this backup.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
