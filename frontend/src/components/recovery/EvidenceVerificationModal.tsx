import { useState, useEffect } from 'react'
import { X, CheckCircle2, AlertTriangle, Lock, Loader2 } from 'lucide-react'
import axios from 'axios'

interface Props {
  assessmentId: string | null
  onClose: () => void
}

interface VerificationResult {
  valid: boolean
  archive_id: string
  sha256_match?: boolean
  signature_valid?: boolean
  worm_mode?: string
  retention_until?: string
  version_id?: string
  storage_object_key?: string
  error?: string
}

export function EvidenceVerificationModal({ assessmentId, onClose }: Props) {
  const [loading, setLoading] = useState(true)
  const [result, setResult] = useState<VerificationResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!assessmentId) return
    setLoading(true)
    setError(null)
    axios.get(`http://127.0.0.1:8000/api/v1/recovery/evidence/${assessmentId}/verify`)
      .then(res => {
        setResult(res.data)
        setLoading(false)
      })
      .catch(err => {
        setError(err.response?.data?.detail || err.message)
        setLoading(false)
      })
  }, [assessmentId])

  if (!assessmentId) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">
              Cryptographic WORM Evidence Verification
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {loading ? (
          <div className="py-8 text-center text-xs text-slate-400 space-y-2">
            <Loader2 className="w-6 h-6 animate-spin mx-auto text-emerald-400" />
            <div>Downloading signed artifact from SeaweedFS S3...</div>
            <div className="text-[11px] text-slate-500">Checking Ed25519 signature & S3 Object Lock compliance</div>
          </div>
        ) : error ? (
          <div className="p-4 bg-rose-950/40 border border-rose-800 rounded-lg text-xs text-rose-300 space-y-1">
            <div className="font-bold flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4" />
              Verification Error
            </div>
            <div>{error}</div>
          </div>
        ) : result ? (
          <div className="space-y-3 text-xs">
            <div className={`p-3 rounded-lg border flex items-center gap-3 ${
              result.valid
                ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                : 'bg-rose-950/30 border-rose-500/40 text-rose-300'
            }`}>
              {result.valid ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
              )}
              <div>
                <div className="font-bold">
                  {result.valid ? 'Cryptographic Integrity Confirmed' : 'Integrity Verification Failed'}
                </div>
                <div className="text-[11px] opacity-90">
                  {result.valid
                    ? 'Payload matches SHA-256 digest and Ed25519 digital signature is authentic.'
                    : 'Artifact or signature has been modified or corrupted.'}
                </div>
              </div>
            </div>

            <div className="bg-slate-950/80 rounded-lg p-3 space-y-2 font-mono text-[11px] border border-slate-800 text-slate-300">
              <div className="flex justify-between">
                <span className="text-slate-500">SHA-256 Digest:</span>
                <span className={result.sha256_match ? 'text-emerald-400' : 'text-rose-400'}>
                  {result.sha256_match ? 'MATCH (Verified)' : 'MISMATCH'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Ed25519 Signature:</span>
                <span className={result.signature_valid ? 'text-emerald-400' : 'text-rose-400'}>
                  {result.signature_valid ? 'VALID (Authentic)' : 'INVALID'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">S3 WORM Mode:</span>
                <span className="text-emerald-400 font-bold">{result.worm_mode || 'COMPLIANCE'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Retention Expiration:</span>
                <span className="text-slate-200">
                  {result.retention_until ? new Date(result.retention_until).toLocaleString() : 'Active'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">S3 Version ID:</span>
                <span className="text-slate-400">{result.version_id ? result.version_id.slice(0, 16) + '...' : 'N/A'}</span>
              </div>
            </div>
          </div>
        ) : null}

        <div className="pt-2 text-right">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
