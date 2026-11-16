import React, { useState } from 'react'
import {
  Shield,
  Lock,
  Mail,
  User,
  Eye,
  EyeOff,
  CheckCircle2,
  AlertCircle,
  X,
  ArrowRight,
  ShieldCheck
} from 'lucide-react'
import axios from 'axios'
import { UserSession } from '../../types/auth'

interface AuthModalProps {
  isOpen: boolean
  onClose: () => void
  apiBase: string
  initialMode?: 'login' | 'register'
  onSuccess: (session: UserSession) => void
}

export function AuthModal({
  isOpen,
  onClose,
  apiBase,
  initialMode = 'login',
  onSuccess
}: AuthModalProps) {
  const [mode, setMode] = useState<'login' | 'register'>(initialMode)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)

  // Login form state
  const [loginIdentifier, setLoginIdentifier] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [showLoginPassword, setShowLoginPassword] = useState(false)
  const [rememberMe, setRememberMe] = useState(true)

  // Registration form state
  const [regFullName, setRegFullName] = useState('')
  const [regEmail, setRegEmail] = useState('')
  const [regUsername, setRegUsername] = useState('')
  const [regPassword, setRegPassword] = useState('')
  const [regConfirmPassword, setRegConfirmPassword] = useState('')
  const [showRegPassword, setShowRegPassword] = useState(false)

  if (!isOpen) return null

  // Password strength calculation
  const getPasswordStrength = (pwd: string) => {
    let score = 0
    if (pwd.length >= 8) score += 1
    if (pwd.length >= 12) score += 1
    if (/[A-Z]/.test(pwd)) score += 1
    if (/[a-z]/.test(pwd)) score += 1
    if (/[0-9]/.test(pwd)) score += 1
    if (/[^A-Za-z0-9]/.test(pwd)) score += 1

    if (score <= 2) return { level: 'Weak', percent: 25, color: 'bg-rose-500', text: 'text-rose-600' }
    if (score <= 4) return { level: 'Fair', percent: 50, color: 'bg-amber-500', text: 'text-amber-600' }
    if (score === 5) return { level: 'Good', percent: 75, color: 'bg-blue-500', text: 'text-blue-600' }
    return { level: 'Strong', percent: 100, color: 'bg-emerald-500', text: 'text-emerald-600' }
  }

  const pwdStrength = getPasswordStrength(regPassword)

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      const res = await axios.post(`${apiBase}/api/v1/auth/login`, {
        username: loginIdentifier.trim(),
        password: loginPassword
      })

      const session: UserSession = {
        username: res.data.username,
        email: res.data.email,
        full_name: res.data.full_name,
        role: res.data.role,
        is_demo_account: res.data.is_demo_account,
        access_token: res.data.access_token,
        permissions: res.data.permissions || []
      }

      if (rememberMe) {
        localStorage.setItem('sqltrust_session', JSON.stringify(session))
      }
      onSuccess(session)
      onClose()
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || 'Login failed. Please check credentials.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setSuccessMsg(null)

    if (regPassword !== regConfirmPassword) {
      setError('Passwords do not match.')
      return
    }

    if (regPassword.length < 8) {
      setError('Password must be at least 8 characters long.')
      return
    }

    setLoading(true)

    try {
      const regRes = await axios.post(`${apiBase}/api/v1/auth/register`, {
        full_name: regFullName.trim(),
        email: regEmail.trim(),
        username: regUsername.trim(),
        password: regPassword,
        confirm_password: regConfirmPassword
      })

      setSuccessMsg(
        `Account created successfully! Assigned default role: ${regRes.data.role}. Signing you in...`
      )

      // Automatically sign in upon registration
      setTimeout(async () => {
        try {
          const loginRes = await axios.post(`${apiBase}/api/v1/auth/login`, {
            username: regUsername.trim(),
            password: regPassword
          })

          const session: UserSession = {
            username: loginRes.data.username,
            email: loginRes.data.email,
            full_name: loginRes.data.full_name,
            role: loginRes.data.role,
            is_demo_account: false,
            access_token: loginRes.data.access_token,
            permissions: loginRes.data.permissions || []
          }

          localStorage.setItem('sqltrust_session', JSON.stringify(session))
          onSuccess(session)
          onClose()
        } catch {
          setMode('login')
          setLoginIdentifier(regUsername)
        }
      }, 1000)
    } catch (err: any) {
      const msg = err.response?.data?.detail || err.message || 'Registration failed.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-modal-title"
      className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto"
    >
      <div className="bg-white rounded-2xl max-w-md w-full border border-gray-200 shadow-modal overflow-hidden animate-in fade-in zoom-in-95 duration-150 my-8">
        {/* Header Strip */}
        <div className="p-5 bg-navy-900 text-white flex items-center justify-between border-b border-navy-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-brand-600 text-cyan-metallic flex items-center justify-center border border-brand-500/40">
              <ShieldCheck className="w-4.5 h-4.5" />
            </div>
            <div>
              <h2 id="auth-modal-title" className="font-bold text-sm tracking-tight text-white">
                SQL-TRUST Authentication
              </h2>
              <p className="text-[11px] text-gray-400 font-mono">
                Cyber Recovery & Forensic Intelligence
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close Authentication Dialog"
            className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-navy-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Toggle */}
        <div className="flex border-b border-gray-200 bg-gray-50/70 p-1">
          <button
            type="button"
            onClick={() => {
              setMode('login')
              setError(null)
              setSuccessMsg(null)
            }}
            className={`flex-1 py-2 text-xs font-semibold rounded-lg transition ${
              mode === 'login'
                ? 'bg-white text-gray-900 shadow-xs border border-gray-200/90'
                : 'text-gray-500 hover:text-gray-900'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setMode('register')
              setError(null)
              setSuccessMsg(null)
            }}
            className={`flex-1 py-2 text-xs font-semibold rounded-lg transition ${
              mode === 'register'
                ? 'bg-white text-gray-900 shadow-xs border border-gray-200/90'
                : 'text-gray-500 hover:text-gray-900'
            }`}
          >
            Create Account
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-4">
          {/* Error Banner */}
          {error && (
            <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Success Banner */}
          {successMsg && (
            <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
              <span>{successMsg}</span>
            </div>
          )}

          {mode === 'login' ? (
            /* LOGIN FORM */
            <form onSubmit={handleLoginSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-gray-700 mb-1">
                  Username or Email
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    required
                    placeholder="e.g. demo_admin or user@domain.com"
                    value={loginIdentifier}
                    onChange={(e) => setLoginIdentifier(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-xs text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:bg-white"
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs font-semibold text-gray-700">Password</label>
                </div>
                <div className="relative">
                  <Lock className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type={showLoginPassword ? 'text' : 'password'}
                    required
                    placeholder="Enter account passphrase"
                    value={loginPassword}
                    onChange={(e) => setLoginPassword(e.target.value)}
                    className="w-full pl-9 pr-10 py-2 bg-gray-50 border border-gray-200 rounded-lg text-xs text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:bg-white font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowLoginPassword(!showLoginPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    {showLoginPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between text-xs text-gray-500">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="rounded border-gray-300 text-brand focus:ring-brand"
                  />
                  <span>Remember session</span>
                </label>
                <span className="text-[11px] font-mono text-gray-400">PBKDF2-HMAC-SHA256</span>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 rounded-lg bg-brand-600 hover:bg-brand-700 disabled:opacity-50 text-white font-semibold text-xs transition shadow-xs flex items-center justify-center gap-2"
              >
                {loading ? 'Authenticating...' : 'Sign In to Control Plane'}
                <ArrowRight className="w-3.5 h-3.5" />
              </button>

              <div className="pt-3 border-t border-gray-100 text-center">
                <p className="text-[11px] text-gray-500">
                  Don't have an operator account?{' '}
                  <button
                    type="button"
                    onClick={() => {
                      setMode('register')
                      setError(null)
                    }}
                    className="text-brand-600 font-semibold hover:underline"
                  >
                    Register new account
                  </button>
                </p>
              </div>
            </form>
          ) : (
            /* REGISTRATION FORM */
            <form onSubmit={handleRegisterSubmit} className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-gray-700 mb-1">
                  Full Legal Name
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    required
                    placeholder="e.g. Sarah Connor"
                    value={regFullName}
                    onChange={(e) => setRegFullName(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-xs text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:bg-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-700 mb-1">
                  Corporate Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="email"
                    required
                    placeholder="user@organization.internal"
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-xs text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:bg-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-700 mb-1">
                  Desired Username
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. sconnor"
                  value={regUsername}
                  onChange={(e) => setRegUsername(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-xs text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:bg-white font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-700 mb-1">
                  Passphrase
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type={showRegPassword ? 'text' : 'password'}
                    required
                    placeholder="Min 8 characters, mixed case, numbers"
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                    className="w-full pl-9 pr-10 py-2 bg-gray-50 border border-gray-200 rounded-lg text-xs text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:bg-white font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowRegPassword(!showRegPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    {showRegPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>

                {/* Strength Meter */}
                {regPassword && (
                  <div className="mt-1.5 space-y-1">
                    <div className="h-1.5 w-full bg-gray-200 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${pwdStrength.color} transition-all duration-300`}
                        style={{ width: `${pwdStrength.percent}%` }}
                      />
                    </div>
                    <div className="flex justify-between text-[10px] text-gray-500 font-mono">
                      <span>Strength: <strong className={pwdStrength.text}>{pwdStrength.level}</strong></span>
                      <span>8+ chars, mixed case, digits</span>
                    </div>
                  </div>
                )}
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-700 mb-1">
                  Confirm Passphrase
                </label>
                <input
                  type="password"
                  required
                  placeholder="Re-enter passphrase"
                  value={regConfirmPassword}
                  onChange={(e) => setRegConfirmPassword(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-xs text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:bg-white font-mono"
                />
              </div>

              {/* Security Safeguard Notice */}
              <div className="p-2.5 rounded-lg bg-teal-50 border border-teal-200 text-teal-deep text-[11px] leading-relaxed">
                <div className="font-semibold flex items-center gap-1 mb-0.5">
                  <Shield className="w-3.5 h-3.5" />
                  Least-Privilege Principle Enforced
                </div>
                New accounts are strictly provisioned with the <strong>READ_ONLY_REVIEWER</strong> role. Role escalation requires administrative authorization.
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 rounded-lg bg-brand-600 hover:bg-brand-700 disabled:opacity-50 text-white font-semibold text-xs transition shadow-xs flex items-center justify-center gap-2 mt-2"
              >
                {loading ? 'Creating Account...' : 'Complete Self-Registration'}
                <ArrowRight className="w-3.5 h-3.5" />
              </button>

              <div className="pt-2 text-center">
                <p className="text-[11px] text-gray-500">
                  Already registered?{' '}
                  <button
                    type="button"
                    onClick={() => {
                      setMode('login')
                      setError(null)
                    }}
                    className="text-brand-600 font-semibold hover:underline"
                  >
                    Sign in here
                  </button>
                </p>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  )
}
