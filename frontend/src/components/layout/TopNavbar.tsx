import { useState, useRef, useEffect } from 'react'
import {
  ShieldCheck,
  Database,
  ShieldAlert,
  Activity,
  Binary,
  RotateCcw,
  FileText,
  Search,
  Menu,
  X,
  Server,
  Lock,
  RefreshCw,
  Bell,
  CheckCircle2,
  ExternalLink,
  LogOut,
  Settings,
  ChevronRight,
  UserCheck
} from 'lucide-react'
import { UserSession } from '../../types/auth'
import { SecurityAlert } from '../../types/security'

export type NavRoute =
  | 'dashboard'
  | 'backups_mgmt'
  | 'backups_history'
  | 'sec_overview'
  | 'sec_alerts_events'
  | 'sec_audit_activity'
  | 'forensics_baselines'
  | 'forensics_timeline'
  | 'evidence_vault'
  | 'recovery_intelligence'
  | 'restore_validation'
  | 'recovery_history'
  | 'investigations'
  | 'response_plans'
  | 'investigation_reports'
  | 'admin_users'
  | 'admin_settings'

export interface PrimaryNavItem {
  id: string
  label: string
  targetRoute: NavRoute
  activeRoutes: NavRoute[]
  icon: typeof Activity
  badge?: number | string
}

interface TopNavbarProps {
  currentRoute: NavRoute
  onNavigate: (route: NavRoute) => void
  apiBase: string
  currentSession: UserSession | null
  onSessionChange: (session: UserSession | null) => void
  onRefreshAll: () => void
  isRefreshing: boolean
  sqlServerConnected: boolean
  wormVaultConnected: boolean
  alerts?: SecurityAlert[]
  counts?: {
    alertsCount?: number
    casesCount?: number
    backupsCount?: number
    validationsCount?: number
  }
  onOpenAuthModal?: (mode: 'login' | 'register') => void
}

export function TopNavbar({
  currentRoute,
  onNavigate,
  apiBase: _apiBase,
  currentSession,
  onSessionChange,
  onRefreshAll,
  isRefreshing,
  sqlServerConnected,
  wormVaultConnected,
  alerts = [],
  counts,
  onOpenAuthModal
}: TopNavbarProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [accountMenuOpen, setAccountMenuOpen] = useState(false)
  const [notificationFilter, setNotificationFilter] = useState<'ALL' | 'CRITICAL' | 'UNRESOLVED'>('UNRESOLVED')
  const [acknowledgedAlertIds, setAcknowledgedAlertIds] = useState<Set<string>>(new Set())

  const navRef = useRef<HTMLElement>(null)
  const notificationRef = useRef<HTMLDivElement>(null)
  const accountMenuRef = useRef<HTMLDivElement>(null)
  const searchInputRef = useRef<HTMLInputElement>(null)

  // Direct Horizontal Navigation Links (Strictly NO Dropdowns)
  const primaryNavItems: PrimaryNavItem[] = [
    {
      id: 'overview',
      label: 'Overview',
      targetRoute: 'dashboard',
      activeRoutes: ['dashboard'],
      icon: Activity
    },
    {
      id: 'protection',
      label: 'Protection',
      targetRoute: 'backups_mgmt',
      activeRoutes: ['backups_mgmt', 'backups_history'],
      icon: Database,
      badge: counts?.backupsCount
    },
    {
      id: 'security',
      label: 'Security',
      targetRoute: 'sec_overview',
      activeRoutes: ['sec_overview', 'sec_alerts_events', 'sec_audit_activity'],
      icon: ShieldAlert,
      badge: counts?.alertsCount && counts.alertsCount > 0 ? counts.alertsCount : undefined
    },
    {
      id: 'forensics',
      label: 'Forensics',
      targetRoute: 'forensics_baselines',
      activeRoutes: ['forensics_baselines', 'forensics_timeline', 'evidence_vault'],
      icon: Binary
    },
    {
      id: 'recovery',
      label: 'Recovery',
      targetRoute: 'recovery_intelligence',
      activeRoutes: ['recovery_intelligence', 'restore_validation', 'recovery_history'],
      icon: RotateCcw,
      badge: counts?.validationsCount && counts.validationsCount > 0 ? counts.validationsCount : undefined
    },
    {
      id: 'investigations',
      label: 'Investigations',
      targetRoute: 'investigations',
      activeRoutes: ['investigations', 'response_plans', 'investigation_reports'],
      icon: FileText,
      badge: counts?.casesCount && counts.casesCount > 0 ? counts.casesCount : undefined
    }
  ]

  // Least-Privilege Route Authorization Check
  const roleName = (currentSession?.role || 'READ_ONLY_REVIEWER').toUpperCase()
  const isSecurityAdmin = roleName.includes('ADMIN')
  const isApprover = roleName.includes('APPROVER')
  const isSeniorAnalyst = roleName.includes('SENIOR_ANALYST')
  const isInvestigator = roleName.includes('INVESTIGATION_ANALYST') || roleName.includes('INVESTIGATOR')
  const isReviewer = roleName.includes('INCIDENT_REVIEWER')
  const isAuditor = roleName.includes('AUDITOR')

  const isRouteAllowed = (targetRoute: NavRoute): boolean => {
    if (isSecurityAdmin) return true

    switch (targetRoute) {
      case 'dashboard':
        return true
      case 'sec_overview':
      case 'sec_alerts_events':
      case 'sec_audit_activity':
        return true
      case 'backups_mgmt':
      case 'backups_history':
        return isSecurityAdmin || isApprover || isSeniorAnalyst || isInvestigator || isAuditor
      case 'forensics_baselines':
      case 'forensics_timeline':
      case 'evidence_vault':
        return isSecurityAdmin || isApprover || isSeniorAnalyst || isInvestigator || isReviewer || isAuditor
      case 'recovery_intelligence':
      case 'restore_validation':
      case 'recovery_history':
        return isSecurityAdmin || isApprover || isSeniorAnalyst || isInvestigator || isAuditor
      case 'investigations':
      case 'response_plans':
      case 'investigation_reports':
        return isSecurityAdmin || isApprover || isSeniorAnalyst || isInvestigator || isReviewer || isAuditor
      case 'admin_users':
      case 'admin_settings':
        return isSecurityAdmin
      default:
        return false
    }
  }

  // Display only pages authorized for current role
  const authorizedNavItems = primaryNavItems.filter((item) => isRouteAllowed(item.targetRoute))

  // Close menus when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as Node
      if (notificationRef.current && !notificationRef.current.contains(target)) {
        setNotificationsOpen(false)
      }
      if (accountMenuRef.current && !accountMenuRef.current.contains(target)) {
        setAccountMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Global Keyboard Shortcuts (Ctrl+K / Cmd+K for search, Escape to close modals)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setSearchOpen((prev) => !prev)
      }
      if (e.key === 'Escape') {
        setSearchOpen(false)
        setNotificationsOpen(false)
        setAccountMenuOpen(false)
        setMobileMenuOpen(false)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  // Auto-focus search input
  useEffect(() => {
    if (searchOpen) {
      setTimeout(() => searchInputRef.current?.focus(), 50)
    }
  }, [searchOpen])

  // Sign out handler
  const handleSignOut = () => {
    localStorage.removeItem('sqltrust_session')
    onSessionChange(null)
    setAccountMenuOpen(false)
  }

  // Switch demo persona
  const handleSwitchDemoPersona = (roleName: string, roleTitle: string) => {
    const session: UserSession = {
      username: `demo_${roleName.toLowerCase()}`,
      full_name: `${roleTitle}`,
      role: roleName,
      is_demo_account: true,
      access_token: `mock_jwt_token_${roleName.toLowerCase()}`
    }
    localStorage.setItem('sqltrust_session', JSON.stringify(session))
    onSessionChange(session)
    setAccountMenuOpen(false)
  }

  // Notification Filtering
  const filteredAlerts = alerts.filter((alert) => {
    if (acknowledgedAlertIds.has(alert.id)) return false
    if (notificationFilter === 'CRITICAL') return alert.severity === 'CRITICAL'
    if (notificationFilter === 'UNRESOLVED') return alert.status !== 'RESOLVED'
    return true
  })

  const unreadAlertsCount = alerts.filter(
    (a) => !acknowledgedAlertIds.has(a.id) && a.status !== 'RESOLVED'
  ).length

  const handleAcknowledgeAlert = (id: string) => {
    setAcknowledgedAlertIds((prev) => new Set([...prev, id]))
  }

  // Compact numeric badge formatter (e.g. 259 -> 99+)
  const formatBadgeCount = (count?: number | string): string | undefined => {
    if (count === undefined || count === null) return undefined
    const num = typeof count === 'number' ? count : parseInt(String(count), 10)
    if (isNaN(num) || num <= 0) return undefined
    if (num > 99) return '99+'
    return String(num)
  }

  // Format user role display & color badge
  const getRoleBadgeStyle = (role?: string) => {
    const normalized = (role || '').toUpperCase()
    if (normalized.includes('ADMIN')) {
      return 'bg-rose-50 text-rose-700 border-rose-200'
    }
    if (normalized.includes('APPROVER') || normalized.includes('REVIEWER')) {
      return 'bg-amber-50 text-amber-700 border-amber-200'
    }
    if (normalized.includes('ANALYST') || normalized.includes('INVESTIGATOR')) {
      return 'bg-indigo-50 text-indigo-700 border-indigo-200'
    }
    if (normalized.includes('AUDITOR')) {
      return 'bg-emerald-50 text-emerald-700 border-emerald-200'
    }
    return 'bg-gray-100 text-gray-700 border-gray-200'
  }

  const formatRoleLabel = (role?: string) => {
    if (!role) return 'User'
    return role.replace(/_/g, ' ')
  }

  const formatCompactRole = (role?: string) => {
    if (!role) return 'USER'
    const normalized = role.toUpperCase()
    if (normalized.includes('ADMIN')) return 'ADMIN'
    if (normalized.includes('APPROVER')) return 'APPROVER'
    if (normalized.includes('SENIOR_ANALYST')) return 'ANALYST'
    if (normalized.includes('INVESTIGAT')) return 'INVESTIGATOR'
    if (normalized.includes('REVIEWER')) return 'REVIEWER'
    if (normalized.includes('AUDITOR')) return 'AUDITOR'
    if (normalized.includes('READ_ONLY')) return 'READ-ONLY'
    return normalized.replace(/_/g, ' ')
  }

  const isAdmin = currentSession?.role?.toUpperCase().includes('ADMIN') || false

  return (
    <header
      ref={navRef}
      role="banner"
      className="sticky top-0 z-50 bg-white/95 backdrop-blur-md border-b border-gray-200/90 shadow-xs"
      className="sticky top-0 z-50 bg-white/95 backdrop-blur-md border-b border-gray-200/90 shadow-xs w-full"
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="w-full max-w-[1720px] mx-auto px-3 sm:px-4 lg:px-6 xl:px-8">
            <div className="flex items-center justify-between h-16 gap-2 lg:gap-3 xl:gap-4 min-w-0">
              {/* 1. LEFT: Brand Identity */}
              <div className="flex items-center gap-3 shrink-0">
                <div className="flex items-center gap-2 sm:gap-2.5 shrink-0 min-w-0">
                  <button
                    onClick={() => onNavigate('dashboard')}
                    aria-label="SQL-TRUST Home Dashboard"
                    className="flex items-center gap-2.5 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-brand rounded-lg group p-1"
                    className="flex items-center gap-2 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-brand rounded-lg group p-1"
                  >
                    <div className="w-8 h-8 rounded-lg bg-brand-600 text-cyan-metallic flex items-center justify-center shadow-xs border border-brand-500/40 group-hover:bg-brand-700 transition">
                      <div className="w-8 h-8 rounded-lg bg-brand-600 text-white flex items-center justify-center shadow-xs border border-brand-500/40 group-hover:bg-brand-700 transition shrink-0">
                        <ShieldCheck className="w-5 h-5 text-white" />
                      </div>
                      <div className="block">
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="font-bold text-sm tracking-tight text-gray-900 group-hover:text-brand-600 transition">
                              <span className="font-bold text-sm tracking-tight text-gray-900 group-hover:text-brand-600 transition whitespace-nowrap">
                                SQL-TRUST
                              </span>
                              <span className="text-[9px] uppercase font-mono px-1.5 py-0.2 rounded bg-slate-900 text-cyan-300 font-semibold tracking-wider">
                                <span className="text-[9px] uppercase font-mono px-1.5 py-0.2 rounded bg-slate-900 text-cyan-300 font-semibold tracking-wider shrink-0">
                                  v1.0
                                </span>
                              </div>
                              <p className="text-[10px] text-gray-500 tracking-tight leading-none mt-0.5 hidden sm:block">
                                <p className="text-[10px] text-gray-500 tracking-tight leading-none mt-0.5 hidden 2xl:block truncate">
                                  Cyber Recovery & Forensics
                                </p>
                              </div>
                            </button>
                          </div>

                          {/* 2. CENTER: Direct-Link Horizontal Navigation (NO DROPDOWNS) */}
                          <nav
                            role="navigation"
                            aria-label="Primary Platform Navigation"
                            className="hidden md:flex items-center gap-1 lg:gap-2"
                            className="hidden lg:flex items-center gap-0.5 xl:gap-1 2xl:gap-1.5 min-w-0 shrink"
                          >
                            {authorizedNavItems.map((item) => {
                              const isActive = item.activeRoutes.includes(currentRoute)
                              const badgeFormatted = formatBadgeCount(item.badge)

                              return (
                                <button
                                  key={item.id}
                                  onClick={() => onNavigate(item.targetRoute)}
                                  className={`relative flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-brand ${className = {`relative flex items-center gap-1 px-2 py-1.5 xl:px-2.5 xl:py-2 rounded-lg text-xs font-semibold tracking-wide transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-brand whitespace-nowrap shrink-0 ${isActive
                                        ? 'text-brand-600 bg-brand-50/90 font-bold'
                                        : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100/80'
                                      }`}
                  aria-current={isActive ? 'page' : undefined}
                  title={`${item.label} ${item.badge ? ` (${item.badge})` : ''}`}
                >
                  <item.icon className={`w - 3.5 h - 3.5 ${ isActive ? 'text-brand-600' : 'text-gray-400' } `} />
                  <item.icon className={`w - 3.5 h - 3.5 shrink - 0 ${ isActive ? 'text-brand-600' : 'text-gray-400' } `} />
                  <span>{item.label}</span>

                  {item.badge !== undefined && Number(item.badge) > 0 && (
                  {badgeFormatted && (
                    <span
                      className={`ml - 1 px - 1.5 py - 0.2 rounded - full text - [10px] font - mono font - bold ${
                                className = {`ml-0.5 px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold leading-none shrink-0 ${item.id === 'security'
                                    ? 'bg-rose-100 text-rose-700'
                                    : item.id === 'investigations'
                                      ? 'bg-amber-100 text-amber-800'
                                      : 'bg-brand-100 text-brand-700'
                                  }`
                              }
                    >
                                { item.badge }
                              { badgeFormatted }
                    </span>
                  )}

                          {/* Active Page Indicator: Subtle Bottom Underline */}
                          {/* Active Page Indicator */}
                          {isActive && (
                            <span className="absolute bottom-0 left-2 right-2 h-0.5 bg-brand-600 rounded-full" />
                          )}
                        </button>
                        )
            })}

                        {/* Direct Admin Link if User has Admin privileges */}
                        {isAdmin && (
                          <button
                            onClick={() => onNavigate('admin_users')}
                            className={`relative flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-brand ${className = {`relative flex items-center gap-1 px-2 py-1.5 xl:px-2.5 xl:py-2 rounded-lg text-xs font-semibold tracking-wide transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-brand whitespace-nowrap shrink-0 ${currentRoute === 'admin_users' || currentRoute === 'admin_settings'
                                  ? 'text-brand-600 bg-brand-50/90 font-bold'
                                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100/80'
                                }`}
                aria-current={currentRoute === 'admin_users' ? 'page' : undefined}
                title="Administration (Security Admin only)"
              >
                <Settings className={`w-3.5 h-3.5 ${currentRoute === 'admin_users' ? 'text-brand-600' : 'text-gray-400'}`} />
                        <Settings className={`w-3.5 h-3.5 shrink-0 ${currentRoute === 'admin_users' ? 'text-brand-600' : 'text-gray-400'}`} />
                        <span>Administration</span>
                        {currentRoute === 'admin_users' && (
                          <span className="absolute bottom-0 left-2 right-2 h-0.5 bg-brand-600 rounded-full" />
                        )}
                      </button>
            )}
                    </nav>

                    {/* 3. RIGHT: Utility Tools & Authentication-Aware Controls */}
                    <div className="flex items-center gap-2 lg:gap-3">
                      <div className="flex items-center gap-1.5 sm:gap-2 xl:gap-2.5 shrink-0 min-w-0">
                        {/* Quick Search Trigger */}
                        <button
                          onClick={() => setSearchOpen(true)}
                          aria-label="Quick Search"
                          className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-gray-200 bg-gray-50/80 text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition text-xs"
                          title="Quick Search (Ctrl+K)"
                          className="flex items-center gap-1.5 px-2 py-1.5 sm:px-2.5 rounded-lg border border-gray-200 bg-gray-50/80 text-gray-500 hover:text-gray-900 hover:bg-gray-100 transition text-xs shrink-0"
                        >
                          <Search className="w-3.5 h-3.5" />
                          <span className="hidden xl:inline text-xs font-medium text-gray-500">Quick search...</span>
                          <kbd className="hidden sm:inline-block px-1.5 py-0.5 rounded bg-white border border-gray-200 text-[10px] font-mono text-gray-400 font-medium">
                            <span className="hidden 2xl:inline text-xs font-medium text-gray-500">Search...</span>
                            <kbd className="hidden sm:inline-block px-1.5 py-0.5 rounded bg-white border border-gray-200 text-[10px] font-mono text-gray-400 font-medium shrink-0">
                              ⌘K
                            </kbd>
                        </button>

                        {/* System Status Indicators (Compact pills) */}
                        <div className="hidden xl:flex items-center gap-1.5 px-2 py-1 rounded-lg bg-gray-50 border border-gray-200 text-[11px] font-medium text-gray-600">
                          <span className="flex items-center gap-1" title="SQL Server Instance Status">
                            <div className="hidden xl:flex items-center gap-1.5 px-2 py-1 rounded-lg bg-gray-50 border border-gray-200 text-[11px] font-medium text-gray-600 shrink-0">
                              <span className="flex items-center gap-1" title={sqlServerConnected ? "SQL Server Instance: Online" : "SQL Server Instance: Offline"}>
                                <Server className="w-3 h-3 text-gray-400" />
                                <span
                                  className={`w-1.5 h-1.5 rounded-full ${sqlServerConnected ? 'bg-emerald-500 ring-2 ring-emerald-500/20' : 'bg-rose-500 ring-2 ring-rose-500/20'
                                    }`}
                                />
                                <span className="text-[10px] text-gray-500">SQL</span>
                                <span className="text-[10px] text-gray-500 font-mono">SQL</span>
                              </span>
                              <span className="text-gray-300">|</span>
                              <span className="flex items-center gap-1" title="SeaweedFS WORM Vault Status">
                                <span className="flex items-center gap-1" title={wormVaultConnected ? "SeaweedFS WORM Vault: Protected" : "SeaweedFS WORM Vault: Offline"}>
                                  <Lock className="w-3 h-3 text-gray-400" />
                                  <span
                                    className={`w-1.5 h-1.5 rounded-full ${wormVaultConnected ? 'bg-emerald-500 ring-2 ring-emerald-500/20' : 'bg-rose-500 ring-2 ring-rose-500/20'
                                      }`}
                                  />
                                  <span className="text-[10px] text-gray-500">WORM</span>
                                  <span className="text-[10px] text-gray-500 font-mono">WORM</span>
                                </span>
                            </div>

                            {/* Refresh Action */}
                            <button
                              onClick={onRefreshAll}
                              disabled={isRefreshing}
                              aria-label="Refresh application state"
                              className="p-2 rounded-lg text-gray-500 hover:text-gray-900 hover:bg-gray-100 transition relative"
                              title="Refresh Telemetry"
                              className="p-1.5 sm:p-2 rounded-lg text-gray-500 hover:text-gray-900 hover:bg-gray-100 transition relative shrink-0"
                            >
                              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-brand-600' : ''}`} />
                              <RefreshCw className={`w-3.5 h-3.5 sm:w-4 sm:h-4 ${isRefreshing ? 'animate-spin text-brand-600' : ''}`} />
                            </button>

                            {/* Notification Bell */}
                            <div className="relative" ref={notificationRef}>
                              <div className="relative shrink-0" ref={notificationRef}>
                                <button
                                  onClick={() => setNotificationsOpen(!notificationsOpen)}
                                  aria-label={`Security Notifications (${unreadAlertsCount} unread)`}
                                  className="p-2 rounded-lg text-gray-500 hover:text-gray-900 hover:bg-gray-100 transition relative"
                                  title={`Security Notifications (${unreadAlertsCount} unread)`}
                                  className="p-1.5 sm:p-2 rounded-lg text-gray-500 hover:text-gray-900 hover:bg-gray-100 transition relative"
                                >
                                  <Bell className="w-4 h-4" />
                                  <Bell className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                                  {unreadAlertsCount > 0 && (
                  <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-rose-600 ring-2 ring-white animate-pulse" />
                  <span className="absolute top-1 right-1 sm:top-1.5 sm:right-1.5 w-2 h-2 rounded-full bg-rose-600 ring-2 ring-white animate-pulse" />
                                  )}
                                </button>

                                {/* Notifications Tray */}
                                {notificationsOpen && (
                                  <div className="absolute right-0 mt-2 w-[calc(100vw-2rem)] sm:w-96 max-w-sm bg-white rounded-xl shadow-xl border border-gray-200 z-50 overflow-hidden text-xs">
                                    <div className="p-3 border-b border-gray-100 bg-gray-50/70 flex items-center justify-between">
                                      <div className="flex items-center gap-2">
                                        <span className="font-bold text-gray-900">Security Telemetry</span>
                                        {unreadAlertsCount > 0 && (
                                          <span className="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200">
                                            {unreadAlertsCount} New
                                          </span>
                                        )}
                                      </div>
                                      <div className="flex items-center gap-1 text-[11px]">
                                        <button
                                          onClick={() => setNotificationFilter('UNRESOLVED')}
                                          className={`px-2 py-0.5 rounded transition ${notificationFilter === 'UNRESOLVED' ? 'bg-white font-bold text-gray-900 shadow-xs' : 'text-gray-500'
                                            }`}
                                        >
                                          Active
                                        </button>
                                        <button
                                          onClick={() => setNotificationFilter('CRITICAL')}
                                          className={`px-2 py-0.5 rounded transition ${notificationFilter === 'CRITICAL' ? 'bg-white font-bold text-gray-900 shadow-xs' : 'text-gray-500'
                                            }`}
                                        >
                                          Critical
                                        </button>
                                      </div>
                                    </div>

                                    <div className="max-h-72 overflow-y-auto divide-y divide-gray-100">
                                      {filteredAlerts.length === 0 ? (
                                        <div className="p-6 text-center text-gray-400">
                                          <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2 opacity-80" />
                                          <p className="font-medium text-gray-600">All alerts cleared</p>
                                          <p className="text-[11px] text-gray-400 mt-0.5">No unresolved threats in queue</p>
                                        </div>
                                      ) : (
                                        filteredAlerts.slice(0, 5).map((alert) => (
                                          <div key={alert.id} className="p-3 hover:bg-gray-50/80 transition flex items-start gap-2.5">
                                            <span
                                              className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${alert.severity === 'CRITICAL' ? 'bg-rose-500' : 'bg-amber-500'
                                                }`}
                                            />
                                            <div className="flex-1 min-w-0">
                                              <div className="flex items-center justify-between gap-1">
                                                <span className="font-semibold text-gray-800 truncate">{alert.title}</span>
                                                <span className="text-[10px] text-gray-400 shrink-0 font-mono">
                                                  {new Date(alert.detection_timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                                </span>
                                              </div>
                                              <p className="text-gray-500 line-clamp-1 mt-0.5">{alert.description || alert.explanation || 'Threat event logged'}</p>
                                            </div>
                                            <button
                                              onClick={() => handleAcknowledgeAlert(alert.id)}
                                              title="Acknowledge alert"
                                              className="p-1 text-gray-400 hover:text-emerald-600 transition"
                                            >
                                              <CheckCircle2 className="w-3.5 h-3.5" />
                                            </button>
                                          </div>
                                        ))
                                      )}
                                    </div>

                                    <div className="p-2 border-t border-gray-100 bg-gray-50/50 text-center">
                                      <button
                                        onClick={() => {
                                          onNavigate('sec_alerts_events')
                                          setNotificationsOpen(false)
                                        }}
                                        className="text-[11px] font-semibold text-brand-600 hover:text-brand-700 inline-flex items-center gap-1"
                                      >
                                        View All Security Alerts <ExternalLink className="w-3 h-3" />
                                      </button>
                                    </div>
                                  </div>
                                )}
                              </div>

                              <div className="h-4 w-px bg-gray-200 hidden sm:block" />

                              {/* 4. AUTHENTICATION-AWARE CONTROLS */}
                              {!currentSession ? (
                                /* LOGGED OUT: Sign In & Sign Up buttons */
                                <div className="flex items-center gap-2">
                                  <button
                                    onClick={() => onOpenAuthModal?.('login')}
                                    className="px-3 py-1.5 rounded-lg text-xs font-semibold text-gray-700 hover:text-gray-900 hover:bg-gray-100 transition"
                                  >
                                    Sign In
                                  </button>
                                  <button
                                    onClick={() => onOpenAuthModal?.('register')}
                                    className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-brand-600 hover:bg-brand-700 text-white shadow-xs transition"
                                  >
                                    Sign Up
                                  </button>
                                </div>
                              ) : (
                                /* LOGGED IN: User Profile & Role Badge */
                                <div className="relative" ref={accountMenuRef}>
                                  <div className="relative shrink-0" ref={accountMenuRef}>
                                    <button
                                      onClick={() => setAccountMenuOpen(!accountMenuOpen)}
                                      aria-label="User Account Menu"
                                      aria-expanded={accountMenuOpen}
                                      className="flex items-center gap-2 p-1 pl-2 pr-1.5 rounded-lg hover:bg-gray-100 transition border border-gray-200/80 bg-white"
                                      className="flex items-center gap-1.5 p-1 pl-1.5 sm:pl-2 pr-1 rounded-lg hover:bg-gray-100 transition border border-gray-200/80 bg-white"
                                    >
                                      <div className="text-left hidden sm:block">
                                        <div className="text-xs font-semibold text-gray-900 line-clamp-1 max-w-[120px]">
                                          <div className="text-left hidden md:block min-w-0">
                                            <div
                                              className="text-xs font-semibold text-gray-900 truncate max-w-[70px] xl:max-w-[105px]"
                                              title={currentSession.full_name || currentSession.username}
                                            >
                                              {currentSession.full_name || currentSession.username}
                                            </div>
                                            <div className="flex items-center gap-1">
                                              <span
                                                className={`text-[9px] font-mono px-1.5 py-0.2 rounded border font-semibold ${getRoleBadgeStyle(
                                                  className = {`hidden xl:inline-block text-[9px] font-mono px-1 py-0.2 rounded border font-semibold tracking-wider ${getRoleBadgeStyle(
                                                    currentSession.role
                                                  )}`}
                      >
                        {formatRoleLabel(currentSession.role)}
                        {formatCompactRole(currentSession.role)}
                      </span>
                    </div>
                  </div>

                  <div className="w-7 h-7 rounded-md bg-brand-100 text-brand-700 flex items-center justify-center font-bold text-xs uppercase border border-brand-200">
                  <div className="w-7 h-7 shrink-0 rounded-md bg-brand-100 text-brand-700 flex items-center justify-center font-bold text-xs uppercase border border-brand-200">
                    {currentSession.full_name
                      ? currentSession.full_name.charAt(0)
                      : currentSession.username.charAt(0)}
                  </div>
                </button>

                {/* Account Dropdown Menu */}
                {accountMenuOpen && (
                  <div className="absolute right-0 mt-2 w-[calc(100vw-2rem)] sm:w-80 max-w-xs bg-white rounded-xl shadow-xl border border-gray-200 z-50 overflow-hidden text-xs">
                    {/* User Identity Card */}
                    <div className="p-3.5 border-b border-gray-100 bg-gray-50/70">
                      <div className="flex items-center gap-2.5">
                        <div className="w-9 h-9 rounded-lg bg-brand-600 text-white flex items-center justify-center font-bold text-sm uppercase">
                          {currentSession.full_name ? currentSession.full_name.charAt(0) : currentSession.username.charAt(0)}
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="font-bold text-gray-900 truncate">
                            {currentSession.full_name || currentSession.username}
                          </p>
                          <p className="text-[11px] text-gray-500 truncate font-mono">
                            @{currentSession.username}
                          </p>
                        </div>
                      </div>

                      <div className="mt-2.5 flex items-center justify-between pt-2 border-t border-gray-200/60">
                        <span className="text-[10px] text-gray-500 font-medium">Assigned Role:</span>
                        <span
                          className={`text-[10px] font-semibold font-mono px-2 py-0.5 rounded border ${getRoleBadgeStyle(
                                                    currentSession.role
                                                  )}`}
                        >
                                              {formatRoleLabel(currentSession.role)}
                                            </span>
                                          </div>
                                        </div>

                                        {/* Quick Demo Persona Switcher (All 7 Roles) */}
                                        <div className="p-2 border-b border-gray-100">
                                          <div className="px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-gray-400">
                                            Switch Persona (RBAC Testing)
                                          </div>
                                          <div className="space-y-0.5 max-h-48 overflow-y-auto">
                                            {[
                                              { role: 'SECURITY_ADMIN', title: 'Security Administrator' },
                                              { role: 'INCIDENT_APPROVER', title: 'Incident Approver (SoD)' },
                                              { role: 'SENIOR_ANALYST', title: 'Senior DFIR Analyst' },
                                              { role: 'INVESTIGATION_ANALYST', title: 'Cyber Investigator' },
                                              { role: 'INCIDENT_REVIEWER', title: 'Incident Reviewer' },
                                              { role: 'AUDITOR', title: 'Compliance Auditor' },
                                              { role: 'READ_ONLY_REVIEWER', title: 'Read-Only Reviewer' }
                                            ].map((p) => (
                                              <button
                                                key={p.role}
                                                onClick={() => handleSwitchDemoPersona(p.role, p.title)}
                                                className={`w-full text-left px-2 py-1.5 rounded-lg flex items-center justify-between transition ${currentSession.role === p.role ? 'bg-brand-50 text-brand-700 font-semibold' : 'hover:bg-gray-50 text-gray-700'
                                                  }`}
                                              >
                                                <span className="text-[11px] truncate">{p.title}</span>
                                                {currentSession.role === p.role && <UserCheck className="w-3.5 h-3.5 text-brand-600" />}
                                              </button>
                                            ))}
                                          </div>
                                        </div>

                                        {/* Navigation Actions */}
                                        <div className="p-1 border-b border-gray-100">
                                          {isAdmin && (
                                            <button
                                              onClick={() => {
                                                onNavigate('admin_users')
                                                setAccountMenuOpen(false)
                                              }}
                                              className="w-full text-left px-3 py-2 rounded-lg flex items-center gap-2 hover:bg-gray-50 text-gray-700 transition"
                                            >
                                              <Settings className="w-3.5 h-3.5 text-gray-500" />
                                              <span>User Management & RBAC</span>
                                            </button>
                                          )}
                                          <button
                                            onClick={() => {
                                              onNavigate('admin_settings')
                                              setAccountMenuOpen(false)
                                            }}
                                            className="w-full text-left px-3 py-2 rounded-lg flex items-center gap-2 hover:bg-gray-50 text-gray-700 transition"
                                          >
                                            <Server className="w-3.5 h-3.5 text-gray-500" />
                                            <span>Platform Infrastructure</span>
                                          </button>
                                        </div>

                                        {/* Sign Out Action */}
                                        <div className="p-1">
                                          <button
                                            onClick={handleSignOut}
                                            className="w-full text-left px-3 py-2 rounded-lg flex items-center gap-2 text-rose-600 hover:bg-rose-50 transition font-medium"
                                          >
                                            <LogOut className="w-3.5 h-3.5" />
                                            <span>Sign Out</span>
                                          </button>
                                        </div>
                                      </div>
                )}
                                  </div>
            )}

                                  {/* Mobile Menu Toggle Button */}
                                  {/* Mobile/Tablet Menu Button (Visible on < 1024px) */}
                                  <button
                                    onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                                    aria-label="Toggle Mobile Navigation"
                                    className="md:hidden p-2 rounded-lg text-gray-500 hover:text-gray-900 hover:bg-gray-100 transition"
                                    aria-label="Toggle Navigation Menu"
                                    className="lg:hidden p-1.5 sm:p-2 rounded-lg text-gray-500 hover:text-gray-900 hover:bg-gray-100 transition shrink-0"
                                  >
                                    {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
                                  </button>
                                </div>
        </div>
                        </div>

                        {/* 5. MOBILE NAVIGATION DRAWER (Direct links, touch target >= 44px, no nested dropdowns) */}
                        {/* 5. RESPONSIVE NAVIGATION DRAWER (Tablets & Mobile, direct links, touch targets >= 44px) */}
                        {mobileMenuOpen && (
                          <div className="md:hidden border-t border-gray-200 bg-white px-4 py-4 space-y-2 shadow-lg animate-in slide-in-from-top-2 duration-200 max-h-[calc(100vh-4rem)] overflow-y-auto w-full max-w-full">
                            <div className="text-[11px] font-bold uppercase tracking-wider text-gray-400 px-3">
                              <div className="lg:hidden border-t border-gray-200 bg-white px-3 sm:px-4 py-3 sm:py-4 space-y-3 shadow-lg animate-in slide-in-from-top-2 duration-200 max-h-[calc(100vh-4rem)] overflow-y-auto w-full max-w-full">
                                {/* Quick search input in drawer */}
                                <button
                                  onClick={() => {
                                    setMobileMenuOpen(false)
                                    setSearchOpen(true)
                                  }}
                                  className="w-full flex items-center justify-between px-3 py-2 rounded-lg border border-gray-200 bg-gray-50 text-xs text-gray-500 hover:bg-gray-100 transition"
                                >
                                  <div className="flex items-center gap-2">
                                    <Search className="w-4 h-4 text-gray-400" />
                                    <span>Quick search platform...</span>
                                  </div>
                                  <kbd className="px-1.5 py-0.5 rounded bg-white border border-gray-200 text-[10px] font-mono text-gray-400 font-medium">
                                    ⌘K
                                  </kbd>
                                </button>

                                {/* Infrastructure Health Status */}
                                <div className="flex items-center justify-between px-3 py-2 bg-gray-50 rounded-lg text-xs">
                                  <span className="font-semibold text-gray-600">Infrastructure:</span>
                                  <div className="flex items-center gap-3">
                                    <span className="flex items-center gap-1.5">
                                      <span
                                        className={`w-2 h-2 rounded-full ${sqlServerConnected ? 'bg-emerald-500' : 'bg-rose-500'
                                          }`}
                                      />
                                      <span className="text-gray-700 font-mono">SQL Server</span>
                                    </span>
                                    <span className="text-gray-300">|</span>
                                    <span className="flex items-center gap-1.5">
                                      <span
                                        className={`w-2 h-2 rounded-full ${wormVaultConnected ? 'bg-emerald-500' : 'bg-rose-500'
                                          }`}
                                      />
                                      <span className="text-gray-700 font-mono">WORM Vault</span>
                                    </span>
                                  </div>
                                </div>

                                <div className="text-[11px] font-bold uppercase tracking-wider text-gray-400 px-3 pt-1">
                                  Primary Platform Navigation
                                </div>

                                <div className="space-y-1">
                                  {authorizedNavItems.map((item) => {
                                    const isActive = item.activeRoutes.includes(currentRoute)
                                    return (
                                      <button
                                        key={item.id}
                                        onClick={() => {
                                          onNavigate(item.targetRoute)
                                          setMobileMenuOpen(false)
                                        }}
                                        className={`w-full flex items-center justify-between px-3 min-h-[44px] rounded-lg text-sm font-semibold transition ${isActive
                                            ? 'bg-brand-50 text-brand-700 font-bold'
                                            : 'text-gray-700 hover:bg-gray-50'
                                          }`}
                                      >
                                        <div className="flex items-center gap-3">
                                          <item.icon className={`w-4 h-4 ${isActive ? 'text-brand-600' : 'text-gray-400'}`} />
                                          <span>{item.label}</span>
                                        </div>
                                        {item.badge !== undefined && Number(item.badge) > 0 && (
                                          <span className="px-2 py-0.5 rounded-full text-xs font-mono font-bold bg-brand-100 text-brand-700">
                                            {item.badge}
                                          </span>
                                        )}
                                      </button>
                                    )
                                  })}

                                  {isAdmin && (
                                    <button
                                      onClick={() => {
                                        onNavigate('admin_users')
                                        setMobileMenuOpen(false)
                                      }}
                                      className={`w-full flex items-center justify-between px-3 min-h-[44px] rounded-lg text-sm font-semibold transition ${currentRoute === 'admin_users'
                                          ? 'bg-brand-50 text-brand-700 font-bold'
                                          : 'text-gray-700 hover:bg-gray-50'
                                        }`}
                                    >
                                      <div className="flex items-center gap-3">
                                        <Settings className="w-4 h-4 text-gray-400" />
                                        <span>Administration & Users</span>
                                      </div>
                                    </button>
                                  )}
                                </div>

                                {/* Mobile Auth actions */}
                                <div className="pt-3 border-t border-gray-200">
                                  {!currentSession ? (
                                    <div className="grid grid-cols-2 gap-2 pt-1">
                                      <button
                                        onClick={() => {
                                          setMobileMenuOpen(false)
                                          onOpenAuthModal?.('login')
                                        }}
                                        className="w-full min-h-[44px] rounded-lg border border-gray-300 text-sm font-semibold text-gray-700 flex items-center justify-center hover:bg-gray-50 transition"
                                      >
                                        Sign In
                                      </button>
                                      <button
                                        onClick={() => {
                                          setMobileMenuOpen(false)
                                          onOpenAuthModal?.('register')
                                        }}
                                        className="w-full min-h-[44px] rounded-lg bg-brand-600 text-sm font-semibold text-white flex items-center justify-center hover:bg-brand-700 transition"
                                      >
                                        Sign Up
                                      </button>
                                    </div>
                                  ) : (
                                    <div className="space-y-2 pt-1">
                                      <div className="flex items-center justify-between px-3 py-2 bg-gray-50 rounded-lg">
                                        <div>
                                          <div className="text-sm font-bold text-gray-900">{currentSession.full_name || currentSession.username}</div>
                                          <div className="text-xs text-gray-500 font-mono">@{currentSession.username}</div>
                                        </div>
                                        <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${getRoleBadgeStyle(currentSession.role)}`}>
                                          {formatRoleLabel(currentSession.role)}
                                        </span>
                                      </div>
                                      <button
                                        onClick={() => {
                                          setMobileMenuOpen(false)
                                          handleSignOut()
                                        }}
                                        className="w-full min-h-[44px] rounded-lg text-sm font-semibold text-rose-600 hover:bg-rose-50 flex items-center justify-center gap-2 transition"
                                      >
                                        <LogOut className="w-4 h-4" />
                                        Sign Out
                                      </button>
                                    </div>
                                  )}
                                </div>
                              </div>
      )}

                              {/* 6. GLOBAL QUICK-SEARCH MODAL */}
                              {searchOpen && (
                                <div className="fixed inset-0 z-50 bg-gray-900/50 backdrop-blur-xs flex items-start justify-center p-4 pt-20">
                                  <div className="bg-white rounded-xl shadow-2xl border border-gray-200 w-full max-w-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
                                    <div className="p-3 border-b border-gray-100 flex items-center gap-2">
                                      <Search className="w-4 h-4 text-gray-400 shrink-0" />
                                      <input
                                        ref={searchInputRef}
                                        type="text"
                                        value={searchQuery}
                                        onChange={(e) => setSearchQuery(e.target.value)}
                                        placeholder="Jump to section, database, baseline, or case..."
                                        className="w-full text-sm outline-none text-gray-900 placeholder:text-gray-400 bg-transparent"
                                      />
                                      <button
                                        onClick={() => setSearchOpen(false)}
                                        className="p-1 text-gray-400 hover:text-gray-700 rounded transition"
                                      >
                                        <X className="w-4 h-4" />
                                      </button>
                                    </div>

                                    <div className="max-h-80 overflow-y-auto p-2">
                                      <div className="text-[11px] font-bold uppercase tracking-wider text-gray-400 px-3 py-1.5">
                                        Quick Navigation
                                      </div>
                                      <div className="space-y-0.5">
                                        {primaryNavItems.map((item) => (
                                          <button
                                            key={item.id}
                                            onClick={() => {
                                              onNavigate(item.targetRoute)
                                              setSearchOpen(false)
                                            }}
                                            className="w-full text-left px-3 py-2 rounded-lg flex items-center justify-between text-xs hover:bg-gray-50 text-gray-700 transition"
                                          >
                                            <div className="flex items-center gap-2.5">
                                              <item.icon className="w-4 h-4 text-brand-600" />
                                              <span className="font-semibold text-gray-900">{item.label}</span>
                                            </div>
                                            <ChevronRight className="w-3.5 h-3.5 text-gray-400" />
                                          </button>
                                        ))}
                                      </div>
                                    </div>

                                    <div className="p-2.5 bg-gray-50 border-t border-gray-100 flex items-center justify-between text-[11px] text-gray-400">
                                      <span>Press ESC to close</span>
                                      <span>SQL-TRUST Enterprise v1.0</span>
                                    </div>
                                  </div>
                                </div>
                              )}
                            </header>
                            )
}
