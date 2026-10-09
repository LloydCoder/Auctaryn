import { useState, useEffect, useMemo } from 'react'
import { Shield, Activity, Network, AlertTriangle, CheckCircle, XCircle, ShieldAlert, LogOut } from 'lucide-react'
import ContextIntegrityPanel from './components/ContextIntegrityPanel'
import ExecutionGatewayPanel from './components/ExecutionGatewayPanel'
import ThreatFadePanel from './components/ThreatFadePanel'
import SystemHealth from './components/SystemHealth'
import AlertFeed from './components/AlertFeed'
import IncidentEvidencePanel from './components/IncidentEvidencePanel'
import { fetchHealth, setApiToken, validateAdminToken } from './utils/api'
import { useWebSocket } from './hooks/useWebSocket'

const TABS = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'context', label: 'Context Integrity', icon: Shield },
  { id: 'gateway', label: 'Execution Gateway', icon: AlertTriangle },
  { id: 'threatfade', label: 'ThreatFade', icon: Network },
  { id: 'incidents', label: 'Incidents & Evidence', icon: ShieldAlert },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('overview')
  const [health, setHealth] = useState(null)
  const [apiConnected, setApiConnected] = useState(false)
  const [apiToken, setApiTokenState] = useState('')
  const [credentialInput, setCredentialInput] = useState('')
  const [authError, setAuthError] = useState('')
  const [authLoading, setAuthLoading] = useState(false)

  // Live WebSocket streams — these are the real-time feeds the dashboard
  // was missing: the backend was already broadcasting, nothing was listening.
  const actionsWs = useWebSocket('/ws/actions', { token: apiToken })
  const alertsWs = useWebSocket('/ws/alerts', { token: apiToken })

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const data = await fetchHealth()
        setHealth(data)
        setApiConnected(true)
      } catch {
        setApiConnected(false)
      }
    }
    checkHealth()
    const interval = setInterval(checkHealth, 10000)
    return () => clearInterval(interval)
  }, [])

  // Derive live decisions (excluding the initial "connected" handshake frame)
  const liveDecisions = useMemo(
    () => actionsWs.messages.filter(m => m.type === 'gateway_decision' || m.type === 'decision_resolved'),
    [actionsWs.messages]
  )
  const liveAlerts = useMemo(
    () => alertsWs.messages.filter(m => m.type === 'alert' || m.type === 'incident_alert'),
    [alertsWs.messages]
  )

  const wsConnected = actionsWs.connected && alertsWs.connected
  const fullyConnected = apiConnected && wsConnected

  const sendApproval = (decisionId, approved) => {
    actionsWs.send({ type: 'approve', decision_id: decisionId, approved })
  }

  const handleSignOut = () => {
    setApiToken('')
    setApiTokenState('')
    setActiveTab('overview')
    setAuthError('')
  }

  const handleAuthenticate = async (event) => {
    event.preventDefault()
    setAuthLoading(true)
    setAuthError('')
    try {
      await validateAdminToken(credentialInput)
      setApiToken(credentialInput)
      setApiTokenState(credentialInput)
      setCredentialInput('')
    } catch (error) {
      setAuthError(error.message || 'Authentication failed.')
    } finally {
      setAuthLoading(false)
    }
  }

  if (!apiToken) {
    return (
      <main className="min-h-screen bg-[#0a0e17] flex items-center justify-center px-6">
        <form onSubmit={handleAuthenticate} className="w-full max-w-md rounded-2xl border border-gray-800 bg-[#111827] p-8 space-y-5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-500 flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-semibold text-white">Auctaryn</h1>
              <p className="text-sm text-gray-400">Administrator sign-in</p>
            </div>
          </div>
          <p className="text-sm text-gray-400">Enter the administrator API key configured on the Auctaryn server. The key is held in memory for this browser session and is not saved to local storage.</p>
          <label className="block space-y-2">
            <span className="text-sm text-gray-300">Administrator API key</span>
            <input
              type="password"
              autoComplete="current-password"
              value={credentialInput}
              onChange={(event) => setCredentialInput(event.target.value)}
              required
              className="w-full rounded-lg border border-gray-700 bg-[#0a0e17] px-3 py-2.5 text-sm text-white outline-none focus:border-emerald-400"
            />
          </label>
          {authError && <p role="alert" className="text-sm text-red-400">{authError}</p>}
          <button type="submit" disabled={authLoading} className="w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-[#061016] disabled:opacity-50">
            {authLoading ? 'Verifying…' : 'Authenticate'}
          </button>
        </form>
      </main>
    )
  }

  return (
    <div className="min-h-screen bg-[#0a0e17]">
      {/* Header */}
      <header className="border-b border-gray-800/50 bg-[#0d1220]/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500 flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-white">Auctaryn</h1>
              <p className="text-xs text-gray-500">Runtime Authority for Autonomous AI</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-sm">
              {fullyConnected ? (
                <>
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                  <span className="text-emerald-400">Live</span>
                </>
              ) : (
                <>
                  <XCircle className="w-4 h-4 text-amber-400" />
                  <span className="text-amber-400">{apiConnected ? 'Reconnecting…' : 'Offline'}</span>
                </>
              )}
            </div>
            <span className="text-xs text-gray-600 font-mono">
              v{health?.version || '0.1.0-alpha'}
            </span>
            <button type="button" onClick={handleSignOut} className="inline-flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-xs text-gray-300 hover:border-emerald-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400" aria-label="Sign out of Auctaryn administrator session">
              <LogOut className="h-4 w-4" /> Sign out
            </button>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav aria-label="Administrator dashboard sections" className="border-b border-gray-800/30 bg-[#0d1220]/40">
        <div role="tablist" aria-label="Auctaryn sections" className="max-w-7xl mx-auto px-6 flex gap-1 overflow-x-auto">
          {TABS.map(tab => {
            const Icon = tab.icon
            const isActive = activeTab === tab.id
            return (
              <button
                key={tab.id}
                id={`tab-${tab.id}`}
                type="button"
                role="tab"
                aria-selected={isActive}
                aria-controls="dashboard-tabpanel"
                onClick={() => setActiveTab(tab.id)}
                onKeyDown={(event) => {
                  const tabs = Array.from(event.currentTarget.parentElement.querySelectorAll('[role="tab"]'))
                  const index = tabs.indexOf(event.currentTarget)
                  let next = index
                  if (event.key === 'ArrowRight') next = (index + 1) % tabs.length
                  else if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length
                  else if (event.key === 'Home') next = 0
                  else if (event.key === 'End') next = tabs.length - 1
                  else return
                  event.preventDefault()
                  tabs[next].focus()
                  tabs[next].click()
                }}
                className={`flex shrink-0 items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-emerald-400 ${
                  isActive
                    ? 'border-emerald-400 text-emerald-400'
                    : 'border-transparent text-gray-500 hover:text-gray-300'
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            )
          })}
        </div>
      </nav>

      {/* Main Content */}
      <main id="dashboard-tabpanel" role="tabpanel" aria-labelledby={`tab-${activeTab}`} tabIndex={0} className="max-w-7xl mx-auto px-6 py-8 focus-visible:outline-none">
        {activeTab === 'overview' && (
          <div className="space-y-8">
            <SystemHealth health={health} connected={apiConnected} />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ContextIntegrityPanel compact />
              <ExecutionGatewayPanel
                compact
                liveDecisions={liveDecisions}
                onApprove={sendApproval}
              />
            </div>
            <AlertFeed liveAlerts={liveAlerts} />
          </div>
        )}
        {activeTab === 'context' && <ContextIntegrityPanel />}
        {activeTab === 'gateway' && (
          <ExecutionGatewayPanel liveDecisions={liveDecisions} onApprove={sendApproval} />
        )}
        {activeTab === 'threatfade' && <ThreatFadePanel />}
        {activeTab === 'incidents' && <IncidentEvidencePanel />}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800/30 mt-16 py-6">
        <div className="max-w-7xl mx-auto px-6 flex justify-between text-xs text-gray-600">
          <span>© 2026 Tinlance Limited</span>
          <span>Built on NVIDIA OpenShell</span>
        </div>
      </footer>
    </div>
  )
}
