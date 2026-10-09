import { Shield, Activity, Network, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'

const STATUS_STYLES = {
  healthy: { color: 'text-emerald-400', bg: 'bg-emerald-400/10', icon: CheckCircle },
  degraded: { color: 'text-amber-400', bg: 'bg-amber-400/10', icon: AlertTriangle },
  error: { color: 'text-red-400', bg: 'bg-red-400/10', icon: XCircle },
  disabled: { color: 'text-gray-500', bg: 'bg-gray-500/10', icon: XCircle },
}

const MODULE_ICONS = {
  context_integrity: Shield,
  execution_gateway: AlertTriangle,
  threatfade_oracle: Network,
}

export default function SystemHealth({ health, connected }) {
  const modules = health?.modules || []

  return (
    <div>
      <h2 className="text-sm font-medium text-gray-400 uppercase tracking-wider mb-4">System Status</h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Overall status */}
        <div className="bg-[#111827] border border-gray-800/50 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-3">
            <Activity className="w-5 h-5 text-emerald-400" />
            <span className="text-sm font-medium text-gray-300">Overall</span>
          </div>
          <div className={`text-2xl font-bold ${connected ? 'text-emerald-400' : 'text-red-400'}`}>
            {connected ? 'Operational' : 'Offline'}
          </div>
          <div className="text-xs text-gray-500 mt-1">
            {health?.overall_status || 'checking...'}
          </div>
        </div>

        {/* Per-module status cards */}
        {modules.map(mod => {
          const style = STATUS_STYLES[mod.status] || STATUS_STYLES.disabled
          const StatusIcon = style.icon
          const ModIcon = MODULE_ICONS[mod.name] || Activity

          return (
            <div key={mod.name} className="bg-[#111827] border border-gray-800/50 rounded-xl p-5">
              <div className="flex items-center gap-3 mb-3">
                <ModIcon className="w-5 h-5 text-gray-400" />
                <span className="text-sm font-medium text-gray-300">
                  {mod.name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <StatusIcon className={`w-5 h-5 ${style.color}`} />
                <span className={`text-lg font-semibold capitalize ${style.color}`}>
                  {mod.status}
                </span>
              </div>
              {mod.uptime_seconds > 0 && (
                <div className="text-xs text-gray-500 mt-1">
                  Uptime: {Math.floor(mod.uptime_seconds / 60)}m
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
