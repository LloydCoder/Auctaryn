import { useMemo } from 'react'
import { Bell, AlertTriangle, ShieldAlert, Info, XCircle } from 'lucide-react'

const SEVERITY_ICONS = {
  critical: XCircle,
  high: ShieldAlert,
  medium: AlertTriangle,
  low: Info,
  info: Bell,
}

const SEVERITY_COLORS = {
  critical: 'text-red-400 border-red-400/20 bg-red-400/5',
  high: 'text-orange-400 border-orange-400/20 bg-orange-400/5',
  medium: 'text-amber-400 border-amber-400/20 bg-amber-400/5',
  low: 'text-blue-400 border-blue-400/20 bg-blue-400/5',
  info: 'text-gray-400 border-gray-700 bg-gray-800/30',
}

export default function AlertFeed({ liveAlerts = [] }) {
  // Most recent first
  const alerts = useMemo(() => [...liveAlerts].reverse(), [liveAlerts])

  return (
    <div className="bg-[#111827] border border-gray-800/50 rounded-xl p-6">
      <div className="flex items-center gap-3 mb-4">
        <Bell className="w-5 h-5 text-gray-400" />
        <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">
          Alert Feed
        </h3>
        {alerts.length > 0 && (
          <span className="px-2 py-0.5 text-xs font-medium text-red-400 bg-red-400/10 rounded-full">
            {alerts.length}
          </span>
        )}
      </div>

      {alerts.length === 0 ? (
        <div className="text-center py-8 text-gray-600 text-sm">
          <Bell className="w-8 h-8 mx-auto mb-2 opacity-20" />
          No alerts. System is quiet.
        </div>
      ) : (
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {alerts.map((alert, i) => {
            const Icon = SEVERITY_ICONS[alert.severity] || Bell
            const colorClass = SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.info
            return (
              <div key={`${alert.timestamp}-${i}`} className={`flex items-start gap-3 p-3 rounded-lg border ${colorClass}`}>
                <Icon className="w-4 h-4 mt-0.5 shrink-0" />
                <div className="min-w-0">
                  <div className="text-sm font-medium text-gray-200">{alert.title}</div>
                  <div className="text-xs text-gray-500 mt-0.5">{alert.message}</div>
                  <div className="text-xs text-gray-600 mt-1">
                    {alert.module} · {new Date(alert.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
