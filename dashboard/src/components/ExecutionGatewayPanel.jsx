import { useState, useEffect, useMemo } from 'react'
import { Check, X, Clock, ShieldAlert } from 'lucide-react'
import { fetchGatewayStatus, fetchPending, fetchDecisions } from '../utils/api'

const RISK_STYLES = {
  safe: { label: 'Safe', color: 'text-emerald-400', bg: 'bg-emerald-400/10', border: 'border-emerald-400/20' },
  moderate: { label: 'Moderate', color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/20' },
  destructive: { label: 'Destructive', color: 'text-amber-400', bg: 'bg-amber-400/10', border: 'border-amber-400/20' },
  critical: { label: 'Critical', color: 'text-red-400', bg: 'bg-red-400/10', border: 'border-red-400/20' },
}

const DECISION_STYLES = {
  approved: 'text-emerald-400',
  pending: 'text-amber-400',
  vetoed: 'text-red-400',
  denied: 'text-red-400',
}

export default function ExecutionGatewayPanel({ compact = false, liveDecisions = [], onApprove }) {
  const [status, setStatus] = useState(null)
  const [pending, setPending] = useState([])
  const [recent, setRecent] = useState([])

  useEffect(() => {
    fetchGatewayStatus().then(setStatus).catch(() => {})
    fetchPending().then(setPending).catch(() => {})
    fetchDecisions(10).then(setRecent).catch(() => {})
  }, [])

  // Re-poll whenever a new live decision arrives over the WebSocket —
  // this is what actually makes the panel feel real-time instead of
  // requiring a manual refresh.
  useEffect(() => {
    if (liveDecisions.length === 0) return
    fetchGatewayStatus().then(setStatus).catch(() => {})
    fetchPending().then(setPending).catch(() => {})
    fetchDecisions(10).then(setRecent).catch(() => {})
  }, [liveDecisions.length])

  const handleApprove = (decisionId, approved) => {
    onApprove?.(decisionId, approved)
    // Optimistically remove from pending list while we wait for the
    // WebSocket round-trip to confirm
    setPending(prev => prev.filter(p => p.id !== decisionId))
  }

  return (
    <div className="bg-[#111827] border border-gray-800/50 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">
            Execution Gateway
          </h3>
        </div>
        {pending.length > 0 && (
          <span className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-amber-400 bg-amber-400/10 border border-amber-400/20 rounded-full">
            <Clock className="w-3 h-3" />
            {pending.length} pending
          </span>
        )}
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4 mb-4">
        <div>
          <div className="text-2xl font-bold text-gray-200">{status?.total_processed ?? 0}</div>
          <div className="text-xs text-gray-500">Processed</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-amber-400">{status?.pending_approvals ?? 0}</div>
          <div className="text-xs text-gray-500">Pending</div>
        </div>
        <div>
          <div className="text-2xl font-bold text-red-400">{status?.total_vetoed ?? 0}</div>
          <div className="text-xs text-gray-500">Vetoed</div>
        </div>
      </div>

      {!compact && (
        <div className="border-t border-gray-800/50 pt-4">
          <h4 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-3">
            Pending Approvals
          </h4>

          {pending.length === 0 ? (
            <div className="text-center py-8 text-gray-600 text-sm">
              No actions awaiting approval.
              <br />
              <span className="text-xs">Destructive actions will appear here for review.</span>
            </div>
          ) : (
            <div className="space-y-2">
              {pending.map((item) => {
                const risk = RISK_STYLES[item.risk_level] || RISK_STYLES.moderate
                return (
                  <div key={item.id} className={`flex items-center justify-between p-3 rounded-lg border ${risk.border} ${risk.bg}`}>
                    <div className="min-w-0 pr-3">
                      <div className="text-sm font-medium text-gray-200 truncate">
                        {item.tool_call?.tool_name}:{item.tool_call?.action}
                      </div>
                      <div className="text-xs text-gray-500 truncate">{item.reason}</div>
                    </div>
                    <div className="flex gap-2 shrink-0">
                      <button
                        onClick={() => handleApprove(item.id, true)}
                        className="p-1.5 rounded-lg bg-emerald-400/10 text-emerald-400 hover:bg-emerald-400/20 transition-colors"
                      >
                        <Check className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleApprove(item.id, false)}
                        className="p-1.5 rounded-lg bg-red-400/10 text-red-400 hover:bg-red-400/20 transition-colors"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          {/* Recent decisions */}
          <h4 className="text-xs font-medium text-gray-400 uppercase tracking-wider mt-6 mb-3">
            Recent Decisions
          </h4>
          {recent.length === 0 ? (
            <div className="text-center py-6 text-gray-600 text-sm">
              No decisions recorded yet.
            </div>
          ) : (
            <div className="space-y-1.5">
              {[...recent].reverse().map((d) => (
                <div key={d.id} className="flex items-center justify-between text-xs py-2 px-3 rounded-lg bg-gray-900/40">
                  <span className="text-gray-400 truncate pr-2">
                    {d.tool_call?.tool_name}:{d.tool_call?.action}
                  </span>
                  <span className={`font-medium uppercase shrink-0 ${DECISION_STYLES[d.decision] || 'text-gray-400'}`}>
                    {d.decision}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
