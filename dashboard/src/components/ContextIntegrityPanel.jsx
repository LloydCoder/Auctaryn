import { useState, useEffect } from 'react'
import { Shield, CheckCircle, AlertTriangle, XCircle, RefreshCw } from 'lucide-react'
import { fetchContextStatus, triggerContextCheck } from '../utils/api'

export default function ContextIntegrityPanel({ compact = false }) {
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetchContextStatus().then(setStatus).catch(() => {})
  }, [])

  const handleCheck = async () => {
    setLoading(true)
    try {
      await triggerContextCheck()
      const updated = await fetchContextStatus()
      setStatus(updated)
    } catch {}
    setLoading(false)
  }

  const statusIcon = {
    intact: <CheckCircle className="w-6 h-6 text-emerald-400" />,
    degraded: <AlertTriangle className="w-6 h-6 text-amber-400" />,
    compromised: <XCircle className="w-6 h-6 text-red-400" />,
  }

  const statusColor = {
    intact: 'text-emerald-400',
    degraded: 'text-amber-400',
    compromised: 'text-red-400',
  }

  return (
    <div className="bg-[#111827] border border-gray-800/50 rounded-xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-cyan-400" />
          <h3 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">
            Context Integrity
          </h3>
        </div>
        {!compact && (
          <button
            onClick={handleCheck}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-cyan-400 border border-cyan-400/30 rounded-lg hover:bg-cyan-400/10 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Check Now
          </button>
        )}
      </div>

      <div className="flex items-center gap-4">
        {statusIcon[status?.status] || statusIcon.intact}
        <div>
          <div className={`text-xl font-bold capitalize ${statusColor[status?.status] || 'text-gray-400'}`}>
            {status?.status || 'Initializing...'}
          </div>
          <div className="text-xs text-gray-500 mt-0.5">
            {status?.instructions_protected || 0} instructions protected
          </div>
        </div>
      </div>

      {!compact && (
        <div className="mt-6 space-y-3">
          <div className="text-xs text-gray-500">
            {status?.message || 'Waiting for first integrity check...'}
          </div>
          <div className="text-xs text-gray-600">
            Last check: {status?.last_check || 'Never'}
          </div>

          {/* Placeholder for integrity check history */}
          <div className="mt-4 border-t border-gray-800/50 pt-4">
            <h4 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-3">
              Recent Checks
            </h4>
            <div className="text-center py-8 text-gray-600 text-sm">
              No integrity checks recorded yet.
              <br />
              <span className="text-xs">Checks will appear here once the Guardian is active.</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
