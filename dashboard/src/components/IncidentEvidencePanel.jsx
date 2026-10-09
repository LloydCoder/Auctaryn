import { useCallback, useEffect, useState } from 'react'
import { Activity, AlertTriangle, CheckCircle, RefreshCw, ShieldAlert, FileCheck2 } from 'lucide-react'
import {
  fetchIncidentStatus,
  fetchIncidentAlerts,
  setEmergencyStop,
  transitionIncidentAlert,
  fetchEvidenceRecords,
  verifyEvidenceChain,
} from '../utils/api'

const panelClass = 'rounded-xl border border-gray-800/70 bg-[#111827] p-5'
const buttonClass = 'rounded-lg border border-gray-700 px-3 py-2 text-sm font-medium text-gray-200 hover:border-emerald-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 disabled:cursor-not-allowed disabled:opacity-50'

function formatTime(value) {
  if (!value) return 'Unknown time'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString()
}

export default function IncidentEvidencePanel() {
  const [status, setStatus] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [evidence, setEvidence] = useState([])
  const [verification, setVerification] = useState(null)
  const [reason, setReason] = useState('')
  const [loading, setLoading] = useState(false)
  const [busyAction, setBusyAction] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const refresh = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [incident, alertPage, evidencePage, verified] = await Promise.all([
        fetchIncidentStatus(),
        fetchIncidentAlerts('', 100),
        fetchEvidenceRecords(100),
        verifyEvidenceChain(),
      ])
      setStatus(incident)
      setAlerts(alertPage.alerts || [])
      setEvidence(evidencePage.records || [])
      setVerification({ ...verified, integrity_mode: evidencePage.integrity_mode })
    } catch (cause) {
      setError(cause?.message || 'Unable to load incident and evidence data.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const updateEmergencyStop = async (enabled) => {
    if (reason.trim().length < 3) {
      setError('Enter a reason of at least 3 characters before changing the emergency stop.')
      return
    }
    setBusyAction('emergency-stop')
    setError('')
    setNotice('')
    try {
      await setEmergencyStop(enabled, reason.trim())
      setNotice(enabled ? 'Emergency stop enabled. New execution is blocked.' : 'Emergency stop disabled.')
      setReason('')
      await refresh()
    } catch (cause) {
      setError(cause?.message || 'Emergency-stop update failed.')
    } finally {
      setBusyAction('')
    }
  }

  const transitionAlert = async (alertId, action) => {
    setBusyAction(alertId)
    setError('')
    setNotice('')
    try {
      await transitionIncidentAlert(alertId, action)
      setNotice(action === 'acknowledge' ? 'Alert acknowledged.' : 'Alert resolved.')
      await refresh()
    } catch (cause) {
      setError(cause?.message || 'Alert transition failed.')
    } finally {
      setBusyAction('')
    }
  }

  return (
    <section className="space-y-6" aria-labelledby="incident-evidence-heading">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 id="incident-evidence-heading" className="text-xl font-semibold text-white">Incidents &amp; evidence</h2>
          <p className="mt-1 text-sm text-gray-400">Administrator-only containment controls, alert lifecycle and bounded forensic metadata.</p>
        </div>
        <button type="button" className={buttonClass} onClick={refresh} disabled={loading} aria-label="Refresh incident and evidence data">
          <span className="inline-flex items-center gap-2"><RefreshCw className="h-4 w-4" />{loading ? 'Refreshing…' : 'Refresh'}</span>
        </button>
      </div>

      {error && <p role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">{error}</p>}
      {notice && <p role="status" aria-live="polite" className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-200">{notice}</p>}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className={panelClass}>
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-amber-300" />
            <h3 className="font-semibold text-white">Global emergency stop</h3>
          </div>
          <p className="mt-3 text-sm text-gray-400">Current state: <strong className={status?.emergency_stop ? 'text-red-300' : 'text-emerald-300'}>{status?.emergency_stop ? 'ENABLED' : 'DISABLED'}</strong></p>
          <label htmlFor="incident-stop-reason" className="mt-4 block text-sm text-gray-300">Reason for change</label>
          <textarea
            id="incident-stop-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            maxLength={512}
            rows={2}
            placeholder="Describe the incident or recovery authorization"
            className="mt-2 w-full rounded-lg border border-gray-700 bg-[#0a0e17] p-3 text-sm text-white outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          />
          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" className={buttonClass} disabled={Boolean(busyAction) || status?.emergency_stop === true} onClick={() => updateEmergencyStop(true)}>Enable stop</button>
            <button type="button" className={buttonClass} disabled={Boolean(busyAction) || status?.emergency_stop !== true} onClick={() => updateEmergencyStop(false)}>Disable stop</button>
          </div>
          <p className="mt-3 text-xs text-gray-500">Server-side administrator authorization is enforced. This local control does not replace Platform-side authorization or multi-replica fencing.</p>
        </div>

        <div className={panelClass}>
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-cyan-300" />
            <h3 className="font-semibold text-white">Incident status</h3>
          </div>
          <dl className="mt-4 grid grid-cols-2 gap-4">
            <div><dt className="text-xs uppercase tracking-wide text-gray-500">Open alerts</dt><dd className="mt-1 text-2xl font-semibold text-white">{status?.alert_counts?.open ?? '—'}</dd></div>
            <div><dt className="text-xs uppercase tracking-wide text-gray-500">Acknowledged</dt><dd className="mt-1 text-2xl font-semibold text-white">{status?.alert_counts?.acknowledged ?? '—'}</dd></div>
            <div><dt className="text-xs uppercase tracking-wide text-gray-500">Quarantined agents</dt><dd className="mt-1 text-2xl font-semibold text-white">{status?.quarantined_agents?.length ?? '—'}</dd></div>
            <div><dt className="text-xs uppercase tracking-wide text-gray-500">Control version</dt><dd className="mt-1 text-2xl font-semibold text-white">{status?.version ?? '—'}</dd></div>
          </dl>
          {status?.quarantined_agents?.length > 0 && (
            <div className="mt-4 border-t border-gray-800 pt-3">
              <h4 className="text-sm font-medium text-gray-300">Quarantined identities</h4>
              <ul className="mt-2 space-y-2">
                {status.quarantined_agents.map(agent => (
                  <li key={agent.agent_id} className="rounded-md bg-[#0a0e17] p-2 text-sm">
                    <span className="font-mono text-amber-200">{agent.agent_id}</span>
                    <p className="mt-1 text-xs text-gray-500">{agent.reason}</p>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      <div className={panelClass}>
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-orange-300" />
          <h3 className="font-semibold text-white">Incident alerts</h3>
          <span className="rounded-full bg-gray-800 px-2 py-0.5 text-xs text-gray-300">{alerts.length}</span>
        </div>
        {alerts.length === 0 ? <p className="mt-4 text-sm text-gray-500">No incident alerts in the returned page.</p> : (
          <ul className="mt-4 space-y-3">
            {alerts.map(alert => (
              <li key={alert.alert_id} className="rounded-lg border border-gray-800 bg-[#0a0e17] p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="font-medium text-white">{alert.title}</p>
                    <p className="mt-1 text-sm text-gray-400">{alert.summary}</p>
                    <p className="mt-2 text-xs text-gray-500">{alert.category} · {formatTime(alert.created_at)} · {alert.status}</p>
                    <p className="mt-1 break-all font-mono text-[11px] text-gray-600">{alert.alert_id}</p>
                  </div>
                  <div className="flex gap-2">
                    {alert.status === 'open' && <button type="button" className={buttonClass} disabled={Boolean(busyAction)} onClick={() => transitionAlert(alert.alert_id, 'acknowledge')}>Acknowledge</button>}
                    {alert.status !== 'resolved' && <button type="button" className={buttonClass} disabled={Boolean(busyAction)} onClick={() => transitionAlert(alert.alert_id, 'resolve')}>Resolve</button>}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className={panelClass}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <FileCheck2 className="h-5 w-5 text-emerald-300" />
            <h3 className="font-semibold text-white">Evidence-chain verification</h3>
          </div>
          <div className="flex items-center gap-2 text-sm">
            {verification?.valid ? <CheckCircle className="h-4 w-4 text-emerald-300" /> : <AlertTriangle className="h-4 w-4 text-amber-300" />}
            <span className={verification?.valid ? 'text-emerald-300' : 'text-amber-300'}>{verification ? (verification.valid ? 'Chain valid' : 'Verification failed') : 'Not verified'}</span>
          </div>
        </div>
        <p className="mt-2 text-sm text-gray-400">Mode: {verification?.integrity_mode || '—'} · Records checked: {verification?.records_checked ?? '—'} · HMAC verified: {verification?.hmac_verified ? 'yes' : 'no'}</p>
        {verification?.reason && <p className="mt-1 text-xs text-gray-500">Verification result: {verification.reason}</p>}
        {verification?.head_hash && <p className="mt-2 break-all font-mono text-[11px] text-gray-500">Head: {verification.head_hash}</p>}
      </div>

      <div className={panelClass}>
        <h3 className="font-semibold text-white">Recent evidence records</h3>
        <p className="mt-1 text-sm text-gray-500">Showing up to 100 records. Payloads and raw request parameters are intentionally omitted.</p>
        {evidence.length === 0 ? <p className="mt-4 text-sm text-gray-500">No evidence records are available.</p> : (
          <div className="mt-4 overflow-x-auto">
            <table className="w-full min-w-[680px] text-left text-sm">
              <thead><tr className="border-b border-gray-800 text-xs uppercase tracking-wide text-gray-500"><th scope="col" className="px-3 py-2">Seq.</th><th scope="col" className="px-3 py-2">Time</th><th scope="col" className="px-3 py-2">Event</th><th scope="col" className="px-3 py-2">Actor</th><th scope="col" className="px-3 py-2">Outcome</th><th scope="col" className="px-3 py-2">Decision</th></tr></thead>
              <tbody>
                {evidence.map(record => (
                  <tr key={record.record_id} className="border-b border-gray-800/60 align-top">
                    <td className="px-3 py-3 font-mono text-gray-400">{record.sequence}</td>
                    <td className="px-3 py-3 text-gray-400">{formatTime(record.occurred_at)}</td>
                    <td className="px-3 py-3 font-mono text-xs text-gray-200">{record.event_type}</td>
                    <td className="px-3 py-3 text-gray-400">{record.actor_id || '—'}</td>
                    <td className="px-3 py-3 text-gray-300">{record.outcome || '—'}</td>
                    <td className="px-3 py-3 text-gray-400">{record.details?.decision || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  )
}
