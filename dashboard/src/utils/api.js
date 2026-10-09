const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8400'
const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8400'
let API_TOKEN = ''

export function setApiToken(token) { API_TOKEN = token }

export async function validateAdminToken(token) {
  const response = await fetch(`${API_BASE}/api/v1/gateway/status`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!response.ok) throw new Error(response.status === 403 ? 'Administrator access required.' : `Authentication failed (${response.status}).`)
  const adminCheck = await fetch(`${API_BASE}/api/v1/gateway/pending`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (adminCheck.status === 403) throw new Error('Administrator access required.')
  if (!adminCheck.ok) throw new Error(`Administrator verification failed (${adminCheck.status}).`)
  const status = await response.json()
  if (status.identity_enforcement_enabled !== true) throw new Error('Gateway identity enforcement is not enabled.')
  return status
}

async function request(path, options = {}) {
  const { headers = {}, ...rest } = options
  const res = await fetch(`${API_BASE}${path}`, {
    ...rest,
    headers: {
      'Content-Type': 'application/json',
      ...(API_TOKEN ? { Authorization: `Bearer ${API_TOKEN}` } : {}),
      ...headers,
    },
  })
  if (!res.ok) throw new Error(`API error: ${res.status}`)
  return res.json()
}

// Health
export const fetchHealth = () => request('/health/detailed')
export const fetchReadiness = () => request('/health/ready')

// Context Integrity
export const fetchContextStatus = () => request('/api/v1/context/status')
export const fetchContextChecks = (limit = 50) => request(`/api/v1/context/checks?limit=${limit}`)
export const triggerContextCheck = () => request('/api/v1/context/check-now', { method: 'POST' })

// Execution Gateway
export const fetchGatewayStatus = () => request('/api/v1/gateway/status')
export const fetchDecisions = (limit = 50) => request(`/api/v1/gateway/decisions?limit=${limit}`)
export const fetchPending = () => request('/api/v1/gateway/pending')
export const evaluateAction = (toolCall) =>
  request('/api/v1/gateway/evaluate', { method: 'POST', body: JSON.stringify(toolCall) })
export const approveAction = (decisionId, approved, reason = '') =>
  request('/api/v1/gateway/approve', {
    method: 'POST',
    body: JSON.stringify({ decision_id: decisionId, approved, reason }),
  })

// ThreatFade
export const fetchThreatFadeStatus = () => request('/api/v1/threatfade/status')
export const fetchDetections = (severity) =>
  request(`/api/v1/threatfade/detections${severity ? `?severity=${severity}` : ''}`)

// WebSocket connections
export function connectActionStream(onMessage) {
  const ws = new WebSocket(`${WS_BASE}/ws/actions`)
  ws.onopen = () => ws.send(JSON.stringify({ type: 'authenticate', token: API_TOKEN }))
  ws.onmessage = (e) => onMessage(JSON.parse(e.data))
  return ws
}

export function connectAlertStream(onMessage) {
  const ws = new WebSocket(`${WS_BASE}/ws/alerts`)
  ws.onopen = () => ws.send(JSON.stringify({ type: 'authenticate', token: API_TOKEN }))
  ws.onmessage = (e) => onMessage(JSON.parse(e.data))
  return ws
}


// Incident response — these routes are administrator-only on the server.
export const fetchIncidentStatus = () => request('/api/v1/incident/status')
export const fetchIncidentAlerts = (status = '', limit = 100) => {
  const params = new URLSearchParams({ limit: String(limit) })
  if (status) params.set('status', status)
  return request(`/api/v1/incident/alerts?${params.toString()}`)
}
export const setEmergencyStop = (enabled, reason) =>
  request('/api/v1/incident/emergency-stop', {
    method: 'POST',
    body: JSON.stringify({ enabled, reason }),
  })
export const setAgentQuarantine = (agentId, quarantined, reason) =>
  request(`/api/v1/incident/agents/${encodeURIComponent(agentId)}/quarantine`, {
    method: 'POST',
    body: JSON.stringify({ quarantined, reason }),
  })
export const transitionIncidentAlert = (alertId, action) =>
  request(`/api/v1/incident/alerts/${encodeURIComponent(alertId)}/${action}`, {
    method: 'POST',
  })

// Forensic evidence is rendered as bounded metadata, never as raw request payloads.
export const fetchEvidenceRecords = (limit = 100) =>
  request(`/api/v1/evidence/records?limit=${limit}`)
export const verifyEvidenceChain = () => request('/api/v1/evidence/verify')
