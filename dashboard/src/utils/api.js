const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8400'
const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8400'

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
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
  ws.onmessage = (e) => onMessage(JSON.parse(e.data))
  ws.onerror = () => setTimeout(() => connectActionStream(onMessage), 5000)
  return ws
}

export function connectAlertStream(onMessage) {
  const ws = new WebSocket(`${WS_BASE}/ws/alerts`)
  ws.onmessage = (e) => onMessage(JSON.parse(e.data))
  ws.onerror = () => setTimeout(() => connectAlertStream(onMessage), 5000)
  return ws
}
