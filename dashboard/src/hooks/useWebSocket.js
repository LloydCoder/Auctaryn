import { useEffect, useRef, useState, useCallback } from 'react'

const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8400'

/**
 * Generic WebSocket hook with auto-reconnect.
 * Maintains a rolling buffer of the last N messages plus connection status.
 */
export function useWebSocket(path, { maxMessages = 100 } = {}) {
  const [connected, setConnected] = useState(false)
  const [messages, setMessages] = useState([])
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)

  const connect = useCallback(() => {
    const ws = new WebSocket(`${WS_BASE}${path}`)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        setMessages(prev => {
          const next = [...prev, data]
          return next.length > maxMessages ? next.slice(-maxMessages) : next
        })
      } catch {
        // ignore non-JSON frames
      }
    }

    ws.onclose = () => {
      setConnected(false)
      reconnectTimer.current = setTimeout(connect, 3000)
    }

    ws.onerror = () => ws.close()
  }, [path, maxMessages])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [connect])

  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
    }
  }, [])

  return { connected, messages, send }
}
