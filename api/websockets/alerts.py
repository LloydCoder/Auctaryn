"""
TwinGuard — Alerts WebSocket
Real-time stream of security alerts across all modules.
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.logging import get_logger

router = APIRouter()
logger = get_logger("websocket.alerts")

_alert_clients: list[WebSocket] = []


async def broadcast_alert(data: dict) -> None:
    """Broadcast an alert to all connected clients."""
    message = json.dumps(data, default=str)
    disconnected = []

    for client in _alert_clients:
        try:
            await client.send_text(message)
        except Exception:
            disconnected.append(client)

    for client in disconnected:
        _alert_clients.remove(client)


@router.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time security alerts."""
    await websocket.accept()
    _alert_clients.append(websocket)
    logger.info("Alert WebSocket client connected", extra={"event": "ws_connect"})

    try:
        await websocket.send_json({
            "type": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "Connected to TwinGuard alert stream",
        })

        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "acknowledge":
                    # TODO: Mark alert as acknowledged (Phase 4)
                    await websocket.send_json({
                        "type": "ack_confirmed",
                        "alert_id": msg.get("alert_id"),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        _alert_clients.remove(websocket)
        logger.info("Alert WebSocket client disconnected", extra={"event": "ws_disconnect"})
