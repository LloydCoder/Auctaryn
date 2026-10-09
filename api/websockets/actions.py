"""
TwinGuard — Actions WebSocket
Real-time stream of action evaluations and approval requests.
Wired to the live ExecutionGateway — broadcast_action() is called from
gateway.py on every evaluate()/evaluate_with_oracle() call, and incoming
"approve" messages resolve real pending decisions.
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.logging import get_logger

router = APIRouter()
logger = get_logger("websocket.actions")

_action_clients: list[WebSocket] = []


async def broadcast_action(data: dict) -> None:
    """Broadcast an action event to all connected clients."""
    message = json.dumps(data, default=str)
    disconnected = []

    for client in _action_clients:
        try:
            await client.send_text(message)
        except Exception:
            disconnected.append(client)

    for client in disconnected:
        if client in _action_clients:
            _action_clients.remove(client)


@router.websocket("/ws/actions")
async def actions_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time action events."""
    await websocket.accept()
    _action_clients.append(websocket)
    logger.info("Action WebSocket client connected", extra={"event": "ws_connect"})

    try:
        await websocket.send_json({
            "type": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "Connected to TwinGuard action stream",
        })

        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "approve":
                    from api.routes.gateway import get_gateway
                    gateway = get_gateway()
                    try:
                        resolved = gateway.resolve_pending(
                            msg.get("decision_id"),
                            approved=bool(msg.get("approved", True)),
                            reason=msg.get("reason", "Resolved via dashboard"),
                        )
                        await broadcast_action({
                            "type": "decision_resolved",
                            "decision_id": resolved.id,
                            "result": resolved.decision.value,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })
                    except KeyError:
                        await websocket.send_json({
                            "type": "error",
                            "message": f"No pending decision {msg.get('decision_id')}",
                        })
            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        if websocket in _action_clients:
            _action_clients.remove(websocket)
        logger.info("Action WebSocket client disconnected", extra={"event": "ws_disconnect"})
