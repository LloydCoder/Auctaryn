"""Authenticated WebSocket stream for Auctaryn action decisions and approvals."""
import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.security import origin_allowed, token_role
from core.logging import get_logger

router = APIRouter()
logger = get_logger("websocket.actions")
_action_clients: list[WebSocket] = []


async def broadcast_action(data: dict) -> None:
    message = json.dumps(data, default=str)
    disconnected = []
    for client in list(_action_clients):
        try:
            await client.send_text(message)
        except Exception:
            disconnected.append(client)
    for client in disconnected:
        if client in _action_clients:
            _action_clients.remove(client)


@router.websocket("/ws/actions")
async def actions_websocket(websocket: WebSocket):
    """Authenticate using the first frame; admin role is required to approve."""
    if not origin_allowed(websocket.headers.get("origin")):
        await websocket.close(code=4403, reason="Origin not allowed")
        return
    await websocket.accept()
    role = None
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
        message = json.loads(raw)
        if message.get("type") != "authenticate":
            await websocket.close(code=4401, reason="Authentication frame required")
            return
        role = token_role(message.get("token"))
        if role is None:
            await websocket.close(code=4401, reason="Invalid WebSocket credential")
            return

        _action_clients.append(websocket)
        await websocket.send_json({
            "type": "authenticated",
            "role": role,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        logger.info("Action WebSocket authenticated", extra={"event": "ws_authenticated", "role": role})

        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "message": "Invalid JSON"})
                continue

            if msg.get("type") == "approve":
                if role != "admin":
                    await websocket.send_json({"type": "error", "message": "Administrator credential required"})
                    continue
                decision_id = msg.get("decision_id")
                if not isinstance(decision_id, str) or not decision_id:
                    await websocket.send_json({"type": "error", "message": "decision_id is required"})
                    continue
                from api.routes.gateway import get_gateway
                try:
                    resolved = get_gateway().resolve_pending(
                        decision_id,
                        approved=msg.get("approved") is True,
                        reason=str(msg.get("reason", "Resolved through authenticated dashboard"))[:500],
                        operator="api_admin",
                    )
                    await broadcast_action({
                        "type": "decision_resolved",
                        "decision_id": resolved.id,
                        "result": resolved.decision.value,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                except KeyError:
                    await websocket.send_json({"type": "error", "message": "Pending decision not found"})
    except asyncio.TimeoutError:
        await websocket.close(code=4408, reason="Authentication timed out")
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("Action WebSocket failed", extra={"event": "ws_error"})
        try:
            await websocket.close(code=1011, reason="WebSocket processing error")
        except Exception:
            pass
    finally:
        if websocket in _action_clients:
            _action_clients.remove(websocket)
        logger.info("Action WebSocket disconnected", extra={"event": "ws_disconnect"})
