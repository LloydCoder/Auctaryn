"""Authenticated WebSocket stream for Auctaryn security alerts."""
import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.security import origin_allowed, token_role
from core.logging import get_logger
from modules.evidence_audit.store import EvidenceStoreError, record_evidence
from modules.incident_response.manager import get_incident_response_manager

router = APIRouter()
logger = get_logger("websocket.alerts")
_alert_clients: list[WebSocket] = []


async def broadcast_alert(data: dict) -> None:
    message = json.dumps(data, default=str)
    disconnected = []
    for client in list(_alert_clients):
        try:
            await client.send_text(message)
        except Exception:
            disconnected.append(client)
    for client in disconnected:
        if client in _alert_clients:
            _alert_clients.remove(client)


@router.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket):
    """Require a valid API credential in the first WebSocket frame."""
    if not origin_allowed(websocket.headers.get("origin")):
        await websocket.close(code=4403, reason="Origin not allowed")
        return
    await websocket.accept()
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
        message = json.loads(raw)
        role = token_role(message.get("token"))
        if message.get("type") != "authenticate" or role is None:
            await websocket.close(code=4401, reason="Valid authentication frame required")
            return

        _alert_clients.append(websocket)
        await websocket.send_json({
            "type": "authenticated",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        logger.info("Alert WebSocket authenticated", extra={"event": "ws_authenticated"})

        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "message": "Invalid JSON"})
                continue
            if msg.get("type") == "acknowledge":
                if role != "admin":
                    await websocket.send_json({"type": "error", "message": "Administrator credential required"})
                    continue
                alert_id = msg.get("alert_id")
                if not isinstance(alert_id, str) or not alert_id or len(alert_id) > 128:
                    await websocket.send_json({"type": "error", "message": "Invalid alert identifier"})
                    continue
                try:
                    await record_evidence(
                        "incident.alert.transition_requested",
                        correlation_id=alert_id,
                        actor_id="authenticated_operator",
                        outcome="acknowledge",
                        details={"decision": "acknowledge"},
                    )
                    alert = get_incident_response_manager().transition_alert(
                        alert_id, "acknowledge", "authenticated_operator"
                    )
                except KeyError:
                    await websocket.send_json({"type": "error", "message": "Alert not found"})
                    continue
                except (ValueError, EvidenceStoreError):
                    await websocket.send_json({"type": "error", "message": "Alert acknowledgement failed"})
                    continue
                evidence_status = "complete"
                try:
                    await record_evidence(
                        "incident.alert.transitioned",
                        correlation_id=alert_id,
                        actor_id="authenticated_operator",
                        outcome=alert["status"],
                        details={"decision": "acknowledge"},
                    )
                except (ValueError, EvidenceStoreError):
                    evidence_status = "terminal_record_failed"
                await websocket.send_json({
                    "type": "alert_acknowledged",
                    "alert_id": alert_id,
                    "status": alert["status"],
                    "evidence_status": evidence_status,
                })
    except asyncio.TimeoutError:
        await websocket.close(code=4408, reason="Authentication timed out")
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("Alert WebSocket failed", extra={"event": "ws_error"})
        try:
            await websocket.close(code=1011, reason="WebSocket processing error")
        except Exception:
            pass
    finally:
        if websocket in _alert_clients:
            _alert_clients.remove(websocket)
        logger.info("Alert WebSocket disconnected", extra={"event": "ws_disconnect"})
