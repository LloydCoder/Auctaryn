"""
TwinGuard — Execution Gateway API Routes
Wired to ExecutionGateway + ThreatFade Oracle (Parliament integration)
+ real-time WebSocket broadcast on every decision.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.models import ToolCall, ActionClassification, GatewayDecision
from modules.execution_gateway.gateway import ExecutionGateway
from modules.threatfade_oracle.oracle import ThreatFadeOracle
from modules.agent_identity.identity import AgentIdentityManager
from modules.inter_agent.circuit_breaker import AgentCircuitBreaker

router = APIRouter()

_oracle = ThreatFadeOracle()
_identity_manager = AgentIdentityManager()
_circuit_breaker = AgentCircuitBreaker(failure_threshold=5, cooldown_seconds=60)

# Identity enforcement is opt-in at the gateway level: passing the manager
# into ExecutionGateway is what makes it load-bearing (tested directly in
# test_gateway_owasp_wiring.py). The production singleton here defaults
# to NOT enforcing identity yet, so existing deployments aren't broken by
# agents that haven't been registered. Call enable_strict_identity() once
# your agent fleet is registered to turn enforcement on.
_gateway = ExecutionGateway(
    auto_approve_safe=True,
    oracle=_oracle,
    identity_manager=_identity_manager,
    circuit_breaker=_circuit_breaker,
)


def get_gateway() -> ExecutionGateway:
    return _gateway


def get_identity_manager() -> AgentIdentityManager:
    return _identity_manager


def get_circuit_breaker() -> AgentCircuitBreaker:
    return _circuit_breaker


def enable_strict_identity_enforcement() -> None:
    """
    Turn on ASI03 identity enforcement at the gateway level. After this
    call, any tool_call without a registered agent_id + matching scope
    will be denied outright. Intended to be called once an operator has
    finished registering their known agent fleet via /api/v1/identity.
    """
    _gateway.identity_manager = _identity_manager


class ToolCallRequest(BaseModel):
    tool_name: str
    action: str
    parameters: dict = {}
    target: str = ""
    agent_id: str = ""
    session_id: str = ""
    identity_token: str = Field(default="", max_length=128)


class ApprovalRequest(BaseModel):
    decision_id: str
    approved: bool
    reason: str = ""


async def _broadcast_decision(decision: GatewayDecision) -> None:
    """Push a gateway decision to all connected dashboard clients."""
    from api.websockets.actions import broadcast_action
    await broadcast_action({
        "type": "gateway_decision",
        "id": decision.id,
        "timestamp": decision.timestamp.isoformat(),
        "tool_name": decision.tool_call.tool_name,
        "action": decision.tool_call.action,
        "risk_level": decision.risk_level.value,
        "decision": decision.decision.value,
        "reason": decision.reason,
        "decided_by": decision.decided_by,
    })

    if decision.decision.value == "vetoed":
        from api.websockets.alerts import broadcast_alert
        await broadcast_alert({
            "type": "alert",
            "severity": "critical",
            "module": "execution_gateway",
            "title": "Action Vetoed",
            "message": f"{decision.tool_call.tool_name}:{decision.tool_call.action} — {decision.reason}",
            "timestamp": decision.timestamp.isoformat(),
        })


@router.get("/status")
async def get_gateway_status() -> dict:
    status = get_gateway().get_status()
    status["timestamp"] = datetime.now(timezone.utc).isoformat()
    status["identity_enforcement_enabled"] = get_gateway().identity_manager is not None
    status["circuit_breaker_enabled"] = get_gateway().circuit_breaker is not None
    return status


@router.post("/identity-enforcement/enable")
async def enable_identity_enforcement() -> dict:
    """Turn on ASI03 strict identity enforcement at the gateway level."""
    enable_strict_identity_enforcement()
    return {"identity_enforcement_enabled": True}


@router.post("/evaluate")
async def evaluate_tool_call(request: ToolCallRequest) -> ActionClassification:
    tc = ToolCall(
        tool_name=request.tool_name, action=request.action,
        parameters=request.parameters, target=request.target,
        agent_id=request.agent_id, session_id=request.session_id,
        identity_token=request.identity_token,
    )
    from modules.execution_gateway.risk_classifier import RiskClassifier
    clf = RiskClassifier()
    return clf.classify(tc)


@router.get("/decisions")
async def list_decisions(limit: int = Query(50, ge=1, le=500)) -> list[GatewayDecision]:
    return get_gateway().history[-limit:]


@router.get("/decisions/{decision_id}")
async def get_decision(decision_id: str) -> GatewayDecision:
    for d in get_gateway().history:
        if d.id == decision_id:
            return d
    raise HTTPException(status_code=404, detail=f"Decision {decision_id} not found")


@router.get("/pending")
async def list_pending_approvals() -> list[GatewayDecision]:
    return get_gateway().get_pending()


@router.post("/approve")
async def approve_action(request: ApprovalRequest) -> dict:
    try:
        resolved = get_gateway().resolve_pending(
            request.decision_id, request.approved, request.reason, operator="api_admin"
        )
        await _broadcast_decision(resolved)
        return {
            "decision_id": resolved.id,
            "result": resolved.decision.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Pending decision {request.decision_id} not found")


@router.post("/intercept")
async def intercept_action(request: ToolCallRequest) -> GatewayDecision:
    """Pattern-only interception — classify AND decide, no Oracle call (fast path)."""
    tc = ToolCall(
        tool_name=request.tool_name, action=request.action,
        parameters=request.parameters, target=request.target,
        agent_id=request.agent_id, session_id=request.session_id,
        identity_token=request.identity_token,
    )
    decision = get_gateway().evaluate(tc)
    await _broadcast_decision(decision)
    return decision


@router.post("/intercept/full")
async def intercept_action_full(request: ToolCallRequest) -> GatewayDecision:
    """Full Parliament interception — pattern classification + ThreatFade Oracle enrichment."""
    tc = ToolCall(
        tool_name=request.tool_name, action=request.action,
        parameters=request.parameters, target=request.target,
        agent_id=request.agent_id, session_id=request.session_id,
        identity_token=request.identity_token,
    )
    decision = await get_gateway().evaluate_with_oracle(tc)
    await _broadcast_decision(decision)
    return decision
