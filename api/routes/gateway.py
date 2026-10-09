"""Auctaryn execution gateway API.

All HTTP routes require a configured service bearer key. Mutating security
controls and human approvals additionally require the operator bearer key.
Deploy behind TLS; static keys are bootstrap controls, not a replacement for
enterprise identity-provider integration.
"""
import hmac
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from core.models import ToolCall, ActionClassification, GatewayDecision
from modules.execution_gateway.gateway import ExecutionGateway
from modules.threatfade_oracle.oracle import ThreatFadeOracle
from modules.agent_identity.identity import AgentIdentityManager
from modules.inter_agent.circuit_breaker import AgentCircuitBreaker

def _authorized(authorization: str | None, env_name: str) -> bool:
    scheme, _, token = (authorization or "").partition(" ")
    expected = os.getenv(env_name, "")
    return scheme.lower() == "bearer" and bool(expected and token) and hmac.compare_digest(token, expected)

async def require_api_key(authorization: str | None = Header(default=None)) -> None:
    if _authorized(authorization, "AUCTARYN_API_KEY"):
        return
    if not os.getenv("AUCTARYN_API_KEY"):
        raise HTTPException(status_code=503, detail="API authentication is not configured")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Valid bearer token required",
                        headers={"WWW-Authenticate": "Bearer"})

async def require_operator_key(authorization: str | None = Header(default=None)) -> None:
    if _authorized(authorization, "AUCTARYN_OPERATOR_API_KEY"):
        return
    if not os.getenv("AUCTARYN_OPERATOR_API_KEY"):
        raise HTTPException(status_code=503, detail="Operator authentication is not configured")
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Valid operator bearer token required",
                        headers={"WWW-Authenticate": "Bearer"})

router = APIRouter(dependencies=[Depends(require_api_key)])
_oracle = ThreatFadeOracle()
_identity_manager = AgentIdentityManager()
_circuit_breaker = AgentCircuitBreaker(failure_threshold=5, cooldown_seconds=60)
# Fail closed: the gateway always has an identity manager. Agents must be
# registered and granted the requested tool scope before protected actions pass.
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
    _gateway.identity_manager = _identity_manager

class ToolCallRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=256)
    parameters: dict = Field(default_factory=dict)
    target: str = Field(default="", max_length=512)
    agent_id: str = Field(default="", max_length=128)
    session_id: str = Field(default="", max_length=128)
    identity_token: str = Field(default="", max_length=128)

class ApprovalRequest(BaseModel):
    decision_id: str = Field(min_length=1, max_length=64)
    approved: bool
    reason: str = Field(default="", max_length=500)

async def _broadcast_decision(decision: GatewayDecision) -> None:
    from api.websockets.actions import broadcast_action
    await broadcast_action({
        "type": "gateway_decision", "id": decision.id,
        "timestamp": decision.timestamp.isoformat(),
        "tool_name": decision.tool_call.tool_name, "action": decision.tool_call.action,
        "risk_level": decision.risk_level.value, "decision": decision.decision.value,
        "reason": decision.reason, "decided_by": decision.decided_by,
    })
    if decision.decision.value == "vetoed":
        from api.websockets.alerts import broadcast_alert
        await broadcast_alert({
            "type": "alert", "severity": "critical", "module": "execution_gateway",
            "title": "Action Vetoed",
            "message": f"{decision.tool_call.tool_name}:{decision.tool_call.action} — {decision.reason}",
            "timestamp": decision.timestamp.isoformat(),
        })

@router.get("/status")
async def get_gateway_status() -> dict:
    result = get_gateway().get_status()
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    result["identity_enforcement_enabled"] = get_gateway().identity_manager is not None
    result["circuit_breaker_enabled"] = get_gateway().circuit_breaker is not None
    return result

@router.post("/identity-enforcement/enable", dependencies=[Depends(require_operator_key)])
async def enable_identity_enforcement() -> dict:
    enable_strict_identity_enforcement()
    return {"identity_enforcement_enabled": True}

@router.post("/evaluate")
async def evaluate_tool_call(request: ToolCallRequest) -> ActionClassification:
    tc = ToolCall(tool_name=request.tool_name, action=request.action, parameters=request.parameters,
                  target=request.target, agent_id=request.agent_id, session_id=request.session_id,
                  identity_token=request.identity_token)
    from modules.execution_gateway.risk_classifier import RiskClassifier
    return RiskClassifier().classify(tc)

@router.get("/decisions")
async def list_decisions(limit: int = Query(50, ge=1, le=500)) -> list[GatewayDecision]:
    return get_gateway().history[-limit:]

@router.get("/decisions/{decision_id}")
async def get_decision(decision_id: str) -> GatewayDecision:
    for decision in get_gateway().history:
        if decision.id == decision_id:
            return decision
    raise HTTPException(status_code=404, detail="Decision not found")

@router.get("/pending")
async def list_pending_approvals() -> list[GatewayDecision]:
    return get_gateway().get_pending()

@router.post("/approve", dependencies=[Depends(require_operator_key)])
async def approve_action(request: ApprovalRequest) -> dict:
    try:
        resolved = get_gateway().resolve_pending(
            request.decision_id, request.approved, request.reason, operator="authenticated_operator"
        )
        await _broadcast_decision(resolved)
        return {"decision_id": resolved.id, "result": resolved.decision.value,
                "timestamp": datetime.now(timezone.utc).isoformat()}
    except KeyError:
        raise HTTPException(status_code=404, detail="Pending decision not found")

@router.post("/intercept")
async def intercept_action(request: ToolCallRequest) -> GatewayDecision:
    tc = ToolCall(tool_name=request.tool_name, action=request.action, parameters=request.parameters,
                  target=request.target, agent_id=request.agent_id, session_id=request.session_id,
                  identity_token=request.identity_token)
    decision = get_gateway().evaluate(tc)
    await _broadcast_decision(decision)
    return decision

@router.post("/intercept/full")
async def intercept_action_full(request: ToolCallRequest) -> GatewayDecision:
    tc = ToolCall(tool_name=request.tool_name, action=request.action, parameters=request.parameters,
                  target=request.target, agent_id=request.agent_id, session_id=request.session_id,
                  identity_token=request.identity_token)
    decision = await get_gateway().evaluate_with_oracle(tc)
    await _broadcast_decision(decision)
    return decision
