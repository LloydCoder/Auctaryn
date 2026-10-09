"""Auctaryn execution gateway API.

All HTTP routes require a configured service bearer key. Mutating security
controls and human approvals additionally require the operator bearer key.
Deploy behind TLS; static keys are bootstrap controls, not a replacement for
enterprise identity-provider integration.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from api.security import require_api_key, require_operator_key
from api.routes.context import get_guardian
from api.websockets.alerts import broadcast_alert

from core.models import ToolCall, ActionClassification, GatewayDecision, ActionDecision, action_intent_fingerprint
from modules.execution_gateway.gateway import ExecutionGateway, ApprovalIntentIntegrityError
from modules.threatfade_oracle.oracle import ThreatFadeOracle
from modules.agent_identity.identity import AgentIdentityManager
from modules.inter_agent.circuit_breaker import AgentCircuitBreaker
from modules.execution_gateway.execution_service import ExecutionService, ActionIntentIntegrityError
from modules.evidence_audit.store import record_evidence, EvidenceStoreError
from modules.incident_response.manager import IncidentResponseBlocked, get_incident_response_manager
from modules.execution_gateway.runtime_adapter import (
    DuplicateExecution,
    RuntimeAdapter,
    RuntimeAdapterFailure,
    RuntimeAdapterUnavailable,
)

router = APIRouter(dependencies=[Depends(require_api_key)])
_oracle = ThreatFadeOracle()
_identity_manager = AgentIdentityManager()
_circuit_breaker = AgentCircuitBreaker(failure_threshold=5, cooldown_seconds=60)


def _context_integrity_preflight(tool_call: ToolCall) -> str | None:
    guardian = get_guardian()
    if guardian.registry.count() == 0 and not tool_call.context_check_id:
        return None
    return guardian.authorize_session_action(
        tool_call.session_id, tool_call.context_check_id, tool_call.id
    )


# Fail closed: the gateway always has an identity manager. Agents must be
# registered and granted the requested tool scope before protected actions pass.
_gateway = ExecutionGateway(
    auto_approve_safe=True,
    oracle=_oracle,
    identity_manager=_identity_manager,
    circuit_breaker=_circuit_breaker,
    context_integrity_guard=_context_integrity_preflight,
)
_execution_service = ExecutionService(_gateway)


def get_execution_service() -> ExecutionService:
    # Keep the service bound to the current gateway when tests or lifecycle
    # management replace the gateway instance.
    _execution_service.gateway = _gateway
    return _execution_service


def configure_runtime_adapter(adapter: RuntimeAdapter | None) -> None:
    """Configure a trusted adapter from deployment/startup code, never via HTTP."""
    _execution_service.adapter = adapter

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
    context_check_id: str = Field(default="", max_length=64)
    identity_token: str = Field(default="", max_length=128)

class ApprovalRequest(BaseModel):
    decision_id: str = Field(min_length=1, max_length=64)
    approved: bool
    reason: str = Field(default="", max_length=500)

async def _publish_decision_alert(decision: GatewayDecision) -> None:
    if decision.risk_level.value != "critical" and decision.decision != ActionDecision.VETOED:
        return
    alert = get_incident_response_manager().create_alert(
        severity="critical" if decision.risk_level.value == "critical" else "high",
        category="agent_action_risk",
        title="Critical agent action risk",
        summary=f"Decision {decision.decision.value}; risk={decision.risk_level.value}",
        decision_id=decision.id,
        actor_id=decision.tool_call.agent_id,
    )
    try:
        await record_evidence(
            "incident.alert.created",
            correlation_id=alert["alert_id"],
            actor_id=decision.tool_call.agent_id,
            decision_id=decision.id,
            outcome=alert["severity"],
            details={"decision": decision.decision.value, "risk_level": decision.risk_level.value},
        )
    except (EvidenceStoreError, ValueError):
        pass
    await broadcast_alert({"type": "incident_alert", "alert": alert})


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
                  context_check_id=request.context_check_id,
                  identity_token=request.identity_token)
    get_gateway().data_guard.validate_tool_call(tc)
    from modules.execution_gateway.risk_classifier import RiskClassifier
    classification = RiskClassifier().classify(tc)
    try:
        await record_evidence(
            "risk.assessed",
            correlation_id=action_intent_fingerprint(tc),
            actor_id=tc.agent_id,
            outcome=classification.risk_level.value,
            details={
                "risk_level": classification.risk_level.value,
                "action_fingerprint": action_intent_fingerprint(tc),
                "confidence": classification.confidence,
            },
        )
    except EvidenceStoreError as exc:
        raise HTTPException(status_code=503, detail="Evidence recording unavailable") from exc
    return classification

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
        await record_evidence(
            "approval.resolution_requested",
            correlation_id=request.decision_id,
            decision_id=request.decision_id,
            outcome="approve_requested" if request.approved else "deny_requested",
            details={"decision": "approved" if request.approved else "denied"},
        )
    except (EvidenceStoreError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Evidence recording unavailable; approval not changed") from exc
    try:
        resolved = get_gateway().resolve_pending(
            request.decision_id, request.approved, request.reason, operator="authenticated_operator"
        )
        evidence_status = "complete"
        try:
            await record_evidence(
                "approval.resolved",
                correlation_id=resolved.id,
                actor_id=resolved.tool_call.agent_id,
                decision_id=resolved.id,
                outcome=resolved.decision.value,
                details={
                    "decision": resolved.decision.value,
                    "action_fingerprint": action_intent_fingerprint(resolved.tool_call),
                },
            )
        except (EvidenceStoreError, ValueError):
            evidence_status = "terminal_record_failed"
        await _broadcast_decision(resolved)
        return {"decision_id": resolved.id, "result": resolved.decision.value,
                "evidence_status": evidence_status,
                "timestamp": datetime.now(timezone.utc).isoformat()}
    except ApprovalIntentIntegrityError as exc:
        raise HTTPException(status_code=409, detail="Pending action intent changed; approval rejected") from exc
    except KeyError:
        raise HTTPException(status_code=404, detail="Pending decision not found")

@router.post("/execute")
async def execute_tool_call(request: ToolCallRequest) -> dict:
    """Evaluate and execute through a trusted adapter; never execute in the API process."""
    tc = ToolCall(tool_name=request.tool_name, action=request.action, parameters=request.parameters,
                  target=request.target, agent_id=request.agent_id, session_id=request.session_id,
                  context_check_id=request.context_check_id,
                  identity_token=request.identity_token)
    fingerprint = action_intent_fingerprint(tc)
    try:
        await record_evidence(
            "execution.requested",
            correlation_id=fingerprint,
            actor_id=tc.agent_id,
            outcome="requested",
            details={"action_fingerprint": fingerprint},
        )
    except (EvidenceStoreError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Evidence recording unavailable; execution not started") from exc
    try:
        decision, receipt = await get_execution_service().execute_tool_call(tc)
    except RuntimeAdapterUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except DuplicateExecution as exc:
        raise HTTPException(status_code=409, detail="Decision already claimed for execution") from exc
    except ActionIntentIntegrityError as exc:
        raise HTTPException(status_code=409, detail="Action intent integrity check failed; execution refused") from exc
    except RuntimeAdapterFailure as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    evidence_status = "complete"
    try:
        await record_evidence(
            "execution.decision",
            correlation_id=fingerprint,
            actor_id=tc.agent_id,
            decision_id=decision.id,
            outcome=decision.decision.value,
            details={"decision": decision.decision.value, "action_fingerprint": fingerprint},
        )
        if receipt is not None:
            await record_evidence(
                "execution.receipt",
                correlation_id=fingerprint,
                actor_id=tc.agent_id,
                decision_id=decision.id,
                execution_id=receipt.execution_id,
                outcome=receipt.status,
                details={
                    "runtime_adapter": receipt.adapter,
                    "receipt_hash": receipt.stdout_sha256,
                    "action_fingerprint": fingerprint,
                },
            )
    except (EvidenceStoreError, ValueError):
        # Do not return an ambiguous failure that may cause a caller to replay an
        # already executed action. The prior execution.requested record remains
        # as a detectable incomplete chain event for operator investigation.
        evidence_status = "terminal_record_failed"
    await _publish_decision_alert(decision)
    return {
        "decision": decision.model_dump(mode="json"),
        "execution": receipt.model_dump(mode="json") if receipt is not None else None,
        "evidence_status": evidence_status,
    }


@router.post("/execute/approved/{decision_id}", dependencies=[Depends(require_operator_key)])
async def execute_approved_decision(decision_id: str) -> dict:
    """Execute the exact immutable decision after an administrator approved it."""
    service = get_execution_service()
    try:
        service.require_adapter()
    except RuntimeAdapterUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    decision = next((item for item in get_gateway().history if item.id == decision_id), None)
    if decision is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    if decision.decision != ActionDecision.APPROVED or decision.decided_by != "authenticated_operator":
        raise HTTPException(status_code=409, detail="Decision has not been explicitly approved by an operator")
    context_denial = _context_integrity_preflight(decision.tool_call)
    if context_denial:
        raise HTTPException(status_code=409, detail=context_denial)
    fingerprint = action_intent_fingerprint(decision.tool_call)
    try:
        await record_evidence(
            "execution.requested",
            correlation_id=fingerprint,
            actor_id=decision.tool_call.agent_id,
            decision_id=decision.id,
            outcome="approved_execution_requested",
            details={"action_fingerprint": fingerprint, "decision": decision.decision.value},
        )
    except (EvidenceStoreError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Evidence recording unavailable; execution not started") from exc
    try:
        receipt = await service.execute_approved_decision(decision)
    except DuplicateExecution as exc:
        raise HTTPException(status_code=409, detail="Decision already claimed for execution") from exc
    except ActionIntentIntegrityError as exc:
        raise HTTPException(status_code=409, detail="Action intent integrity check failed; execution refused") from exc
    except RuntimeAdapterFailure as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    evidence_status = "complete"
    try:
        await record_evidence(
            "execution.receipt",
            correlation_id=fingerprint,
            actor_id=decision.tool_call.agent_id,
            decision_id=decision.id,
            execution_id=receipt.execution_id,
            outcome=receipt.status,
            details={
                "runtime_adapter": receipt.adapter,
                "receipt_hash": receipt.stdout_sha256,
                "action_fingerprint": fingerprint,
            },
        )
    except (EvidenceStoreError, ValueError):
        evidence_status = "terminal_record_failed"
    await _publish_decision_alert(decision)
    return {"decision_id": decision.id, "execution": receipt.model_dump(mode="json"),
            "evidence_status": evidence_status}


@router.post("/intercept")
async def intercept_action(request: ToolCallRequest) -> GatewayDecision:
    tc = ToolCall(tool_name=request.tool_name, action=request.action, parameters=request.parameters,
                  target=request.target, agent_id=request.agent_id, session_id=request.session_id,
                  context_check_id=request.context_check_id,
                  identity_token=request.identity_token)
    get_gateway().data_guard.validate_tool_call(tc)
    decision = get_gateway().evaluate(tc)
    await record_evidence(
        "decision.created",
        correlation_id=decision.id,
        actor_id=decision.tool_call.agent_id,
        decision_id=decision.id,
        outcome=decision.decision.value,
        details={
            "decision": decision.decision.value,
            "risk_level": decision.risk_level.value,
            "action_fingerprint": action_intent_fingerprint(decision.tool_call),
        },
    )
    await _publish_decision_alert(decision)
    await _broadcast_decision(decision)
    return decision

@router.post("/intercept/full")
async def intercept_action_full(request: ToolCallRequest) -> GatewayDecision:
    tc = ToolCall(tool_name=request.tool_name, action=request.action, parameters=request.parameters,
                  target=request.target, agent_id=request.agent_id, session_id=request.session_id,
                  context_check_id=request.context_check_id,
                  identity_token=request.identity_token)
    get_gateway().data_guard.validate_tool_call(tc)
    decision = await get_gateway().evaluate_with_oracle(tc)
    await _publish_decision_alert(decision)
    await _broadcast_decision(decision)
    return decision
