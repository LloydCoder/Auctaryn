"""Administrator-only incident controls, alert lifecycle and recovery endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.routes.gateway import get_identity_manager
from api.security import require_api_key, require_operator_key
from modules.evidence_audit.store import EvidenceStoreError, record_evidence
from modules.incident_response.manager import get_incident_response_manager

router = APIRouter(dependencies=[Depends(require_api_key)])


class EmergencyStopRequest(BaseModel):
    enabled: bool
    reason: str = Field(min_length=3, max_length=512)


class AgentQuarantineRequest(BaseModel):
    quarantined: bool
    reason: str = Field(min_length=3, max_length=512)


@router.get("/status", dependencies=[Depends(require_operator_key)])
async def incident_status() -> dict:
    return get_incident_response_manager().get_status()


@router.post("/emergency-stop", dependencies=[Depends(require_operator_key)])
async def set_emergency_stop(request: EmergencyStopRequest) -> dict:
    actor = "authenticated_operator"
    try:
        await record_evidence(
            "incident.emergency_stop.requested",
            actor_id=actor,
            outcome="enable" if request.enabled else "disable",
            details={"decision": "emergency_stop"},
        )
    except (EvidenceStoreError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Evidence recording unavailable; control unchanged") from exc
    status = get_incident_response_manager().set_emergency_stop(request.enabled, actor, request.reason)
    evidence_status = "complete"
    try:
        await record_evidence(
            "incident.emergency_stop.changed",
            actor_id=actor,
            outcome="enabled" if request.enabled else "disabled",
            details={"decision": "emergency_stop"},
        )
    except (EvidenceStoreError, ValueError):
        evidence_status = "terminal_record_failed"
    return {"status": status, "evidence_status": evidence_status}


@router.post("/agents/{agent_id}/quarantine", dependencies=[Depends(require_operator_key)])
async def set_agent_quarantine(agent_id: str, request: AgentQuarantineRequest) -> dict:
    identity_manager = get_identity_manager()
    if identity_manager.get_identity(agent_id) is None:
        raise HTTPException(status_code=404, detail="Agent identity not found")
    actor = "authenticated_operator"
    decision = "quarantine" if request.quarantined else "release_quarantine"
    try:
        await record_evidence(
            "incident.agent_quarantine.requested",
            correlation_id=agent_id,
            actor_id=actor,
            outcome="enable" if request.quarantined else "disable",
            details={"decision": decision},
        )
    except (EvidenceStoreError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Evidence recording unavailable; quarantine unchanged") from exc
    revoked = identity_manager.revoke_agent_tokens(agent_id) if request.quarantined else 0
    state = get_incident_response_manager().set_agent_quarantine(
        agent_id, request.quarantined, actor, request.reason
    )
    evidence_status = "complete"
    try:
        await record_evidence(
            "incident.agent_quarantine.changed",
            correlation_id=agent_id,
            actor_id=actor,
            outcome="quarantined" if request.quarantined else "released",
            details={"decision": decision},
        )
    except (EvidenceStoreError, ValueError):
        evidence_status = "terminal_record_failed"
    return {**state, "revoked_token_count": revoked, "evidence_status": evidence_status}


@router.get("/alerts", dependencies=[Depends(require_operator_key)])
async def list_incident_alerts(
    status: str | None = Query(default=None, pattern="^(open|acknowledged|resolved)$"),
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    manager = get_incident_response_manager()
    return {"alerts": manager.list_alerts(status=status, limit=limit), "count": len(manager.list_alerts(status=status, limit=limit))}


async def _transition_alert(alert_id: str, action: str) -> dict:
    actor = "authenticated_operator"
    try:
        await record_evidence(
            "incident.alert.transition_requested",
            correlation_id=alert_id,
            actor_id=actor,
            outcome=action,
            details={"decision": action},
        )
    except (EvidenceStoreError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Evidence recording unavailable; alert unchanged") from exc
    try:
        alert = get_incident_response_manager().transition_alert(alert_id, action, actor)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Alert not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="Alert transition is not allowed") from exc
    evidence_status = "complete"
    try:
        await record_evidence(
            "incident.alert.transitioned",
            correlation_id=alert_id,
            actor_id=actor,
            outcome=alert["status"],
            details={"decision": action},
        )
    except (EvidenceStoreError, ValueError):
        evidence_status = "terminal_record_failed"
    return {"alert": alert, "evidence_status": evidence_status}


@router.post("/alerts/{alert_id}/acknowledge", dependencies=[Depends(require_operator_key)])
async def acknowledge_alert(alert_id: str) -> dict:
    return await _transition_alert(alert_id, "acknowledge")


@router.post("/alerts/{alert_id}/resolve", dependencies=[Depends(require_operator_key)])
async def resolve_alert(alert_id: str) -> dict:
    return await _transition_alert(alert_id, "resolve")
