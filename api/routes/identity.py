"""Authenticated agent identity and privilege administration routes."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.exceptions import PolicyViolation
from api.routes.gateway import get_identity_manager, require_api_key, require_operator_key

router = APIRouter(dependencies=[Depends(require_api_key)])

class RegisterRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    owner: str = Field(min_length=1, max_length=256)

class ScopeRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    scope: str = Field(min_length=1, max_length=256)

class DelegateRequest(BaseModel):
    delegator_agent_id: str = Field(min_length=1, max_length=128)
    delegate_agent_id: str = Field(min_length=1, max_length=128)
    scopes: list[str] = Field(min_length=1, max_length=100)
    ttl_seconds: int = Field(default=300, ge=1, le=3600)

@router.post("/register", dependencies=[Depends(require_operator_key)])
async def register_agent(request: RegisterRequest) -> dict:
    identity = get_identity_manager().register(request.agent_id, request.owner)
    return {"agent_id": identity.agent_id, "identity_id": identity.identity_id,
            "owner": identity.owner, "scopes": list(identity.scopes)}

@router.post("/grant", dependencies=[Depends(require_operator_key)])
async def grant_scope(request: ScopeRequest) -> dict:
    try:
        get_identity_manager().grant_scope(request.agent_id, request.scope)
        return {"granted": True, "agent_id": request.agent_id, "scope": request.scope}
    except PolicyViolation as exc:
        raise HTTPException(status_code=404, detail="Agent identity not found") from exc

@router.post("/revoke", dependencies=[Depends(require_operator_key)])
async def revoke_scope(request: ScopeRequest) -> dict:
    try:
        get_identity_manager().revoke_scope(request.agent_id, request.scope)
        return {"revoked": True, "agent_id": request.agent_id, "scope": request.scope}
    except PolicyViolation as exc:
        raise HTTPException(status_code=404, detail="Agent identity or scope not found") from exc

class TokenRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    scopes: list[str] = Field(min_length=1, max_length=100)
    ttl_seconds: int = Field(default=300, ge=1, le=3600)


@router.post("/token", dependencies=[Depends(require_operator_key)])
async def issue_agent_token(request: TokenRequest) -> dict:
    try:
        token = get_identity_manager().issue_token(request.agent_id, request.ttl_seconds, request.scopes)
        return {"token_id": token.token_id, "agent_id": token.agent_id,
                "scopes": sorted(token.scopes), "expires_at": token.expires_at.isoformat()}
    except PolicyViolation as exc:
        raise HTTPException(status_code=403, detail="Token issuance policy denied") from exc


@router.get("/{agent_id}")
async def get_agent_identity(agent_id: str) -> dict:
    identity = get_identity_manager().get_identity(agent_id)
    if identity is None:
        raise HTTPException(status_code=404, detail="Agent identity not found")
    return {"agent_id": identity.agent_id, "identity_id": identity.identity_id,
            "owner": identity.owner, "scopes": list(identity.scopes),
            "created_at": identity.created_at.isoformat()}

@router.get("/{agent_id}/authorized/{tool_name}")
async def check_authorization(agent_id: str, tool_name: str) -> dict:
    authorized = get_identity_manager().is_authorized(agent_id, tool_name)
    return {"agent_id": agent_id, "tool_name": tool_name, "authorized": authorized}

@router.post("/delegate", dependencies=[Depends(require_operator_key)])
async def delegate_scopes(request: DelegateRequest) -> dict:
    try:
        token = get_identity_manager().delegate(
            request.delegator_agent_id, request.delegate_agent_id,
            request.scopes, request.ttl_seconds,
        )
        return {"token_id": token.token_id, "agent_id": token.agent_id,
                "scopes": list(token.scopes), "expires_at": token.expires_at.isoformat()}
    except PolicyViolation as exc:
        raise HTTPException(status_code=403, detail="Delegation policy denied the request") from exc
