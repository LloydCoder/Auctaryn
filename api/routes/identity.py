"""
TwinGuard — Agent Identity API Routes
Exposes the ASI03 Agent Identity & Privilege Manager.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from modules.agent_identity.identity import AgentIdentityManager
from core.exceptions import PolicyViolation

router = APIRouter()
def get_identity_manager() -> AgentIdentityManager:
    """Return the same identity manager enforced by the production gateway."""
    from api.routes.gateway import get_identity_manager as get_gateway_identity_manager
    return get_gateway_identity_manager()


class RegisterRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    owner: str = Field(min_length=1, max_length=256)


class ScopeRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    scope: str = Field(min_length=1, max_length=128)


class TokenRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    ttl_seconds: int = Field(default=300, ge=1, le=3600)


class RevokeTokenRequest(BaseModel):
    token_id: str = Field(min_length=1, max_length=128)


class DelegateRequest(BaseModel):
    delegator_agent_id: str
    delegate_agent_id: str
    scopes: list[str]
    ttl_seconds: int = Field(default=300, ge=1, le=3600)


@router.post("/register")
async def register_agent(request: RegisterRequest) -> dict:
    identity = get_identity_manager().register(request.agent_id, request.owner)
    return {
        "agent_id": identity.agent_id,
        "identity_id": identity.identity_id,
        "owner": identity.owner,
        "scopes": list(identity.scopes),
    }




@router.post("/token")
async def issue_agent_token(request: TokenRequest) -> dict:
    """Issue a short-lived, scoped bearer capability for an already-authorized agent."""
    try:
        token = get_identity_manager().issue_token(request.agent_id, request.ttl_seconds)
        return {
            "token_id": token.token_id,
            "agent_id": token.agent_id,
            "scopes": list(token.scopes),
            "expires_at": token.expires_at.isoformat(),
        }
    except PolicyViolation as exc:
        raise HTTPException(status_code=404, detail="Agent identity not found") from exc


@router.post("/token/revoke")
async def revoke_agent_token(request: RevokeTokenRequest) -> dict:
    get_identity_manager().revoke_token(request.token_id)
    return {"revoked": True, "token_id": request.token_id}


@router.post("/grant")
async def grant_scope(request: ScopeRequest) -> dict:
    try:
        get_identity_manager().grant_scope(request.agent_id, request.scope)
        return {"granted": True, "agent_id": request.agent_id, "scope": request.scope}
    except PolicyViolation as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/revoke")
async def revoke_scope(request: ScopeRequest) -> dict:
    get_identity_manager().revoke_scope(request.agent_id, request.scope)
    return {"revoked": True, "agent_id": request.agent_id, "scope": request.scope}


@router.get("/{agent_id}")
async def get_agent_identity(agent_id: str) -> dict:
    identity = get_identity_manager().get_identity(agent_id)
    if identity is None:
        raise HTTPException(status_code=404, detail=f"No identity registered for {agent_id}")
    return {
        "agent_id": identity.agent_id,
        "identity_id": identity.identity_id,
        "owner": identity.owner,
        "scopes": list(identity.scopes),
        "created_at": identity.created_at.isoformat(),
    }


@router.get("/{agent_id}/authorized/{tool_name}")
async def check_authorization(agent_id: str, tool_name: str) -> dict:
    authorized = get_identity_manager().is_authorized(agent_id, tool_name)
    return {"agent_id": agent_id, "tool_name": tool_name, "authorized": authorized}


@router.post("/delegate")
async def delegate_scopes(request: DelegateRequest) -> dict:
    try:
        token = get_identity_manager().delegate(
            request.delegator_agent_id, request.delegate_agent_id,
            request.scopes, request.ttl_seconds,
        )
        return {
            "token_id": token.token_id,
            "agent_id": token.agent_id,
            "scopes": list(token.scopes),
            "expires_at": token.expires_at.isoformat(),
        }
    except PolicyViolation as e:
        raise HTTPException(status_code=403, detail=str(e))
