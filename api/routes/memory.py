"""Memory-defender routes bound to scoped agent identity and server-issued sessions."""
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from api.routes.gateway import get_identity_manager
from modules.memory_defender.defender import (
    MAX_MEMORY_CONTENT_CHARS,
    MemoryDefender,
)

router = APIRouter()
_defender = MemoryDefender()


def get_memory_defender() -> MemoryDefender:
    return _defender


def _require_memory_scope(
    agent_id: str | None, identity_token: str | None, scope: str
) -> tuple[str, str]:
    if not agent_id or not identity_token:
        raise HTTPException(status_code=403, detail="Scoped agent identity is required")
    authorized = get_identity_manager().is_authorized(
        agent_id, scope, token_id=identity_token, require_token=True,
    )
    if not authorized:
        raise HTTPException(status_code=403, detail="Agent token lacks required memory scope")
    return agent_id, identity_token


class StoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str = Field(min_length=1, max_length=MAX_MEMORY_CONTENT_CHARS)
    source: str = Field(min_length=1, max_length=48)
    session_id: str = Field(min_length=1, max_length=128)


@router.post("/sessions")
async def create_memory_session(
    agent_id: str | None = Header(default=None, alias="X-Agent-ID"),
    identity_token: str | None = Header(default=None, alias="X-Agent-Identity-Token"),
) -> dict:
    owner, token_id = _require_memory_scope(agent_id, identity_token, "memory:write")
    try:
        session_id = get_memory_defender().create_session(owner, token_id)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Memory session capacity reached") from exc
    return {"session_id": session_id, "agent_id": owner}


@router.post("/evaluate")
async def evaluate_for_storage(
    request: StoreRequest,
    agent_id: str | None = Header(default=None, alias="X-Agent-ID"),
    identity_token: str | None = Header(default=None, alias="X-Agent-Identity-Token"),
) -> dict:
    owner, token_id = _require_memory_scope(agent_id, identity_token, "memory:write")
    defender = get_memory_defender()
    if not defender.session_owned_by(request.session_id, owner, token_id):
        raise HTTPException(status_code=404, detail="Memory session not found")
    # Public API input cannot assert trusted provenance. Prefix it so it is
    # always quarantined until a trusted, separately authenticated ingest path exists.
    try:
        decision = defender.evaluate_for_storage(
            request.content,
            source=f"api:{request.source.strip().lower()}",
            session_id=request.session_id,
            agent_id=owner,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Memory input rejected by bounds") from exc
    return {
        "allow_storage": decision.allow_storage,
        "quarantined": decision.quarantined,
        "reason": decision.reason,
        "entry_id": decision.entry_id,
    }


@router.get("/readable/{key}/{session_id}")
async def check_readability(
    key: str,
    session_id: str,
    agent_id: str | None = Header(default=None, alias="X-Agent-ID"),
    identity_token: str | None = Header(default=None, alias="X-Agent-Identity-Token"),
) -> dict:
    owner, token_id = _require_memory_scope(agent_id, identity_token, "memory:read")
    defender = get_memory_defender()
    if not defender.session_owned_by(session_id, owner, token_id):
        raise HTTPException(status_code=404, detail="Memory session not found")
    entry = defender.store.get(key)
    if entry is None:
        raise HTTPException(status_code=404, detail="Memory entry not found")
    # This call verifies and restores tampered metadata before ownership is evaluated.
    readable = defender.is_readable_by_session(key, session_id, owner)
    entry = defender.store.get(key)
    if entry is None or entry.agent_id != owner:
        raise HTTPException(status_code=404, detail="Memory entry not found")
    return {"key": key, "session_id": session_id, "readable": readable}


@router.get("/entry/{key}")
async def get_entry(
    key: str,
    agent_id: str | None = Header(default=None, alias="X-Agent-ID"),
    identity_token: str | None = Header(default=None, alias="X-Agent-Identity-Token"),
) -> dict:
    owner, token_id = _require_memory_scope(agent_id, identity_token, "memory:read")
    defender = get_memory_defender()
    entry = defender.store.get(key)
    if entry is None:
        raise HTTPException(status_code=404, detail="Memory entry not found")

    integrity_ok = defender.store.verify_integrity(key)
    tamper_detected = not integrity_ok
    rolled_back = False
    if tamper_detected:
        rolled_back = defender.store.rollback(key)
        entry = defender.store.get(key)
        integrity_ok = defender.store.verify_integrity(key)
    if entry is None or entry.agent_id != owner:
        raise HTTPException(status_code=404, detail="Memory entry not found")

    return {
        "found": True,
        "key": entry.key,
        "source": entry.source,
        "agent_id": entry.agent_id,
        "quarantined": entry.quarantined,
        "integrity_ok": integrity_ok,
        "tamper_detected": tamper_detected,
        "rolled_back": rolled_back,
        "created_at": entry.created_at.isoformat(),
    }



@router.get("/content/{key}/{session_id}")
async def get_memory_content(
    key: str,
    session_id: str,
    agent_id: str | None = Header(default=None, alias="X-Agent-ID"),
    identity_token: str | None = Header(default=None, alias="X-Agent-Identity-Token"),
) -> dict:
    owner, token_id = _require_memory_scope(agent_id, identity_token, "memory:read")
    defender = get_memory_defender()
    if not defender.session_owned_by(session_id, owner, token_id):
        raise HTTPException(status_code=404, detail="Memory session not found")
    entry = defender.store.get(key)
    if entry is None:
        raise HTTPException(status_code=404, detail="Memory entry not found")
    readable = defender.is_readable_by_session(key, session_id, owner)
    entry = defender.store.get(key)
    if entry is None or entry.agent_id != owner:
        raise HTTPException(status_code=404, detail="Memory entry not found")
    if not readable:
        raise HTTPException(status_code=403, detail="Quarantined memory is isolated to its originating session")
    if not defender.store.verify_integrity(key):
        raise HTTPException(status_code=409, detail="Memory integrity could not be restored")
    return {
        "key": entry.key,
        "session_id": entry.session_id,
        "source": entry.source,
        "content": entry.content,
        "quarantined": entry.quarantined,
        "integrity_ok": True,
    }
