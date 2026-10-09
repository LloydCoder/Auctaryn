"""
TwinGuard — Memory Defender API Routes
Exposes the ASI06 Memory Poisoning Defender.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from modules.memory_defender.defender import MemoryDefender

router = APIRouter()
_defender = MemoryDefender()


def get_memory_defender() -> MemoryDefender:
    return _defender


class StoreRequest(BaseModel):
    content: str
    source: str
    session_id: str = ""


@router.post("/evaluate")
async def evaluate_for_storage(request: StoreRequest) -> dict:
    decision = get_memory_defender().evaluate_for_storage(
        request.content, request.source, request.session_id
    )
    return {
        "allow_storage": decision.allow_storage,
        "quarantined": decision.quarantined,
        "reason": decision.reason,
    }


@router.get("/readable/{key}/{session_id}")
async def check_readability(key: str, session_id: str) -> dict:
    readable = get_memory_defender().is_readable_by_session(key, session_id)
    return {"key": key, "session_id": session_id, "readable": readable}


@router.get("/entry/{key}")
async def get_entry(key: str) -> dict:
    entry = get_memory_defender().store.get(key)
    if entry is None:
        return {"found": False}
    integrity_ok = get_memory_defender().store.verify_integrity(key)
    return {
        "found": True,
        "key": entry.key,
        "source": entry.source,
        "quarantined": entry.quarantined,
        "integrity_ok": integrity_ok,
        "created_at": entry.created_at.isoformat(),
    }
