"""
TwinGuard — Context Integrity API Routes
"""

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

from core.models import IntegrityCheckResult, IntegrityStatus, CompactionEvent
from modules.context_integrity.guardian import ContextIntegrityGuardian, generate_alert

router = APIRouter()
_guardian = ContextIntegrityGuardian(degradation_threshold=10.0)

def get_guardian() -> ContextIntegrityGuardian:
    return _guardian

class RegisterRequest(BaseModel):
    tag: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=10000)

class CheckRequest(BaseModel):
    context: str = Field(min_length=1, max_length=200000)
    session_id: str = Field(default="", max_length=128)

@router.get("/status")
async def get_integrity_status() -> dict:
    guardian = get_guardian()
    status = guardian.get_status()
    status["timestamp"] = datetime.now(timezone.utc).isoformat()
    return status

@router.get("/checks")
async def list_integrity_checks(limit: int = Query(50, ge=1, le=500)) -> list[IntegrityCheckResult]:
    return get_guardian().history[-limit:]

@router.get("/checks/{check_id}")
async def get_integrity_check(check_id: str) -> IntegrityCheckResult:
    for check in get_guardian().history:
        if check.id == check_id:
            return check
    raise HTTPException(status_code=404, detail=f"Check {check_id} not found")

@router.post("/register")
async def register_protected_instruction(request: RegisterRequest) -> dict:
    guardian = get_guardian()
    inst = guardian.register_instruction(request.tag, request.content)
    return {
        "registered": True, "tag": inst.tag, "hash": inst.hash,
        "total_protected": guardian.registry.count(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@router.post("/check")
async def run_integrity_check(request: CheckRequest) -> IntegrityCheckResult:
    guardian = get_guardian()
    result = guardian.check(request.context, session_id=request.session_id or None)

    if result.blocked or result.status != IntegrityStatus.INTACT:
        alert = generate_alert(result)
        if alert:
            from api.websockets.alerts import broadcast_alert
            await broadcast_alert({
                "type": "alert",
                "severity": alert.severity.value,
                "module": alert.module,
                "title": alert.title,
                "message": alert.message,
                "timestamp": alert.timestamp.isoformat(),
            })

    return result

@router.post("/check-now")
async def trigger_integrity_check() -> IntegrityCheckResult:
    guardian = get_guardian()
    if guardian.registry.count() == 0:
        return IntegrityCheckResult(
            status=IntegrityStatus.INTACT,
            instructions_total=0, instructions_intact=0,
            instructions_degraded=0, degradation_percent=0.0,
        )
    return guardian.check("")

@router.get("/compactions")
async def list_compaction_events(limit: int = Query(50, ge=1, le=500)) -> list[CompactionEvent]:
    return get_guardian().compaction_history[-limit:]

@router.get("/instructions")
async def list_protected_instructions() -> list[dict]:
    return [
        {"tag": inst.tag, "hash": inst.hash,
         "registered_at": inst.registered_at.isoformat(),
         "content_preview": inst.content[:100] + ("..." if len(inst.content) > 100 else "")}
        for inst in get_guardian().registry.get_all()
    ]

@router.post("/sessions/{session_id}/clear", dependencies=[])
async def clear_session_quarantine(
    session_id: str = Path(..., min_length=1, max_length=128),
) -> dict:
    """Clear a quarantined session; a fresh clean context check is then required."""
    guardian = get_guardian()
    if not guardian.clear_session(session_id):
        raise HTTPException(status_code=404, detail="No quarantined session found")
    return {
        "session_id": session_id,
        "quarantine_cleared": True,
        "fresh_integrity_check_required": guardian.registry.count() > 0,
    }


@router.delete("/instructions/{tag}")
async def remove_protected_instruction(tag: str) -> dict:
    guardian = get_guardian()
    if not guardian.registry.remove(tag):
        raise HTTPException(status_code=404, detail=f"Instruction '{tag}' not found")
    return {"removed": True, "tag": tag, "remaining": guardian.registry.count()}
