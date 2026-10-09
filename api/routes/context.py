"""
TwinGuard — Context Integrity API Routes
"""

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.models import IntegrityCheckResult, IntegrityStatus, CompactionEvent
from modules.context_integrity.guardian import ContextIntegrityGuardian, generate_alert

router = APIRouter()
_guardian = ContextIntegrityGuardian(degradation_threshold=10.0)

def get_guardian() -> ContextIntegrityGuardian:
    return _guardian

class RegisterRequest(BaseModel):
    tag: str
    content: str

class CheckRequest(BaseModel):
    context: str

@router.get("/status")
async def get_integrity_status() -> dict:
    guardian = get_guardian()
    status = guardian.get_status()
    status["timestamp"] = datetime.now(timezone.utc).isoformat()
    return status

@router.get("/checks")
async def list_integrity_checks(limit: int = 50) -> list[IntegrityCheckResult]:
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
    result = guardian.check(request.context)

    if result.status != IntegrityStatus.INTACT:
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
async def list_compaction_events(limit: int = 50) -> list[CompactionEvent]:
    return get_guardian().compaction_history[-limit:]

@router.get("/instructions")
async def list_protected_instructions() -> list[dict]:
    return [
        {"tag": inst.tag, "hash": inst.hash,
         "registered_at": inst.registered_at.isoformat(),
         "content_preview": inst.content[:100] + ("..." if len(inst.content) > 100 else "")}
        for inst in get_guardian().registry.get_all()
    ]

@router.delete("/instructions/{tag}")
async def remove_protected_instruction(tag: str) -> dict:
    guardian = get_guardian()
    if not guardian.registry.remove(tag):
        raise HTTPException(status_code=404, detail=f"Instruction '{tag}' not found")
    return {"removed": True, "tag": tag, "remaining": guardian.registry.count()}
