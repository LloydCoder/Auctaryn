"""
TwinGuard — Skill Vetting API Routes
Exposes the ASI04 Skill/Dependency Vetting Service.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from modules.skill_vetting.vetting import SkillVettingService

router = APIRouter()

# Seeded with placeholder trust config — in production this comes from
# a signed trust list, not hardcoded. Empty known_skills means no
# typosquat detection until the registry is populated.
_service = SkillVettingService(trusted_publishers=set(), known_skills=set())


def get_vetting_service() -> SkillVettingService:
    return _service


class ManifestRequest(BaseModel):
    name: str
    version: str
    content_hash: str = ""
    signature: str = ""
    permissions: list[str] = []
    publisher: str = ""


class TrustPublisherRequest(BaseModel):
    publisher: str


@router.post("/vet")
async def vet_skill(request: ManifestRequest) -> dict:
    manifest = request.model_dump()
    verdict = get_vetting_service().vet(manifest)
    return {
        "verdict_id": verdict.verdict_id,
        "skill_name": verdict.skill_name,
        "approved": verdict.approved,
        "reasons": verdict.reasons,
        "timestamp": verdict.timestamp.isoformat(),
    }


@router.post("/trust-publisher")
async def trust_publisher(request: TrustPublisherRequest) -> dict:
    get_vetting_service().trusted_publishers.add(request.publisher)
    return {"trusted": True, "publisher": request.publisher}


@router.get("/history")
async def vetting_history(limit: int = 50) -> list[dict]:
    history = get_vetting_service().history[-limit:]
    return [
        {
            "verdict_id": v.verdict_id, "skill_name": v.skill_name,
            "approved": v.approved, "reasons": v.reasons,
            "timestamp": v.timestamp.isoformat(),
        }
        for v in history
    ]
