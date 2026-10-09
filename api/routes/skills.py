"""Skill artifact vetting API."""
import base64
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from api.security import require_operator_key
from modules.skill_vetting.secure_vetting import SecureSkillVettingService

router = APIRouter()
_service = SecureSkillVettingService()
def get_vetting_service() -> SecureSkillVettingService:
    return _service

class ManifestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    content_hash: str = Field(min_length=1, max_length=64)
    signature: str = Field(min_length=1, max_length=256)
    permissions: list[str] = Field(default_factory=list, max_length=100)
    publisher: str = Field(min_length=1, max_length=256)
    artifact_b64: str = Field(min_length=1, max_length=1398104)

    @field_validator("permissions")
    @classmethod
    def validate_permission_bounds(cls, values: list[str]) -> list[str]:
        if any(not value or len(value) > 128 for value in values):
            raise ValueError("permission names must contain 1–128 characters")
        if len(set(values)) != len(values):
            raise ValueError("duplicate permission names are not allowed")
        return values


class TrustPublisherRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    publisher: str = Field(min_length=1, max_length=256)
    public_key: str = Field(min_length=1, max_length=128)


class KnownSkillRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128)

@router.post("/vet")
async def vet_skill(request: ManifestRequest) -> dict:
    try:
        artifact = base64.b64decode(request.artifact_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="Invalid artifact encoding") from exc
    if len(artifact) > 1048576:
        raise HTTPException(status_code=413, detail="Artifact too large")
    verdict = get_vetting_service().vet(request.model_dump(exclude={"artifact_b64"}), artifact)
    return {"verdict_id": verdict.verdict_id, "skill_name": verdict.skill_name,
            "approved": verdict.approved, "reasons": verdict.reasons,
            "timestamp": verdict.timestamp.isoformat()}

@router.post("/trust-publisher", dependencies=[Depends(require_operator_key)])
async def trust_publisher(request: TrustPublisherRequest) -> dict:
    try:
        get_vetting_service().trust_publisher(request.publisher, request.public_key)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid publisher key") from exc
    return {"trusted": True, "publisher": request.publisher, "key_type": "ed25519"}

@router.post("/registry/known-skill", dependencies=[Depends(require_operator_key)])
async def register_known_skill(request: KnownSkillRequest) -> dict:
    name = request.name.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise HTTPException(status_code=422, detail="Invalid skill name")
    get_vetting_service().known_skills.add(name)
    return {"registered": True, "name": name}


@router.get("/history")
async def vetting_history(limit: int = Query(default=50, ge=1, le=500)) -> list[dict]:
    return [{"verdict_id": v.verdict_id, "skill_name": v.skill_name,
             "approved": v.approved, "reasons": v.reasons, "timestamp": v.timestamp.isoformat()}
            for v in get_vetting_service().history[-limit:]]
