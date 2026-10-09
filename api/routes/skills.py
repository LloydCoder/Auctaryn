"""Skill supply-chain vetting API.

Vetting is available to authenticated service callers. Trust-store and known-skill
registry mutations require a distinct administrator credential.
"""
import base64
import binascii

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from api.security import require_operator_key
from modules.skill_vetting.vetting import (
    MAX_ARTIFACT_BASE64_CHARS,
    MAX_ARTIFACT_BYTES,
    MAX_MANIFEST_PERMISSIONS,
    SkillVettingService,
)

router = APIRouter()
_service = SkillVettingService()


def get_vetting_service() -> SkillVettingService:
    return _service


class ManifestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    version: str = Field(
        min_length=5,
        max_length=128,
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$",
    )
    content_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$")
    signature: str = Field(min_length=1, max_length=200)
    permissions: list[str] = Field(default_factory=list, max_length=MAX_MANIFEST_PERMISSIONS)
    publisher: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
    artifact_b64: str = Field(min_length=4, max_length=MAX_ARTIFACT_BASE64_CHARS)


class TrustPublisherRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    publisher: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
    public_key_b64: str = Field(min_length=40, max_length=64)
    replace: bool = False


class KnownSkillRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")


@router.post("/vet")
async def vet_skill(request: ManifestRequest) -> dict:
    try:
        artifact = base64.b64decode(request.artifact_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=422, detail="artifact_b64 must be valid base64") from exc
    if not artifact or len(artifact) > MAX_ARTIFACT_BYTES:
        raise HTTPException(status_code=413, detail="Artifact must be between 1 byte and 1 MiB")

    manifest = request.model_dump(exclude={"artifact_b64"})
    verdict = get_vetting_service().vet(manifest, artifact)
    return {
        "verdict_id": verdict.verdict_id,
        "skill_name": verdict.skill_name,
        "publisher": verdict.publisher,
        "version": verdict.version,
        "artifact_hash": verdict.artifact_hash,
        "approved": verdict.approved,
        "reasons": verdict.reasons,
        "timestamp": verdict.timestamp.isoformat(),
    }


@router.post("/trust-publisher", dependencies=[Depends(require_operator_key)])
async def trust_publisher(request: TrustPublisherRequest) -> dict:
    try:
        fingerprint = get_vetting_service().trust_publisher(
            request.publisher, request.public_key_b64, replace=request.replace,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "trusted": True,
        "publisher": request.publisher,
        "public_key_fingerprint": fingerprint,
        "rotated": request.replace,
    }


@router.delete("/trust-publisher/{publisher}", dependencies=[Depends(require_operator_key)])
async def revoke_publisher(publisher: str) -> dict:
    if not get_vetting_service().revoke_publisher(publisher):
        raise HTTPException(status_code=404, detail="Trusted publisher not found")
    return {"trusted": False, "publisher": publisher}


@router.post("/known-skill", dependencies=[Depends(require_operator_key)])
async def register_known_skill(request: KnownSkillRequest) -> dict:
    try:
        registered = get_vetting_service().register_known_skill(request.name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"registered": registered, "name": request.name}


@router.delete("/known-skill/{name}", dependencies=[Depends(require_operator_key)])
async def remove_known_skill(name: str) -> dict:
    if not get_vetting_service().remove_known_skill(name):
        raise HTTPException(status_code=404, detail="Known skill not found")
    return {"registered": False, "name": name}


@router.get("/history")
async def vetting_history(limit: int = Query(50, ge=1, le=100)) -> list[dict]:
    history = get_vetting_service().history[-limit:]
    return [
        {
            "verdict_id": verdict.verdict_id,
            "skill_name": verdict.skill_name,
            "publisher": verdict.publisher,
            "version": verdict.version,
            "artifact_hash": verdict.artifact_hash,
            "approved": verdict.approved,
            "reasons": verdict.reasons,
            "timestamp": verdict.timestamp.isoformat(),
        }
        for verdict in history
    ]
