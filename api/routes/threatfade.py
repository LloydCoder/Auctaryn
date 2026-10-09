"""Authenticated ThreatFade advisory API routes."""
from fastapi import APIRouter, HTTPException, UploadFile, File, Query
from pydantic import BaseModel, Field

from core.exceptions import ThreatFadeConnectionError
from core.models import ThreatFadeResult, Severity
from modules.threatfade_oracle.client import MAX_PCAP_BYTES
from modules.threatfade_oracle.oracle import ThreatFadeOracle

router = APIRouter()
_oracle = ThreatFadeOracle()


def get_oracle() -> ThreatFadeOracle:
    return _oracle


class ScenarioRequest(BaseModel):
    scenario: str = Field(min_length=1, max_length=64)


@router.get("/status")
async def get_oracle_status() -> dict:
    return await get_oracle().get_status()


@router.post("/scenario")
async def run_scenario(request: ScenarioRequest) -> ThreatFadeResult:
    try:
        return await get_oracle().run_scenario(request.scenario)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid ThreatFade scenario") from exc
    except ThreatFadeConnectionError as exc:
        raise HTTPException(status_code=502, detail="ThreatFade service unavailable or response invalid") from exc


@router.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)) -> dict:
    try:
        content = await file.read(MAX_PCAP_BYTES + 1)
        if not content:
            raise HTTPException(status_code=400, detail="PCAP file must not be empty")
        if len(content) > MAX_PCAP_BYTES:
            raise HTTPException(status_code=413, detail=f"PCAP file exceeds {MAX_PCAP_BYTES} bytes")
        return await get_oracle().client.detect_pcap(content, file.filename or "")
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid PCAP upload") from exc
    except ThreatFadeConnectionError as exc:
        raise HTTPException(status_code=502, detail="ThreatFade PCAP analysis unavailable") from exc
    finally:
        await file.close()


@router.get("/results")
async def list_results(limit: int = Query(50, ge=1, le=200)) -> list[ThreatFadeResult]:
    return get_oracle().get_recent_results(limit)


@router.get("/results/{index}")
async def get_result(index: int) -> ThreatFadeResult:
    results = get_oracle().history
    if index < 0 or index >= len(results):
        raise HTTPException(status_code=404, detail="ThreatFade result not found")
    return results[index]


@router.get("/detections")
async def list_detections(severity: Severity | None = None) -> list[ThreatFadeResult]:
    results = get_oracle().get_recent_results(200)
    if severity:
        results = [result for result in results if result.severity == severity]
    return results


@router.get("/events")
async def get_live_events(limit: int = Query(50, ge=1, le=200)) -> dict:
    try:
        return await get_oracle().client.get_events(limit)
    except (ThreatFadeConnectionError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="ThreatFade events service unavailable") from exc
