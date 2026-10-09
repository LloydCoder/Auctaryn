"""
TwinGuard — ThreatFade Oracle API Routes
Wired to the live FusionOps API at 13.50.16.19.
"""

from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel

from core.models import ThreatFadeResult, Severity
from modules.threatfade_oracle.oracle import ThreatFadeOracle

router = APIRouter()
_oracle = ThreatFadeOracle()


def get_oracle() -> ThreatFadeOracle:
    return _oracle


class ScenarioRequest(BaseModel):
    scenario: str


@router.get("/status")
async def get_oracle_status() -> dict:
    """Live FusionOps connectivity status."""
    return await get_oracle().get_status()


@router.post("/scenario")
async def run_scenario(request: ScenarioRequest) -> ThreatFadeResult:
    """Run a named demo scenario against the live FusionOps engine."""
    try:
        return await get_oracle().run_scenario(request.scenario)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)) -> dict:
    """Upload a PCAP file for real threat analysis via FusionOps."""
    content = await file.read()
    try:
        result = await get_oracle().client.detect_pcap(content, file.filename)
        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"FusionOps analysis failed: {e}")


@router.get("/results")
async def list_results(limit: int = 50) -> list[ThreatFadeResult]:
    """List recent ThreatFade Oracle analysis results."""
    return get_oracle().get_recent_results(limit)


@router.get("/results/{index}")
async def get_result(index: int) -> ThreatFadeResult:
    """Get a specific result by index."""
    results = get_oracle().history
    if index < 0 or index >= len(results):
        raise HTTPException(status_code=404, detail=f"Result {index} not found")
    return results[index]


@router.get("/detections")
async def list_detections(severity: Severity | None = None) -> list[ThreatFadeResult]:
    """List detections, optionally filtered by severity."""
    results = get_oracle().get_recent_results(200)
    if severity:
        results = [r for r in results if r.severity == severity]
    return results


@router.get("/events")
async def get_live_events(limit: int = 50) -> dict:
    """Proxy to FusionOps /events endpoint — live SOC dashboard feed."""
    try:
        return await get_oracle().client.get_events(limit)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"FusionOps unreachable: {e}")
