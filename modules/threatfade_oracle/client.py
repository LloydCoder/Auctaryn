"""
TwinGuard — FusionOps HTTP Client
Calls the configured FusionOps API (ThreatFade Oracle) over an explicitly configured endpoint.

API contract v0.3.0 (Tinlance Limited):
  GET  /health
  GET  /events?limit=N
  POST /detect/json     {timestamps, values, source_label}
  POST /detect/scenario {scenario}
  POST /detect/pcap     (multipart)
  POST /triage          (DetectionResult dict)
"""

import os
import random
from urllib.parse import urlparse

import httpx
from core.exceptions import ThreatFadeConnectionError
from core.models import ToolCall
from core.logging import get_logger

logger = get_logger("threatfade_oracle.client")

DEFAULT_BASE_URL = "http://threatfade:8401"
MIN_DATA_POINTS = 10

VALID_SCENARIOS = {
    "c2_quieting",
    "lotl_gradual",
    "gnss_jam",
    "normal_with_fade",
    "mixed",
}


class FusionOpsClient:
    """Async HTTP client for the FusionOps API."""

    def __init__(self, base_url: str | None = None, timeout: float = 10.0):
        configured_url = (base_url or os.getenv("THREATFADE_SERVICE_URL") or DEFAULT_BASE_URL).strip()
        parsed = urlparse(configured_url)
        local_hosts = {"localhost", "127.0.0.1", "::1", "threatfade"}
        allow_insecure = os.getenv("AUCTARYN_ALLOW_INSECURE_THREATFADE_HTTP", "").lower() in {"1", "true", "yes"}
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and (parsed.hostname in local_hosts or allow_insecure)
        ):
            raise ValueError(
                "ThreatFade endpoint must use HTTPS unless it is a local/Docker service. "
                "For isolated testing only, set AUCTARYN_ALLOW_INSECURE_THREATFADE_HTTP=true."
            )
        if not parsed.hostname:
            raise ValueError("THREATFADE_SERVICE_URL must be an absolute HTTP(S) URL")
        self.base_url = configured_url.rstrip("/")
        self.timeout = timeout

    async def health_check(self) -> dict:
        """GET /health — liveness check for both FusionOps and ThreatFade."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.base_url}/health")
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            logger.warning(f"FusionOps health check failed: {e}",
                           extra={"event": "fusionops_unreachable"})
            return {"status": "unreachable", "threatfade": "unreachable", "error": str(e)}

    async def get_events(self, limit: int = 50) -> dict:
        """GET /events?limit=N — recent detection events for the dashboard."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.base_url}/events", params={"limit": limit})
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            raise ThreatFadeConnectionError(f"Failed to fetch events: {e}") from e

    async def detect_json(self, timestamps: list[float], values: list[float],
                          source_label: str = "") -> dict:
        """POST /detect/json — analyze signal data, returns FullAnalysisResult."""
        if len(timestamps) != len(values):
            raise ValueError("timestamps and values must be the same length")
        if len(values) < MIN_DATA_POINTS:
            raise ValueError(f"Need at least {MIN_DATA_POINTS} data points, got {len(values)}")

        payload = {"timestamps": timestamps, "values": values, "source_label": source_label}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/detect/json", json=payload)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            logger.error(f"FusionOps /detect/json failed: {e}",
                        extra={"event": "fusionops_detect_failed"})
            raise ThreatFadeConnectionError(f"FusionOps unreachable: {e}") from e

    async def detect_scenario(self, scenario: str) -> dict:
        """POST /detect/scenario — run a named simulation."""
        if scenario not in VALID_SCENARIOS:
            raise ValueError(
                f"Invalid scenario '{scenario}'. Must be one of: {', '.join(sorted(VALID_SCENARIOS))}"
            )

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/detect/scenario",
                                         json={"scenario": scenario})
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            raise ThreatFadeConnectionError(f"FusionOps unreachable: {e}") from e

    async def detect_pcap(self, file_bytes: bytes, filename: str) -> dict:
        """POST /detect/pcap — analyze a real PCAP file (multipart)."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout * 3) as client:
                files = {"file": (filename, file_bytes, "application/octet-stream")}
                resp = await client.post(f"{self.base_url}/detect/pcap", files=files)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            raise ThreatFadeConnectionError(f"FusionOps unreachable: {e}") from e

    async def triage(self, detection_result: dict) -> dict:
        """POST /triage — run triage agent on an existing detection result."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/triage", json=detection_result)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            raise ThreatFadeConnectionError(f"FusionOps unreachable: {e}") from e


def generate_synthetic_signal(tool_call: ToolCall, num_points: int = 20) -> tuple[list[float], list[float]]:
    """
    MVP Option A: derive a synthetic entropy signal from tool call parameters,
    since TwinGuard doesn't yet capture real network traffic from the OpenShell
    sandbox (that's Phase 2 with real PCAP capture via /detect/pcap).

    Riskier actions (bulk operations, destructive verbs) produce a signal with
    more variance and a steeper drop — mimicking a fade/evasion pattern so
    FusionOps' detection engine has something meaningful to score.
    """
    import time

    now = time.time()
    timestamps = [now + i * 60 for i in range(num_points)]

    # Baseline entropy around 3.0 (typical for benign traffic per ThreatFade docs)
    base = 3.0
    risk_factor = 0.0

    params = tool_call.parameters or {}
    bulk_indicators = ("count", "limit", "recipients", "ids", "files", "targets")
    for key, value in params.items():
        if key.lower() in bulk_indicators:
            if isinstance(value, (int, float)) and value >= 10:
                risk_factor += min(value / 100.0, 1.0)
            elif isinstance(value, (list, tuple)) and len(value) >= 10:
                risk_factor += min(len(value) / 100.0, 1.0)

    action = (tool_call.action or "").lower()
    if any(w in action for w in ("bulk", "delete", "wipe", "purge", "drop")):
        risk_factor += 0.5

    values = []
    for i in range(num_points):
        noise = random.uniform(-0.15, 0.15)
        # Simulate a gradual fade/drop proportional to risk
        drift = -(risk_factor * 0.15 * i)
        values.append(round(max(base + drift + noise, 0.1), 4))

    return timestamps, values
