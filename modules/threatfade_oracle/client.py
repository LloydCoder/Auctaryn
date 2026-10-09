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

import json
import math
import os
import random
from pathlib import PurePath
from urllib.parse import urlparse

import httpx
from core.exceptions import ThreatFadeConnectionError
from core.models import ToolCall
from core.logging import get_logger

logger = get_logger("threatfade_oracle.client")

DEFAULT_BASE_URL = "http://threatfade:8401"
MIN_DATA_POINTS = 10
MAX_DATA_POINTS = 10_000
MAX_SOURCE_LABEL_LENGTH = 256
MAX_PCAP_BYTES = 25 * 1024 * 1024
MAX_TRIAGE_PAYLOAD_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 2_000_000
MAX_EVENTS_LIMIT = 200
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

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
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("ThreatFade base URL must not contain credentials, query parameters, or fragments")
        api_key = os.getenv("THREATFADE_API_KEY", "").strip()
        if len(api_key) > 4096 or any(ord(char) < 32 for char in api_key):
            raise ValueError("THREATFADE_API_KEY is invalid")
        if parsed.hostname not in local_hosts and not api_key:
            raise ValueError("THREATFADE_API_KEY is required for non-local ThreatFade endpoints")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
            raise ValueError("timeout must be greater than 0 and at most 60 seconds")
        self.base_url = configured_url.rstrip("/")
        self.timeout = float(timeout)
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    @staticmethod
    def _json_object(response: httpx.Response, endpoint: str) -> dict:
        body = getattr(response, "content", b"")
        if isinstance(body, bytes) and len(body) > MAX_RESPONSE_BYTES:
            raise ThreatFadeConnectionError(
                f"FusionOps response exceeded the size limit for {endpoint}."
            )
        try:
            data = response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise ThreatFadeConnectionError(
                f"FusionOps returned invalid JSON for {endpoint}."
            ) from exc
        if not isinstance(data, dict):
            raise ThreatFadeConnectionError(
                f"FusionOps returned an invalid response shape for {endpoint}."
            )
        return data

    @staticmethod
    def _validate_full_analysis(data: dict, endpoint: str) -> dict:
        try:
            encoded = json.dumps(data, allow_nan=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ThreatFadeConnectionError(
                f"FusionOps returned non-JSON analysis data for {endpoint}."
            ) from exc
        if len(encoded) > MAX_RESPONSE_BYTES:
            raise ThreatFadeConnectionError(
                f"FusionOps analysis exceeded the size limit for {endpoint}."
            )
        detection = data.get("detection")
        triage = data.get("triage")
        remediation = data.get("remediation")
        if not isinstance(detection, dict) or not isinstance(triage, dict) or not isinstance(remediation, dict):
            raise ThreatFadeConnectionError(
                f"FusionOps returned an invalid analysis schema for {endpoint}."
            )
        for key in ("score", "entropy", "drop_ratio", "z_outlier"):
            value = detection.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ThreatFadeConnectionError(
                    f"FusionOps returned an invalid numeric field for {endpoint}."
                )
        if not 0 <= detection["score"] <= 1 or not 0 <= detection["drop_ratio"] <= 1:
            raise ThreatFadeConnectionError(
                f"FusionOps returned an out-of-range score for {endpoint}."
            )
        if not 0 <= detection["entropy"] <= 1_000_000 or not 0 <= detection["z_outlier"] <= 1_000_000:
            raise ThreatFadeConnectionError(
                f"FusionOps returned an out-of-range statistic for {endpoint}."
            )
        severity = detection.get("severity")
        if not isinstance(severity, str) or severity.upper() not in VALID_SEVERITIES:
            raise ThreatFadeConnectionError(
                f"FusionOps returned an invalid severity for {endpoint}."
            )
        if not isinstance(detection.get("detected"), bool):
            raise ThreatFadeConnectionError(
                f"FusionOps returned an invalid detection flag for {endpoint}."
            )
        if (
            not isinstance(triage.get("category"), str)
            or len(triage["category"]) > 128
            or not isinstance(triage.get("recommended_action"), str)
            or len(triage["recommended_action"]) > 128
        ):
            raise ThreatFadeConnectionError(
                f"FusionOps returned invalid triage fields for {endpoint}."
            )
        if not isinstance(triage.get("escalate"), bool):
            raise ThreatFadeConnectionError(
                f"FusionOps returned an invalid escalation flag for {endpoint}."
            )
        return data

    async def health_check(self) -> dict:
        """GET /health — liveness check for both FusionOps and ThreatFade."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.base_url}/health", headers=self.headers)
                resp.raise_for_status()
                data = self._json_object(resp, "/health")
                if not isinstance(data.get("status"), str):
                    return {"status": "unreachable", "threatfade": "unreachable", "error": "invalid_health_response"}
                return data
        except (httpx.HTTPError, ThreatFadeConnectionError) as e:
            logger.warning("FusionOps health check failed",
                           extra={"event": "fusionops_unreachable", "error_type": type(e).__name__})
            return {"status": "unreachable", "threatfade": "unreachable", "error": type(e).__name__}

    async def get_events(self, limit: int = 50) -> dict:
        """GET /events?limit=N — recent detection events for the dashboard."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_EVENTS_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_EVENTS_LIMIT}")
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.base_url}/events", params={"limit": limit}, headers=self.headers)
                resp.raise_for_status()
                return self._json_object(resp, "/events")
        except httpx.HTTPError as e:
            raise ThreatFadeConnectionError("Failed to fetch events from FusionOps.") from e

    async def detect_json(self, timestamps: list[float], values: list[float],
                          source_label: str = "") -> dict:
        """POST /detect/json — analyze signal data, returns FullAnalysisResult."""
        if not isinstance(timestamps, list) or not isinstance(values, list):
            raise ValueError("timestamps and values must be lists")
        if len(timestamps) != len(values):
            raise ValueError("timestamps and values must be the same length")
        if not MIN_DATA_POINTS <= len(values) <= MAX_DATA_POINTS:
            raise ValueError(f"Data points must be between {MIN_DATA_POINTS} and {MAX_DATA_POINTS}")
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
               for value in timestamps + values):
            raise ValueError("timestamps and values must contain only finite numbers")
        if any(timestamps[index] > timestamps[index + 1] for index in range(len(timestamps) - 1)):
            raise ValueError("timestamps must be ordered non-decreasingly")
        if not isinstance(source_label, str) or len(source_label) > MAX_SOURCE_LABEL_LENGTH:
            raise ValueError(f"source_label must be a string of at most {MAX_SOURCE_LABEL_LENGTH} characters")

        payload = {"timestamps": timestamps, "values": values, "source_label": source_label}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/detect/json", json=payload, headers=self.headers)
                resp.raise_for_status()
                data = self._json_object(resp, "/detect/json")
                return self._validate_full_analysis(data, "/detect/json")
        except httpx.HTTPError as e:
            logger.error("FusionOps /detect/json failed",
                        extra={"event": "fusionops_detect_failed", "error_type": type(e).__name__})
            raise ThreatFadeConnectionError("FusionOps detection request failed.") from e

    async def detect_scenario(self, scenario: str) -> dict:
        """POST /detect/scenario — run a named simulation."""
        if scenario not in VALID_SCENARIOS:
            raise ValueError(
                f"Invalid scenario '{scenario}'. Must be one of: {', '.join(sorted(VALID_SCENARIOS))}"
            )

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/detect/scenario",
                                         json={"scenario": scenario}, headers=self.headers)
                resp.raise_for_status()
                data = self._json_object(resp, "/detect/scenario")
                return self._validate_full_analysis(data, "/detect/scenario")
        except httpx.HTTPError as e:
            raise ThreatFadeConnectionError("FusionOps scenario request failed.") from e

    async def detect_pcap(self, file_bytes: bytes, filename: str) -> dict:
        """POST /detect/pcap — analyze a real PCAP file (multipart)."""
        if not isinstance(file_bytes, bytes) or not 1 <= len(file_bytes) <= MAX_PCAP_BYTES:
            raise ValueError(f"PCAP content must be between 1 and {MAX_PCAP_BYTES} bytes")
        if (
            not isinstance(filename, str)
            or not filename
            or len(filename) > 255
            or PurePath(filename).name != filename
            or "/" in filename
            or "\\" in filename
            or any(ord(char) < 32 for char in filename)
        ):
            raise ValueError("filename must be a bounded basename without control characters")
        try:
            async with httpx.AsyncClient(timeout=self.timeout * 3) as client:
                files = {"file": (filename, file_bytes, "application/octet-stream")}
                resp = await client.post(f"{self.base_url}/detect/pcap", files=files, headers=self.headers)
                resp.raise_for_status()
                data = self._json_object(resp, "/detect/pcap")
                return self._validate_full_analysis(data, "/detect/pcap")
        except httpx.HTTPError as e:
            raise ThreatFadeConnectionError("FusionOps PCAP analysis request failed.") from e

    async def triage(self, detection_result: dict) -> dict:
        """POST /triage — run triage agent on an existing detection result."""
        if not isinstance(detection_result, dict):
            raise ValueError("detection_result must be a mapping")
        try:
            serialized = json.dumps(detection_result, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("detection_result must be JSON serializable without NaN/Infinity") from exc
        if len(serialized.encode("utf-8")) > MAX_TRIAGE_PAYLOAD_BYTES:
            raise ValueError(f"detection_result exceeds {MAX_TRIAGE_PAYLOAD_BYTES} bytes")
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/triage", json=detection_result, headers=self.headers)
                resp.raise_for_status()
                return self._json_object(resp, "/triage")
        except httpx.HTTPError as e:
            raise ThreatFadeConnectionError("FusionOps triage request failed.") from e


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
