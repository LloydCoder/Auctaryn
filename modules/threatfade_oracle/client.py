"""ThreatFade/FusionOps HTTP client with bounded inputs and validated responses."""
import math
import os
import random
import re
import time
from pathlib import PurePath
from urllib.parse import urlparse

import httpx
from core.exceptions import ThreatFadeConnectionError
from core.models import ToolCall
from core.logging import get_logger

logger = get_logger("threatfade_oracle.client")
DEFAULT_BASE_URL = "http://threatfade:8401"
MIN_DATA_POINTS = 10
MAX_SIGNAL_POINTS = 10_000
MAX_JSON_RESPONSE_BYTES = 1_000_000
MAX_PCAP_BYTES = 10 * 1024 * 1024
VALID_SCENARIOS = {"c2_quieting", "lotl_gradual", "gnss_jam", "normal_with_fade", "mixed"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class FusionOpsClient:
    """Async HTTP client for the configured FusionOps API."""
    def __init__(self, base_url: str | None = None, timeout: float = 10.0):
        configured_url = (base_url or os.getenv("THREATFADE_SERVICE_URL") or DEFAULT_BASE_URL).strip()
        parsed = urlparse(configured_url)
        local_hosts = {"localhost", "127.0.0.1", "::1", "threatfade"}
        allow_insecure = os.getenv("AUCTARYN_ALLOW_INSECURE_THREATFADE_HTTP", "").lower() in {"1", "true", "yes"}
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and (parsed.hostname in local_hosts or allow_insecure)
        ):
            raise ValueError("ThreatFade endpoint must use HTTPS unless it is a local/Docker service.")
        if not parsed.hostname:
            raise ValueError("THREATFADE_SERVICE_URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("ThreatFade base URL must not contain credentials, query parameters, or fragments")
        if not math.isfinite(timeout) or not 0.1 <= timeout <= 60:
            raise ValueError("ThreatFade timeout must be between 0.1 and 60 seconds")
        self.base_url = configured_url.rstrip("/")
        self.timeout = timeout
        self._headers = {"Accept": "application/json"}
        service_token = os.getenv("THREATFADE_SERVICE_TOKEN", "").strip()
        if service_token and (
            len(service_token) > 4096 or any(ord(char) < 33 or ord(char) > 126 for char in service_token)
        ):
            raise ValueError("THREATFADE_SERVICE_TOKEN contains invalid characters")
        if parsed.scheme == "https" and not service_token:
            raise ValueError("THREATFADE_SERVICE_TOKEN is required for external HTTPS ThreatFade endpoints")
        if service_token:
            self._headers["Authorization"] = f"Bearer {service_token}"

    @staticmethod
    def _parse_json_response(response: httpx.Response, *, analysis: bool = False) -> dict:
        headers = getattr(response, "headers", {})
        length = headers.get("content-length") if hasattr(headers, "get") else None
        if isinstance(length, str) and length.isdigit() and int(length) > MAX_JSON_RESPONSE_BYTES:
            raise ThreatFadeConnectionError("ThreatFade response exceeded the configured size limit")
        body = getattr(response, "content", None)
        if isinstance(body, (bytes, bytearray)) and len(body) > MAX_JSON_RESPONSE_BYTES:
            raise ThreatFadeConnectionError("ThreatFade response exceeded the configured size limit")
        try:
            payload = response.json()
        except (ValueError, TypeError) as exc:
            raise ThreatFadeConnectionError("ThreatFade returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise ThreatFadeConnectionError("ThreatFade response must be a JSON object")
        if analysis:
            detection, triage = payload.get("detection"), payload.get("triage")
            if not isinstance(detection, dict) or not isinstance(triage, dict):
                raise ThreatFadeConnectionError("ThreatFade analysis response is missing detection or triage objects")
            severity = detection.get("severity")
            if not isinstance(severity, str) or severity.upper() not in VALID_SEVERITIES:
                raise ThreatFadeConnectionError("ThreatFade analysis response contains an invalid severity")
            for field in ("score", "entropy", "drop_ratio", "z_outlier"):
                value = detection.get(field)
                if value is not None and (
                    not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value)
                ):
                    raise ThreatFadeConnectionError(f"ThreatFade analysis response contains invalid {field}")
            if "detected" in detection and not isinstance(detection["detected"], bool):
                raise ThreatFadeConnectionError("ThreatFade analysis response contains invalid detected flag")
            if "escalate" in triage and not isinstance(triage["escalate"], bool):
                raise ThreatFadeConnectionError("ThreatFade analysis response contains invalid escalation flag")
        return payload

    async def health_check(self) -> dict:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=self._headers, follow_redirects=False) as client:
                response = await client.get(f"{self.base_url}/health")
                response.raise_for_status()
                return self._parse_json_response(response)
        except (httpx.HTTPError, ThreatFadeConnectionError) as exc:
            logger.warning("ThreatFade health check failed (%s)", type(exc).__name__,
                           extra={"event": "fusionops_unreachable"})
            return {"status": "unreachable", "threatfade": "unreachable"}

    async def get_events(self, limit: int = 50) -> dict:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=self._headers, follow_redirects=False) as client:
                response = await client.get(f"{self.base_url}/events", params={"limit": limit})
                response.raise_for_status()
                return self._parse_json_response(response)
        except httpx.HTTPError as exc:
            raise ThreatFadeConnectionError("Failed to fetch ThreatFade events") from exc

    async def detect_json(self, timestamps: list[float], values: list[float], source_label: str = "") -> dict:
        if len(timestamps) != len(values):
            raise ValueError("timestamps and values must be the same length")
        if not MIN_DATA_POINTS <= len(values) <= MAX_SIGNAL_POINTS:
            raise ValueError(f"Signal must contain {MIN_DATA_POINTS}–{MAX_SIGNAL_POINTS} data points")
        if any(not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v)
               for v in [*timestamps, *values]):
            raise ValueError("Signal timestamps and values must be finite numbers")
        if not isinstance(source_label, str) or len(source_label) > 256:
            raise ValueError("source_label must be a string of at most 256 characters")
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=self._headers, follow_redirects=False) as client:
                response = await client.post(f"{self.base_url}/detect/json",
                    json={"timestamps": timestamps, "values": values, "source_label": source_label})
                response.raise_for_status()
                return self._parse_json_response(response, analysis=True)
        except httpx.HTTPError as exc:
            logger.warning("ThreatFade analysis request failed (%s)", type(exc).__name__,
                           extra={"event": "fusionops_detect_failed"})
            raise ThreatFadeConnectionError("ThreatFade analysis service unavailable") from exc

    async def detect_scenario(self, scenario: str) -> dict:
        if scenario not in VALID_SCENARIOS:
            raise ValueError("Invalid ThreatFade scenario")
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=self._headers, follow_redirects=False) as client:
                response = await client.post(f"{self.base_url}/detect/scenario", json={"scenario": scenario})
                response.raise_for_status()
                return self._parse_json_response(response, analysis=True)
        except httpx.HTTPError as exc:
            raise ThreatFadeConnectionError("ThreatFade scenario service unavailable") from exc

    async def detect_pcap(self, file_bytes: bytes, filename: str) -> dict:
        if not isinstance(file_bytes, bytes) or not 1 <= len(file_bytes) <= MAX_PCAP_BYTES:
            raise ValueError(f"PCAP upload must be between 1 byte and {MAX_PCAP_BYTES} bytes")
        if (not isinstance(filename, str) or len(filename) > 128 or PurePath(filename).name != filename
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", filename)):
            raise ValueError("Invalid PCAP filename")
        try:
            async with httpx.AsyncClient(timeout=self.timeout * 3, headers=self._headers, follow_redirects=False) as client:
                response = await client.post(f"{self.base_url}/detect/pcap",
                    files={"file": (filename, file_bytes, "application/octet-stream")})
                response.raise_for_status()
                return self._parse_json_response(response)
        except httpx.HTTPError as exc:
            raise ThreatFadeConnectionError("ThreatFade PCAP analysis service unavailable") from exc

    async def triage(self, detection_result: dict) -> dict:
        if not isinstance(detection_result, dict):
            raise ValueError("detection_result must be a JSON object")
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=self._headers, follow_redirects=False) as client:
                response = await client.post(f"{self.base_url}/triage", json=detection_result)
                response.raise_for_status()
                return self._parse_json_response(response)
        except httpx.HTTPError as exc:
            raise ThreatFadeConnectionError("ThreatFade triage service unavailable") from exc


def generate_synthetic_signal(tool_call: ToolCall, num_points: int = 20) -> tuple[list[float], list[float]]:
    """Generate demo-only synthetic data; this is not observed network telemetry."""
    if not 1 <= num_points <= MAX_SIGNAL_POINTS:
        raise ValueError("num_points is outside the supported range")
    now = time.time()
    timestamps = [now + i * 60 for i in range(num_points)]
    base, risk_factor = 3.0, 0.0
    for key, value in (tool_call.parameters or {}).items():
        if key.lower() in {"count", "limit", "recipients", "ids", "files", "targets"}:
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 10:
                risk_factor += min(value / 100.0, 1.0)
            elif isinstance(value, (list, tuple)) and len(value) >= 10:
                risk_factor += min(len(value) / 100.0, 1.0)
    action = (tool_call.action or "").lower()
    if any(word in action for word in ("bulk", "delete", "wipe", "purge", "drop")):
        risk_factor += 0.5
    values = []
    for index in range(num_points):
        values.append(round(max(base - risk_factor * 0.15 * index + random.uniform(-0.15, 0.15), 0.1), 4))
    return timestamps, values
