"""ThreatFade Oracle: bounded advisory analysis with conservative failure behavior."""
import os
import threading
import time
from datetime import datetime, timezone

from core.models import ToolCall, ThreatFadeResult, Severity
from core.exceptions import ThreatFadeConnectionError
from core.logging import get_logger
from modules.threatfade_oracle.client import FusionOpsClient, generate_synthetic_signal
from modules.threatfade_oracle.parliament_adapter import to_threatfade_result, should_escalate

logger = get_logger("threatfade_oracle")
MAX_HISTORY = 500


class OracleCircuitBreaker:
    """Thread-safe closed/open/half-open breaker for an unreliable upstream."""
    def __init__(self, failure_threshold: int = 3, cooldown_seconds: float = 30.0):
        if failure_threshold < 1 or cooldown_seconds <= 0:
            raise ValueError("Circuit-breaker threshold and cooldown must be positive")
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._failures = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False
        self._lock = threading.Lock()

    def allow_request(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return True
            if time.monotonic() - self._opened_at < self.cooldown_seconds or self._probe_in_flight:
                return False
            self._probe_in_flight = True
            return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._probe_in_flight = False

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            self._probe_in_flight = False
            if self._failures >= self.failure_threshold:
                self._opened_at = time.monotonic()

    def reset(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None
            self._probe_in_flight = False


class ThreatFadeOracle:
    """Advisory threat signal source; it cannot authorize or execute actions."""
    def __init__(self, base_url: str | None = None):
        self.client = FusionOpsClient(base_url=base_url) if base_url else FusionOpsClient()
        self.history: list[ThreatFadeResult] = []
        self.raw_results: list[dict] = []
        self.circuit_breaker = OracleCircuitBreaker()

    def _remember(self, result: ThreatFadeResult, raw: dict | None = None) -> None:
        self.history.append(result)
        del self.history[:-MAX_HISTORY]
        if raw is not None:
            self.raw_results.append(raw)
            del self.raw_results[:-MAX_HISTORY]

    @staticmethod
    def _fallback(source_label: str) -> ThreatFadeResult:
        return ThreatFadeResult(score=0.0, z_score=0.0, entropy=0.0, drop_ratio=0.0,
            severity=Severity.INFO, confidence="0.0", mitre_ttps=[], fade_detected=False,
            source_file=source_label)

    async def analyze(self, tool_call: ToolCall) -> ThreatFadeResult:
        """Synthetic input is disabled by default because it is not observed telemetry."""
        source_label = f"auctaryn:{tool_call.tool_name}:{tool_call.action}"
        if os.getenv("AUCTARYN_THREATFADE_ALLOW_SYNTHETIC_SIGNAL", "").lower() not in {"1", "true", "yes"}:
            result = self._fallback("synthetic-analysis-disabled")
            self._remember(result)
            return result
        if not self.circuit_breaker.allow_request():
            result = self._fallback("threatfade-circuit-open")
            self._remember(result)
            return result
        try:
            timestamps, values = generate_synthetic_signal(tool_call)
            full_result = await self.client.detect_json(timestamps, values, source_label)
            result = to_threatfade_result(full_result)
            self.circuit_breaker.record_success()
            self._remember(result, full_result)
            if should_escalate(full_result):
                logger.warning("ThreatFade Oracle escalation for %s:%s", tool_call.tool_name, tool_call.action,
                    extra={"event": "oracle_escalation", "module_name": "threatfade_oracle"})
            return result
        except Exception as exc:
            self.circuit_breaker.record_failure()
            logger.warning("ThreatFade analysis unavailable; retaining local decision (%s)", type(exc).__name__,
                extra={"event": "oracle_fallback", "module_name": "threatfade_oracle"})
            result = self._fallback(source_label)
            self._remember(result)
            return result

    async def run_scenario(self, scenario: str) -> ThreatFadeResult:
        if not self.circuit_breaker.allow_request():
            raise ThreatFadeConnectionError("ThreatFade circuit breaker is open")
        try:
            full_result = await self.client.detect_scenario(scenario)
            result = to_threatfade_result(full_result)
            self.circuit_breaker.record_success()
            self._remember(result, full_result)
            return result
        except Exception as exc:
            self.circuit_breaker.record_failure()
            if isinstance(exc, (ValueError, ThreatFadeConnectionError)):
                raise
            raise ThreatFadeConnectionError("ThreatFade scenario response was invalid") from exc

    async def get_status(self) -> dict:
        health = await self.client.health_check()
        return {
            "status": "connected" if health.get("status") == "ok" else "degraded",
            "connected": health.get("status") == "ok",
            "threatfade_version": health.get("version", "unknown"),
            "fusionops_status": health.get("status", "unknown"),
            "threatfade_engine_status": health.get("threatfade", "unknown"),
            "base_url": self.client.base_url,
            "circuit_breaker": "open" if self.circuit_breaker._opened_at is not None else "closed",
            "total_analyses": len(self.history),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_recent_results(self, limit: int = 50) -> list[ThreatFadeResult]:
        if not 1 <= limit <= MAX_HISTORY:
            raise ValueError(f"limit must be between 1 and {MAX_HISTORY}")
        return self.history[-limit:]
