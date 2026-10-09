"""
TwinGuard — ThreatFade Oracle Service
Full service combining the FusionOps client and Parliament adapter.
This is what api/routes/threatfade.py and the Execution Gateway call.

Fails safe: if FusionOps is unreachable, returns an INFO-level result
rather than crashing or blocking legitimate agent actions.
"""

from datetime import datetime, timezone
import threading
import time

from pydantic import ValidationError

from core.models import ToolCall, ThreatFadeResult, Severity
from core.exceptions import ThreatFadeConnectionError
from core.logging import get_logger
from modules.threatfade_oracle.client import (
    FusionOpsClient, generate_synthetic_signal, MAX_SOURCE_LABEL_LENGTH, VALID_SCENARIOS,
)
from modules.threatfade_oracle.parliament_adapter import (
    to_threatfade_result, should_escalate,
)

logger = get_logger("threatfade_oracle")


class ThreatFadeOracle:
    """
    Main entry point for ThreatFade network threat intelligence.
    Wraps FusionOpsClient with TwinGuard-specific logic: synthetic signal
    generation, result mapping, history tracking, and graceful degradation.
    """

    def __init__(self, base_url: str | None = None):
        self.client = FusionOpsClient(base_url=base_url) if base_url else FusionOpsClient()
        self.history: list[ThreatFadeResult] = []
        self.raw_results: list[dict] = []
        self.max_history = 1000
        self.oracle_failure_threshold = 5
        self.oracle_reset_timeout = 30.0
        self._oracle_consecutive_failures = 0
        self._oracle_open_until = 0.0
        self._oracle_half_open_probe = False
        self._oracle_breaker_lock = threading.Lock()

    def _begin_oracle_call(self) -> bool:
        with self._oracle_breaker_lock:
            now = time.monotonic()
            if self._oracle_open_until <= 0:
                return True
            if now < self._oracle_open_until or self._oracle_half_open_probe:
                return False
            self._oracle_half_open_probe = True
            return True

    def _record_oracle_success(self) -> None:
        with self._oracle_breaker_lock:
            self._oracle_consecutive_failures = 0
            self._oracle_open_until = 0.0
            self._oracle_half_open_probe = False

    def _record_oracle_failure(self) -> None:
        with self._oracle_breaker_lock:
            self._oracle_consecutive_failures += 1
            self._oracle_half_open_probe = False
            if self._oracle_consecutive_failures >= self.oracle_failure_threshold:
                self._oracle_open_until = time.monotonic() + self.oracle_reset_timeout

    def _oracle_breaker_state(self) -> str:
        with self._oracle_breaker_lock:
            if self._oracle_open_until <= 0:
                return "closed"
            if time.monotonic() < self._oracle_open_until:
                return "open"
            return "half_open"

    def _record_result(self, result: ThreatFadeResult, raw_result: dict | None = None) -> None:
        self.history.append(result)
        if raw_result is not None:
            self.raw_results.append(raw_result)
        if len(self.history) > self.max_history:
            del self.history[:len(self.history) - self.max_history]
        if len(self.raw_results) > self.max_history:
            del self.raw_results[:len(self.raw_results) - self.max_history]

    @staticmethod
    def _fallback_result(source_label: str) -> ThreatFadeResult:
        return ThreatFadeResult(
            score=0.0,
            z_score=0.0,
            entropy=0.0,
            drop_ratio=0.0,
            severity=Severity.INFO,
            confidence="0.0",
            mitre_ttps=[],
            fade_detected=False,
            source_file=source_label,
        )

    async def analyze(self, tool_call: ToolCall) -> ThreatFadeResult:
        """
        Analyze a tool call by generating a synthetic signal and sending it
        to FusionOps for entropy/z-score analysis. Falls back gracefully
        if FusionOps is unreachable.
        """
        timestamps, values = generate_synthetic_signal(tool_call)
        source_label = f"twinguard:{tool_call.tool_name}:{tool_call.action}"[:MAX_SOURCE_LABEL_LENGTH]
        if not self._begin_oracle_call():
            fallback = self._fallback_result(source_label)
            self._record_result(fallback)
            logger.warning("ThreatFade Oracle circuit breaker is open",
                           extra={"event": "oracle_circuit_open"})
            return fallback

        try:
            full_result = await self.client.detect_json(
                timestamps=timestamps, values=values, source_label=source_label,
            )
            result = to_threatfade_result(full_result)
        except (ThreatFadeConnectionError, ValidationError, KeyError, TypeError, ValueError) as exc:
            self._record_oracle_failure()
            logger.warning(
                "ThreatFade Oracle unavailable or returned invalid analysis; using INFO fallback",
                extra={"event": "oracle_fallback", "module_name": "threatfade_oracle",
                       "error_type": type(exc).__name__},
            )
            fallback = self._fallback_result(source_label)
            self._record_result(fallback)
            return fallback

        self._record_oracle_success()
        self._record_result(result, full_result)
        if should_escalate(full_result):
            logger.warning(
                "ThreatFade Oracle escalation",
                extra={"event": "oracle_escalation", "module_name": "threatfade_oracle",
                       "category": full_result.get("triage", {}).get("category")},
            )
        return result

    async def run_scenario(self, scenario: str) -> ThreatFadeResult:
        """Run a named demo scenario directly against FusionOps."""
        if not isinstance(scenario, str) or scenario not in VALID_SCENARIOS:
            raise ValueError("Invalid ThreatFade scenario.")
        if not self._begin_oracle_call():
            raise ThreatFadeConnectionError("ThreatFade Oracle circuit breaker is open.")
        try:
            full_result = await self.client.detect_scenario(scenario)
            result = to_threatfade_result(full_result)
        except ThreatFadeConnectionError:
            self._record_oracle_failure()
            raise
        except (ValidationError, KeyError, TypeError, ValueError) as exc:
            self._record_oracle_failure()
            raise ThreatFadeConnectionError("FusionOps returned an invalid scenario analysis.") from exc
        self._record_oracle_success()
        self._record_result(result, full_result)
        return result

    async def get_status(self) -> dict:
        """Current oracle/FusionOps connectivity status."""
        health = await self.client.health_check()
        return {
            "status": "connected" if health.get("status") == "ok" else "initialized",
            "connected": health.get("status") == "ok",
            "threatfade_version": health.get("version", "0.2.0-beta"),
            "fusionops_status": health.get("status", "unknown"),
            "threatfade_engine_status": health.get("threatfade", "unknown"),
            "base_url": self.client.base_url,
            "total_analyses": len(self.history),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "oracle_circuit_breaker": self._oracle_breaker_state(),
        }

    def get_recent_results(self, limit: int = 50) -> list[ThreatFadeResult]:
        return self.history[-limit:]
