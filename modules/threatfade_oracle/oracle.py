"""
TwinGuard — ThreatFade Oracle Service
Full service combining the FusionOps client and Parliament adapter.
This is what api/routes/threatfade.py and the Execution Gateway call.

Fails safe: if FusionOps is unreachable, returns an INFO-level result
rather than crashing or blocking legitimate agent actions.
"""

from datetime import datetime, timezone

from core.models import ToolCall, ThreatFadeResult, Severity
from core.exceptions import ThreatFadeConnectionError
from core.logging import get_logger
from modules.threatfade_oracle.client import FusionOpsClient, generate_synthetic_signal
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

    async def analyze(self, tool_call: ToolCall) -> ThreatFadeResult:
        """
        Analyze a tool call by generating a synthetic signal and sending it
        to FusionOps for entropy/z-score analysis. Falls back gracefully
        if FusionOps is unreachable.
        """
        timestamps, values = generate_synthetic_signal(tool_call)
        source_label = f"twinguard:{tool_call.tool_name}:{tool_call.action}"

        try:
            full_result = await self.client.detect_json(
                timestamps=timestamps, values=values, source_label=source_label,
            )
            self.raw_results.append(full_result)

            result = to_threatfade_result(full_result)
            self.history.append(result)

            if should_escalate(full_result):
                logger.warning(
                    f"ThreatFade Oracle escalation: {tool_call.tool_name}:{tool_call.action} "
                    f"— category={full_result.get('triage', {}).get('category')}",
                    extra={"event": "oracle_escalation", "module_name": "threatfade_oracle"},
                )

            return result

        except ThreatFadeConnectionError as e:
            logger.warning(
                f"ThreatFade Oracle unreachable, failing safe: {e}",
                extra={"event": "oracle_fallback", "module_name": "threatfade_oracle"},
            )
            fallback = ThreatFadeResult(
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
            self.history.append(fallback)
            return fallback

    async def run_scenario(self, scenario: str) -> ThreatFadeResult:
        """Run a named demo scenario directly against FusionOps."""
        full_result = await self.client.detect_scenario(scenario)
        self.raw_results.append(full_result)
        result = to_threatfade_result(full_result)
        self.history.append(result)
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
        }

    def get_recent_results(self, limit: int = 50) -> list[ThreatFadeResult]:
        return self.history[-limit:]
