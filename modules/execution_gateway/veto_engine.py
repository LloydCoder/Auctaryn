"""
TwinGuard — Veto Engine
Decides approve / pending / veto for each classified action.
"""

import uuid
from datetime import datetime, timezone
from core.models import (
    RiskLevel, ActionDecision, ActionClassification, GatewayDecision,
)
from core.logging import get_logger

logger = get_logger("execution_gateway.veto")

RISK_ORDER = {
    RiskLevel.SAFE: 0,
    RiskLevel.MODERATE: 1,
    RiskLevel.DESTRUCTIVE: 2,
    RiskLevel.CRITICAL: 3,
}


class VetoEngine:
    def __init__(self, auto_approve_safe: bool = True):
        self.auto_approve_safe = auto_approve_safe

    def decide(self, classification: ActionClassification) -> GatewayDecision:
        import time
        start = time.monotonic()

        risk = classification.risk_level
        tc = classification.tool_call

        if risk == RiskLevel.CRITICAL:
            decision = ActionDecision.VETOED
            reason = (
                f"CRITICAL action '{tc.tool_name}:{tc.action}' is permanently blocked. "
                "Policy/config/privilege modifications are never permitted."
            )
            decided_by = "veto_engine"

        elif risk == RiskLevel.DESTRUCTIVE:
            decision = ActionDecision.PENDING
            reason = (
                f"Destructive action '{tc.tool_name}:{tc.action}' requires operator approval. "
                f"Reason: {classification.reason}"
            )
            decided_by = "veto_engine"

        elif risk in (RiskLevel.SAFE, RiskLevel.MODERATE):
            if self.auto_approve_safe:
                decision = ActionDecision.APPROVED
                reason = f"Auto-approved: {classification.reason}"
                decided_by = "auto"
            else:
                decision = ActionDecision.PENDING
                reason = "Manual approval required (auto-approve disabled)."
                decided_by = "veto_engine"
        else:
            decision = ActionDecision.PENDING
            reason = "Unknown risk level — pending operator review."
            decided_by = "veto_engine"

        elapsed_ms = (time.monotonic() - start) * 1000

        gd = GatewayDecision(
            id=uuid.uuid4().hex[:12],
            tool_call=tc,
            risk_level=risk,
            decision=decision,
            reason=reason,
            decided_by=decided_by,
            response_time_ms=round(elapsed_ms, 2),
        )

        logger.info(
            f"Gateway decision: {tc.tool_name}:{tc.action} → {decision.value} "
            f"(risk={risk.value}, by={decided_by})",
            extra={"event": "gateway_decision", "decision": decision.value,
                   "risk_level": risk.value},
        )
        return gd
