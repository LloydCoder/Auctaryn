"""
Auctaryn execution gateway.
Evaluates agent actions and records enforceable decisions before execution.
"""

import uuid
from datetime import datetime, timezone

from core.models import (
    ToolCall, GatewayDecision, ActionDecision, ActionClassification,
    Alert, Severity, RiskLevel,
)
from core.logging import get_logger
from modules.execution_gateway.risk_classifier import RiskClassifier
from modules.execution_gateway.veto_engine import VetoEngine

logger = get_logger("execution_gateway")


class ExecutionGateway:
    def __init__(self, auto_approve_safe: bool = True, oracle=None,
                 identity_manager=None, circuit_breaker=None):
        self.classifier = RiskClassifier()
        self.veto_engine = VetoEngine(auto_approve_safe=auto_approve_safe)
        self.history: list[GatewayDecision] = []
        self._pending: dict[str, GatewayDecision] = {}
        self.total_processed: int = 0
        self.total_vetoed: int = 0
        self.oracle = oracle
        self.identity_manager = identity_manager
        self.circuit_breaker = circuit_breaker

    def _check_identity_and_breaker(self, tool_call: ToolCall) -> GatewayDecision | None:
        """Return a terminal denial if the caller lacks identity/scope or is isolated."""
        agent_id = tool_call.agent_id

        if self.circuit_breaker is not None:
            if not agent_id or self.circuit_breaker.is_open(agent_id):
                return GatewayDecision(
                    id=uuid.uuid4().hex[:12],
                    tool_call=tool_call,
                    risk_level=RiskLevel.CRITICAL,
                    decision=ActionDecision.DENIED,
                    reason=f"Agent '{agent_id}' is isolated or missing identity for circuit-breaker enforcement",
                    decided_by="circuit_breaker",
                )

        if self.identity_manager is not None:
            if not agent_id or not self.identity_manager.is_authorized(agent_id, tool_call.tool_name, token_id=tool_call.identity_token, require_token=True):
                return GatewayDecision(
                    id=uuid.uuid4().hex[:12],
                    tool_call=tool_call,
                    risk_level=RiskLevel.CRITICAL,
                    decision=ActionDecision.DENIED,
                    reason=f"Agent '{agent_id}' is not registered or lacks scope for '{tool_call.tool_name}'",
                    decided_by="identity_manager",
                )

        return None

    def _record_preflight_denial(self, decision: GatewayDecision) -> GatewayDecision:
        # Never retain or return the caller's bearer capability in decision history.
        decision.tool_call = decision.tool_call.model_copy(update={"identity_token": ""})
        self.history.append(decision)
        self.total_processed += 1
        self.total_vetoed += 1
        self._record_breaker_outcome(decision.tool_call.agent_id, success=False)
        return decision

    def evaluate(self, tool_call: ToolCall) -> GatewayDecision:
        """Evaluate a tool call using local policy without Oracle enrichment."""
        preflight = self._check_identity_and_breaker(tool_call)
        if preflight is not None:
            return self._record_preflight_denial(preflight)

        # Token is consumed by preflight; all downstream state is credential-free.
        tool_call = tool_call.model_copy(update={"identity_token": ""})
        classification = self.classifier.classify(tool_call)
        decision = self.veto_engine.decide(classification)
        self.history.append(decision)
        self.total_processed += 1

        if decision.decision in (ActionDecision.VETOED, ActionDecision.DENIED):
            self.total_vetoed += 1
            self._emit_veto_alert(decision)
            self._record_breaker_outcome(tool_call.agent_id, success=False)
        elif decision.decision == ActionDecision.PENDING:
            self._pending[decision.id] = decision
        elif decision.decision == ActionDecision.APPROVED:
            self._record_breaker_outcome(tool_call.agent_id, success=True)
        return decision

    def _record_breaker_outcome(self, agent_id: str, success: bool) -> None:
        if self.circuit_breaker is None or not agent_id:
            return
        if success:
            self.circuit_breaker.record_success(agent_id)
        else:
            self.circuit_breaker.record_failure(agent_id)

    async def evaluate_with_oracle(self, tool_call: ToolCall) -> GatewayDecision:
        """Apply the same mandatory preflight checks before optional Oracle enrichment."""
        preflight = self._check_identity_and_breaker(tool_call)
        if preflight is not None:
            return self._record_preflight_denial(preflight)

        # Token is consumed by preflight; all downstream state is credential-free.
        tool_call = tool_call.model_copy(update={"identity_token": ""})
        classification = self.classifier.classify(tool_call)
        decision = self.veto_engine.decide(classification)

        if self.oracle and classification.risk_level in (RiskLevel.DESTRUCTIVE, RiskLevel.CRITICAL):
            decision = await self._enrich_with_oracle(tool_call, classification, decision)

        self.history.append(decision)
        self.total_processed += 1

        if decision.decision in (ActionDecision.VETOED, ActionDecision.DENIED):
            self.total_vetoed += 1
            self._emit_veto_alert(decision)
            self._record_breaker_outcome(tool_call.agent_id, success=False)
        elif decision.decision == ActionDecision.PENDING:
            self._pending[decision.id] = decision
        elif decision.decision == ActionDecision.APPROVED:
            self._record_breaker_outcome(tool_call.agent_id, success=True)
        return decision

    async def _enrich_with_oracle(self, tool_call: ToolCall,
                                  classification: ActionClassification,
                                  decision: GatewayDecision) -> GatewayDecision:
        """Enrich a decision without ever turning a pending destructive action into an approval."""
        try:
            tf_result = await self.oracle.analyze(tool_call)
        except Exception as exc:
            # Destructive actions already require approval; critical actions remain vetoed.
            # Do not silently convert a pending/vetoed decision into an approval on Oracle failure.
            logger.warning(
                "Oracle enrichment unavailable; retaining conservative local decision (%s)",
                type(exc).__name__,
                extra={"event": "oracle_enrichment_failed"},
            )
            return decision

        if tf_result.severity in (Severity.CRITICAL, Severity.HIGH) and decision.decision not in (
            ActionDecision.VETOED, ActionDecision.DENIED
        ):
            escalated = GatewayDecision(
                id=decision.id,
                timestamp=datetime.now(timezone.utc),
                tool_call=tool_call,
                risk_level=RiskLevel.CRITICAL,
                decision=ActionDecision.VETOED,
                reason=(
                    f"{decision.reason} | ESCALATED by ThreatFade Oracle: "
                    f"severity={tf_result.severity.value}, z_score={tf_result.z_score:.2f}"
                ),
                decided_by="parliament:oracle_escalation",
            )
            logger.warning(
                "Oracle escalated %s:%s to vetoed (severity=%s)",
                tool_call.tool_name, tool_call.action, tf_result.severity.value,
                extra={"event": "parliament_escalation"},
            )
            return escalated
        return decision

    def get_pending(self) -> list[GatewayDecision]:
        return list(self._pending.values())

    def resolve_pending(self, decision_id: str, approved: bool,
                        reason: str = "", operator: str = "operator") -> GatewayDecision:
        if decision_id not in self._pending:
            raise KeyError(f"No pending decision with id {decision_id}")

        original = self._pending.pop(decision_id)
        new_decision = ActionDecision.APPROVED if approved else ActionDecision.DENIED
        resolved = GatewayDecision(
            id=original.id,
            timestamp=datetime.now(timezone.utc),
            tool_call=original.tool_call,
            risk_level=original.risk_level,
            decision=new_decision,
            reason=reason or f"{'Approved' if approved else 'Denied'} by {operator}",
            decided_by=operator,
        )

        for index, history_item in enumerate(self.history):
            if history_item.id == decision_id:
                self.history[index] = resolved
                break

        logger.info(
            "Pending decision resolved: %s -> %s",
            original.tool_call.tool_name, new_decision.value,
            extra={"event": "pending_resolved", "decision": new_decision.value},
        )
        return resolved

    def get_status(self) -> dict:
        return {
            "status": "active",
            "total_processed": self.total_processed,
            "total_vetoed": self.total_vetoed,
            "pending_approvals": len(self._pending),
            "oracle_enabled": self.oracle is not None,
            "identity_enforcement_enabled": self.identity_manager is not None,
            "circuit_breaker_enabled": self.circuit_breaker is not None,
        }

    def _emit_veto_alert(self, decision: GatewayDecision) -> Alert:
        tc = decision.tool_call
        alert = Alert(
            id=uuid.uuid4().hex[:12],
            severity=Severity.CRITICAL,
            module="execution_gateway",
            title="Critical Action Vetoed",
            message=(
                f"Agent attempted critical action '{tc.tool_name}:{tc.action}' "
                f"— blocked by Execution Gateway. {decision.reason}"
            ),
            data={"decision_id": decision.id, "tool_name": tc.tool_name,
                  "action": tc.action, "risk_level": decision.risk_level.value},
        )
        logger.warning("VETO ALERT: %s", alert.message,
                       extra={"event": "veto_alert", "alert_id": alert.id})
        return alert
