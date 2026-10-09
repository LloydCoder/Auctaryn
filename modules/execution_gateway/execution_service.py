"""Execution service that mediates decisions and trusted runtime invocation.

The service fails closed when no adapter is configured. Only APPROVED decisions
can reach the adapter; pending, denied, vetoed, timed-out, and unknown outcomes
never execute. Raw runtime output is hashed and excluded from API receipts.
"""
import hashlib
import hmac
import logging

from core.models import ActionDecision, GatewayDecision, ToolCall, action_intent_fingerprint
from modules.execution_gateway.gateway import ExecutionGateway
from modules.incident_response.manager import get_incident_response_manager
from modules.execution_gateway.runtime_adapter import (
    DuplicateExecution,
    RuntimeAdapter,
    RuntimeAdapterFailure,
    RuntimeAdapterUnavailable,
    RuntimeExecutionReceipt,
)

logger = logging.getLogger("execution_gateway.execution_service")


class ActionIntentIntegrityError(RuntimeAdapterFailure):
    """Raised when an approved decision no longer matches its recorded intent."""


class ExecutionService:
    def __init__(self, gateway: ExecutionGateway, adapter: RuntimeAdapter | None = None):
        self.gateway = gateway
        self.adapter = adapter
        # In-process at-most-once guard. The adapter must additionally honor the
        # decision ID as an idempotency key; durable deduplication belongs to the
        # production runtime/control-plane integration.
        self._claimed_decisions: set[str] = set()

    def require_adapter(self) -> RuntimeAdapter:
        if self.adapter is None:
            raise RuntimeAdapterUnavailable(
                "No trusted runtime adapter is configured; tool execution is disabled."
            )
        return self.adapter

    async def execute_tool_call(self, tool_call: ToolCall) -> tuple[GatewayDecision, RuntimeExecutionReceipt | None]:
        """Evaluate a call and execute it only when local policy approves it."""
        self.gateway.data_guard.validate_tool_call(tool_call)
        get_incident_response_manager().assert_execution_allowed(tool_call.agent_id)
        self.require_adapter()
        decision = await self.gateway.evaluate_with_oracle(tool_call)
        if decision.decision != ActionDecision.APPROVED:
            return decision, None
        receipt = await self.execute_approved_decision(decision)
        return decision, receipt

    async def execute_approved_decision(
        self, decision: GatewayDecision
    ) -> RuntimeExecutionReceipt:
        """Execute an already approved immutable decision exactly once per process."""
        get_incident_response_manager().assert_execution_allowed(decision.tool_call.agent_id)
        adapter = self.require_adapter()
        if decision.decision != ActionDecision.APPROVED:
            raise RuntimeAdapterFailure("Only approved decisions may be executed.")
        # Recheck at the actual adapter boundary, not only when the decision was created.
        # The guardian permits the same check/action binding but rejects a compromised
        # session or reuse of the check for a different action.
        if self.gateway.context_integrity_guard is not None:
            try:
                context_denial = self.gateway.context_integrity_guard(decision.tool_call)
            except Exception:
                context_denial = "Context integrity preflight unavailable; execution refused."
            if context_denial:
                raise ActionIntentIntegrityError(context_denial)
        current_fingerprint = action_intent_fingerprint(decision.tool_call)
        if (
            not decision.action_fingerprint
            or not hmac.compare_digest(decision.action_fingerprint, current_fingerprint)
        ):
            raise ActionIntentIntegrityError(
                "Action intent integrity check failed; execution was refused."
            )
        # Recheck after all preflight work, as close as possible to adapter invocation.
        get_incident_response_manager().assert_execution_allowed(decision.tool_call.agent_id)
        if decision.id in self._claimed_decisions:
            raise DuplicateExecution("This decision has already been claimed for execution.")

        self._claimed_decisions.add(decision.id)
        try:
            result = await adapter.execute(
                decision.tool_call, idempotency_key=decision.id
            )
        except Exception as exc:
            self.gateway.record_execution_outcome(decision.tool_call.agent_id, success=False)
            logger.error(
                "Trusted runtime execution failed for decision %s (%s)",
                decision.id,
                type(exc).__name__,
                extra={"event": "runtime_execution_failed", "decision_id": decision.id},
            )
            raise RuntimeAdapterFailure(
                "Trusted runtime execution failed; no successful receipt was produced."
            ) from exc

        self.gateway.record_execution_outcome(
            decision.tool_call.agent_id, success=result.status == "succeeded"
        )
        if result.status != "succeeded":
            logger.warning(
                "Runtime did not complete decision %s successfully (status=%s)",
                decision.id,
                result.status,
                extra={"event": "runtime_execution_incomplete", "decision_id": decision.id},
            )

        return RuntimeExecutionReceipt(
            decision_id=decision.id,
            execution_id=result.execution_id,
            adapter=result.adapter,
            status=result.status,
            exit_code=result.exit_code,
            stdout_sha256=hashlib.sha256(result.stdout.encode("utf-8")).hexdigest(),
            stderr_sha256=hashlib.sha256(result.stderr.encode("utf-8")).hexdigest(),
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
            finished_at=result.finished_at,
        )
