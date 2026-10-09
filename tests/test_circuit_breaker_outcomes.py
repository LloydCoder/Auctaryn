"""Circuit-breaker state changes only on actual runtime outcomes."""

import asyncio

import pytest

from core.models import ActionDecision, ToolCall
from modules.execution_gateway.execution_service import ExecutionService
from modules.execution_gateway.gateway import ExecutionGateway
from modules.execution_gateway.runtime_adapter import AdapterExecutionResult, RuntimeAdapterFailure


class RecordingBreaker:
    def __init__(self):
        self.successes = []
        self.failures = []

    def is_open(self, agent_id):
        return False

    def record_success(self, agent_id):
        self.successes.append(agent_id)

    def record_failure(self, agent_id):
        self.failures.append(agent_id)


class SuccessfulAdapter:
    async def execute(self, tool_call, *, idempotency_key):
        return AdapterExecutionResult(
            execution_id="runtime-success",
            adapter="test",
            status="succeeded",
            exit_code=0,
        )


class FailingAdapter:
    async def execute(self, tool_call, *, idempotency_key):
        raise RuntimeError("simulated runtime failure")


def test_policy_pending_or_veto_does_not_change_runtime_circuit_breaker():
    breaker = RecordingBreaker()
    gateway = ExecutionGateway(circuit_breaker=breaker)

    pending = gateway.evaluate(
        ToolCall(tool_name="delete_file", action="delete", agent_id="breaker-agent")
    )
    vetoed = gateway.evaluate(
        ToolCall(tool_name="shell", action="sudo", agent_id="breaker-agent")
    )

    assert pending.decision == ActionDecision.PENDING
    assert vetoed.decision == ActionDecision.VETOED
    assert breaker.successes == []
    assert breaker.failures == []


def test_successful_runtime_execution_records_breaker_success():
    breaker = RecordingBreaker()
    gateway = ExecutionGateway(circuit_breaker=breaker)
    service = ExecutionService(gateway, SuccessfulAdapter())

    decision, receipt = asyncio.run(service.execute_tool_call(
        ToolCall(tool_name="read_file", action="read", agent_id="breaker-agent")
    ))

    assert decision.decision == ActionDecision.APPROVED
    assert receipt.status == "succeeded"
    assert breaker.successes == ["breaker-agent"]
    assert breaker.failures == []


def test_runtime_exception_records_breaker_failure():
    breaker = RecordingBreaker()
    gateway = ExecutionGateway(circuit_breaker=breaker)
    service = ExecutionService(gateway, FailingAdapter())

    with pytest.raises(RuntimeAdapterFailure):
        asyncio.run(service.execute_tool_call(
            ToolCall(tool_name="read_file", action="read", agent_id="breaker-agent")
        ))

    assert breaker.successes == []
    assert breaker.failures == ["breaker-agent"]
