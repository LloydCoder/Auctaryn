"""Regression tests for enforcement paths that must fail closed."""
import pytest

from core.models import ActionDecision, ToolCall
from modules.agent_identity.identity import AgentIdentityManager
from modules.execution_gateway.gateway import ExecutionGateway


class ExplodingOracle:
    def __init__(self):
        self.calls = 0

    async def analyze(self, tool_call):
        self.calls += 1
        raise RuntimeError("simulated Oracle outage")


@pytest.mark.asyncio
async def test_oracle_path_denies_unregistered_agent_before_oracle_call():
    identities = AgentIdentityManager()
    oracle = ExplodingOracle()
    gateway = ExecutionGateway(identity_manager=identities, oracle=oracle)

    decision = await gateway.evaluate_with_oracle(
        ToolCall(
            tool_name="read_file",
            action="read",
            agent_id="unregistered-agent",
        )
    )

    assert decision.decision == ActionDecision.DENIED
    assert decision.decided_by == "identity_manager"
    assert oracle.calls == 0


def test_moderate_write_action_requires_operator_approval():
    gateway = ExecutionGateway()
    decision = gateway.evaluate(
        ToolCall(
            tool_name="write_file",
            action="create",
            agent_id="local-test-agent",
        )
    )

    assert decision.decision == ActionDecision.PENDING
    assert decision.id in {item.id for item in gateway.get_pending()}


def test_gateway_history_is_bounded(monkeypatch):
    import modules.execution_gateway.gateway as gateway_module

    monkeypatch.setattr(gateway_module, "MAX_DECISION_HISTORY", 2)
    gateway = ExecutionGateway()
    for index in range(3):
        gateway.evaluate(
            ToolCall(
                tool_name="read_file",
                action="read",
                parameters={"path": f"/tmp/{index}.txt"},
                agent_id=f"history-agent-{index}",
            )
        )
    assert len(gateway.history) == 2


def test_gateway_denies_new_pending_action_when_approval_queue_is_full(monkeypatch):
    import modules.execution_gateway.gateway as gateway_module

    monkeypatch.setattr(gateway_module, "MAX_PENDING_APPROVALS", 1)
    gateway = ExecutionGateway()
    first = gateway.evaluate(
        ToolCall(tool_name="write_file", action="create", agent_id="capacity-agent-1")
    )
    second = gateway.evaluate(
        ToolCall(tool_name="write_file", action="create", agent_id="capacity-agent-2")
    )

    assert first.decision == ActionDecision.PENDING
    assert second.decision == ActionDecision.DENIED
    assert second.decided_by == "capacity_guard"
    assert "capacity reached" in second.reason.lower()
    assert len(gateway.get_pending()) == 1
