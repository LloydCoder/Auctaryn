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
