"""
TwinGuard — Gateway OWASP Module Wiring Tests (TDD)
Closes the gap flagged previously: Agent Identity and Circuit Breaker
existed as standalone modules but were never consulted inside the
actual Gateway decision path. This makes them load-bearing.
"""

import pytest
from core.models import ToolCall, ActionDecision, RiskLevel


class TestIdentityEnforcement:
    """Gateway must consult Agent Identity before approving ANY action,
    not just classify by pattern."""

    def test_unregistered_agent_is_denied_even_for_safe_action(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from modules.agent_identity.identity import AgentIdentityManager

        identity_mgr = AgentIdentityManager()
        gw = ExecutionGateway(identity_manager=identity_mgr)

        tc = ToolCall(tool_name="read_file", action="read", agent_id="rogue-unregistered")
        decision = gw.evaluate(tc)
        assert decision.decision == ActionDecision.DENIED
        assert "identity" in decision.reason.lower() or "registered" in decision.reason.lower()

    def test_registered_agent_with_scope_proceeds_normally(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from modules.agent_identity.identity import AgentIdentityManager

        identity_mgr = AgentIdentityManager()
        identity_mgr.register("agent-001", owner="user-1")
        identity_mgr.grant_scope("agent-001", "read_*")
        gw = ExecutionGateway(identity_manager=identity_mgr)

        tc = ToolCall(tool_name="read_file", action="read", agent_id="agent-001")
        decision = gw.evaluate(tc)
        assert decision.decision == ActionDecision.APPROVED

    def test_registered_agent_without_scope_is_denied(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from modules.agent_identity.identity import AgentIdentityManager

        identity_mgr = AgentIdentityManager()
        identity_mgr.register("agent-001", owner="user-1")
        # No scopes granted
        gw = ExecutionGateway(identity_manager=identity_mgr)

        tc = ToolCall(tool_name="read_file", action="read", agent_id="agent-001")
        decision = gw.evaluate(tc)
        assert decision.decision == ActionDecision.DENIED

    def test_no_identity_manager_means_open_mode_for_backward_compat(self):
        """If no identity_manager is wired, gateway behaves exactly as before (no breaking change)."""
        from modules.execution_gateway.gateway import ExecutionGateway

        gw = ExecutionGateway()  # no identity_manager passed
        tc = ToolCall(tool_name="read_file", action="read", agent_id="any-agent")
        decision = gw.evaluate(tc)
        assert decision.decision == ActionDecision.APPROVED


class TestCircuitBreakerEnforcement:
    """Gateway must isolate agents whose circuit breaker has tripped."""

    def test_tripped_agent_is_denied_regardless_of_risk_level(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from modules.inter_agent.circuit_breaker import AgentCircuitBreaker

        breaker = AgentCircuitBreaker(failure_threshold=2)
        breaker.record_failure("flaky-agent")
        breaker.record_failure("flaky-agent")

        gw = ExecutionGateway(circuit_breaker=breaker)
        tc = ToolCall(tool_name="read_file", action="read", agent_id="flaky-agent")
        decision = gw.evaluate(tc)
        assert decision.decision == ActionDecision.DENIED
        assert "breaker" in decision.reason.lower() or "isolated" in decision.reason.lower()

    def test_vetoed_decision_records_a_failure_on_the_breaker(self):
        """A critical/vetoed action counts as a failure signal for that agent."""
        from modules.execution_gateway.gateway import ExecutionGateway
        from modules.inter_agent.circuit_breaker import AgentCircuitBreaker

        breaker = AgentCircuitBreaker(failure_threshold=2)
        gw = ExecutionGateway(circuit_breaker=breaker)

        tc1 = ToolCall(tool_name="modify_config", action="write", agent_id="bad-agent")
        tc2 = ToolCall(tool_name="modify_policy", action="write", agent_id="bad-agent")
        gw.evaluate(tc1)
        gw.evaluate(tc2)

        assert breaker.is_open("bad-agent") is True

    def test_approved_decision_does_not_trip_breaker(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from modules.inter_agent.circuit_breaker import AgentCircuitBreaker

        breaker = AgentCircuitBreaker(failure_threshold=2)
        gw = ExecutionGateway(circuit_breaker=breaker)

        for _ in range(5):
            tc = ToolCall(tool_name="read_file", action="read", agent_id="good-agent")
            gw.evaluate(tc)

        assert breaker.is_open("good-agent") is False
