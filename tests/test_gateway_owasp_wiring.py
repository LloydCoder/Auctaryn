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
        token = identity_mgr.issue_token("agent-001")
        gw = ExecutionGateway(identity_manager=identity_mgr)

        tc = ToolCall(tool_name="read_file", action="read", agent_id="agent-001", identity_token=token.token_id)
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

    def test_missing_token_is_denied_when_identity_manager_is_enabled(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from modules.agent_identity.identity import AgentIdentityManager

        identity_mgr = AgentIdentityManager()
        identity_mgr.register("agent-001", owner="user-1")
        identity_mgr.grant_scope("agent-001", "read_file")
        gw = ExecutionGateway(identity_manager=identity_mgr)
        decision = gw.evaluate(ToolCall(tool_name="read_file", action="read", agent_id="agent-001"))
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


class TestScopedIdentityCapabilities:
    def test_revoked_scope_invalidates_previously_issued_token(self):
        from modules.agent_identity.identity import AgentIdentityManager

        manager = AgentIdentityManager()
        manager.register("agent-token", owner="test")
        manager.grant_scope("agent-token", "read_file")
        token = manager.issue_token("agent-token")
        assert manager.is_authorized(
            "agent-token", "read_file", token_id=token.token_id, require_token=True
        )
        manager.revoke_scope("agent-token", "read_file")
        assert not manager.is_authorized(
            "agent-token", "read_file", token_id=token.token_id, require_token=True
        )

    def test_delegated_scope_is_token_scoped_and_revocable_by_delegator(self):
        from modules.agent_identity.identity import AgentIdentityManager

        manager = AgentIdentityManager()
        manager.register("manager", owner="test")
        manager.register("delegate", owner="test")
        manager.grant_scope("manager", "read_file")
        token = manager.delegate("manager", "delegate", ["read_file"], ttl_seconds=60)

        assert not manager.is_authorized("delegate", "read_file")
        assert manager.is_authorized(
            "delegate", "read_file", token_id=token.token_id, require_token=True
        )
        manager.revoke_scope("manager", "read_file")
        assert not manager.is_authorized(
            "delegate", "read_file", token_id=token.token_id, require_token=True
        )

    def test_expired_token_is_denied(self):
        from datetime import datetime, timedelta, timezone
        from modules.agent_identity.identity import AgentIdentityManager

        manager = AgentIdentityManager()
        manager.register("agent-expired", owner="test")
        manager.grant_scope("agent-expired", "read_file")
        token = manager.issue_token("agent-expired")
        token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

        assert not manager.is_authorized(
            "agent-expired", "read_file", token_id=token.token_id, require_token=True
        )
