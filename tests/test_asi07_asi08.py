"""
TwinGuard — ASI07 (Insecure Inter-Agent Communication) +
ASI08 (Cascading Agent Failures) Tests (TDD)

ASI07: when multiple agents communicate (delegation, sub-agent spawning,
shared task state), messages must be signed and provenance-tracked so
one agent can't impersonate another or inject unsigned instructions
into a peer's task queue.

ASI08: a failing/erratic agent must not be allowed to cascade — repeated
failures from one agent_id trip a circuit breaker that isolates it
(stops processing its actions) before it can flood the gateway or
poison shared state.

Written FIRST. Implementation follows.
"""

import pytest
from datetime import datetime, timezone, timedelta


class TestSignedAgentMessages:
    """ASI07: inter-agent messages must be signed by the sending agent's identity."""

    def test_sign_and_verify_message(self):
        from modules.inter_agent.messaging import AgentMessageBus
        bus = AgentMessageBus()
        bus.register_agent_key("agent-A", "secret-key-A")
        message = bus.send("agent-A", "agent-B", {"task": "summarize document"})
        assert bus.verify(message) is True

    def test_tampered_message_fails_verification(self):
        from modules.inter_agent.messaging import AgentMessageBus
        bus = AgentMessageBus()
        bus.register_agent_key("agent-A", "secret-key-A")
        message = bus.send("agent-A", "agent-B", {"task": "summarize document"})
        message.payload["task"] = "delete everything"  # tampered after signing
        assert bus.verify(message) is False

    def test_unsigned_message_rejected_by_default(self):
        from modules.inter_agent.messaging import AgentMessageBus, AgentMessage
        bus = AgentMessageBus()
        forged = AgentMessage(
            message_id="forged-1", sender_id="agent-X", recipient_id="agent-B",
            payload={"task": "do something"}, signature="", timestamp=datetime.now(timezone.utc),
        )
        assert bus.verify(forged) is False

    def test_impersonation_detected(self):
        """An agent without a registered key cannot send as a known agent_id."""
        from modules.inter_agent.messaging import AgentMessageBus
        bus = AgentMessageBus()
        bus.register_agent_key("agent-A", "secret-key-A")
        with pytest.raises(PermissionError):
            bus.send("agent-A", "agent-B", {"task": "x"}, signing_key="wrong-key")

    def test_message_delivery_tracked(self):
        from modules.inter_agent.messaging import AgentMessageBus
        bus = AgentMessageBus()
        bus.register_agent_key("agent-A", "secret-key-A")
        bus.send("agent-A", "agent-B", {"task": "y"})
        inbox = bus.get_inbox("agent-B")
        assert len(inbox) == 1
        assert inbox[0].sender_id == "agent-A"

    def test_recipient_only_sees_own_inbox(self):
        from modules.inter_agent.messaging import AgentMessageBus
        bus = AgentMessageBus()
        bus.register_agent_key("agent-A", "secret-key-A")
        bus.send("agent-A", "agent-B", {"task": "y"})
        bus.send("agent-A", "agent-C", {"task": "z"})
        assert len(bus.get_inbox("agent-B")) == 1
        assert len(bus.get_inbox("agent-C")) == 1
        assert len(bus.get_inbox("agent-D")) == 0


class TestCircuitBreaker:
    """ASI08: repeated failures from one agent trip a breaker and isolate it."""

    def test_breaker_starts_closed(self):
        from modules.inter_agent.circuit_breaker import AgentCircuitBreaker
        cb = AgentCircuitBreaker(failure_threshold=3)
        assert cb.is_open("agent-001") is False

    def test_breaker_opens_after_threshold_failures(self):
        from modules.inter_agent.circuit_breaker import AgentCircuitBreaker
        cb = AgentCircuitBreaker(failure_threshold=3)
        cb.record_failure("agent-001")
        cb.record_failure("agent-001")
        cb.record_failure("agent-001")
        assert cb.is_open("agent-001") is True

    def test_breaker_does_not_open_below_threshold(self):
        from modules.inter_agent.circuit_breaker import AgentCircuitBreaker
        cb = AgentCircuitBreaker(failure_threshold=3)
        cb.record_failure("agent-001")
        cb.record_failure("agent-001")
        assert cb.is_open("agent-001") is False

    def test_breaker_is_per_agent_isolated(self):
        """One agent tripping the breaker must not affect another agent."""
        from modules.inter_agent.circuit_breaker import AgentCircuitBreaker
        cb = AgentCircuitBreaker(failure_threshold=2)
        cb.record_failure("agent-001")
        cb.record_failure("agent-001")
        assert cb.is_open("agent-001") is True
        assert cb.is_open("agent-002") is False

    def test_success_resets_failure_count(self):
        from modules.inter_agent.circuit_breaker import AgentCircuitBreaker
        cb = AgentCircuitBreaker(failure_threshold=3)
        cb.record_failure("agent-001")
        cb.record_failure("agent-001")
        cb.record_success("agent-001")
        cb.record_failure("agent-001")
        assert cb.is_open("agent-001") is False  # count reset, only 1 failure since success

    def test_breaker_auto_recovers_after_cooldown(self):
        from modules.inter_agent.circuit_breaker import AgentCircuitBreaker
        cb = AgentCircuitBreaker(failure_threshold=2, cooldown_seconds=30)
        cb.record_failure("agent-001")
        cb.record_failure("agent-001")
        assert cb.is_open("agent-001") is True
        # Immediately after tripping, still within cooldown
        assert cb.is_open("agent-001", now=datetime.now(timezone.utc) + timedelta(seconds=5)) is True
        # After cooldown elapses, breaker auto-recovers
        assert cb.is_open("agent-001", now=datetime.now(timezone.utc) + timedelta(seconds=35)) is False

    def test_blast_radius_isolation_blocks_dependent_agents(self):
        """
        OWASP: 'Failure propagation patterns.' If agent-001 (a delegator)
        trips its breaker, any agent it spawned/delegated to should also
        be isolated to stop the cascade.
        """
        from modules.inter_agent.circuit_breaker import AgentCircuitBreaker
        cb = AgentCircuitBreaker(failure_threshold=2)
        cb.register_dependency("sub-agent-A", parent="manager-agent")
        cb.record_failure("manager-agent")
        cb.record_failure("manager-agent")
        assert cb.is_open("manager-agent") is True
        assert cb.is_open("sub-agent-A") is True  # cascades to dependent
