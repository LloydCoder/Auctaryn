"""ASI07/ASI08 regressions for inter-agent messages and cascade containment."""
from datetime import datetime, timedelta, timezone

import pytest

from modules.inter_agent.circuit_breaker import AgentCircuitBreaker
from modules.inter_agent.messaging import AgentMessage, AgentMessageBus


def _message_test_key(seed: str) -> str:
    return f"{seed}-A1b2C3d4E5f6G7h8J9k0L1m2N3p4Q5r6"


def _bus() -> AgentMessageBus:
    bus = AgentMessageBus(allow_unbound_test_mode=True)
    bus.register_agent_key("agent-A", _message_test_key("A"))
    bus.register_agent_key("agent-B", _message_test_key("B"))
    return bus


def test_sign_and_verify_message():
    bus = _bus()
    message = bus.send("agent-A", "agent-B", {"task": "summarize document"})
    assert bus.verify(message) is True
    assert bus.verify(message) is False


def test_tampered_message_fails_verification():
    bus = _bus()
    message = bus.send("agent-A", "agent-B", {"task": "summarize document"})
    message.payload["task"] = "changed after signing"
    assert bus.verify(message) is False


def test_unsigned_message_rejected_by_default():
    bus = AgentMessageBus(allow_unbound_test_mode=True)
    now = datetime.now(timezone.utc)
    forged = AgentMessage(
        message_id="f" * 32,
        sender_id="agent-X",
        recipient_id="agent-B",
        payload={"task": "unsigned"},
        signature="",
        timestamp=now,
        expires_at=now + timedelta(seconds=60),
    )
    assert bus.verify(forged) is False


def test_unregistered_sender_cannot_send_as_known_agent():
    bus = _bus()
    with pytest.raises(PermissionError):
        bus.send("agent-A", "agent-B", {"task": "x"}, signing_key="wrong-key")


def test_message_delivery_is_recipient_scoped():
    bus = _bus()
    bus.register_agent_key("agent-C", _message_test_key("C"))
    bus.send("agent-A", "agent-B", {"task": "y"})
    bus.send("agent-A", "agent-C", {"task": "z"})
    assert len(bus.get_inbox("agent-B")) == 1
    assert len(bus.get_inbox("agent-C")) == 1
    assert bus.get_inbox("agent-D") == []


def test_breaker_starts_closed_and_is_per_agent():
    breaker = AgentCircuitBreaker(failure_threshold=2)
    assert breaker.is_open("agent-001") is False
    breaker.record_failure("agent-001")
    breaker.record_failure("agent-001")
    assert breaker.is_open("agent-001") is True
    assert breaker.is_open("agent-002") is False


def test_success_resets_failure_count():
    breaker = AgentCircuitBreaker(failure_threshold=3)
    breaker.record_failure("agent-001")
    breaker.record_failure("agent-001")
    breaker.record_success("agent-001")
    breaker.record_failure("agent-001")
    assert breaker.is_open("agent-001") is False


def test_breaker_recovers_with_one_half_open_probe():
    breaker = AgentCircuitBreaker(failure_threshold=2, cooldown_seconds=30)
    breaker.record_failure("agent-001")
    breaker.record_failure("agent-001")
    assert breaker.is_open("agent-001") is True
    assert breaker.is_open("agent-001", now=datetime.now(timezone.utc) + timedelta(seconds=5)) is True
    assert breaker.is_open("agent-001", now=datetime.now(timezone.utc) + timedelta(seconds=35)) is False


def test_parent_failure_contains_dependent_agents():
    breaker = AgentCircuitBreaker(failure_threshold=2)
    breaker.register_dependency("sub-agent-A", parent_agent_id="manager-agent")
    breaker.record_failure("manager-agent")
    breaker.record_failure("manager-agent")
    assert breaker.is_open("manager-agent") is True
    assert breaker.is_open("sub-agent-A") is True
