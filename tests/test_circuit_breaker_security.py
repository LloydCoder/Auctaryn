"""Adversarial tests for dependency-aware circuit-breaker containment."""
from datetime import datetime, timedelta, timezone

import pytest

from modules.inter_agent.circuit_breaker import AgentCircuitBreaker


def test_tripped_parent_contains_children_but_not_unrelated_agents():
    breaker = AgentCircuitBreaker(failure_threshold=2, cooldown_seconds=60)
    breaker.register_dependency("child-a", "parent")
    breaker.record_failure("parent")
    breaker.record_failure("parent")
    assert breaker.is_open("parent") is True
    assert breaker.is_open("child-a") is True
    assert breaker.is_open("unrelated") is False


def test_dependency_cycles_and_self_edges_are_rejected():
    breaker = AgentCircuitBreaker()
    breaker.register_dependency("child", "parent")
    breaker.register_dependency("grandchild", "child")
    with pytest.raises(ValueError, match="cycle"):
        breaker.register_dependency("parent", "grandchild")
    with pytest.raises(ValueError, match="itself"):
        breaker.register_dependency("self", "self")


def test_parent_remains_effective_after_child_cooldown_elapses():
    breaker = AgentCircuitBreaker(failure_threshold=1, cooldown_seconds=5)
    breaker.register_dependency("child", "parent")
    breaker.record_failure("parent")
    breaker.record_failure("child")
    now = datetime.now(timezone.utc)
    breaker._states["child"].tripped_at = now - timedelta(seconds=10)
    breaker._states["parent"].tripped_at = now
    assert breaker.is_open("child", now=now + timedelta(seconds=1)) is True


def test_invalid_clock_fails_closed():
    breaker = AgentCircuitBreaker()
    assert breaker.is_open("agent", now=datetime.now()) is True


def test_configuration_bounds_are_enforced():
    with pytest.raises(ValueError):
        AgentCircuitBreaker(failure_threshold=0)
    with pytest.raises(ValueError):
        AgentCircuitBreaker(cooldown_seconds=0)


def test_corrupt_dependency_cycle_fails_closed():
    breaker = AgentCircuitBreaker()
    breaker._dependencies["agent-a"] = "agent-b"
    breaker._dependencies["agent-b"] = "agent-a"
    assert breaker.is_open("agent-a") is True



def test_half_open_allows_one_probe_and_failure_retrips():
    breaker = AgentCircuitBreaker(failure_threshold=1, cooldown_seconds=5)
    breaker.record_failure("probe-agent")
    now = datetime.now(timezone.utc)
    breaker._states["probe-agent"].tripped_at = now - timedelta(seconds=10)
    assert breaker.is_open("probe-agent", now=now) is False
    assert breaker.is_open("probe-agent", now=now + timedelta(seconds=1)) is True
    breaker.record_failure("probe-agent")
    assert breaker.is_open("probe-agent") is True
    next_probe = breaker._states["probe-agent"].tripped_at + timedelta(seconds=6)
    assert breaker.is_open("probe-agent", now=next_probe) is False
    breaker.record_success("probe-agent")
    assert breaker.is_open("probe-agent") is False


def test_descendants_stay_blocked_until_parent_probe_succeeds():
    breaker = AgentCircuitBreaker(failure_threshold=1, cooldown_seconds=5)
    breaker.register_dependency("child-agent", "parent-agent")
    breaker.record_failure("parent-agent")
    now = datetime.now(timezone.utc)
    breaker._states["parent-agent"].tripped_at = now - timedelta(seconds=10)

    # A child request must not accidentally become the parent's recovery probe.
    assert breaker.is_open("child-agent", now=now) is True
    assert breaker.is_open("parent-agent", now=now) is False
    assert breaker.is_open("child-agent", now=now + timedelta(seconds=1)) is True

    breaker.record_success("parent-agent")
    assert breaker.is_open("child-agent", now=now + timedelta(seconds=2)) is False
