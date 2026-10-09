"""Approval lifecycle regression tests: expiry, replay resistance, and identifiers."""

from datetime import datetime, timedelta, timezone

import pytest

from core.models import ActionDecision, ToolCall
from modules.execution_gateway.gateway import ExecutionGateway


def _pending_gateway(ttl_seconds: int = 900):
    gateway = ExecutionGateway(pending_ttl_seconds=ttl_seconds)
    decision = gateway.evaluate(
        ToolCall(
            tool_name="delete_file",
            action="delete",
            parameters={"path": "/tmp/important.db"},
            agent_id="approval-test-agent",
        )
    )
    assert decision.decision == ActionDecision.PENDING
    return gateway, decision


def test_expired_approval_is_removed_and_marked_timeout():
    gateway, decision = _pending_gateway(ttl_seconds=60)
    decision.timestamp = datetime.now(timezone.utc) - timedelta(seconds=61)

    assert gateway.get_pending() == []
    assert gateway.history[0].decision == ActionDecision.TIMEOUT
    assert gateway.history[0].decided_by == "approval_timeout"


def test_expired_approval_cannot_be_approved():
    gateway, decision = _pending_gateway(ttl_seconds=60)
    decision.timestamp = datetime.now(timezone.utc) - timedelta(seconds=61)

    with pytest.raises(KeyError):
        gateway.resolve_pending(decision.id, approved=True, operator="test-operator")

    assert gateway.history[0].decision == ActionDecision.TIMEOUT


def test_pending_approval_is_one_time_use():
    gateway, decision = _pending_gateway()
    resolved = gateway.resolve_pending(decision.id, approved=True, operator="test-operator")

    assert resolved.decision == ActionDecision.APPROVED
    with pytest.raises(KeyError):
        gateway.resolve_pending(decision.id, approved=True, operator="test-operator")


def test_decision_ids_have_sufficient_entropy_for_references():
    gateway, decision = _pending_gateway()
    assert len(decision.id) == 32


def test_pending_approval_ttl_must_be_positive():
    with pytest.raises(ValueError, match="pending_ttl_seconds must be positive"):
        ExecutionGateway(pending_ttl_seconds=0)
