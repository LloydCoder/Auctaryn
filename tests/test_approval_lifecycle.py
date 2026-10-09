"""Approval lifecycle regression tests: expiry, replay resistance, and identifiers."""

from datetime import datetime, timedelta, timezone

import pytest

from core.models import ActionDecision, ToolCall
from modules.execution_gateway.gateway import ExecutionGateway, ApprovalIntentIntegrityError


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
    original_fingerprint = decision.action_fingerprint
    resolved = gateway.resolve_pending(decision.id, approved=True, operator="test-operator")

    assert resolved.decision == ActionDecision.APPROVED
    assert resolved.action_fingerprint == original_fingerprint
    with pytest.raises(KeyError):
        gateway.resolve_pending(decision.id, approved=True, operator="test-operator")


def test_decision_ids_have_sufficient_entropy_for_references():
    gateway, decision = _pending_gateway()
    assert len(decision.id) == 32


def test_pending_approval_ttl_must_be_positive():
    with pytest.raises(ValueError, match="pending_ttl_seconds must be positive"):
        ExecutionGateway(pending_ttl_seconds=0)

def test_gateway_status_does_not_report_expired_approvals_as_pending():
    gateway, decision = _pending_gateway(ttl_seconds=60)
    decision.timestamp = datetime.now(timezone.utc) - timedelta(seconds=61)

    status = gateway.get_status()

    assert status["pending_approvals"] == 0
    assert gateway.history[0].decision == ActionDecision.TIMEOUT



def test_pending_action_mutation_is_denied_and_cannot_be_approved():
    gateway, decision = _pending_gateway()
    decision.tool_call.parameters["path"] = "/tmp/attacker-selected.db"

    with pytest.raises(ApprovalIntentIntegrityError, match="intent changed"):
        gateway.resolve_pending(decision.id, approved=True, operator="test-operator")

    assert gateway.get_pending() == []
    assert gateway.history[0].decision == ActionDecision.DENIED
    assert gateway.history[0].decided_by == "intent_integrity_guard"
