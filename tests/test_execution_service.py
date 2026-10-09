"""Tests for the governed execution boundary and trusted runtime adapter contract."""

import asyncio
import hashlib

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from core.models import ActionDecision, GatewayDecision, RiskLevel, ToolCall, action_intent_fingerprint
from modules.execution_gateway.execution_service import ExecutionService
from modules.execution_gateway.gateway import ExecutionGateway
from modules.execution_gateway.runtime_adapter import (
    AdapterExecutionResult,
    DuplicateExecution,
    RuntimeAdapterFailure,
    RuntimeAdapterUnavailable,
)


class FakeRuntimeAdapter:
    def __init__(self):
        self.calls = []

    async def execute(self, tool_call: ToolCall, *, idempotency_key: str) -> AdapterExecutionResult:
        self.calls.append((tool_call, idempotency_key))
        return AdapterExecutionResult(
            execution_id="runtime-exec-001",
            adapter="fake-runtime",
            status="succeeded",
            exit_code=0,
            stdout="private stdout",
            stderr="",
        )


def test_execution_fails_closed_when_no_runtime_adapter_is_configured():
    gateway = ExecutionGateway()
    service = ExecutionService(gateway)

    with pytest.raises(RuntimeAdapterUnavailable):
        asyncio.run(service.execute_tool_call(
            ToolCall(tool_name="read_file", action="read", agent_id="test-agent")
        ))

    assert gateway.history == []


def test_pending_decision_never_reaches_runtime_adapter():
    adapter = FakeRuntimeAdapter()
    service = ExecutionService(ExecutionGateway(), adapter)

    decision, receipt = asyncio.run(service.execute_tool_call(
        ToolCall(
            tool_name="delete_file",
            action="delete",
            parameters={"path": "/tmp/data.db"},
            agent_id="test-agent",
        )
    ))

    assert decision.decision == ActionDecision.PENDING
    assert receipt is None
    assert adapter.calls == []


def test_approved_action_runs_only_through_adapter_and_receipt_redacts_output():
    adapter = FakeRuntimeAdapter()
    service = ExecutionService(ExecutionGateway(), adapter)

    decision, receipt = asyncio.run(service.execute_tool_call(
        ToolCall(
            tool_name="read_file",
            action="read",
            parameters={"path": "/tmp/readme.md"},
            agent_id="test-agent",
            identity_token="must-not-reach-runtime",
        )
    ))

    assert decision.decision == ActionDecision.APPROVED
    assert receipt is not None
    assert receipt.status == "succeeded"
    assert receipt.stdout_sha256 == hashlib.sha256(b"private stdout").hexdigest()
    assert "private stdout" not in receipt.model_dump_json()
    passed_call, idempotency_key = adapter.calls[0]
    assert passed_call.identity_token == ""
    assert idempotency_key == decision.id


def test_explicitly_approved_decision_is_at_most_once_per_service():
    adapter = FakeRuntimeAdapter()
    service = ExecutionService(ExecutionGateway(), adapter)
    approved_call = ToolCall(
        tool_name="delete_file", action="delete", agent_id="test-agent"
    )
    decision = GatewayDecision(
        id="operator-approved-decision",
        tool_call=approved_call,
        risk_level=RiskLevel.DESTRUCTIVE,
        decision=ActionDecision.APPROVED,
        decided_by="authenticated_operator",
        action_fingerprint=action_intent_fingerprint(approved_call),
    )

    receipt = asyncio.run(service.execute_approved_decision(decision))
    assert receipt.status == "succeeded"
    with pytest.raises(DuplicateExecution):
        asyncio.run(service.execute_approved_decision(decision))
    assert len(adapter.calls) == 1


def test_mutated_approved_decision_is_rejected_before_runtime_call():
    adapter = FakeRuntimeAdapter()
    gateway = ExecutionGateway()
    service = ExecutionService(gateway, adapter)
    decision = gateway.evaluate(
        ToolCall(
            tool_name="read_file",
            action="read",
            parameters={"path": "/safe/file.txt"},
            agent_id="test-agent",
        )
    )
    assert decision.decision == ActionDecision.APPROVED
    decision.tool_call.parameters["path"] = "/sensitive/other.txt"

    with pytest.raises(RuntimeAdapterFailure, match="intent integrity"):
        asyncio.run(service.execute_approved_decision(decision))
    assert adapter.calls == []


def test_action_intent_fingerprint_is_stable_and_changes_with_parameters():
    from core.models import action_intent_fingerprint

    original = ToolCall(
        tool_name="read_file",
        action="read",
        parameters={"path": "/safe/file.txt"},
        target="workspace",
        agent_id="agent-a",
        session_id="session-a",
    )
    same_intent = ToolCall(
        tool_name="read_file",
        action="read",
        parameters={"path": "/safe/file.txt"},
        target="workspace",
        agent_id="agent-a",
        session_id="session-a",
    )
    changed_intent = same_intent.model_copy(
        update={"parameters": {"path": "/different/file.txt"}}
    )
    assert action_intent_fingerprint(original) == action_intent_fingerprint(same_intent)
    assert action_intent_fingerprint(original) != action_intent_fingerprint(changed_intent)


def test_action_fingerprint_is_not_exposed_in_decision_serialization():
    gateway = ExecutionGateway()
    decision = gateway.evaluate(
        ToolCall(tool_name="read_file", action="read", agent_id="test-agent")
    )
    assert decision.action_fingerprint
    assert "action_fingerprint" not in decision.model_dump()
    assert "action_fingerprint" not in decision.model_dump_json()


def test_non_approved_decision_cannot_be_executed():
    adapter = FakeRuntimeAdapter()
    service = ExecutionService(ExecutionGateway(), adapter)
    decision = GatewayDecision(
        id="pending-decision",
        tool_call=ToolCall(tool_name="delete_file", action="delete"),
        risk_level=RiskLevel.DESTRUCTIVE,
        decision=ActionDecision.PENDING,
    )

    with pytest.raises(RuntimeAdapterFailure):
        asyncio.run(service.execute_approved_decision(decision))
    assert adapter.calls == []


def test_api_execute_endpoint_returns_503_without_trusted_adapter(monkeypatch):
    monkeypatch.setenv("AUCTARYN_ALLOW_DIRECT_EXECUTION", "true")
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/gateway/execute",
        headers={"Authorization": "Bearer test-admin-secret"},
        json={
            "tool_name": "read_file",
            "action": "read",
            "parameters": {"path": "/tmp/readme.md"},
            "agent_id": "test-agent",
        },
    )

    assert response.status_code == 503
    assert "No trusted runtime adapter" in response.json()["detail"]

def test_api_rejects_execution_of_auto_approved_decision_as_if_operator_approved(monkeypatch):
    from api.routes.gateway import configure_runtime_adapter, get_gateway

    monkeypatch.setenv("AUCTARYN_ALLOW_DIRECT_EXECUTION", "true")
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")
    gateway = get_gateway()
    decision = GatewayDecision(
        id="auto-approved-not-operator-approved",
        tool_call=ToolCall(
            tool_name="read_file",
            action="read",
            parameters={"path": "/tmp/readme.md"},
            agent_id="test-agent",
        ),
        risk_level=RiskLevel.SAFE,
        decision=ActionDecision.APPROVED,
        decided_by="veto_engine",
    )
    gateway.history.append(decision)
    configure_runtime_adapter(FakeRuntimeAdapter())
    try:
        response = TestClient(create_app()).post(
            f"/api/v1/gateway/execute/approved/{decision.id}",
            headers={"Authorization": "Bearer test-admin-secret"},
        )
    finally:
        configure_runtime_adapter(None)

    assert response.status_code == 409
    assert "explicitly approved by an operator" in response.json()["detail"]


def test_context_integrity_is_rechecked_at_runtime_execution_boundary():
    adapter = FakeRuntimeAdapter()
    calls = {"count": 0}

    def context_guard(_tool_call):
        calls["count"] += 1
        if calls["count"] == 1:
            return None
        return "Context became compromised before runtime execution."

    gateway = ExecutionGateway(context_integrity_guard=context_guard)
    service = ExecutionService(gateway, adapter)

    with pytest.raises(RuntimeAdapterFailure, match="Context became compromised"):
        asyncio.run(service.execute_tool_call(
            ToolCall(
                tool_name="read_file",
                action="read",
                parameters={"path": "/safe/file.txt"},
                agent_id="test-agent",
                session_id="session-a",
                context_check_id="context-check-a",
            )
        ))

    assert calls["count"] == 2
    assert adapter.calls == []


def test_execution_service_fails_closed_when_deduplication_capacity_is_reached(monkeypatch):
    import modules.execution_gateway.execution_service as service_module

    monkeypatch.setattr(service_module, "MAX_CLAIMED_DECISIONS", 1)
    adapter = FakeRuntimeAdapter()
    service = ExecutionService(ExecutionGateway(), adapter)
    first_call = ToolCall(tool_name="read_file", action="read", agent_id="dedup-agent")
    first_decision, first_receipt = asyncio.run(service.execute_tool_call(first_call))
    assert first_decision.decision == ActionDecision.APPROVED
    assert first_receipt is not None

    second_call = ToolCall(tool_name="read_file", action="read", agent_id="dedup-agent")
    second_decision = GatewayDecision(
        id="another-approved-decision",
        tool_call=second_call,
        risk_level=RiskLevel.SAFE,
        decision=ActionDecision.APPROVED,
        decided_by="policy",
        action_fingerprint=action_intent_fingerprint(second_call),
    )
    with pytest.raises(RuntimeAdapterFailure, match="deduplication capacity reached"):
        asyncio.run(service.execute_approved_decision(second_decision))
    assert len(adapter.calls) == 1
