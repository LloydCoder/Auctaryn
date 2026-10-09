"""Sensitive-data guard regression tests."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from core.models import ToolCall
from modules.execution_gateway.data_guard import SensitiveDataBlocked, SensitiveDataGuard
from modules.execution_gateway.execution_service import ExecutionService
from modules.execution_gateway.gateway import ExecutionGateway


def test_raw_sensitive_key_is_blocked_without_exposing_value():
    call = ToolCall(
        tool_name="http_request",
        action="send",
        parameters={"headers": {"Authorization": "Bearer example-placeholder-value-not-a-credential"}},
        agent_id="data-guard-agent",
    )

    with pytest.raises(SensitiveDataBlocked) as exc:
        SensitiveDataGuard().validate_tool_call(call)

    assert "parameters.headers.Authorization" in exc.value.paths
    assert "example-placeholder-value-not-a-credential" not in str(exc.value)


def test_secret_patterns_in_command_arguments_are_blocked():
    call = ToolCall(
        tool_name="openshell_exec",
        action="exec",
        parameters={"argv": ["curl", "--api-key=placeholder-value-not-a-credential"]},
        agent_id="data-guard-agent",
    )

    with pytest.raises(SensitiveDataBlocked):
        SensitiveDataGuard().validate_tool_call(call)


def test_target_urls_with_embedded_credentials_are_blocked():
    call = ToolCall(
        tool_name="http_request",
        action="get",
        target="https://operator:placeholder-password@example.invalid/path",
        agent_id="data-guard-agent",
    )

    with pytest.raises(SensitiveDataBlocked) as exc:
        SensitiveDataGuard().validate_tool_call(call)

    assert "target" in exc.value.paths


def test_governed_secret_reference_is_allowed_without_resolving_it():
    call = ToolCall(
        tool_name="http_request",
        action="send",
        parameters={"api_key": "vault://production/service/api-key"},
        agent_id="data-guard-agent",
    )

    SensitiveDataGuard().validate_tool_call(call)


def test_benign_parameters_are_allowed():
    call = ToolCall(
        tool_name="read_file",
        action="read",
        parameters={"path": "/workspace/README.md", "limit": 100},
        agent_id="data-guard-agent",
    )

    SensitiveDataGuard().validate_tool_call(call)


def test_execution_service_blocks_sensitive_payload_before_adapter_check():
    service = ExecutionService(ExecutionGateway())
    call = ToolCall(
        tool_name="http_request",
        action="send",
        parameters={"password": "raw-password-placeholder"},
        agent_id="data-guard-agent",
    )

    with pytest.raises(SensitiveDataBlocked):
        asyncio.run(service.execute_tool_call(call))


def test_api_returns_422_with_paths_and_no_secret_value(monkeypatch):
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")
    secret_value = "never-return-this-raw-password"
    response = TestClient(create_app()).post(
        "/api/v1/gateway/intercept",
        headers={"Authorization": "Bearer test-admin-secret"},
        json={
            "tool_name": "http_request",
            "action": "send",
            "parameters": {"password": secret_value},
            "agent_id": "data-guard-agent",
        },
    )

    assert response.status_code == 422
    body = response.json()
    assert body["detail"]["code"] == "sensitive_data_blocked"
    assert "parameters.password" in body["detail"]["paths"]
    assert secret_value not in response.text

@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/gateway/evaluate",
        "/api/v1/gateway/intercept",
        "/api/v1/gateway/intercept/full",
    ],
)
def test_classification_routes_block_secrets_before_echoing(client, path):
    secret_value = "never-return-this-classification-secret"
    response = client.post(
        path,
        json={
            "tool_name": "http_request",
            "action": "send",
            "parameters": {"password": secret_value},
            "agent_id": "data-guard-agent",
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "sensitive_data_blocked"
    assert "parameters.password" in response.json()["detail"]["paths"]
    assert secret_value not in response.text
