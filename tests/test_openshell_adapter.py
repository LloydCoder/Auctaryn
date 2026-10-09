"""Tests for the NVIDIA OpenShell adapter without requiring a live gateway."""

import asyncio
from types import SimpleNamespace

import pytest

from core.models import ToolCall
from modules.execution_gateway.openshell_adapter import OpenShellRuntimeAdapter, create_openshell_adapter_from_environment
from modules.execution_gateway.runtime_adapter import DuplicateExecution, RuntimeAdapterFailure, RuntimeAdapterUnavailable


class FakeOpenShellClient:
    def __init__(self, exit_code=0, stdout="sandbox output", stderr=""):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.calls = []

    def exec(self, sandbox_name, argv, *, workspace):
        self.calls.append((sandbox_name, argv, workspace))
        return SimpleNamespace(exit_code=self.exit_code, stdout=self.stdout, stderr=self.stderr)


def _tool_call(argv=None, tool_name="openshell_exec", action="exec"):
    return ToolCall(
        tool_name=tool_name,
        action=action,
        parameters={"argv": argv or ["python", "-c", "print('ok')"]},
        agent_id="openshell-test-agent",
    )


def test_adapter_uses_server_configured_sandbox_and_argv_array():
    client = FakeOpenShellClient()
    adapter = OpenShellRuntimeAdapter(
        client, sandbox_name="approved-sandbox", workspace="prod", timeout_seconds=45
    )

    result = asyncio.run(adapter.execute(_tool_call(), idempotency_key="decision-001"))

    sandbox_name, argv, workspace = client.calls[0]
    assert sandbox_name == "approved-sandbox"
    assert workspace == "prod"
    assert argv == ["timeout", "45s", "python", "-c", "print('ok')"]
    assert result.status == "succeeded"
    assert result.adapter == "nvidia-openshell"


def test_adapter_rejects_unknown_tool_or_action():
    adapter = OpenShellRuntimeAdapter(FakeOpenShellClient(), sandbox_name="s", workspace="w")

    with pytest.raises(RuntimeAdapterFailure):
        asyncio.run(adapter.execute(
            _tool_call(tool_name="shell", action="exec"), idempotency_key="decision-002"
        ))


@pytest.mark.parametrize("argv", [None, [], ["python", ""], ["python", 4], ["x" * 9000], ["x"] * 129])
def test_adapter_rejects_malformed_or_unbounded_argv(argv):
    adapter = OpenShellRuntimeAdapter(FakeOpenShellClient(), sandbox_name="s", workspace="w")

    with pytest.raises(RuntimeAdapterFailure):
        asyncio.run(adapter.execute(_tool_call(argv=argv), idempotency_key="decision-003"))


def test_adapter_rejects_duplicate_idempotency_key():
    client = FakeOpenShellClient()
    adapter = OpenShellRuntimeAdapter(client, sandbox_name="s", workspace="w")
    asyncio.run(adapter.execute(_tool_call(), idempotency_key="decision-004"))

    with pytest.raises(DuplicateExecution):
        asyncio.run(adapter.execute(_tool_call(), idempotency_key="decision-004"))

    assert len(client.calls) == 1


def test_adapter_marks_timeout_exit_code():
    adapter = OpenShellRuntimeAdapter(
        FakeOpenShellClient(exit_code=124), sandbox_name="s", workspace="w"
    )

    result = asyncio.run(adapter.execute(_tool_call(), idempotency_key="decision-005"))

    assert result.status == "timed_out"
    assert result.exit_code == 124


def test_adapter_bounds_output_and_marks_truncation():
    adapter = OpenShellRuntimeAdapter(
        FakeOpenShellClient(stdout="x" * 1_000_001), sandbox_name="s", workspace="w"
    )

    result = asyncio.run(adapter.execute(_tool_call(), idempotency_key="decision-006"))

    assert len(result.stdout) == 1_000_000
    assert result.stdout_truncated is True


def test_openshell_adapter_is_disabled_unless_explicitly_enabled(monkeypatch):
    monkeypatch.delenv("AUCTARYN_RUNTIME_ADAPTER", raising=False)
    assert create_openshell_adapter_from_environment() is None


def test_enabled_adapter_requires_sandbox_name(monkeypatch):
    monkeypatch.setenv("AUCTARYN_RUNTIME_ADAPTER", "openshell")
    monkeypatch.delenv("OPENSHELL_SANDBOX_NAME", raising=False)

    with pytest.raises(RuntimeAdapterUnavailable, match="OPENSHELL_SANDBOX_NAME is required"):
        create_openshell_adapter_from_environment()
