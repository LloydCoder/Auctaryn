"""Tests for the NVIDIA OpenShell adapter without requiring a live gateway."""

import asyncio
import base64
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.models import ToolCall
from modules.execution_gateway.openshell_adapter import BOUNDED_EXEC_WRAPPER, OpenShellRuntimeAdapter, create_openshell_adapter_from_environment
from modules.execution_gateway.runtime_adapter import DuplicateExecution, RuntimeAdapterFailure, RuntimeAdapterUnavailable


def _envelope(exit_code=0, stdout="sandbox output", stderr="", stdout_truncated=False, stderr_truncated=False):
    return json.dumps({
        "exit_code": exit_code,
        "stdout": base64.b64encode(stdout.encode("utf-8")).decode("ascii"),
        "stderr": base64.b64encode(stderr.encode("utf-8")).decode("ascii"),
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    })


class FakeOpenShellClient:
    def __init__(self, exit_code=0, stdout="sandbox output", stderr="", stdout_truncated=False, stderr_truncated=False, sdk_exit_code=0):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.stdout_truncated = stdout_truncated
        self.stderr_truncated = stderr_truncated
        self.sdk_exit_code = sdk_exit_code
        self.calls = []

    def health(self):
        return SimpleNamespace(version="0.1.0")

    def exec(self, sandbox_name, argv, *, workspace):
        self.calls.append((sandbox_name, argv, workspace))
        return SimpleNamespace(
            exit_code=self.sdk_exit_code,
            stdout=_envelope(
                self.exit_code, self.stdout, self.stderr,
                self.stdout_truncated, self.stderr_truncated,
            ),
            stderr="",
        )


_DEFAULT_ARGV = object()


def _tool_call(argv=_DEFAULT_ARGV, tool_name="openshell_exec", action="exec"):
    selected_argv = ["python", "-c", "print('ok')"] if argv is _DEFAULT_ARGV else argv
    return ToolCall(
        tool_name=tool_name,
        action=action,
        parameters={"argv": selected_argv},
        agent_id="openshell-test-agent",
    )


def test_adapter_live_health_probe_reports_runtime_identity():
    adapter = OpenShellRuntimeAdapter(FakeOpenShellClient(), sandbox_name="s", workspace="w")
    assert adapter.runtime_name == "openshell"
    assert asyncio.run(adapter.health_check()) is True


def test_adapter_live_health_probe_fails_closed_when_version_missing():
    class ClientWithoutVersion(FakeOpenShellClient):
        def health(self):
            return SimpleNamespace(version="")

    adapter = OpenShellRuntimeAdapter(ClientWithoutVersion(), sandbox_name="s", workspace="w")
    assert asyncio.run(adapter.health_check()) is False


def test_adapter_live_health_probe_fails_closed_on_timeout(monkeypatch):
    import modules.execution_gateway.openshell_adapter as adapter_module

    async def timeout_probe(awaitable, *, timeout):
        awaitable.close()
        assert timeout == 5.0
        raise TimeoutError("probe timed out")

    monkeypatch.setattr(adapter_module.asyncio, "wait_for", timeout_probe)
    adapter = OpenShellRuntimeAdapter(FakeOpenShellClient(), sandbox_name="s", workspace="w")
    assert asyncio.run(adapter.health_check()) is False


def test_adapter_live_health_probe_fails_closed_on_gateway_error():
    class UnavailableClient(FakeOpenShellClient):
        def health(self):
            raise RuntimeError("gateway unavailable")

    adapter = OpenShellRuntimeAdapter(UnavailableClient(), sandbox_name="s", workspace="w")
    assert asyncio.run(adapter.health_check()) is False


def test_adapter_uses_server_configured_sandbox_and_argv_array():
    client = FakeOpenShellClient()
    adapter = OpenShellRuntimeAdapter(
        client, sandbox_name="approved-sandbox", workspace="prod", timeout_seconds=45
    )

    result = asyncio.run(adapter.execute(_tool_call(), idempotency_key="decision-001"))

    sandbox_name, argv, workspace = client.calls[0]
    assert sandbox_name == "approved-sandbox"
    assert workspace == "prod"
    assert argv[:2] == ["python", "-c"]
    assert json.loads(argv[3]) == ["python", "-c", "print('ok')"]
    assert argv[4] == "45"
    assert argv[5] == "1000000"
    assert result.status == "succeeded"
    assert result.adapter == "nvidia-openshell"


def test_adapter_rejects_invalid_sandbox_identifier():
    with pytest.raises(ValueError, match="unsupported characters"):
        OpenShellRuntimeAdapter(FakeOpenShellClient(), sandbox_name="--help", workspace="default")


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
        FakeOpenShellClient(stdout="x" * 1_000_000, stdout_truncated=True), sandbox_name="s", workspace="w"
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

def test_enabled_adapter_rejects_invalid_sandbox_name_before_connecting(monkeypatch):
    monkeypatch.setenv("AUCTARYN_RUNTIME_ADAPTER", "openshell")
    monkeypatch.setenv("OPENSHELL_SANDBOX_NAME", "--help")

    with pytest.raises(RuntimeAdapterUnavailable, match="must use only letters"):
        create_openshell_adapter_from_environment()


def test_enabled_adapter_rejects_invalid_timeout_before_connecting(monkeypatch):
    monkeypatch.setenv("AUCTARYN_RUNTIME_ADAPTER", "openshell")
    monkeypatch.setenv("OPENSHELL_SANDBOX_NAME", "sandbox")
    monkeypatch.setenv("OPENSHELL_EXECUTION_TIMEOUT_SECONDS", "0")

    with pytest.raises(RuntimeAdapterUnavailable, match="between 1 and 3600"):
        create_openshell_adapter_from_environment()

def test_enabled_adapter_requires_service_credentials_or_explicit_local_override(monkeypatch):
    monkeypatch.setenv("AUCTARYN_RUNTIME_ADAPTER", "openshell")
    monkeypatch.setenv("OPENSHELL_SANDBOX_NAME", "sandbox")
    monkeypatch.setenv("OPENSHELL_WORKSPACE", "default")
    monkeypatch.delenv("OPENSHELL_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("OPENSHELL_OIDC_CLIENT_ID", raising=False)
    monkeypatch.delenv("OPENSHELL_OIDC_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("OPENSHELL_OIDC_AUDIENCE", raising=False)
    monkeypatch.delenv("OPENSHELL_ALLOW_USER_CREDENTIALS", raising=False)

    with pytest.raises(RuntimeAdapterUnavailable, match="Configure OpenShell OIDC service credentials"):
        create_openshell_adapter_from_environment()


def test_enabled_adapter_rejects_partial_oidc_credentials(monkeypatch):
    monkeypatch.setenv("AUCTARYN_RUNTIME_ADAPTER", "openshell")
    monkeypatch.setenv("OPENSHELL_SANDBOX_NAME", "sandbox")
    monkeypatch.setenv("OPENSHELL_OIDC_CLIENT_ID", "service-client")
    monkeypatch.delenv("OPENSHELL_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("OPENSHELL_OIDC_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("OPENSHELL_OIDC_AUDIENCE", raising=False)

    with pytest.raises(RuntimeAdapterUnavailable, match="required together"):
        create_openshell_adapter_from_environment()

def test_enabled_adapter_fails_closed_when_baseline_policy_is_invalid(monkeypatch):
    import modules.execution_gateway.openshell_adapter as adapter_module
    from modules.execution_gateway.policy_validation import PolicyValidationError

    monkeypatch.setenv("AUCTARYN_RUNTIME_ADAPTER", "openshell")
    monkeypatch.setenv("OPENSHELL_SANDBOX_NAME", "sandbox")
    monkeypatch.setenv("OPENSHELL_WORKSPACE", "default")
    monkeypatch.setenv("OPENSHELL_ALLOW_USER_CREDENTIALS", "true")

    def invalid_baseline(_path):
        raise PolicyValidationError("unsafe baseline")

    monkeypatch.setattr(adapter_module, "load_and_validate_baseline", invalid_baseline)
    with pytest.raises(RuntimeAdapterUnavailable, match="baseline policy"):
        create_openshell_adapter_from_environment()


def test_enabled_adapter_validates_baseline_and_retains_source_digest(monkeypatch):
    import sys
    import types
    import modules.execution_gateway.openshell_adapter as adapter_module

    class FakeCredentials:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeClientContext:
        def __enter__(self):
            return FakeOpenShellClient()

        def __exit__(self, exc_type, exc, traceback):
            return False

    class FakeSandboxClient:
        @staticmethod
        def from_active_cluster(*, client_credentials):
            assert isinstance(client_credentials, FakeCredentials)
            return FakeClientContext()

    fake_sdk = types.ModuleType("openshell")
    fake_sdk.ClientCredentialsAuth = FakeCredentials
    fake_sdk.SandboxClient = FakeSandboxClient
    monkeypatch.setitem(sys.modules, "openshell", fake_sdk)

    monkeypatch.setenv("AUCTARYN_RUNTIME_ADAPTER", "openshell")
    monkeypatch.setenv("OPENSHELL_SANDBOX_NAME", "sandbox")
    monkeypatch.setenv("OPENSHELL_WORKSPACE", "default")
    monkeypatch.setenv("OPENSHELL_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("OPENSHELL_OIDC_CLIENT_ID", "service-client")
    monkeypatch.setenv("OPENSHELL_OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("OPENSHELL_OIDC_AUDIENCE", "openshell-api")

    adapter = adapter_module.create_openshell_adapter_from_environment()
    assert adapter is not None
    assert len(adapter.baseline_policy_sha256) == 64
    adapter.close()


def test_bounded_exec_wrapper_runs_argv_without_shell():
    child_argv = [sys.executable, "-c", "print('bounded-ok')"]
    completed = subprocess.run(
        [sys.executable, "-c", BOUNDED_EXEC_WRAPPER, json.dumps(child_argv), "3", "1000"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    envelope = json.loads(completed.stdout)
    output = base64.b64decode(envelope["stdout"]).decode("utf-8")

    assert envelope["exit_code"] == 0
    assert output.strip() == "bounded-ok"
    assert envelope["stdout_truncated"] is False


def test_bounded_exec_wrapper_caps_output_and_kills_timed_out_process():
    child_argv = [
        sys.executable,
        "-c",
        "import time; print('x' * 10000, flush=True); time.sleep(5)",
    ]
    completed = subprocess.run(
        [sys.executable, "-c", BOUNDED_EXEC_WRAPPER, json.dumps(child_argv), "1", "100"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    envelope = json.loads(completed.stdout)
    output = base64.b64decode(envelope["stdout"])

    assert envelope["exit_code"] == 124
    assert len(output) <= 100
    assert envelope["stdout_truncated"] is True


def test_adapter_fails_closed_when_idempotency_capacity_is_reached(monkeypatch):
    import modules.execution_gateway.openshell_adapter as adapter_module

    monkeypatch.setattr(adapter_module, "MAX_SEEN_IDEMPOTENCY_KEYS", 1)
    client = FakeOpenShellClient()
    adapter = OpenShellRuntimeAdapter(client, sandbox_name="s", workspace="w")
    asyncio.run(adapter.execute(_tool_call(), idempotency_key="capacity-1"))

    with pytest.raises(RuntimeAdapterUnavailable, match="idempotency capacity reached"):
        asyncio.run(adapter.execute(_tool_call(), idempotency_key="capacity-2"))

    assert len(client.calls) == 1
