"""NVIDIA OpenShell runtime adapter.

Only the server-configured sandbox is addressable. Calls use an argv array,
never shell=True or a caller-supplied sandbox name. OpenShell's sandbox policy
remains the execution security boundary; Auctaryn decisions are an additional
gate, not a replacement for OpenShell isolation.
"""
import asyncio
import base64
import json
import os
import re
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from core.models import ToolCall
from modules.execution_gateway.policy_validation import (
    PolicyValidationError,
    default_baseline_path,
    load_and_validate_baseline,
)
from modules.execution_gateway.runtime_adapter import (
    AdapterExecutionResult,
    DuplicateExecution,
    RuntimeAdapterFailure,
    RuntimeAdapterUnavailable,
)

MAX_ARGV_COUNT = 128
MAX_ARG_LENGTH = 8192
MAX_TOTAL_ARG_LENGTH = 32768
MAX_OUTPUT_CHARS = 1_000_000

# Output is bounded while being read inside the sandbox, not only after the SDK
# has already buffered a child process's output. argv is JSON and shell=False.
BOUNDED_EXEC_WRAPPER = r"""
import base64, json, os, signal, subprocess, sys, threading
argv = json.loads(sys.argv[1])
timeout = int(sys.argv[2])
cap = int(sys.argv[3])
buffers = {"stdout": bytearray(), "stderr": bytearray()}
truncated = {"stdout": False, "stderr": False}

def drain(stream, key):
    while True:
        chunk = stream.read(8192)
        if not chunk:
            return
        remaining = cap - len(buffers[key])
        if remaining > 0:
            buffers[key].extend(chunk[:remaining])
        if len(chunk) > max(remaining, 0):
            truncated[key] = True

try:
    process = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    )
except OSError as exc:
    message = str(exc).encode("utf-8")
    data = {
        "exit_code": 127,
        "stdout": "",
        "stderr": base64.b64encode(message[:cap]).decode("ascii"),
        "stdout_truncated": False,
        "stderr_truncated": len(message) > cap,
    }
else:
    threads = [
        threading.Thread(target=drain, args=(process.stdout, "stdout"), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, "stderr"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        exit_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        exit_code = 124
    for thread in threads:
        thread.join()
    data = {
        "exit_code": exit_code,
        "stdout": base64.b64encode(bytes(buffers["stdout"])).decode("ascii"),
        "stderr": base64.b64encode(bytes(buffers["stderr"])).decode("ascii"),
        "stdout_truncated": truncated["stdout"],
        "stderr_truncated": truncated["stderr"],
    }
print(json.dumps(data, separators=(",", ":")))
"""


class OpenShellRuntimeAdapter:
    """Execute a narrowly defined argv-based tool inside one configured sandbox."""

    def __init__(
        self,
        client: Any,
        *,
        sandbox_name: str,
        workspace: str,
        timeout_seconds: int = 60,
        close_callback: Callable[[], None] | None = None,
        baseline_policy_sha256: str | None = None,
    ):
        if not isinstance(sandbox_name, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", sandbox_name
        ):
            raise ValueError("sandbox_name contains unsupported characters")
        if not isinstance(workspace, str) or not workspace.strip() or len(workspace) > 128:
            raise ValueError("workspace must be non-empty and at most 128 characters")
        if not 1 <= timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be between 1 and 3600")
        self.client = client
        self.sandbox_name = sandbox_name
        self.workspace = workspace
        self.timeout_seconds = timeout_seconds
        self.close_callback = close_callback
        self.baseline_policy_sha256 = baseline_policy_sha256
        self._seen_idempotency_keys: set[str] = set()

    @property
    def runtime_name(self) -> str:
        """Stable runtime identifier consumed by the readiness endpoint."""
        return "openshell"

    async def health_check(self) -> bool:
        """Probe the active OpenShell gateway without blocking the API event loop.

        A configured adapter is not considered ready solely because it was
        constructed. Readiness requires a bounded live health request with a
        non-empty gateway version in the response.
        """
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(self.client.health),
                timeout=5.0,
            )
        except Exception:
            return False

        version = getattr(response, "version", None)
        return isinstance(version, str) and bool(version.strip())

    @staticmethod
    def _validate_argv(tool_call: ToolCall) -> list[str]:
        if tool_call.tool_name != "openshell_exec" or tool_call.action != "exec":
            raise RuntimeAdapterFailure(
                "OpenShell adapter supports only tool_name='openshell_exec', action='exec'."
            )
        argv = tool_call.parameters.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or len(argv) > MAX_ARGV_COUNT
            or any(not isinstance(arg, str) or not arg or len(arg) > MAX_ARG_LENGTH for arg in argv)
            or sum(len(arg) for arg in argv) > MAX_TOTAL_ARG_LENGTH
        ):
            raise RuntimeAdapterFailure(
                "parameters.argv must be a bounded, non-empty list of non-empty strings."
            )
        return list(argv)

    async def execute(
        self, tool_call: ToolCall, *, idempotency_key: str
    ) -> AdapterExecutionResult:
        if not idempotency_key or len(idempotency_key) > 128:
            raise RuntimeAdapterFailure("A bounded idempotency key is required.")
        if idempotency_key in self._seen_idempotency_keys:
            raise DuplicateExecution("OpenShell execution key has already been submitted.")

        argv = self._validate_argv(tool_call)
        self._seen_idempotency_keys.add(idempotency_key)

        # The wrapper enforces timeout and output caps inside the sandbox.
        # Host-side thread cancellation is avoided because it would not prove
        # that the sandboxed process stopped.
        bounded_argv = [
            "python",
            "-c",
            BOUNDED_EXEC_WRAPPER,
            json.dumps(argv, separators=(",", ":")),
            str(self.timeout_seconds),
            str(MAX_OUTPUT_CHARS),
        ]
        try:
            result = await asyncio.to_thread(
                self.client.exec,
                self.sandbox_name,
                bounded_argv,
                workspace=self.workspace,
            )
        except Exception as exc:
            raise RuntimeAdapterFailure(
                "OpenShell execution request failed; completion state may be unknown."
            ) from exc

        wrapper_stdout = getattr(result, "stdout", "")
        wrapper_exit_code = getattr(result, "exit_code", None)
        if not isinstance(wrapper_stdout, str) or wrapper_exit_code != 0:
            raise RuntimeAdapterFailure(
                "OpenShell did not return a valid bounded-execution envelope."
            )
        try:
            envelope = json.loads(wrapper_stdout)
            exit_code = envelope["exit_code"]
            if not isinstance(exit_code, int) or isinstance(exit_code, bool):
                raise ValueError("invalid child exit code")
            stdout = base64.b64decode(envelope["stdout"], validate=True).decode("utf-8", errors="replace")
            stderr = base64.b64decode(envelope["stderr"], validate=True).decode("utf-8", errors="replace")
            stdout_truncated = envelope["stdout_truncated"]
            stderr_truncated = envelope["stderr_truncated"]
            if not isinstance(stdout_truncated, bool) or not isinstance(stderr_truncated, bool):
                raise ValueError("invalid truncation flags")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeAdapterFailure(
                "OpenShell returned a malformed bounded-execution envelope."
            ) from exc

        status = "timed_out" if exit_code == 124 else ("succeeded" if exit_code == 0 else "failed")
        return AdapterExecutionResult(
            execution_id=uuid.uuid4().hex,
            adapter="nvidia-openshell",
            status=status,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            finished_at=datetime.now(timezone.utc),
        )

    def close(self) -> None:
        if self.close_callback is not None:
            self.close_callback()
            self.close_callback = None


def create_openshell_adapter_from_environment() -> OpenShellRuntimeAdapter | None:
    """Create the adapter only when explicitly enabled and configured."""
    if os.getenv("AUCTARYN_RUNTIME_ADAPTER", "").strip().lower() != "openshell":
        return None

    sandbox_name = os.getenv("OPENSHELL_SANDBOX_NAME", "").strip()
    workspace = os.getenv("OPENSHELL_WORKSPACE", "default").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", sandbox_name):
        raise RuntimeAdapterUnavailable(
            "OPENSHELL_SANDBOX_NAME is required and must use only letters, digits, dot, underscore or hyphen."
        )
    try:
        timeout_seconds = int(os.getenv("OPENSHELL_EXECUTION_TIMEOUT_SECONDS", "60"))
    except ValueError as exc:
        raise RuntimeAdapterUnavailable(
            "OPENSHELL_EXECUTION_TIMEOUT_SECONDS must be an integer."
        ) from exc
    if not 1 <= timeout_seconds <= 3600:
        raise RuntimeAdapterUnavailable(
            "OPENSHELL_EXECUTION_TIMEOUT_SECONDS must be between 1 and 3600."
        )
    if not workspace:
        raise RuntimeAdapterUnavailable("OPENSHELL_WORKSPACE must be non-empty.")

    oidc_keys = (
        "OPENSHELL_OIDC_ISSUER",
        "OPENSHELL_OIDC_CLIENT_ID",
        "OPENSHELL_OIDC_CLIENT_SECRET",
        "OPENSHELL_OIDC_AUDIENCE",
    )
    configured_oidc = [bool(os.getenv(key, "").strip()) for key in oidc_keys]
    if any(configured_oidc) and not all(configured_oidc):
        raise RuntimeAdapterUnavailable(
            "All OpenShell OIDC service credential settings are required together."
        )
    use_user_credentials = os.getenv("OPENSHELL_ALLOW_USER_CREDENTIALS", "").lower() == "true"
    if not all(configured_oidc) and not use_user_credentials:
        raise RuntimeAdapterUnavailable(
            "Configure OpenShell OIDC service credentials; user credentials require "
            "OPENSHELL_ALLOW_USER_CREDENTIALS=true and are intended only for local development."
        )

    try:
        _, baseline_policy_sha256 = load_and_validate_baseline(default_baseline_path())
    except (OSError, PolicyValidationError) as exc:
        raise RuntimeAdapterUnavailable(
            "The checked-in OpenShell baseline policy is missing or failed security validation."
        ) from exc

    client_context = None
    try:
        from openshell import ClientCredentialsAuth, SandboxClient

        if all(configured_oidc):
            auth = ClientCredentialsAuth(
                issuer=os.environ["OPENSHELL_OIDC_ISSUER"],
                client_id=os.environ["OPENSHELL_OIDC_CLIENT_ID"],
                client_secret=lambda: os.environ["OPENSHELL_OIDC_CLIENT_SECRET"],
                audience=os.environ["OPENSHELL_OIDC_AUDIENCE"],
            )
            client_context = SandboxClient.from_active_cluster(client_credentials=auth)
        else:
            client_context = SandboxClient.from_active_cluster()
        client = client_context.__enter__()
        health = client.health()
        if not getattr(health, "version", None):
            raise RuntimeError("OpenShell health response did not include a version.")
    except Exception as exc:
        if client_context is not None:
            try:
                client_context.__exit__(type(exc), exc, exc.__traceback__)
            except Exception:
                pass
        raise RuntimeAdapterUnavailable(
            "Could not initialize or verify the configured OpenShell gateway."
        ) from exc

    return OpenShellRuntimeAdapter(
        client,
        sandbox_name=sandbox_name,
        workspace=workspace,
        timeout_seconds=timeout_seconds,
        close_callback=lambda: client_context.__exit__(None, None, None),
        baseline_policy_sha256=baseline_policy_sha256,
    )
