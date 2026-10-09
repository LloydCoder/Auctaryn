"""NVIDIA OpenShell runtime adapter.

Only the server-configured sandbox is addressable. Calls use an argv array,
never shell=True or a caller-supplied sandbox name. OpenShell's sandbox policy
remains the execution security boundary; Auctaryn decisions are an additional
gate, not a replacement for OpenShell isolation.
"""
import asyncio
import os
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from core.models import ToolCall
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
    ):
        if not sandbox_name.strip() or not workspace.strip():
            raise ValueError("sandbox_name and workspace must be non-empty")
        if not 1 <= timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be between 1 and 3600")
        self.client = client
        self.sandbox_name = sandbox_name
        self.workspace = workspace
        self.timeout_seconds = timeout_seconds
        self.close_callback = close_callback
        self._seen_idempotency_keys: set[str] = set()

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

        # GNU timeout bounds command lifetime inside the sandbox. No host-side
        # cancellation is attempted because cancelling an SDK thread would not
        # prove that the sandboxed process stopped.
        bounded_argv = ["timeout", f"{self.timeout_seconds}s", *argv]
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

        stdout = getattr(result, "stdout", "")
        stderr = getattr(result, "stderr", "")
        exit_code = getattr(result, "exit_code", None)
        if not isinstance(stdout, str) or not isinstance(stderr, str):
            raise RuntimeAdapterFailure("OpenShell returned an invalid execution result.")
        if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)):
            raise RuntimeAdapterFailure("OpenShell returned an invalid exit code.")

        stdout_truncated = len(stdout) > MAX_OUTPUT_CHARS
        stderr_truncated = len(stderr) > MAX_OUTPUT_CHARS
        stdout = stdout[:MAX_OUTPUT_CHARS]
        stderr = stderr[:MAX_OUTPUT_CHARS]
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
    if not sandbox_name:
        raise RuntimeAdapterUnavailable(
            "OPENSHELL_SANDBOX_NAME is required when AUCTARYN_RUNTIME_ADAPTER=openshell."
        )
    try:
        timeout_seconds = int(os.getenv("OPENSHELL_EXECUTION_TIMEOUT_SECONDS", "60"))
    except ValueError as exc:
        raise RuntimeAdapterUnavailable(
            "OPENSHELL_EXECUTION_TIMEOUT_SECONDS must be an integer."
        ) from exc

    try:
        from openshell import SandboxClient

        client_context = SandboxClient.from_active_cluster()
        client = client_context.__enter__()
        client.health()
    except Exception as exc:
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
    )
