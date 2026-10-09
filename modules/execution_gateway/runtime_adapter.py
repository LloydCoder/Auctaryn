"""Trusted runtime adapter contract.

Auctaryn never executes tool calls in the API process. A configured adapter must
forward an approved, credential-free ToolCall to a separately governed runtime.
"""
from datetime import datetime, timezone
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from core.models import ToolCall


class AdapterExecutionResult(BaseModel):
    """Internal adapter result. Raw output is consumed only for hashing."""

    execution_id: str = Field(min_length=1, max_length=256)
    adapter: str = Field(min_length=1, max_length=128)
    status: Literal["succeeded", "failed", "timed_out"]
    exit_code: int | None = None
    stdout: str = Field(default="", max_length=1_000_000, repr=False)
    stderr: str = Field(default="", max_length=1_000_000, repr=False)
    finished_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RuntimeExecutionReceipt(BaseModel):
    """Safe, bounded receipt exposed to API clients; never includes raw output."""

    decision_id: str
    execution_id: str
    adapter: str
    status: Literal["succeeded", "failed", "timed_out"]
    exit_code: int | None = None
    stdout_sha256: str
    stderr_sha256: str
    finished_at: datetime


@runtime_checkable
class RuntimeAdapter(Protocol):
    """Implementations must enforce the configured sandbox and honor idempotency."""

    async def execute(
        self, tool_call: ToolCall, *, idempotency_key: str
    ) -> AdapterExecutionResult:
        """Execute the exact tool call in a protected runtime or raise on failure."""
        ...


class RuntimeAdapterUnavailable(RuntimeError):
    """Raised when no trusted runtime adapter is configured."""


class RuntimeAdapterFailure(RuntimeError):
    """Raised when the adapter cannot provide a trustworthy execution result."""


class DuplicateExecution(RuntimeError):
    """Raised when a decision has already been claimed for execution."""
