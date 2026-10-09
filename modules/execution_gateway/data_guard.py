"""Pre-execution sensitive-data guard.

Raw credentials must be delivered through a governed secret-provider mechanism,
not embedded in agent tool-call arguments. Findings contain paths only, never values.
"""
import re
from collections.abc import Mapping, Sequence
from typing import Any

from core.models import ToolCall

_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|private[_-]?key|authorization|bearer|credential|cookie|"
    r"session[_-]?token)",
    re.IGNORECASE,
)
_SECRET_REFERENCE = re.compile(
    r"^(?:secret|vault|aws-secretsmanager|azure-keyvault|gcp-secret)://[^\s]+$",
    re.IGNORECASE,
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bsk-proj-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    re.compile(r"\b[^\s/@:]+:[^\s/@]+@[^\s/]+"),
    re.compile(
        r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|authorization)\s*[:=]\s*[^\s]+",
        re.IGNORECASE,
    ),
)
_MAX_REPORTED_PATHS = 50


class SensitiveDataBlocked(ValueError):
    """Raised when raw sensitive data is present in an agent tool call."""

    def __init__(self, paths: Sequence[str]):
        self.paths = tuple(paths[:_MAX_REPORTED_PATHS])
        self.additional_count = max(0, len(paths) - _MAX_REPORTED_PATHS)
        super().__init__("Tool call contains raw sensitive data; use governed secret references.")


class SensitiveDataGuard:
    """Reject obvious raw secrets before risk analysis, logging, or execution."""

    @staticmethod
    def _looks_like_secret(value: str) -> bool:
        if _SECRET_REFERENCE.fullmatch(value.strip()):
            return False
        return any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS)

    def validate_tool_call(self, tool_call: ToolCall) -> None:
        findings: list[str] = []

        def visit(value: Any, path: str, key: str | None = None) -> None:
            if key is not None and _SENSITIVE_KEY.search(key):
                if isinstance(value, str) and _SECRET_REFERENCE.fullmatch(value.strip()):
                    return
                if value not in (None, "", [], {}):
                    findings.append(path)
                    return

            if isinstance(value, Mapping):
                for child_key, child_value in value.items():
                    child_key_str = str(child_key)
                    visit(child_value, f"{path}.{child_key_str}", child_key_str)
                return

            if isinstance(value, list):
                for index, child_value in enumerate(value):
                    visit(child_value, f"{path}[{index}]")
                return

            if isinstance(value, str) and self._looks_like_secret(value):
                findings.append(path)

        visit(tool_call.parameters, "parameters")
        if tool_call.target and self._looks_like_secret(tool_call.target):
            findings.append("target")

        if findings:
            # Preserve first occurrence order while removing duplicate paths.
            unique_paths = list(dict.fromkeys(findings))
            raise SensitiveDataBlocked(unique_paths)
