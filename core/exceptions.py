"""
TwinGuard — Exception Hierarchy
"""


class TwinGuardError(Exception):
    """Base exception for all TwinGuard errors."""
    pass


class ConfigError(TwinGuardError):
    """Configuration loading or validation failed."""
    pass


class IntegrityViolation(TwinGuardError):
    """Context integrity check detected instruction loss."""
    pass


class ActionVetoed(TwinGuardError):
    """Execution Gateway vetoed a destructive action."""

    def __init__(self, tool_call_id: str, reason: str):
        self.tool_call_id = tool_call_id
        self.reason = reason
        super().__init__(f"Action {tool_call_id} vetoed: {reason}")


class ThreatFadeConnectionError(TwinGuardError):
    """Cannot reach ThreatFade Oracle service."""
    pass


class OpenShellConnectionError(TwinGuardError):
    """Cannot reach OpenShell gateway."""
    pass


class AuthenticationError(TwinGuardError):
    """API key missing or invalid."""
    pass


class PolicyViolation(TwinGuardError):
    """Action violates the active security policy."""

    def __init__(self, policy_rule: str, action: str):
        self.policy_rule = policy_rule
        self.action = action
        super().__init__(f"Policy '{policy_rule}' blocks action: {action}")
