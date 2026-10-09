"""
TwinGuard — Execution Gateway Risk Classifier
Pattern-based + heuristic risk classification for tool calls.
"""

import re
from core.models import RiskLevel, ToolCall, ActionClassification
from core.logging import get_logger

logger = get_logger("execution_gateway.classifier")

# --- Pattern definitions ---
# (tool_pattern, action_pattern) -> RiskLevel
# Checked in order: CRITICAL first, then DESTRUCTIVE, MODERATE, SAFE

CRITICAL_PATTERNS = [
    (r"modify_policy|update_policy|set_policy", r".*"),
    (r"modify_config|update_config|write_config|set_config", r".*"),
    (r"escalate_priv|sudo|root_exec|gain_access", r".*"),
    (r"disable_security|disable_guard|disable_monitor", r".*"),
    (r"exfiltrate|data_exfil|extract_secrets", r".*"),
    (r".*", r"escalate|privilege|sudo|root"),
]

DESTRUCTIVE_PATTERNS = [
    (r"delete_.*|.*_delete|remove_.*|.*_remove|drop_.*", r".*"),
    (r".*", r"delete|bulk_delete|drop|truncate|wipe|erase|purge"),
    (r"write_file|overwrite_.*", r"overwrite|replace"),
    (r"send_email|send_message|broadcast", r"bulk|mass|all"),
    (r"modify_.*|update_.*|edit_.*", r"bulk|batch|all|mass"),
    (r"gmail_.*|email_.*|mail_.*", r"bulk.*|.*bulk|delete|remove"),
]

MODERATE_PATTERNS = [
    (r"write_file|create_file|save_file", r"create|write|save"),
    (r"send_message|send_email|send_.*", r"send|post|publish"),
    (r"create_.*|add_.*|insert_.*|new_.*", r".*"),
    (r"update_.*|modify_.*|edit_.*|patch_.*", r".*"),
    (r"execute_.*|run_.*", r".*"),
]

SAFE_PATTERNS = [
    (r"read_.*|.*_read", r".*"),
    (r"list_.*|.*_list|get_.*|.*_get|fetch_.*|.*_fetch", r".*"),
    (r"search_.*|.*_search|find_.*|.*_find|query_.*|.*_query", r".*"),
    (r"view_.*|show_.*|display_.*|preview_.*", r".*"),
    (r".*", r"read|list|get|fetch|search|find|query|view|show"),
]

# Bulk thresholds — parameters that elevate risk
BULK_KEYS = {"count", "limit", "recipients", "ids", "files", "targets"}
BULK_THRESHOLD = 10


def _matches(tool_name: str, action: str, tool_pattern: str, action_pattern: str) -> bool:
    return (re.search(tool_pattern, tool_name, re.IGNORECASE) is not None and
            re.search(action_pattern, action, re.IGNORECASE) is not None)


def _has_bulk_parameters(parameters: dict) -> bool:
    for key, value in parameters.items():
        if key.lower() in BULK_KEYS:
            if isinstance(value, (list, tuple)) and len(value) >= BULK_THRESHOLD:
                return True
            if isinstance(value, (int, float)) and value >= BULK_THRESHOLD:
                return True
    return False


def classify_by_pattern(tool_name: str, action: str, parameters: dict) -> RiskLevel:
    """Fast pattern-based classification. No external calls."""
    # Critical first — always block these
    for tp, ap in CRITICAL_PATTERNS:
        if _matches(tool_name, action, tp, ap):
            return RiskLevel.CRITICAL

    # Destructive
    for tp, ap in DESTRUCTIVE_PATTERNS:
        if _matches(tool_name, action, tp, ap):
            return RiskLevel.DESTRUCTIVE

    # Check if bulk parameters elevate a moderate action to destructive
    if _has_bulk_parameters(parameters):
        # Check if it would otherwise be moderate
        for tp, ap in MODERATE_PATTERNS:
            if _matches(tool_name, action, tp, ap):
                return RiskLevel.DESTRUCTIVE
        return RiskLevel.DESTRUCTIVE

    # Moderate
    for tp, ap in MODERATE_PATTERNS:
        if _matches(tool_name, action, tp, ap):
            return RiskLevel.MODERATE

    # Safe
    for tp, ap in SAFE_PATTERNS:
        if _matches(tool_name, action, tp, ap):
            return RiskLevel.SAFE

    # Unknown — default to moderate (safe default: require log, not block)
    return RiskLevel.MODERATE


class RiskClassifier:
    """
    Full risk classifier combining pattern matching with confidence scoring.
    Phase 2 will add Claude API semantic classification for ambiguous cases.
    """

    def classify(self, tool_call: ToolCall) -> ActionClassification:
        risk_level = classify_by_pattern(
            tool_call.tool_name, tool_call.action, tool_call.parameters
        )
        confidence, reason = self._score(tool_call, risk_level)

        classification = ActionClassification(
            tool_call=tool_call,
            risk_level=risk_level,
            confidence=confidence,
            reason=reason,
            matched_pattern=f"{tool_call.tool_name}:{tool_call.action}",
        )

        logger.info(
            f"Classified {tool_call.tool_name}:{tool_call.action} → {risk_level.value} "
            f"(confidence={confidence:.2f})",
            extra={"event": "action_classified", "risk_level": risk_level.value},
        )
        return classification

    def _score(self, tool_call: ToolCall, risk_level: RiskLevel) -> tuple[float, str]:
        """Return (confidence, reason) for a classified action."""
        tool = tool_call.tool_name.lower()
        action = tool_call.action.lower()
        params = tool_call.parameters

        if risk_level == RiskLevel.CRITICAL:
            return 1.0, (
                f"Action '{tool}:{action}' matches critical pattern. "
                "Policy/config/privilege operations are always blocked."
            )

        if risk_level == RiskLevel.DESTRUCTIVE:
            bulk = _has_bulk_parameters(params)
            if bulk:
                return 0.95, (
                    f"Action '{tool}:{action}' with bulk parameters "
                    f"({list(params.keys())}) classified as destructive."
                )
            return 0.90, (
                f"Action '{tool}:{action}' matches destructive pattern "
                "(delete/remove/wipe/purge)."
            )

        if risk_level == RiskLevel.MODERATE:
            return 0.80, (
                f"Action '{tool}:{action}' is a write/create/update operation. "
                "Logged and auto-approved."
            )

        # SAFE
        return 0.99, f"Action '{tool}:{action}' is a read-only operation."
