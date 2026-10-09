"""Regression tests for fail-closed handling of unrecognized tool actions."""

from core.models import ActionDecision, RiskLevel, ToolCall
from modules.execution_gateway.risk_classifier import RiskClassifier
from modules.execution_gateway.veto_engine import VetoEngine


def test_unrecognized_action_has_low_confidence_and_requires_review():
    call = ToolCall(
        tool_name="custom_connector_operation",
        action="invoke_unmapped_capability",
        parameters={},
        agent_id="test-agent",
    )

    classification = RiskClassifier().classify(call)

    assert classification.risk_level == RiskLevel.MODERATE
    assert classification.confidence <= 0.5
    assert classification.matched_pattern == "unrecognized"
    assert "operator approval is required" in classification.reason.lower()


def test_unrecognized_action_is_never_auto_approved():
    call = ToolCall(
        tool_name="custom_connector_operation",
        action="invoke_unmapped_capability",
        parameters={},
        agent_id="test-agent",
    )
    classification = RiskClassifier().classify(call)

    decision = VetoEngine(auto_approve_safe=True).decide(classification)

    assert decision.decision == ActionDecision.PENDING
    assert decision.decided_by == "veto_engine"


def test_known_safe_read_action_remains_recognized():
    call = ToolCall(
        tool_name="read_file",
        action="read",
        parameters={"path": "/docs/readme.md"},
        agent_id="test-agent",
    )

    classification = RiskClassifier().classify(call)

    assert classification.risk_level == RiskLevel.SAFE
    assert classification.confidence > 0.9
    assert classification.matched_pattern != "unrecognized"
