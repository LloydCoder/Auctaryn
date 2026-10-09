"""
TwinGuard — Execution Gateway Tests (TDD Red-Green-Refactor)
Tests written FIRST. Implementation follows.
"""

import pytest
from core.models import RiskLevel, ActionDecision


class TestActionPatternMatching:
    """Pattern-based risk classification tests."""

    def test_safe_read_action(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        result = classify_by_pattern("read_file", "read", {})
        assert result == RiskLevel.SAFE

    def test_safe_list_action(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        assert classify_by_pattern("list_emails", "list", {}) == RiskLevel.SAFE

    def test_safe_get_action(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        assert classify_by_pattern("get_calendar", "get", {}) == RiskLevel.SAFE

    def test_safe_search_action(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        assert classify_by_pattern("search_web", "search", {}) == RiskLevel.SAFE

    def test_moderate_create_action(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        result = classify_by_pattern("create_file", "create", {})
        assert result == RiskLevel.MODERATE

    def test_moderate_send_message(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        result = classify_by_pattern("send_message", "send", {"recipient": "team"})
        assert result == RiskLevel.MODERATE

    def test_destructive_delete_action(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        result = classify_by_pattern("delete_file", "delete", {})
        assert result == RiskLevel.DESTRUCTIVE

    def test_destructive_bulk_email_delete(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        result = classify_by_pattern("delete_emails", "bulk", {"count": 500})
        assert result == RiskLevel.DESTRUCTIVE

    def test_critical_modify_policy(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        result = classify_by_pattern("modify_policy", "update", {})
        assert result == RiskLevel.CRITICAL

    def test_critical_modify_config(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        result = classify_by_pattern("modify_config", "write", {})
        assert result == RiskLevel.CRITICAL

    def test_critical_escalate_privileges(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        result = classify_by_pattern("escalate_privileges", "sudo", {})
        assert result == RiskLevel.CRITICAL

    def test_unknown_tool_defaults_moderate(self):
        from modules.execution_gateway.risk_classifier import classify_by_pattern
        result = classify_by_pattern("unknown_tool_xyz", "do_something", {})
        assert result in (RiskLevel.MODERATE, RiskLevel.DESTRUCTIVE)


class TestRiskClassifier:
    """Full risk classifier with confidence scoring."""

    def test_classify_safe_action(self):
        from modules.execution_gateway.risk_classifier import RiskClassifier
        from core.models import ToolCall
        clf = RiskClassifier()
        tc = ToolCall(tool_name="read_file", action="read", parameters={"path": "/doc.pdf"})
        classification = clf.classify(tc)
        assert classification.risk_level == RiskLevel.SAFE
        assert classification.confidence > 0.0
        assert classification.reason != ""

    def test_classify_destructive_action(self):
        from modules.execution_gateway.risk_classifier import RiskClassifier
        from core.models import ToolCall
        clf = RiskClassifier()
        tc = ToolCall(tool_name="delete_emails", action="delete",
                      parameters={"folder": "inbox", "count": 500})
        classification = clf.classify(tc)
        assert classification.risk_level == RiskLevel.DESTRUCTIVE
        assert classification.confidence > 0.5

    def test_classify_critical_action(self):
        from modules.execution_gateway.risk_classifier import RiskClassifier
        from core.models import ToolCall
        clf = RiskClassifier()
        tc = ToolCall(tool_name="modify_config", action="write",
                      parameters={"file": "twinguard.yaml"})
        classification = clf.classify(tc)
        assert classification.risk_level == RiskLevel.CRITICAL

    def test_bulk_parameter_elevates_risk(self):
        """A normally moderate action with bulk parameters should elevate risk."""
        from modules.execution_gateway.risk_classifier import RiskClassifier
        from core.models import ToolCall
        clf = RiskClassifier()
        # Send email to 100+ recipients — should be at least destructive
        tc = ToolCall(tool_name="send_email", action="send",
                      parameters={"recipients": list(range(100)), "subject": "test"})
        classification = clf.classify(tc)
        assert classification.risk_level in (RiskLevel.DESTRUCTIVE, RiskLevel.CRITICAL)


class TestVetoEngine:
    """Veto engine decision logic tests."""

    def test_safe_action_auto_approved(self):
        from modules.execution_gateway.veto_engine import VetoEngine
        from core.models import ToolCall, ActionClassification
        engine = VetoEngine(auto_approve_safe=True)
        tc = ToolCall(tool_name="read_file", action="read")
        classification = ActionClassification(
            tool_call=tc, risk_level=RiskLevel.SAFE, confidence=0.99, reason="Safe read"
        )
        decision = engine.decide(classification)
        assert decision.decision == ActionDecision.APPROVED
        assert decision.decided_by == "auto"

    def test_moderate_action_auto_approved(self):
        from modules.execution_gateway.veto_engine import VetoEngine
        from core.models import ToolCall, ActionClassification
        engine = VetoEngine(auto_approve_safe=True)
        tc = ToolCall(tool_name="create_file", action="create")
        classification = ActionClassification(
            tool_call=tc, risk_level=RiskLevel.MODERATE, confidence=0.8, reason="Moderate create"
        )
        decision = engine.decide(classification)
        assert decision.decision == ActionDecision.APPROVED

    def test_destructive_action_pending_approval(self):
        from modules.execution_gateway.veto_engine import VetoEngine
        from core.models import ToolCall, ActionClassification
        engine = VetoEngine()
        tc = ToolCall(tool_name="delete_emails", action="delete",
                      parameters={"count": 500})
        classification = ActionClassification(
            tool_call=tc, risk_level=RiskLevel.DESTRUCTIVE,
            confidence=0.95, reason="Bulk delete"
        )
        decision = engine.decide(classification)
        assert decision.decision == ActionDecision.PENDING

    def test_critical_action_always_vetoed(self):
        from modules.execution_gateway.veto_engine import VetoEngine
        from core.models import ToolCall, ActionClassification
        engine = VetoEngine()
        tc = ToolCall(tool_name="modify_policy", action="write")
        classification = ActionClassification(
            tool_call=tc, risk_level=RiskLevel.CRITICAL,
            confidence=1.0, reason="Policy modification"
        )
        decision = engine.decide(classification)
        assert decision.decision == ActionDecision.VETOED
        assert decision.decided_by == "veto_engine"

    def test_veto_returns_reason(self):
        from modules.execution_gateway.veto_engine import VetoEngine
        from core.models import ToolCall, ActionClassification
        engine = VetoEngine()
        tc = ToolCall(tool_name="escalate_privileges", action="sudo")
        classification = ActionClassification(
            tool_call=tc, risk_level=RiskLevel.CRITICAL,
            confidence=1.0, reason="Privilege escalation"
        )
        decision = engine.decide(classification)
        assert len(decision.reason) > 0


class TestGatewayService:
    """Full Gateway service lifecycle tests."""

    def test_gateway_initialization(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        gw = ExecutionGateway()
        assert gw.total_processed == 0
        assert gw.total_vetoed == 0

    def test_gateway_processes_safe_action(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from core.models import ToolCall
        gw = ExecutionGateway()
        tc = ToolCall(tool_name="read_file", action="read", parameters={"path": "/doc.pdf"})
        decision = gw.evaluate(tc)
        assert decision.decision == ActionDecision.APPROVED
        assert gw.total_processed == 1

    def test_gateway_vetoes_critical_action(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from core.models import ToolCall
        gw = ExecutionGateway()
        tc = ToolCall(tool_name="modify_config", action="write")
        decision = gw.evaluate(tc)
        assert decision.decision == ActionDecision.VETOED
        assert gw.total_vetoed == 1

    def test_gateway_queues_destructive_action(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from core.models import ToolCall
        gw = ExecutionGateway()
        tc = ToolCall(tool_name="delete_all_files", action="delete",
                      parameters={"path": "/*"})
        decision = gw.evaluate(tc)
        assert decision.decision == ActionDecision.PENDING
        assert len(gw.get_pending()) == 1

    def test_gateway_tracks_decision_history(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from core.models import ToolCall
        gw = ExecutionGateway()
        gw.evaluate(ToolCall(tool_name="read_file", action="read"))
        gw.evaluate(ToolCall(tool_name="search_web", action="search"))
        gw.evaluate(ToolCall(tool_name="modify_config", action="write"))
        assert gw.total_processed == 3
        assert len(gw.history) == 3

    def test_gateway_approve_pending(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from core.models import ToolCall
        gw = ExecutionGateway()
        tc = ToolCall(tool_name="delete_file", action="delete",
                      parameters={"path": "/tmp/test.txt"})
        decision = gw.evaluate(tc)
        assert decision.decision == ActionDecision.PENDING

        approved = gw.resolve_pending(decision.id, approved=True, reason="Operator confirmed")
        assert approved.decision == ActionDecision.APPROVED

    def test_gateway_deny_pending(self):
        from modules.execution_gateway.gateway import ExecutionGateway
        from core.models import ToolCall
        gw = ExecutionGateway()
        tc = ToolCall(tool_name="delete_emails", action="delete",
                      parameters={"count": 200})
        decision = gw.evaluate(tc)
        denied = gw.resolve_pending(decision.id, approved=False, reason="Not authorized")
        assert denied.decision == ActionDecision.DENIED

    def test_summer_yue_email_delete_blocked(self):
        """
        Simulate the exact Summer Yue scenario through the gateway:
        Agent attempts bulk email deletion — should require operator approval.
        """
        from modules.execution_gateway.gateway import ExecutionGateway
        from core.models import ToolCall
        gw = ExecutionGateway()
        tc = ToolCall(
            tool_name="gmail_delete",
            action="bulk_delete",
            parameters={"folder": "inbox", "query": "is:unread", "count": 847},
            agent_id="openclone-agent-001",
            session_id="yue-session-feb23"
        )
        decision = gw.evaluate(tc)
        # Must NOT auto-approve. Must be PENDING or VETOED.
        assert decision.decision in (ActionDecision.PENDING, ActionDecision.VETOED)
        assert decision.decision != ActionDecision.APPROVED
