"""TwinGuard — Phase 1 Tests"""

import pytest


class TestHealthEndpoints:
    def test_basic_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "alive"
        assert "version" in d

    def test_detailed_health(self, client):
        r = client.get("/health/detailed")
        assert r.status_code == 200
        d = r.json()
        names = {m["name"] for m in d["modules"]}
        assert names == {"context_integrity", "execution_gateway", "threatfade_oracle", "openshell_runtime"}

    def test_readiness(self, client):
        r = client.get("/health/ready")
        assert r.status_code == 200
        assert r.json()["ready"] is False
        assert r.json()["checks"]["openshell_connected"] is False


class TestContextIntegrityRoutes:
    def test_status_no_instructions(self, client):
        r = client.get("/api/v1/context/status")
        assert r.status_code == 200
        d = r.json()
        assert d["instructions_protected"] == 0

    def test_list_checks_empty(self, client):
        r = client.get("/api/v1/context/checks")
        assert r.status_code == 200
        assert r.json() == []

    def test_get_check_not_found(self, client):
        r = client.get("/api/v1/context/checks/nonexistent")
        assert r.status_code == 404

    def test_trigger_check_no_instructions(self, client):
        r = client.post("/api/v1/context/check-now")
        assert r.status_code == 200
        assert r.json()["instructions_total"] == 0


class TestExecutionGatewayRoutes:
    def test_status(self, client):
        r = client.get("/api/v1/gateway/status")
        assert r.status_code == 200
        assert r.json()["status"] == "active"

    def test_evaluate_tool_call(self, client, safe_tool_call):
        r = client.post("/api/v1/gateway/evaluate", json=safe_tool_call)
        assert r.status_code == 200
        assert "risk_level" in r.json()

    def test_list_decisions_empty(self, client):
        r = client.get("/api/v1/gateway/decisions")
        assert r.status_code == 200
        assert r.json() == []

    def test_list_pending_empty(self, client):
        r = client.get("/api/v1/gateway/pending")
        assert r.status_code == 200
        assert r.json() == []


class TestThreatFadeRoutes:
    def test_status(self, client):
        r = client.get("/api/v1/threatfade/status")
        assert r.status_code == 200
        assert "threatfade_version" in r.json()

    def test_list_results_empty(self, client):
        r = client.get("/api/v1/threatfade/results")
        assert r.status_code == 200
        assert r.json() == []

    def test_get_result_not_found(self, client):
        r = client.get("/api/v1/threatfade/results/999")
        assert r.status_code == 404


class TestConfigLoading:
    def test_config_loads(self):
        from core.config import load_config
        config = load_config()
        assert config.branding.name == "Auctaryn"

    def test_config_singleton(self):
        from core.config import get_config
        assert get_config() is get_config()


class TestModels:
    def test_tool_call_model(self):
        from core.models import ToolCall
        tc = ToolCall(tool_name="delete_file", action="delete")
        assert tc.parameters == {}

    def test_alert_model(self):
        from core.models import Alert, Severity
        a = Alert(severity=Severity.CRITICAL, module="context_integrity",
                  title="Test", message="Test message")
        assert a.acknowledged is False


class TestExceptions:
    def test_action_vetoed(self):
        from core.exceptions import ActionVetoed
        exc = ActionVetoed("tc-001", "Bulk delete blocked")
        assert exc.tool_call_id == "tc-001"

    def test_policy_violation(self):
        from core.exceptions import PolicyViolation
        exc = PolicyViolation("no_bulk_delete", "delete_emails:bulk")
        assert exc.policy_rule == "no_bulk_delete"
