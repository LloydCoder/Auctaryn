"""TwinGuard — Gateway API Integration Tests"""

import pytest


class TestGatewayAPI:
    @staticmethod
    def _register_scope(client, agent_id, tool_name):
        client.post("/api/v1/identity/register", json={"agent_id": agent_id, "owner": "test"})
        client.post("/api/v1/identity/grant", json={"agent_id": agent_id, "scope": tool_name})
        token = client.post("/api/v1/identity/token", json={"agent_id": agent_id})
        assert token.status_code == 200
        return token.json()["token_id"]

    def test_status(self, client):
        r = client.get("/api/v1/gateway/status")
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "active"
        assert "total_processed" in d

    def test_evaluate_safe_action(self, client):
        r = client.post("/api/v1/gateway/evaluate", json={
            "tool_name": "read_file", "action": "read",
            "parameters": {"path": "/docs/report.pdf"}
        })
        assert r.status_code == 200
        assert r.json()["risk_level"] == "safe"

    def test_evaluate_critical_action(self, client):
        r = client.post("/api/v1/gateway/evaluate", json={
            "tool_name": "modify_config", "action": "write"
        })
        assert r.status_code == 200
        assert r.json()["risk_level"] == "critical"

    def test_intercept_safe_auto_approved(self, client):
        self._register_scope(client, "search-agent", "search_web")
        r = client.post("/api/v1/gateway/intercept", json={
            "tool_name": "search_web", "action": "search",
            "parameters": {"query": "weather today"}, "agent_id": "search-agent"
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "approved"

    def test_intercept_critical_vetoed(self, client):
        self._register_scope(client, "policy-agent", "modify_policy")
        r = client.post("/api/v1/gateway/intercept", json={
            "tool_name": "modify_policy", "action": "update", "agent_id": "policy-agent"
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "vetoed"

    def test_intercept_destructive_pending(self, client):
        self._register_scope(client, "delete-email-agent", "delete_emails")
        r = client.post("/api/v1/gateway/intercept", json={
            "tool_name": "delete_emails", "action": "bulk_delete",
            "parameters": {"count": 500, "folder": "inbox"}, "agent_id": "delete-email-agent"
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "pending"

    def test_pending_queue_populated(self, client):
        self._register_scope(client, "delete-file-agent", "delete_file")
        client.post("/api/v1/gateway/intercept", json={
            "tool_name": "delete_file", "action": "delete",
            "parameters": {"path": "/important.db"}, "agent_id": "delete-file-agent"
        })
        r = client.get("/api/v1/gateway/pending")
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_approve_pending_action(self, client):
        self._register_scope(client, "approve-delete-agent", "delete_file")
        # First create a pending action
        r = client.post("/api/v1/gateway/intercept", json={
            "tool_name": "delete_file", "action": "delete", "agent_id": "approve-delete-agent"
        })
        decision_id = r.json()["id"]

        # Then approve it
        r = client.post("/api/v1/gateway/approve", json={
            "decision_id": decision_id,
            "approved": True,
            "reason": "Operator confirmed safe to delete"
        })
        assert r.status_code == 200
        assert r.json()["result"] == "approved"

    def test_yue_scenario_via_api(self, client):
        """Summer Yue bulk email delete — must not auto-approve."""
        r = client.post("/api/v1/gateway/intercept", json={
            "tool_name": "gmail_delete",
            "action": "bulk_delete",
            "parameters": {"folder": "inbox", "query": "is:unread", "count": 847},
            "agent_id": "rogue-agent-001"
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "denied"
