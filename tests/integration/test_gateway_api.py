"""TwinGuard — Gateway API Integration Tests"""

import pytest


class TestGatewayAPI:
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
        r = client.post("/api/v1/gateway/intercept", json={
            "tool_name": "search_web", "action": "search",
            "parameters": {"query": "weather today"}
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "approved"

    def test_intercept_critical_vetoed(self, client):
        r = client.post("/api/v1/gateway/intercept", json={
            "tool_name": "modify_policy", "action": "update"
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "vetoed"

    def test_intercept_destructive_pending(self, client):
        r = client.post("/api/v1/gateway/intercept", json={
            "tool_name": "delete_emails", "action": "bulk_delete",
            "parameters": {"count": 500, "folder": "inbox"}
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "pending"

    def test_pending_queue_populated(self, client):
        client.post("/api/v1/gateway/intercept", json={
            "tool_name": "delete_file", "action": "delete",
            "parameters": {"path": "/important.db"}
        })
        r = client.get("/api/v1/gateway/pending")
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_approve_pending_action(self, client):
        # First create a pending action
        r = client.post("/api/v1/gateway/intercept", json={
            "tool_name": "delete_file", "action": "delete"
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
        assert r.json()["decision"] in ("pending", "vetoed")
        assert r.json()["decision"] != "approved"
