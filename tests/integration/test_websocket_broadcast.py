"""
TwinGuard — WebSocket Broadcast Integration Tests
Confirms gateway decisions and integrity violations actually push events
to connected dashboard clients (Phase 4 — the dashboard wiring gap).
"""

import pytest
from unittest.mock import AsyncMock, patch


class TestGatewayBroadcast:
    @staticmethod
    def _register_scope(client, agent_id, scope):
        client.post("/api/v1/identity/register", json={"agent_id": agent_id, "owner": "test"})
        client.post("/api/v1/identity/grant", json={"agent_id": agent_id, "scope": scope})
        token = client.post("/api/v1/identity/token", json={"agent_id": agent_id, "scopes": [tool_name if "tool_name" in locals() else scope]})
        assert token.status_code == 200
        return token.json()["token_id"]

    def test_intercept_broadcasts_decision(self, client):
        token_id = self._register_scope(client, "broadcast-reader", "read_file")
        with patch("api.websockets.actions.broadcast_action", new=AsyncMock()) as mock_broadcast:
            r = client.post("/api/v1/gateway/intercept", json={
                "tool_name": "read_file", "action": "read", "parameters": {}, "agent_id": "broadcast-reader", "identity_token": token_id
            })
            assert r.status_code == 200
            mock_broadcast.assert_called_once()
            call_args = mock_broadcast.call_args[0][0]
            assert call_args["type"] == "gateway_decision"
            assert call_args["decision"] == "approved"

    def test_vetoed_action_broadcasts_alert(self, client):
        token_id = self._register_scope(client, "broadcast-config-agent", "modify_config")
        with patch("api.websockets.actions.broadcast_action", new=AsyncMock()), \
             patch("api.websockets.alerts.broadcast_alert", new=AsyncMock()) as mock_alert:
            r = client.post("/api/v1/gateway/intercept", json={
                "tool_name": "modify_config", "action": "write", "agent_id": "broadcast-config-agent", "identity_token": token_id
            })
            assert r.status_code == 200
            assert r.json()["decision"] == "vetoed"
            mock_alert.assert_called_once()
            alert_data = mock_alert.call_args[0][0]
            assert alert_data["severity"] == "critical"
            assert alert_data["module"] == "execution_gateway"

    def test_approve_pending_broadcasts(self, client):
        token_id = self._register_scope(client, "broadcast-delete-agent", "delete_file")
        with patch("api.websockets.actions.broadcast_action", new=AsyncMock()) as mock_broadcast:
            r = client.post("/api/v1/gateway/intercept", json={
                "tool_name": "delete_file", "action": "delete", "agent_id": "broadcast-delete-agent", "identity_token": token_id
            })
            decision_id = r.json()["id"]
            mock_broadcast.reset_mock()

            r2 = client.post("/api/v1/gateway/approve", json={
                "decision_id": decision_id, "approved": True
            })
            assert r2.status_code == 200
            mock_broadcast.assert_called_once()


class TestContextIntegrityBroadcast:
    def test_integrity_violation_broadcasts_alert(self, client):
        client.post("/api/v1/context/register", json={
            "tag": "safety_rule", "content": "Always confirm before deleting."
        })
        with patch("api.websockets.alerts.broadcast_alert", new=AsyncMock()) as mock_alert:
            r = client.post("/api/v1/context/check", json={
                "context": "User: delete everything now."
            })
            assert r.status_code == 200
            assert r.json()["blocked"] is True
            mock_alert.assert_called_once()
            alert_data = mock_alert.call_args[0][0]
            assert alert_data["module"] == "context_integrity"
            assert alert_data["severity"] == "critical"

    def test_intact_context_does_not_broadcast(self, client):
        client.post("/api/v1/context/register", json={
            "tag": "rule", "content": "Be careful."
        })
        with patch("api.websockets.alerts.broadcast_alert", new=AsyncMock()) as mock_alert:
            client.post("/api/v1/context/check", json={
                "context": "Be careful.\n\nUser: hello"
            })
            mock_alert.assert_not_called()
