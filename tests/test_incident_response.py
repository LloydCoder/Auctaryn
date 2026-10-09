"""Regression tests for incident containment, revocation and alert lifecycle."""
import pytest

from core.exceptions import PolicyViolation
from modules.agent_identity.identity import AgentIdentityManager
from modules.incident_response.manager import IncidentResponseBlocked, IncidentResponseManager


def test_emergency_stop_persists_and_blocks_execution(tmp_path):
    path = str(tmp_path / "evidence.sqlite3")
    manager = IncidentResponseManager(path)
    manager.set_emergency_stop(True, "operator", "Incident containment")
    restarted = IncidentResponseManager(path)
    with pytest.raises(IncidentResponseBlocked):
        restarted.assert_execution_allowed("agent-a")
    restarted.set_emergency_stop(False, "operator", "Containment released")
    restarted.assert_execution_allowed("agent-a")


def test_agent_quarantine_is_scoped_and_recoverable(tmp_path):
    manager = IncidentResponseManager(str(tmp_path / "evidence.sqlite3"))
    manager.set_agent_quarantine("agent-a", True, "operator", "Suspected compromise")
    with pytest.raises(IncidentResponseBlocked):
        manager.assert_execution_allowed("agent-a")
    manager.assert_execution_allowed("agent-b")
    manager.set_agent_quarantine("agent-a", False, "operator", "Investigation complete")
    manager.assert_execution_allowed("agent-a")


def test_alert_lifecycle_is_persistent_and_terminal_after_resolution(tmp_path):
    path = str(tmp_path / "evidence.sqlite3")
    manager = IncidentResponseManager(path)
    alert = manager.create_alert("critical", "agent_action_risk", "Critical risk", "Vetoed policy mutation",
                                 decision_id="decision-1", actor_id="agent-a")
    manager.transition_alert(alert["alert_id"], "acknowledge", "operator")
    restarted = IncidentResponseManager(path)
    acknowledged = restarted.list_alerts(status="acknowledged")
    assert any(item["alert_id"] == alert["alert_id"] for item in acknowledged)
    resolved = restarted.transition_alert(alert["alert_id"], "resolve", "operator")
    assert resolved["status"] == "resolved"
    with pytest.raises(ValueError):
        restarted.transition_alert(alert["alert_id"], "acknowledge", "operator")


def test_agent_wide_token_revocation_invalidates_issued_capabilities():
    manager = AgentIdentityManager()
    manager.register("agent-a", "team-a")
    manager.grant_scope("agent-a", "read_file")
    token = manager.issue_token("agent-a", scopes=["read_file"])
    revoked = manager.revoke_agent_tokens("agent-a")
    assert revoked == 1
    assert manager.validate_token(token.token_id) is False
    assert manager.is_authorized("agent-a", "read_file", token_id=token.token_id, require_token=True) is False


def test_emergency_stop_blocks_api_execution_and_can_be_released(client, monkeypatch):
    monkeypatch.setenv("AUCTARYN_ALLOW_DIRECT_EXECUTION", "true")
    enabled = client.post(
        "/api/v1/incident/emergency-stop",
        json={"enabled": True, "reason": "Contain suspected active compromise"},
    )
    assert enabled.status_code == 200
    try:
        response = client.post(
            "/api/v1/gateway/execute",
            json={
                "tool_name": "read_file",
                "action": "read",
                "parameters": {"path": "/workspace/blocked.txt"},
                "agent_id": "incident-stop-test-agent",
            },
        )
        assert response.status_code == 423
    finally:
        disabled = client.post(
            "/api/v1/incident/emergency-stop",
            json={"enabled": False, "reason": "Incident response completed"},
        )
        assert disabled.status_code == 200


def test_critical_decision_creates_durable_alert_and_admin_can_resolve(client):
    response = client.post(
        "/api/v1/gateway/intercept",
        json={
            "tool_name": "modify_policy",
            "action": "update_policy",
            "parameters": {"target": "runtime"},
            "agent_id": "incident-alert-test-agent",
        },
    )
    assert response.status_code == 200
    page = client.get("/api/v1/incident/alerts?status=open&limit=100")
    assert page.status_code == 200
    alerts = [a for a in page.json()["alerts"] if a["decision_id"] == response.json()["id"]]
    assert alerts
    alert_id = alerts[0]["alert_id"]
    ack = client.post(f"/api/v1/incident/alerts/{alert_id}/acknowledge")
    assert ack.status_code == 200
    assert ack.json()["alert"]["status"] == "acknowledged"
    resolved = client.post(f"/api/v1/incident/alerts/{alert_id}/resolve")
    assert resolved.status_code == 200
    assert resolved.json()["alert"]["status"] == "resolved"


def test_service_credential_cannot_change_incident_controls(client, monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")
    service_client = TestClient(client.app, headers={"Authorization": "Bearer test-service-secret"})
    response = service_client.post(
        "/api/v1/incident/emergency-stop",
        json={"enabled": True, "reason": "Must be admin controlled"},
    )
    assert response.status_code == 403


def test_websocket_acknowledgement_is_admin_only_and_persistent(client):
    from modules.incident_response.manager import get_incident_response_manager
    alert = get_incident_response_manager().create_alert(
        "high", "test", "Test alert", "Safe summary", decision_id="ws-alert-decision"
    )
    with client.websocket_connect("/ws/alerts") as websocket:
        websocket.send_json({"type": "authenticate", "token": "test-service-secret"})
        assert websocket.receive_json()["type"] == "authenticated"
        websocket.send_json({"type": "acknowledge", "alert_id": alert["alert_id"]})
        assert websocket.receive_json()["type"] == "error"
    assert any(item["alert_id"] == alert["alert_id"] for item in get_incident_response_manager().list_alerts(status="open"))
    with client.websocket_connect("/ws/alerts") as websocket:
        websocket.send_json({"type": "authenticate", "token": "test-admin-secret"})
        assert websocket.receive_json()["type"] == "authenticated"
        websocket.send_json({"type": "acknowledge", "alert_id": alert["alert_id"]})
        result = websocket.receive_json()
        assert result["type"] == "alert_acknowledged"
        assert result["status"] == "acknowledged"


def test_alert_creation_deduplicates_unresolved_decision_alerts(tmp_path):
    manager = IncidentResponseManager(str(tmp_path / "evidence.sqlite3"))
    first = manager.create_alert("critical", "agent_action_risk", "Critical risk", "Vetoed action",
                                 decision_id="same-decision", actor_id="agent-a")
    second = manager.create_alert("critical", "agent_action_risk", "Critical risk", "Vetoed action",
                                  decision_id="same-decision", actor_id="agent-a")
    assert first["alert_id"] == second["alert_id"]
    assert len([a for a in manager.list_alerts() if a["decision_id"] == "same-decision"]) == 1


def test_quarantine_revokes_tokens_and_release_does_not_restore_them(client):
    agent_id = "incident-quarantine-api-agent"
    assert client.post("/api/v1/identity/register", json={"agent_id": agent_id, "owner": "team"}).status_code == 200
    assert client.post("/api/v1/identity/grant", json={"agent_id": agent_id, "scope": "read_file"}).status_code == 200
    issued = client.post("/api/v1/identity/token", json={"agent_id": agent_id, "scopes": ["read_file"]})
    assert issued.status_code == 200
    token_id = issued.json()["token_id"]

    quarantine = client.post(
        f"/api/v1/incident/agents/{agent_id}/quarantine",
        json={"quarantined": True, "reason": "Contain suspected agent compromise"},
    )
    assert quarantine.status_code == 200
    assert quarantine.json()["revoked_token_count"] == 1
    denied = client.get(
        f"/api/v1/identity/{agent_id}/authorized/read_file",
        headers={"X-Agent-Identity-Token": token_id},
    )
    assert denied.status_code == 200
    assert denied.json()["authorized"] is False

    release = client.post(
        f"/api/v1/incident/agents/{agent_id}/quarantine",
        json={"quarantined": False, "reason": "Investigation complete"},
    )
    assert release.status_code == 200
    still_denied = client.get(
        f"/api/v1/identity/{agent_id}/authorized/read_file",
        headers={"X-Agent-Identity-Token": token_id},
    )
    assert still_denied.json()["authorized"] is False


@pytest.mark.asyncio
async def test_runtime_failure_emits_durable_alert():
    from api.routes.gateway import _publish_runtime_failure_alert
    from modules.incident_response.manager import get_incident_response_manager
    fingerprint = "d" * 64
    await _publish_runtime_failure_alert("runtime-failure-agent", fingerprint, "RuntimeAdapterFailure", "decision-runtime-1")
    alerts = get_incident_response_manager().list_alerts(status="open")
    assert any(item["category"] == "runtime_failure" and item["decision_id"] == "decision-runtime-1"
               for item in alerts)


@pytest.mark.asyncio
async def test_alert_broadcast_is_not_disclosed_to_service_websocket_clients():
    from api.websockets import alerts as alerts_ws

    class FakeSocket:
        def __init__(self):
            self.messages = []

        async def send_text(self, message):
            self.messages.append(message)

    operator = FakeSocket()
    service = FakeSocket()
    previous = dict(alerts_ws._alert_clients)
    try:
        alerts_ws._alert_clients.clear()
        alerts_ws._alert_clients[operator] = "admin"
        alerts_ws._alert_clients[service] = "api"
        await alerts_ws.broadcast_alert({
            "type": "incident_alert",
            "alert": {"alert_id": "sensitive-alert", "summary": "Restricted incident metadata"},
        })
        assert len(operator.messages) == 1
        assert service.messages == []
    finally:
        alerts_ws._alert_clients.clear()
        alerts_ws._alert_clients.update(previous)
