"""Regression tests for API authentication and privileged operations."""
from fastapi.testclient import TestClient

from api.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def test_api_routes_fail_closed_when_credentials_are_not_configured(monkeypatch):
    monkeypatch.delenv("AUCTARYN_API_KEY", raising=False)
    monkeypatch.delenv("AUCTARYN_ADMIN_API_KEY", raising=False)

    response = _client().get("/api/v1/gateway/status")

    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_api_routes_require_bearer_credential(monkeypatch):
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")

    response = _client().get("/api/v1/gateway/status")

    assert response.status_code == 401


def test_service_credential_cannot_access_identity_administration(monkeypatch):
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")

    response = _client().get(
        "/api/v1/identity/unknown-agent",
        headers={"Authorization": "Bearer test-service-secret"},
    )

    assert response.status_code == 403


def test_admin_credential_can_reach_identity_route(monkeypatch):
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")

    response = _client().get(
        "/api/v1/identity/unknown-agent",
        headers={"Authorization": "Bearer test-admin-secret"},
    )

    assert response.status_code == 404


def test_health_liveness_remains_available_without_api_credentials(monkeypatch):
    monkeypatch.delenv("AUCTARYN_API_KEY", raising=False)
    monkeypatch.delenv("AUCTARYN_ADMIN_API_KEY", raising=False)

    response = _client().get("/health")

    assert response.status_code == 200

def test_identical_service_and_admin_keys_fail_closed(monkeypatch):
    monkeypatch.setenv("AUCTARYN_API_KEY", "same-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "same-secret")

    response = _client().get(
        "/api/v1/gateway/status",
        headers={"Authorization": "Bearer same-secret"},
    )

    assert response.status_code == 503


def test_service_websocket_credential_cannot_approve(monkeypatch):
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")

    with _client() as client:
        with client.websocket_connect("/ws/actions", headers={"origin": "http://localhost:3000"}) as websocket:
            websocket.send_json({"type": "authenticate", "token": "test-service-secret"})
            assert websocket.receive_json()["role"] == "api"
            websocket.send_json({
                "type": "approve",
                "decision_id": "does-not-exist",
                "approved": True,
            })
            response = websocket.receive_json()
            assert response["type"] == "error"
            assert response["message"] == "Administrator credential required"

def test_service_credential_cannot_approve_pending_action(monkeypatch):
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")

    response = _client().post(
        "/api/v1/gateway/approve",
        headers={"Authorization": "Bearer test-service-secret"},
        json={"decision_id": "not-pending", "approved": True, "reason": "test"},
    )

    assert response.status_code == 403


def test_service_credential_cannot_register_agent(monkeypatch):
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")

    response = _client().post(
        "/api/v1/identity/register",
        headers={"Authorization": "Bearer test-service-secret"},
        json={"agent_id": "agent-forbidden", "owner": "test"},
    )

    assert response.status_code == 403



def test_approval_endpoint_returns_conflict_when_action_intent_changes(monkeypatch):
    from api.routes import gateway as gateway_routes
    from core.models import ActionDecision, ToolCall
    from modules.execution_gateway.gateway import ExecutionGateway

    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")
    gateway = ExecutionGateway()
    monkeypatch.setattr(gateway_routes, "_gateway", gateway)
    decision = gateway.evaluate(
        ToolCall(
            tool_name="delete_file",
            action="delete",
            parameters={"path": "/tmp/original.db"},
            agent_id="approval-intent-test",
        )
    )
    assert decision.decision == ActionDecision.PENDING
    decision.tool_call.parameters["path"] = "/tmp/changed.db"

    response = _client().post(
        "/api/v1/gateway/approve",
        headers={"Authorization": "Bearer test-admin-secret"},
        json={"decision_id": decision.id, "approved": True, "reason": "test"},
    )

    assert response.status_code == 409
    assert "intent changed" in response.json()["detail"]
    assert gateway.history[0].decision == ActionDecision.DENIED



def test_execute_approved_endpoint_returns_conflict_for_mutated_decision(monkeypatch):
    from api.routes import gateway as gateway_routes
    from core.models import ActionDecision, ToolCall
    from modules.execution_gateway.gateway import ExecutionGateway

    class NeverCalledAdapter:
        async def execute(self, tool_call, *, idempotency_key):
            raise AssertionError("mutated action must not reach the runtime adapter")

    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")
    gateway = ExecutionGateway()
    monkeypatch.setattr(gateway_routes, "_gateway", gateway)
    adapter = NeverCalledAdapter()
    gateway_routes.configure_runtime_adapter(adapter)
    try:
        pending = gateway.evaluate(
            ToolCall(
                tool_name="delete_file",
                action="delete",
                parameters={"path": "/tmp/original.db"},
                agent_id="approval-intent-test",
            )
        )
        assert pending.decision == ActionDecision.PENDING
        approved = gateway.resolve_pending(
            pending.id, approved=True, operator="authenticated_operator"
        )
        approved.tool_call.parameters["path"] = "/tmp/changed.db"

        response = _client().post(
            f"/api/v1/gateway/execute/approved/{approved.id}",
            headers={"Authorization": "Bearer test-admin-secret"},
        )
    finally:
        gateway_routes.configure_runtime_adapter(None)

    assert response.status_code == 409
    assert "intent integrity" in response.json()["detail"]
