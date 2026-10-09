"""API authorization and gateway-to-evidence integration tests."""
from fastapi.testclient import TestClient


def test_evidence_inspection_requires_administrator(client, monkeypatch):
    response = client.get("/api/v1/evidence/verify")
    assert response.status_code == 200
    assert response.json()["valid"] is True

    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")
    service_client = TestClient(client.app, headers={"Authorization": "Bearer test-service-secret"})
    denied = service_client.get("/api/v1/evidence/records")
    assert denied.status_code == 403


def test_gateway_decision_is_recorded_without_raw_action_parameters(client):
    response = client.post(
        "/api/v1/gateway/intercept",
        json={
            "tool_name": "read_file",
            "action": "read",
            "parameters": {"path": "/workspace/safe.txt"},
            "agent_id": "evidence-test-agent",
        },
    )
    assert response.status_code == 200
    decision_id = response.json()["id"]

    page = client.get("/api/v1/evidence/records?limit=100")
    assert page.status_code == 200
    records = page.json()["records"]
    matched = [record for record in records if record["event_type"] == "decision.created"
               and record["decision_id"] == decision_id]
    assert matched
    assert "parameters" not in matched[-1]["details"]
    assert "path" not in matched[-1]["details"]


def test_execution_intent_is_recorded_before_missing_runtime_is_reported(client):
    response = client.post(
        "/api/v1/gateway/execute",
        json={
            "tool_name": "read_file",
            "action": "read",
            "parameters": {"path": "/workspace/report.txt"},
            "agent_id": "evidence-preflight-agent",
        },
    )
    assert response.status_code == 503
    page = client.get("/api/v1/evidence/records?limit=100")
    assert page.status_code == 200
    assert any(
        record["event_type"] == "execution.requested"
        and record["actor_id"] == "evidence-preflight-agent"
        for record in page.json()["records"]
    )
