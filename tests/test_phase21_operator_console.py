"""Phase 21 regressions for administrator console API contracts."""
from fastapi.testclient import TestClient

from api.main import app
from modules.incident_response.manager import get_incident_response_manager


def test_incident_and_evidence_surfaces_are_admin_only(client, monkeypatch):
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")
    service = TestClient(app, headers={"Authorization": "Bearer test-service-secret"})

    assert service.get("/api/v1/incident/status").status_code == 403
    assert service.get("/api/v1/incident/alerts").status_code == 403
    assert service.get("/api/v1/evidence/records").status_code == 403
    assert service.get("/api/v1/evidence/verify").status_code == 403

    status = client.get("/api/v1/incident/status")
    assert status.status_code == 200
    assert "emergency_stop" in status.json()
    assert "alert_counts" in status.json()

    records = client.get("/api/v1/evidence/records?limit=5")
    assert records.status_code == 200
    assert records.json()["schema"] == "auctaryn.evidence-page.v1"
    assert len(records.json()["records"]) <= 5
    assert client.get("/api/v1/evidence/verify").status_code == 200


def test_incident_alert_lifecycle_contract_is_visible_to_admin(client):
    manager = get_incident_response_manager()
    alert = manager.create_alert(
        "high", "phase21_test", "Console lifecycle test", "Safe test summary",
        decision_id="phase21-console-lifecycle", actor_id="test-agent",
    )
    listed = client.get("/api/v1/incident/alerts?status=open&limit=10")
    assert listed.status_code == 200
    assert any(item["alert_id"] == alert["alert_id"] for item in listed.json()["alerts"])

    acknowledged = client.post(f"/api/v1/incident/alerts/{alert['alert_id']}/acknowledge")
    assert acknowledged.status_code == 200
    assert acknowledged.json()["alert"]["status"] == "acknowledged"

    resolved = client.post(f"/api/v1/incident/alerts/{alert['alert_id']}/resolve")
    assert resolved.status_code == 200
    assert resolved.json()["alert"]["status"] == "resolved"
