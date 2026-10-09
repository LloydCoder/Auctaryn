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
