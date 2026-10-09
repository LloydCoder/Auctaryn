"""Readiness reports configured and live runtime controls separately."""

from types import SimpleNamespace


def test_readiness_explains_missing_runtime_adapter(client):
    response = client.get("/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is False
    assert body["checks"]["trusted_runtime_adapter_configured"] is False
    assert body["checks"]["runtime_health_probe_available"] is False
    assert body["checks"]["runtime_health_probe_passed"] is False
    assert body["checks"]["openshell_connected"] is False


def test_readiness_requires_successful_openshell_health_probe(client, monkeypatch):
    class HealthyOpenShellAdapter:
        runtime_name = "openshell"

        async def health_check(self):
            return True

    monkeypatch.setattr(
        "api.routes.gateway.get_execution_service",
        lambda: SimpleNamespace(adapter=HealthyOpenShellAdapter()),
    )
    response = client.get("/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    assert body["checks"]["trusted_runtime_adapter_configured"] is True
    assert body["checks"]["runtime_health_probe_available"] is True
    assert body["checks"]["runtime_health_probe_passed"] is True
    assert body["checks"]["openshell_connected"] is True
