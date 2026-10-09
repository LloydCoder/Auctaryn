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


def test_detailed_health_uses_the_same_live_openshell_probe(client, monkeypatch):
    class HealthyOpenShellAdapter:
        runtime_name = "openshell"

        async def health_check(self):
            return True

    monkeypatch.setattr(
        "api.routes.gateway.get_execution_service",
        lambda: SimpleNamespace(adapter=HealthyOpenShellAdapter()),
    )
    response = client.get("/health/detailed")

    assert response.status_code == 200
    body = response.json()
    assert body["openshell_connected"] is True
    runtime = next(module for module in body["modules"] if module["name"] == "openshell_runtime")
    assert runtime["status"] == "healthy"
    assert runtime["error_message"] is None
    # The other enabled modules still have no live probes, so aggregate health
    # remains degraded rather than overstating overall readiness.
    assert body["overall_status"] == "degraded"


def test_readiness_fails_closed_when_runtime_probe_times_out(client, monkeypatch):
    import asyncio

    class HangingOpenShellAdapter:
        runtime_name = "openshell"

        async def health_check(self):
            await asyncio.sleep(0.1)
            return True

    monkeypatch.setattr(
        "api.routes.gateway.get_execution_service",
        lambda: SimpleNamespace(adapter=HangingOpenShellAdapter()),
    )
    monkeypatch.setattr("api.routes.health.RUNTIME_PROBE_TIMEOUT_SECONDS", 0.001)
    response = client.get("/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is False
    assert body["checks"]["runtime_health_probe_passed"] is False
    assert body["checks"]["openshell_connected"] is False


def test_detailed_health_does_not_claim_probe_is_unimplemented(client):
    response = client.get("/health/detailed")

    assert response.status_code == 200
    body = response.json()
    assert body["openshell_connected"] is False
    runtime = next(module for module in body["modules"] if module["name"] == "openshell_runtime")
    assert runtime["status"] == "degraded"
    assert "not configured" in runtime["error_message"].lower()
