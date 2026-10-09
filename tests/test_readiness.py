    _set_strong_credentials(monkeypatch)\n    _set_strong_credentials(monkeypatch)\n    _set_strong_credentials(monkeypatch)\n    _set_strong_credentials(monkeypatch)\n    _set_strong_credentials(monkeypatch)\n"""Readiness reports configured and live runtime controls separately."""

import logging
from types import SimpleNamespace\n\n\ndef _set_strong_credentials(monkeypatch):\n    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-key-0123456789abcdef")\n    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-key-0123456789abcdef")

import pytest


def test_readiness_explains_missing_runtime_adapter(client, monkeypatch):
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


def test_detailed_health_does_not_claim_probe_is_unimplemented(client, monkeypatch):
    response = client.get("/health/detailed")

    assert response.status_code == 200
    body = response.json()
    assert body["openshell_connected"] is False
    runtime = next(module for module in body["modules"] if module["name"] == "openshell_runtime")
    assert runtime["status"] == "degraded"
    assert "not configured" in runtime["error_message"].lower()


@pytest.mark.asyncio
async def test_startup_keeps_unhealthy_runtime_adapter_disabled(monkeypatch, tmp_path):
    from fastapi import FastAPI
    from api.main import lifespan

    class UnhealthyAdapter:
        closed = False

        async def health_check(self):
            return False

        def close(self):
            self.closed = True

    adapter = UnhealthyAdapter()
    configured = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("api.main.create_openshell_adapter_from_environment", lambda: adapter)
    monkeypatch.setattr("api.main.setup_logging", lambda **kwargs: logging.getLogger("startup-test"))
    monkeypatch.setattr(
        "api.main.gateway.configure_runtime_adapter",
        lambda value: configured.append(value),
    )

    async with lifespan(FastAPI()):
        assert configured and all(value is None for value in configured)
        assert adapter.closed is True
