"""Adversarial regression tests for the ThreatFade Oracle trust boundary."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.exceptions import ThreatFadeConnectionError
from core.models import ToolCall, Severity
from modules.threatfade_oracle.client import (
    FusionOpsClient,
    MAX_JSON_RESPONSE_BYTES,
)
from modules.threatfade_oracle.oracle import ThreatFadeOracle


def test_external_endpoint_requires_service_credential(monkeypatch):
    monkeypatch.delenv("THREATFADE_SERVICE_TOKEN", raising=False)
    with pytest.raises(ValueError, match="required for external"):
        FusionOpsClient(base_url="https://threatfade.example.test")


def test_external_endpoint_uses_bearer_service_credential(monkeypatch):
    monkeypatch.setenv("THREATFADE_SERVICE_TOKEN", "test-service-token")
    client = FusionOpsClient(base_url="https://threatfade.example.test")
    assert client._headers["Authorization"] == "Bearer test-service-token"


def test_invalid_timeout_is_rejected_before_client_use(monkeypatch):
    monkeypatch.setenv("THREATFADE_SERVICE_TOKEN", "test-service-token")
    with pytest.raises(ValueError, match="between 0.1 and 60"):
        FusionOpsClient(base_url="https://threatfade.example.test", timeout=0.01)


def test_oversized_json_response_is_rejected():
    response = MagicMock()
    response.headers = {}
    response.content = b"x" * (MAX_JSON_RESPONSE_BYTES + 1)
    with pytest.raises(ThreatFadeConnectionError, match="size limit"):
        FusionOpsClient._parse_json_response(response)


@pytest.mark.asyncio
async def test_malformed_analysis_schema_is_rejected():
    client = FusionOpsClient()
    response = MagicMock()
    response.headers = {}
    response.content = b"{}"
    response.json.return_value = {"detection": [], "triage": {}}
    response.raise_for_status.return_value = None

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=response)):
        with pytest.raises(ThreatFadeConnectionError, match="missing detection or triage"):
            await client.detect_json(
                timestamps=[float(i) for i in range(10)],
                values=[float(i) for i in range(10)],
                source_label="test",
            )


@pytest.mark.asyncio
async def test_oracle_fails_conservatively_and_opens_breaker(monkeypatch):
    monkeypatch.setenv("AUCTARYN_THREATFADE_ALLOW_SYNTHETIC_SIGNAL", "true")
    oracle = ThreatFadeOracle()
    oracle.circuit_breaker.failure_threshold = 2
    oracle.client.detect_json = AsyncMock(
        side_effect=ThreatFadeConnectionError("upstream internal detail")
    )
    call = ToolCall(tool_name="read_file", action="read", parameters={})

    first = await oracle.analyze(call)
    second = await oracle.analyze(call)
    third = await oracle.analyze(call)

    assert first.severity == Severity.INFO
    assert second.severity == Severity.INFO
    assert third.severity == Severity.INFO
    assert oracle.client.detect_json.await_count == 2
    assert oracle.history[-1].source_file == "threatfade-circuit-open"
    assert oracle.raw_results == []
