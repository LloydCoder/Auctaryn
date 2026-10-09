"""Regression tests for ThreatFade resilience, input validation and advisory boundaries."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from core.exceptions import ThreatFadeConnectionError
from core.models import Severity, ToolCall
from modules.threatfade_oracle.client import FusionOpsClient, MAX_PCAP_BYTES
from modules.threatfade_oracle.oracle import OracleCircuitBreaker, ThreatFadeOracle


def _analysis_payload(severity="INFO"):
    return {
        "detection": {
            "severity": severity, "score": 0.1, "entropy": 2.0,
            "drop_ratio": 0.1, "z_outlier": 0.2, "detected": False,
        },
        "triage": {"confidence": 0.2, "escalate": False},
    }


def _response(payload, *, content=b"{}"):
    return SimpleNamespace(
        headers={"content-length": str(len(content))},
        content=content,
        json=lambda: payload,
    )


def test_synthetic_signal_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AUCTARYN_THREATFADE_ALLOW_SYNTHETIC_SIGNAL", raising=False)
    oracle = ThreatFadeOracle()
    oracle.client.detect_json = AsyncMock(side_effect=AssertionError("must not call upstream"))
    result = asyncio.run(oracle.analyze(ToolCall(
        tool_name="delete_file", action="delete", agent_id="agent-test",
    )))
    assert result.severity == Severity.INFO
    assert result.source_file == "synthetic-analysis-disabled"
    oracle.client.detect_json.assert_not_awaited()


def test_analysis_response_rejects_unknown_severity():
    with pytest.raises(ThreatFadeConnectionError, match="invalid severity"):
        FusionOpsClient._parse_json_response(_response(_analysis_payload("UNRECOGNIZED")), analysis=True)


def test_analysis_response_rejects_nan_scores():
    payload = _analysis_payload()
    payload["detection"]["score"] = float("nan")
    with pytest.raises(ThreatFadeConnectionError, match="invalid score"):
        FusionOpsClient._parse_json_response(_response(payload), analysis=True)


def test_response_size_limit_rejects_oversized_content():
    with pytest.raises(ThreatFadeConnectionError, match="size limit"):
        FusionOpsClient._parse_json_response(_response({}, content=b"x" * (MAX_PCAP_BYTES + 1)))


def test_circuit_breaker_opens_after_threshold_and_resets_on_success():
    breaker = OracleCircuitBreaker(failure_threshold=2, cooldown_seconds=60)
    assert breaker.allow_request() is True
    breaker.record_failure()
    assert breaker.allow_request() is True
    breaker.record_failure()
    assert breaker.allow_request() is False
    breaker.reset()
    assert breaker.allow_request() is True
    breaker.record_failure()
    breaker.record_success()
    assert breaker.allow_request() is True


def test_threatfade_service_token_is_sent_as_bearer_header(monkeypatch):
    monkeypatch.setenv("THREATFADE_SERVICE_TOKEN", "service-test-token")
    client = FusionOpsClient(base_url="https://threatfade.example")
    assert client._headers["Authorization"] == "Bearer service-test-token"


def test_threatfade_service_token_rejects_control_characters(monkeypatch):
    monkeypatch.setenv("THREATFADE_SERVICE_TOKEN", "bad\nvalue")
    with pytest.raises(ValueError, match="invalid characters"):
        FusionOpsClient(base_url="https://threatfade.example")


def test_pcap_client_rejects_path_like_filename_and_oversized_payload():
    client = FusionOpsClient()
    with pytest.raises(ValueError, match="filename"):
        asyncio.run(client.detect_pcap(b"pcap", "../capture.pcap"))
    with pytest.raises(ValueError, match="between 1 byte"):
        asyncio.run(client.detect_pcap(b"x" * (MAX_PCAP_BYTES + 1), "capture.pcap"))


def test_events_limit_is_bounded():
    client = FusionOpsClient()
    with pytest.raises(ValueError, match="between 1 and 200"):
        asyncio.run(client.get_events(100_000))



def test_pcap_api_rejects_oversized_upload_before_forwarding(client, monkeypatch):
    import api.routes.threatfade as route_module

    monkeypatch.setattr(route_module, "MAX_PCAP_BYTES", 3)
    response = client.post(
        "/api/v1/threatfade/analyze",
        files={"file": ("capture.pcap", b"four", "application/octet-stream")},
    )
    assert response.status_code == 413
