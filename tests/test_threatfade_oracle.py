"""
TwinGuard — ThreatFade Oracle Tests (TDD Red-Green-Refactor)
Tests the FusionOps HTTP client and Parliament adapter.
Written FIRST. Implementation follows.

FusionOps API contract (v0.3.0, endpoint configured via environment):
- GET  /health
- GET  /events?limit=N
- POST /detect/json   {timestamps, values, source_label}
- POST /detect/scenario {scenario}
- POST /detect/pcap   (multipart)
- POST /triage        (DetectionResult dict)

Response shape: FullAnalysisResult { detection, triage, remediation }
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from core.models import Severity, RiskLevel, ActionDecision


# --- Sample FusionOps responses (from the documented API contract) ---

SAMPLE_FULL_RESULT = {
    "detection": {
        "event_id": "evt-001",
        "timestamp": "2026-05-27T23:24:19.836810Z",
        "source": "scenario:c2_quieting",
        "detected": True,
        "score": 0.3966,
        "entropy": 2.9616,
        "drop_ratio": 0.71,
        "z_outlier": 1.89,
        "fade_start": 50,
        "mitre_ttp": "T1205 – Traffic Signaling",
        "volatility_artifacts": "firefox.exe (PID 2847)",
        "severity": "LOW",
    },
    "triage": {
        "event_id": "evt-001",
        "triaged_at": "2026-05-27T23:24:19Z",
        "priority": "LOW",
        "category": "C2_EVASION",
        "recommended_action": "LOG_AND_WATCH",
        "confidence": 0.272,
        "reasoning": "Z-score 1.89 (LOW anomaly)",
        "mitre_ttp": "T1205 – Traffic Signaling",
        "escalate": False,
        "auto_remediate": True,
    },
    "remediation": {
        "plan_id": "plan-001",
        "event_id": "evt-001",
        "created_at": "2026-05-27T23:24:19Z",
        "threat_category": "C2_EVASION",
        "priority": "LOW",
        "recommended_action": "LOG_AND_WATCH",
        "estimated_effort": "Minimal — automated",
        "requires_human": False,
        "audit_entry": "[2026-05-27T...] FUSIONOPS REMEDIATION EVENT",
        "actions": [],
    },
}

SAMPLE_CRITICAL_RESULT = {
    "detection": {
        "event_id": "evt-002",
        "timestamp": "2026-06-30T10:00:00Z",
        "source": "agent:twinguard-001",
        "detected": True,
        "score": 0.94,
        "entropy": 7.2,
        "drop_ratio": 0.95,
        "z_outlier": 14.76,
        "fade_start": 5,
        "mitre_ttp": "T1027 – Obfuscated Files",
        "volatility_artifacts": "",
        "severity": "CRITICAL",
    },
    "triage": {
        "event_id": "evt-002",
        "triaged_at": "2026-06-30T10:00:01Z",
        "priority": "CRITICAL",
        "category": "AI_AGENT_ABUSE",
        "recommended_action": "BLOCK_IMMEDIATE",
        "confidence": 0.97,
        "reasoning": "Z-score 14.76 — severe anomaly matching known C2 pattern",
        "mitre_ttp": "T1027 – Obfuscated Files",
        "escalate": True,
        "auto_remediate": False,
    },
    "remediation": {
        "plan_id": "plan-002",
        "event_id": "evt-002",
        "created_at": "2026-06-30T10:00:01Z",
        "threat_category": "AI_AGENT_ABUSE",
        "priority": "CRITICAL",
        "recommended_action": "BLOCK_IMMEDIATE",
        "estimated_effort": "Immediate",
        "requires_human": True,
        "audit_entry": "[2026-06-30T...] CRITICAL AGENT ABUSE DETECTED",
        "actions": [],
    },
}


# --- Client tests ---

class TestFusionOpsClient:
    """HTTP client for the live FusionOps API."""

    def test_client_initialization(self, monkeypatch):
        from modules.threatfade_oracle.client import FusionOpsClient
        monkeypatch.setenv("THREATFADE_API_KEY", "test-service-token")
        client = FusionOpsClient(base_url="https://fusionops.example.test")
        assert client.base_url == "https://fusionops.example.test"

    def test_client_rejects_plaintext_external_endpoint_and_embedded_credentials(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        with pytest.raises(ValueError):
            FusionOpsClient(base_url="http://external.example.test")
        with pytest.raises(ValueError):
            FusionOpsClient(base_url="https://user:password@fusionops.example.test")

    def test_remote_endpoint_requires_service_credential(self, monkeypatch):
        from modules.threatfade_oracle.client import FusionOpsClient
        monkeypatch.delenv("THREATFADE_API_KEY", raising=False)
        with pytest.raises(ValueError, match="required for non-local"):
            FusionOpsClient(base_url="https://fusionops.example.test")

    @pytest.mark.asyncio
    async def test_remote_endpoint_sends_bearer_service_credential(self, monkeypatch):
        from modules.threatfade_oracle.client import FusionOpsClient
        monkeypatch.setenv("THREATFADE_API_KEY", "test-service-token")
        client = FusionOpsClient(base_url="https://fusionops.example.test")
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"status": "ok"}
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=response)) as get:
            await client.health_check()
        assert get.await_args.kwargs["headers"] == {
            "Authorization": "Bearer test-service-token"
        }

    def test_client_default_url(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        client = FusionOpsClient()
        assert client.base_url == "http://threatfade:8401"

    @pytest.mark.asyncio
    async def test_health_check_success(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        client = FusionOpsClient()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "ok", "service": "FusionOps API", "version": "0.3.0",
            "threatfade": "ok", "threatfade_url": "http://127.0.0.1:8000",
            "environment": "production",
        }

        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_response)):
            result = await client.health_check()
            assert result["status"] == "ok"
            assert result["threatfade"] == "ok"

    @pytest.mark.asyncio
    async def test_health_check_unreachable(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        import httpx
        client = FusionOpsClient()

        with patch("httpx.AsyncClient.get", new=AsyncMock(side_effect=httpx.ConnectError("refused"))):
            result = await client.health_check()
            assert result["status"] == "unreachable"

    @pytest.mark.asyncio
    async def test_detect_json_success(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        client = FusionOpsClient()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_FULL_RESULT

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_response)):
            result = await client.detect_json(
                timestamps=[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0],
                values=[3.1, 2.9, 2.8, 2.5, 2.1, 1.9, 1.5, 1.2, 0.9, 0.5],
                source_label="twinguard-agent-001",
            )
            assert result["detection"]["severity"] == "LOW"
            assert result["triage"]["category"] == "C2_EVASION"

    @pytest.mark.asyncio
    async def test_detect_json_insufficient_data_raises(self):
        """Fewer than 10 data points should raise before even calling the API."""
        from modules.threatfade_oracle.client import FusionOpsClient
        from core.exceptions import ThreatFadeConnectionError
        client = FusionOpsClient()

        with pytest.raises(ValueError):
            await client.detect_json(
                timestamps=[1.0, 2.0], values=[1.0, 2.0], source_label="test"
            )

    @pytest.mark.asyncio
    async def test_detect_scenario(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        client = FusionOpsClient()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_FULL_RESULT

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_response)):
            result = await client.detect_scenario("c2_quieting")
            assert result["detection"]["source"] == "scenario:c2_quieting"

    @pytest.mark.asyncio
    async def test_detect_scenario_invalid_name(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        client = FusionOpsClient()

        with pytest.raises(ValueError):
            await client.detect_scenario("not_a_real_scenario")

    @pytest.mark.asyncio
    async def test_service_unreachable_raises_custom_exception(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        from core.exceptions import ThreatFadeConnectionError
        import httpx
        client = FusionOpsClient()

        with patch("httpx.AsyncClient.post", new=AsyncMock(side_effect=httpx.ConnectError("refused"))):
            with pytest.raises(ThreatFadeConnectionError):
                await client.detect_scenario("c2_quieting")

    def test_client_rejects_invalid_timeout(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        with pytest.raises(ValueError):
            FusionOpsClient(base_url="https://fusionops.example.test", timeout=0)

    @pytest.mark.asyncio
    async def test_detect_json_rejects_non_finite_input(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        client = FusionOpsClient()
        with pytest.raises(ValueError, match="finite numbers"):
            await client.detect_json(
                timestamps=[float(i) for i in range(10)],
                values=[1.0] * 9 + [float("nan")],
                source_label="test",
            )

    @pytest.mark.asyncio
    async def test_detect_json_rejects_malformed_remote_schema(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        from core.exceptions import ThreatFadeConnectionError
        client = FusionOpsClient()
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"detection": [], "triage": {}, "remediation": {}}
        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=response)):
            with pytest.raises(ThreatFadeConnectionError, match="invalid analysis schema"):
                await client.detect_json(
                    timestamps=[float(i) for i in range(10)],
                    values=[float(i) for i in range(10)],
                    source_label="test",
                )

    @pytest.mark.asyncio
    async def test_health_check_invalid_json_fails_closed(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        client = FusionOpsClient()
        response = MagicMock()
        response.status_code = 200
        response.json.side_effect = ValueError("invalid response")
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=response)):
            result = await client.health_check()
        assert result["status"] == "unreachable"
        assert result["error"] == "ThreatFadeConnectionError"

    @pytest.mark.asyncio
    async def test_get_events_rejects_out_of_range_limit(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        client = FusionOpsClient()
        with pytest.raises(ValueError, match="between 1 and 200"):
            await client.get_events(201)

    @pytest.mark.asyncio
    async def test_pcap_rejects_filename_with_directory_component(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        client = FusionOpsClient()
        filename = "folder" + chr(47) + "sample.pcap"
        with pytest.raises(ValueError, match="basename"):
            await client.detect_pcap(b"pcap", filename)

    @pytest.mark.asyncio
    async def test_triage_rejects_non_finite_payload(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        client = FusionOpsClient()
        with pytest.raises(ValueError, match="JSON serializable"):
            await client.triage({"score": float("nan")})

    def test_json_object_rejects_oversized_response_body(self):
        from modules.threatfade_oracle.client import FusionOpsClient, MAX_RESPONSE_BYTES
        from core.exceptions import ThreatFadeConnectionError
        response = MagicMock()
        response.content = b"x" * (MAX_RESPONSE_BYTES + 1)
        with pytest.raises(ThreatFadeConnectionError, match="size limit"):
            FusionOpsClient._json_object(response, "/test")

    @pytest.mark.asyncio
    async def test_pcap_rejects_oversized_content(self, monkeypatch):
        import modules.threatfade_oracle.client as client_module
        client = client_module.FusionOpsClient()
        monkeypatch.setattr(client_module, "MAX_PCAP_BYTES", 4)
        with pytest.raises(ValueError, match="PCAP content"):
            await client.detect_pcap(b"12345", "sample.pcap")

    @pytest.mark.asyncio
    async def test_triage_rejects_oversized_payload(self, monkeypatch):
        import modules.threatfade_oracle.client as client_module
        client = client_module.FusionOpsClient()
        monkeypatch.setattr(client_module, "MAX_TRIAGE_PAYLOAD_BYTES", 4)
        with pytest.raises(ValueError, match="exceeds"):
            await client.triage({"value": "too-large"})

    @pytest.mark.asyncio
    async def test_get_events(self):
        from modules.threatfade_oracle.client import FusionOpsClient
        client = FusionOpsClient()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"events": [SAMPLE_FULL_RESULT], "total": 1, "detections": 1}

        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_response)):
            result = await client.get_events(limit=10)
            assert result["total"] == 1


# --- Parliament Adapter tests ---

class TestParliamentAdapter:
    """Maps FusionOps FullAnalysisResult to TwinGuard's internal models."""

    def test_map_low_severity_to_threatfade_result(self):
        from modules.threatfade_oracle.parliament_adapter import to_threatfade_result
        result = to_threatfade_result(SAMPLE_FULL_RESULT)
        assert result.severity == Severity.LOW
        assert result.z_score == 1.89
        assert result.entropy == 2.9616
        assert "T1205" in result.mitre_ttps[0]

    def test_map_critical_severity(self):
        from modules.threatfade_oracle.parliament_adapter import to_threatfade_result
        result = to_threatfade_result(SAMPLE_CRITICAL_RESULT)
        assert result.severity == Severity.CRITICAL
        assert result.fade_detected is True

    def test_severity_enum_mapping_all_levels(self):
        from modules.threatfade_oracle.parliament_adapter import map_severity
        assert map_severity("CRITICAL") == Severity.CRITICAL
        assert map_severity("HIGH") == Severity.HIGH
        assert map_severity("MEDIUM") == Severity.MEDIUM
        assert map_severity("LOW") == Severity.LOW
        assert map_severity("INFO") == Severity.INFO
        assert map_severity("unknown_value") == Severity.INFO

    def test_ai_agent_abuse_forces_critical_classification(self):
        """The AI_AGENT_ABUSE category should always escalate regardless of raw severity."""
        from modules.threatfade_oracle.parliament_adapter import should_escalate
        assert should_escalate(SAMPLE_CRITICAL_RESULT) is True

    def test_low_severity_c2_evasion_does_not_escalate(self):
        from modules.threatfade_oracle.parliament_adapter import should_escalate
        assert should_escalate(SAMPLE_FULL_RESULT) is False

    def test_block_immediate_maps_to_vetoed(self):
        from modules.threatfade_oracle.parliament_adapter import recommended_decision
        decision = recommended_decision(SAMPLE_CRITICAL_RESULT)
        assert decision == ActionDecision.VETOED

    def test_log_and_watch_maps_to_approved(self):
        from modules.threatfade_oracle.parliament_adapter import recommended_decision
        decision = recommended_decision(SAMPLE_FULL_RESULT)
        assert decision == ActionDecision.APPROVED

    def test_escalate_to_analyst_maps_to_pending(self):
        from modules.threatfade_oracle.parliament_adapter import recommended_decision
        result = dict(SAMPLE_FULL_RESULT)
        result["triage"] = dict(result["triage"])
        result["triage"]["recommended_action"] = "ESCALATE_TO_ANALYST"
        decision = recommended_decision(result)
        assert decision == ActionDecision.PENDING


# --- Synthetic signal generation (Option A for MVP) ---

class TestSyntheticSignalGeneration:
    """
    For MVP, TwinGuard derives entropy signal data from tool call parameters
    rather than capturing real network traffic (that's Phase 2 with OpenShell hooks).
    """

    def test_generate_signal_from_tool_call(self):
        from modules.threatfade_oracle.client import generate_synthetic_signal
        from core.models import ToolCall
        tc = ToolCall(tool_name="send_email", action="bulk", parameters={"count": 500})
        timestamps, values = generate_synthetic_signal(tc)
        assert len(timestamps) >= 10
        assert len(values) >= 10
        assert len(timestamps) == len(values)

    def test_bulk_action_produces_higher_entropy_signal(self):
        """Bulk/destructive actions should generate a more anomalous signal."""
        from modules.threatfade_oracle.client import generate_synthetic_signal
        from core.models import ToolCall

        safe_tc = ToolCall(tool_name="read_file", action="read", parameters={})
        bulk_tc = ToolCall(tool_name="delete_emails", action="bulk", parameters={"count": 500})

        _, safe_values = generate_synthetic_signal(safe_tc)
        _, bulk_values = generate_synthetic_signal(bulk_tc)

        # Bulk action signal should show more variance/drop (simulating anomaly)
        safe_range = max(safe_values) - min(safe_values)
        bulk_range = max(bulk_values) - min(bulk_values)
        assert bulk_range >= safe_range


# --- ThreatFade Oracle Service tests ---

class TestThreatFadeOracleService:
    """Full service combining client + adapter, used by API routes."""

    @pytest.mark.asyncio
    async def test_oracle_analyze_tool_call(self):
        from modules.threatfade_oracle.oracle import ThreatFadeOracle
        from core.models import ToolCall

        oracle = ThreatFadeOracle()
        tc = ToolCall(tool_name="send_email", action="bulk", parameters={"count": 50})

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_FULL_RESULT

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_response)):
            result = await oracle.analyze(tc)
            assert result.severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_oracle_falls_back_on_malformed_analysis_schema(self):
        from modules.threatfade_oracle.oracle import ThreatFadeOracle
        from core.models import ToolCall

        oracle = ThreatFadeOracle()
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"detection": [], "triage": {}, "remediation": {}}

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=response)):
            result = await oracle.analyze(
                ToolCall(tool_name="read_file", action="read", parameters={})
            )
        assert result.severity == Severity.INFO
        assert result.fade_detected is False
        assert len(oracle.history) == 1
        assert oracle.raw_results == []

    @pytest.mark.asyncio
    async def test_oracle_circuit_breaker_opens_after_repeated_failures(self):
        from modules.threatfade_oracle.oracle import ThreatFadeOracle
        from core.exceptions import ThreatFadeConnectionError
        from core.models import ToolCall

        oracle = ThreatFadeOracle()
        oracle.oracle_failure_threshold = 2
        oracle.client.detect_json = AsyncMock(
            side_effect=ThreatFadeConnectionError("simulated service error")
        )
        call = ToolCall(tool_name="read_file", action="read", parameters={})

        await oracle.analyze(call)
        await oracle.analyze(call)
        assert oracle._oracle_breaker_state() == "open"
        await oracle.analyze(call)
        assert oracle.client.detect_json.await_count == 2
        assert oracle.history[-1].severity == Severity.INFO

    @pytest.mark.asyncio
    async def test_oracle_half_open_probe_resets_after_success(self, monkeypatch):
        import modules.threatfade_oracle.oracle as oracle_module
        from modules.threatfade_oracle.oracle import ThreatFadeOracle
        from core.exceptions import ThreatFadeConnectionError
        from core.models import ToolCall

        clock = [100.0]
        monkeypatch.setattr(oracle_module.time, "monotonic", lambda: clock[0])
        oracle = ThreatFadeOracle()
        oracle.oracle_failure_threshold = 1
        oracle.client.detect_json = AsyncMock(
            side_effect=[ThreatFadeConnectionError("simulated service error"), SAMPLE_FULL_RESULT]
        )
        call = ToolCall(tool_name="read_file", action="read", parameters={})

        await oracle.analyze(call)
        assert oracle._oracle_breaker_state() == "open"
        clock[0] += 31
        result = await oracle.analyze(call)
        assert result.severity == Severity.LOW
        assert oracle._oracle_breaker_state() == "closed"
        assert oracle.client.detect_json.await_count == 2

    @pytest.mark.asyncio
    async def test_oracle_tracks_history(self):
        from modules.threatfade_oracle.oracle import ThreatFadeOracle
        from core.models import ToolCall

        oracle = ThreatFadeOracle()
        tc = ToolCall(tool_name="read_file", action="read", parameters={})

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_FULL_RESULT

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_response)):
            await oracle.analyze(tc)
            assert len(oracle.history) == 1

    @pytest.mark.asyncio
    async def test_oracle_graceful_fallback_when_unreachable(self):
        """If FusionOps is down, TwinGuard should NOT crash — fail safe."""
        from modules.threatfade_oracle.oracle import ThreatFadeOracle
        from core.models import ToolCall
        import httpx

        oracle = ThreatFadeOracle()
        tc = ToolCall(tool_name="read_file", action="read", parameters={})

        with patch("httpx.AsyncClient.post", new=AsyncMock(side_effect=httpx.ConnectError("refused"))):
            result = await oracle.analyze(tc)
            # Graceful fallback: returns a safe/info-level result, doesn't crash
            assert result.severity == Severity.INFO
            assert result.fade_detected is False
