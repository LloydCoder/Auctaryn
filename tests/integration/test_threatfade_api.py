"""
TwinGuard — ThreatFade Oracle + Parliament Integration Tests
Mocked FusionOps calls (no live network dependency in CI).
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


SAMPLE_CRITICAL = {
    "detection": {
        "event_id": "evt-100", "timestamp": "2026-06-30T10:00:00Z",
        "source": "agent:test", "detected": True, "score": 0.94,
        "entropy": 7.2, "drop_ratio": 0.95, "z_outlier": 14.76,
        "fade_start": 5, "mitre_ttp": "T1027 – Obfuscated Files",
        "volatility_artifacts": "", "severity": "CRITICAL",
    },
    "triage": {
        "event_id": "evt-100", "triaged_at": "2026-06-30T10:00:01Z",
        "priority": "CRITICAL", "category": "AI_AGENT_ABUSE",
        "recommended_action": "BLOCK_IMMEDIATE", "confidence": 0.97,
        "reasoning": "Z-score 14.76", "mitre_ttp": "T1027",
        "escalate": True, "auto_remediate": False,
    },
    "remediation": {
        "plan_id": "plan-100", "event_id": "evt-100",
        "created_at": "2026-06-30T10:00:01Z", "threat_category": "AI_AGENT_ABUSE",
        "priority": "CRITICAL", "recommended_action": "BLOCK_IMMEDIATE",
        "estimated_effort": "Immediate", "requires_human": True,
        "audit_entry": "x", "actions": [],
    },
}

SAMPLE_BENIGN = {
    "detection": {
        "event_id": "evt-101", "timestamp": "2026-06-30T10:00:00Z",
        "source": "agent:test", "detected": False, "score": 0.05,
        "entropy": 2.9, "drop_ratio": 0.1, "z_outlier": 0.4,
        "fade_start": 0, "mitre_ttp": "", "volatility_artifacts": "",
        "severity": "INFO",
    },
    "triage": {
        "event_id": "evt-101", "triaged_at": "2026-06-30T10:00:01Z",
        "priority": "INFO", "category": "FALSE_POSITIVE",
        "recommended_action": "DISMISS", "confidence": 0.1,
        "reasoning": "Normal traffic", "mitre_ttp": "",
        "escalate": False, "auto_remediate": True,
    },
    "remediation": {
        "plan_id": "plan-101", "event_id": "evt-101",
        "created_at": "2026-06-30T10:00:01Z", "threat_category": "FALSE_POSITIVE",
        "priority": "INFO", "recommended_action": "DISMISS",
        "estimated_effort": "None", "requires_human": False,
        "audit_entry": "x", "actions": [],
    },
}


class TestThreatFadeAPI:
    def test_status_endpoint(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "ok", "service": "FusionOps API", "version": "0.3.0",
            "threatfade": "ok", "threatfade_url": "http://127.0.0.1:8000",
        }
        with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_response)):
            r = client.get("/api/v1/threatfade/status")
            assert r.status_code == 200
            assert r.json()["connected"] is True

    def test_status_unreachable(self, client):
        import httpx
        with patch("httpx.AsyncClient.get", new=AsyncMock(side_effect=httpx.ConnectError("refused"))):
            r = client.get("/api/v1/threatfade/status")
            assert r.status_code == 200
            assert r.json()["connected"] is False

    def test_run_scenario(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_BENIGN
        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_response)):
            r = client.post("/api/v1/threatfade/scenario", json={"scenario": "normal_with_fade"})
            assert r.status_code == 200
            assert r.json()["severity"] == "info"

    def test_run_invalid_scenario(self, client):
        r = client.post("/api/v1/threatfade/scenario", json={"scenario": "fake_scenario_xyz"})
        assert r.status_code == 400

    def test_list_results_after_scenario(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_BENIGN
        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_response)):
            client.post("/api/v1/threatfade/scenario", json={"scenario": "mixed"})
        r = client.get("/api/v1/threatfade/results")
        assert r.status_code == 200
        assert len(r.json()) >= 1


class TestParliamentEscalation:
    """The key integration: Execution Gateway consults ThreatFade Oracle
    and escalates pattern-approved/pending actions when the network oracle
    detects critical severity."""

    def test_full_intercept_escalates_on_critical_oracle_verdict(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_CRITICAL

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_response)):
            r = client.post("/api/v1/gateway/intercept/full", json={
                "tool_name": "send_email", "action": "bulk",
                "parameters": {"recipients": list(range(50))}
            })
        assert r.status_code == 200
        d = r.json()
        # Pattern alone would have queued this as PENDING; Oracle escalates to VETOED
        assert d["decision"] == "vetoed"
        assert "ESCALATED" in d["reason"]

    def test_full_intercept_does_not_escalate_on_benign_oracle_verdict(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = SAMPLE_BENIGN

        with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_response)):
            r = client.post("/api/v1/gateway/intercept/full", json={
                "tool_name": "delete_emails", "action": "bulk",
                "parameters": {"count": 200}
            })
        assert r.status_code == 200
        d = r.json()
        # Pattern says destructive → PENDING. Oracle says benign → stays PENDING (not auto-approved)
        assert d["decision"] == "pending"

    def test_safe_actions_skip_oracle_entirely(self, client):
        """Safe actions shouldn't trigger an Oracle call at all — saves latency."""
        with patch("httpx.AsyncClient.post") as mock_post:
            r = client.post("/api/v1/gateway/intercept/full", json={
                "tool_name": "read_file", "action": "read", "parameters": {}
            })
            assert r.status_code == 200
            assert r.json()["decision"] == "approved"
            mock_post.assert_not_called()

    def test_oracle_failure_does_not_crash_gateway(self, client):
        """If FusionOps is down mid-request, gateway falls back to pattern verdict."""
        import httpx
        with patch("httpx.AsyncClient.post", new=AsyncMock(side_effect=httpx.ConnectError("refused"))):
            r = client.post("/api/v1/gateway/intercept/full", json={
                "tool_name": "delete_file", "action": "delete",
                "parameters": {"path": "/tmp/x"}
            })
        assert r.status_code == 200
        # Falls back to pattern-only verdict (PENDING for destructive), doesn't 500
        assert r.json()["decision"] in ("pending", "vetoed")
