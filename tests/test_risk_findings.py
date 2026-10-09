"""Regression tests for bounded, explainable advisory risk findings."""
from core.models import RiskLevel
from modules.execution_gateway.risk_findings import build_risk_findings


def test_finding_is_stable_and_carries_provenance_without_raw_parameters():
    kwargs = {
        "tool_name": "delete_files",
        "action": "bulk_delete",
        "risk_level": RiskLevel.DESTRUCTIVE,
        "confidence": 0.91,
        "reason": "Destructive action matched.",
        "matched_pattern": "delete_pattern_v1",
        "input_fingerprint": "a" * 64,
    }
    first = build_risk_findings(**kwargs)
    second = build_risk_findings(**kwargs)
    assert first == second
    finding = first[0]
    assert finding["finding_id"] == second[0]["finding_id"]
    assert finding["severity"] == "high"
    assert "OWASP-ASI02" in finding["control_refs"]
    assert finding["provenance"] == {
        "source": "caller_supplied_action_metadata",
        "analyzer": "local_pattern_classifier",
        "runtime_observed": False,
    }
    assert "parameters" not in finding
    assert "input_fingerprint" not in finding


def test_unknown_action_is_explained_as_low_confidence_not_authorized():
    finding = build_risk_findings(
        tool_name="custom_connector",
        action="mystery_operation",
        risk_level=RiskLevel.MODERATE,
        confidence=0.35,
        reason="Unrecognized tool/action; operator approval is required.",
        matched_pattern="unrecognized",
        input_fingerprint="b" * 64,
    )[0]
    assert finding["severity"] == "medium"
    assert finding["confidence"] == 0.35
    assert "authoritative policy engine" in finding["recommendation"]
    assert finding["evidence_refs"] == ["request_fingerprint"]


def test_finding_bounds_untrusted_explanation_and_rule():
    finding = build_risk_findings(
        tool_name="tool",
        action="action",
        risk_level=RiskLevel.CRITICAL,
        confidence=9.0,
        reason="X" * 2000,
        matched_pattern="R" * 500,
        input_fingerprint="c" * 64,
    )[0]
    assert len(finding["rationale"]) <= 512
    assert len(finding["rule_id"]) <= 128
    assert finding["confidence"] == 1.0
    assert finding["severity"] == "critical"


def test_risk_api_returns_advisory_findings_without_changing_authority(client):
    response = client.post(
        "/api/v1/risk/assess",
        json={
            "tool_name": "delete_files",
            "action": "bulk_delete",
            "parameters": {"count": 20},
            "agent_id": "phase15-test-agent",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["contract_version"] == "auctaryn-risk-assessment.v1"
    assert body["authority"] == "advisory_only"
    assert body["evidence_quality"] == "caller_supplied_metadata"
    assert len(body["findings"]) == 1
    finding = body["findings"][0]
    assert finding["finding_type"] == "advisory_action_risk"
    assert finding["provenance"]["runtime_observed"] is False
    assert "decision" not in body
    assert "execution" not in body
    assert "parameters" not in finding
