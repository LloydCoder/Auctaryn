"""Contract tests for Auctaryn's Platform-consumable advisory risk API."""

def test_risk_assessment_is_versioned_and_never_authorizes(client):
    response = client.post(
        "/api/v1/risk/assess",
        json={
            "tool_name": "read_file",
            "action": "read",
            "parameters": {"path": "/workspace/report.txt"},
            "agent_id": "platform-agent",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["contract_version"] == "auctaryn-risk-assessment.v1"
    assert body["authority"] == "advisory_only"
    assert body["risk_level"] == "safe"
    assert 0.0 <= body["confidence"] <= 1.0
    assert len(body["input_fingerprint"]) == 64
    assert "decision" not in body
    assert "execution" not in body
    assert "parameters" not in body
    assert "identity_token" not in body


def test_risk_assessment_rejects_raw_secrets_without_echoing_them(client):
    secret = "never-return-this-raw-password"
    response = client.post(
        "/api/v1/risk/assess",
        json={
            "tool_name": "http_request",
            "action": "send",
            "parameters": {"password": secret},
            "agent_id": "platform-agent",
        },
    )

    assert response.status_code == 422
    assert "parameters.password" in response.json()["detail"]["paths"]
    assert secret not in response.text


def test_risk_contract_rejects_untrusted_tenant_identity_fields(client):
    response = client.post(
        "/api/v1/risk/assess",
        json={
            "tool_name": "read_file",
            "action": "read",
            "parameters": {"path": "/workspace/report.txt"},
            "agent_id": "platform-agent",
            "tenant_id": "caller-asserted-tenant",
        },
    )
    assert response.status_code == 422
    assert "tenant_id" in response.text
