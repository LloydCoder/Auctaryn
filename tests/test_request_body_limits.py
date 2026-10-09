"""Regression tests for bounded API request ingress."""

def test_json_api_request_body_is_bounded_before_parsing(client, monkeypatch):
    monkeypatch.setattr("api.main.MAX_API_REQUEST_BYTES", 64)
    response = client.post(
        "/api/v1/gateway/intercept",
        headers={"Content-Type": "application/json"},
        content=b"x" * 65,
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "API request exceeds size limit"


def test_pcap_upload_uses_its_separate_bounded_ingress_limit(client, monkeypatch):
    monkeypatch.setattr("api.main.PCAP_UPLOAD_REQUEST_LIMIT", 64)
    response = client.post(
        "/api/v1/threatfade/analyze",
        headers={"Content-Type": "application/octet-stream"},
        content=b"x" * 65,
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "PCAP request exceeds size limit"
