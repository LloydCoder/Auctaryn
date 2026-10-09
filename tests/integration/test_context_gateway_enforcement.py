"""End-to-end context-integrity enforcement at the gateway boundary."""

def _register_scope(client, agent_id: str, tool_name: str) -> str:
    registered = client.post("/api/v1/identity/register", json={"agent_id": agent_id, "owner": "context-enforcement-test"})
    assert registered.status_code == 200
    granted = client.post("/api/v1/identity/grant", json={"agent_id": agent_id, "scope": tool_name})
    assert granted.status_code == 200
    issued = client.post("/api/v1/identity/token", json={"agent_id": agent_id, "scopes": [tool_name]})
    assert issued.status_code == 200
    return issued.json()["token_id"]


def test_compromised_session_is_denied_until_admin_clear_and_fresh_check(client):
    registered = client.post("/api/v1/context/register", json={
        "tag": "customer_delete_safety",
        "content": "Never delete customer records without explicit confirmation.",
    })
    assert registered.status_code == 200
    session_id = "context-enforcement-session"
    check = client.post("/api/v1/context/check", json={
        "session_id": session_id, "context": "User asks to delete every customer record.",
    })
    assert check.status_code == 200
    assert check.json()["status"] == "compromised"
    assert check.json()["blocked"] is True

    token_id = _register_scope(client, "context-enforcement-agent", "read_file")
    payload = {
        "tool_name": "read_file", "action": "read",
        "parameters": {"path": "/documents/report.pdf"},
        "agent_id": "context-enforcement-agent", "session_id": session_id,
        "context_check_id": check.json()["id"], "identity_token": token_id,
    }
    denied = client.post("/api/v1/gateway/intercept", json=payload)
    assert denied.status_code == 200
    assert denied.json()["decision"] == "denied"
    assert denied.json()["decided_by"] == "context_integrity_guard"

    service_key = client.post(
        f"/api/v1/context/sessions/{session_id}/clear",
        headers={"Authorization": "Bearer test-service-secret"},
    )
    assert service_key.status_code == 403
    cleared = client.post(f"/api/v1/context/sessions/{session_id}/clear")
    assert cleared.status_code == 200

    unchecked = client.post("/api/v1/gateway/intercept", json=payload)
    assert unchecked.status_code == 200
    assert unchecked.json()["decision"] == "denied"

    clean = client.post("/api/v1/context/check", json={
        "session_id": session_id,
        "context": "Never delete customer records without explicit confirmation.\nUser asks for a report.",
    })
    assert clean.status_code == 200
    assert clean.json()["status"] == "intact"
    payload["context_check_id"] = clean.json()["id"]
    allowed = client.post("/api/v1/gateway/intercept", json=payload)
    assert allowed.status_code == 200
    assert allowed.json()["decision"] == "approved"

    replayed = client.post("/api/v1/gateway/intercept", json=payload)
    assert replayed.status_code == 200
    assert replayed.json()["decision"] == "denied"
    assert replayed.json()["decided_by"] == "context_integrity_guard"
