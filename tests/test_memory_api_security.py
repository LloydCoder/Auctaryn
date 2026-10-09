"""API security and provenance tests for Phase 12 memory isolation."""
def _agent_token(client, agent_id, scopes=("memory:read", "memory:write")):
    registered = client.post("/api/v1/identity/register", json={"agent_id": agent_id, "owner": f"owner-{agent_id}"})
    assert registered.status_code == 200
    for scope in set(scopes):
        granted = client.post("/api/v1/identity/grant", json={"agent_id": agent_id, "scope": scope})
        assert granted.status_code == 200
    response = client.post(
        "/api/v1/identity/token",
        json={"agent_id": agent_id, "scopes": list(scopes), "ttl_seconds": 300},
    )
    assert response.status_code == 200
    return {"X-Agent-ID": agent_id, "X-Agent-Identity-Token": response.json()["token_id"]}


def _session(client, headers):
    response = client.post("/api/v1/memory/sessions", headers=headers)
    assert response.status_code == 200
    return response.json()["session_id"]


def _store(client, headers, session_id, content="A benign memory note.", source="user_conversation"):
    return client.post(
        "/api/v1/memory/evaluate",
        headers=headers,
        json={"content": content, "source": source, "session_id": session_id},
    )


def test_memory_routes_require_scoped_agent_token(client):
    response = client.post("/api/v1/memory/sessions")
    assert response.status_code == 403


def test_read_scope_can_create_session_but_cannot_write_memory(client):
    headers = _agent_token(client, "agent-read-only", scopes=("memory:read",))
    session_id = _session(client, headers)
    response = _store(client, headers, session_id)
    assert response.status_code == 403


def test_memory_session_is_bound_to_agent_identity(client):
    owner_headers = _agent_token(client, "memory-owner")
    other_headers = _agent_token(client, "memory-other")
    owner_session = _session(client, owner_headers)
    response = _store(client, other_headers, owner_session)
    assert response.status_code == 404


def test_api_submitted_memory_is_quarantined_even_if_source_claims_trusted(client):
    headers = _agent_token(client, "memory-source")
    session_id = _session(client, headers)
    response = _store(client, headers, session_id, source="user_conversation")
    assert response.status_code == 200
    payload = response.json()
    assert payload["allow_storage"] is True
    assert payload["quarantined"] is True
    assert payload["entry_id"]
    entry = client.get(f"/api/v1/memory/entry/{payload['entry_id']}", headers=headers)
    assert entry.status_code == 200
    assert entry.json()["source"] == "api:user_conversation"
    assert entry.json()["quarantined"] is True
    assert "content" not in entry.json()


def test_memory_entry_ids_do_not_overwrite_same_source(client):
    headers = _agent_token(client, "memory-unique")
    session_id = _session(client, headers)
    first = _store(client, headers, session_id, content="first note").json()
    second = _store(client, headers, session_id, content="second note").json()
    assert first["entry_id"] != second["entry_id"]


def test_quarantined_memory_cannot_cross_sessions(client):
    headers = _agent_token(client, "memory-session-isolation")
    first_session = _session(client, headers)
    second_session = _session(client, headers)
    stored = _store(client, headers, first_session).json()
    response = client.get(
        f"/api/v1/memory/readable/{stored['entry_id']}/{second_session}",
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["readable"] is False


def test_memory_entry_cannot_be_read_by_another_agent(client):
    owner_headers = _agent_token(client, "memory-entry-owner")
    other_headers = _agent_token(client, "memory-entry-other")
    session_id = _session(client, owner_headers)
    entry = _store(client, owner_headers, session_id).json()
    response = client.get(f"/api/v1/memory/entry/{entry['entry_id']}", headers=other_headers)
    assert response.status_code == 404


def test_memory_api_detects_and_rolls_back_metadata_tampering(client):
    import api.routes.memory as memory_routes

    headers = _agent_token(client, "memory-tamper")
    session_id = _session(client, headers)
    stored = _store(client, headers, session_id).json()
    memory_routes.get_memory_defender().store._entries[stored["entry_id"]].quarantined = False
    response = client.get(f"/api/v1/memory/entry/{stored['entry_id']}", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["tamper_detected"] is True
    assert payload["rolled_back"] is True
    assert payload["integrity_ok"] is True
    assert payload["quarantined"] is True


def test_memory_api_rejects_oversized_content(client):
    headers = _agent_token(client, "memory-bounds")
    session_id = _session(client, headers)
    response = _store(client, headers, session_id, content="x" * 32769)
    assert response.status_code == 422



def test_readability_check_rolls_back_tampered_quarantine_metadata(client):
    import api.routes.memory as memory_routes

    headers = _agent_token(client, "memory-read-tamper")
    owner_session = _session(client, headers)
    other_session = _session(client, headers)
    stored = _store(client, headers, owner_session).json()
    memory_routes.get_memory_defender().store._entries[stored["entry_id"]].quarantined = False
    response = client.get(
        f"/api/v1/memory/readable/{stored['entry_id']}/{other_session}",
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["readable"] is False
    assert memory_routes.get_memory_defender().store.get(stored["entry_id"]).quarantined is True



def test_entry_access_rolls_back_tampered_agent_binding(client):
    import api.routes.memory as memory_routes

    headers = _agent_token(client, "memory-agent-binding")
    session_id = _session(client, headers)
    stored = _store(client, headers, session_id).json()
    memory_routes.get_memory_defender().store._entries[stored["entry_id"]].agent_id = "attacker-agent"
    response = client.get(f"/api/v1/memory/entry/{stored['entry_id']}", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["tamper_detected"] is True
    assert payload["rolled_back"] is True
    assert payload["agent_id"] == "memory-agent-binding"



def test_quarantined_memory_content_is_not_readable_by_any_agent_session(client):
    headers = _agent_token(client, "memory-content-isolation")
    owner_session = _session(client, headers)
    other_session = _session(client, headers)
    stored = _store(client, headers, owner_session, content="review-only note").json()

    owner_read = client.get(
        f"/api/v1/memory/content/{stored['entry_id']}/{owner_session}",
        headers=headers,
    )
    assert owner_read.status_code == 403

    other_read = client.get(
        f"/api/v1/memory/content/{stored['entry_id']}/{other_session}",
        headers=headers,
    )
    assert other_read.status_code == 403


def test_operator_can_inspect_quarantined_content_but_agents_cannot(client):
    headers = _agent_token(client, "memory-quarantine-review")
    session_id = _session(client, headers)
    stored = _store(client, headers, session_id, content="needs human review").json()

    agent_read = client.get(
        f"/api/v1/memory/content/{stored['entry_id']}/{session_id}",
        headers=headers,
    )
    assert agent_read.status_code == 403

    operator_read = client.get(f"/api/v1/memory/quarantine/{stored['entry_id']}")
    assert operator_read.status_code == 200
    assert operator_read.json()["content"] == "needs human review"
    assert operator_read.json()["quarantined"] is True
    assert operator_read.json()["integrity_ok"] is True


def test_service_token_cannot_inspect_quarantined_content(client):
    headers = _agent_token(client, "memory-quarantine-admin-only")
    session_id = _session(client, headers)
    stored = _store(client, headers, session_id).json()
    response = client.get(
        f"/api/v1/memory/quarantine/{stored['entry_id']}",
        headers={"Authorization": "Bearer test-service-secret"},
    )
    assert response.status_code == 403


def test_memory_content_endpoint_never_returns_tampered_content(client):
    import api.routes.memory as memory_routes

    headers = _agent_token(client, "memory-content-tamper")
    session_id = _session(client, headers)
    stored = _store(client, headers, session_id, content="original").json()
    memory_routes.get_memory_defender().store._entries[stored["entry_id"]].content = "tampered"
    response = client.get(f"/api/v1/memory/quarantine/{stored['entry_id']}")
    assert response.status_code == 200
    assert response.json()["content"] == "original"
    assert response.json()["integrity_ok"] is True



def test_memory_session_is_bound_to_exact_token(client):
    first_token = _agent_token(client, "memory-token-binding")
    session_id = _session(client, first_token)
    second_token = _agent_token(client, "memory-token-binding")
    response = _store(client, second_token, session_id)
    assert response.status_code == 404



def test_quarantine_queue_restores_tampered_quarantine_flag(client):
    import api.routes.memory as memory_routes

    headers = _agent_token(client, "memory-quarantine-queue-integrity")
    session_id = _session(client, headers)
    stored = _store(client, headers, session_id).json()
    memory_routes.get_memory_defender().store._entries[stored["entry_id"]].quarantined = False
    response = client.get("/api/v1/memory/quarantine")
    assert response.status_code == 200
    assert any(item["key"] == stored["entry_id"] for item in response.json()["entries"])
    assert memory_routes.get_memory_defender().store.get(stored["entry_id"]).quarantined is True
