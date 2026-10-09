"""TwinGuard — Shared Test Fixtures"""

import pytest
from fastapi.testclient import TestClient
from api.main import app


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset all module singletons before each test."""
    from api.routes.context import _guardian
    _guardian.registry._instructions.clear()
    _guardian.history.clear()
    _guardian.compaction_history.clear()
    _guardian.check_count = 0
    _guardian._last_token_count = 0
    _guardian._last_combined_hash = ""

    from api.routes.gateway import _gateway, _oracle as gw_oracle
    _gateway.history.clear()
    _gateway._pending.clear()
    _gateway.total_processed = 0
    _gateway.total_vetoed = 0
    gw_oracle.history.clear()
    gw_oracle.raw_results.clear()

    from api.routes.threatfade import _oracle as tf_oracle
    tf_oracle.history.clear()
    tf_oracle.raw_results.clear()

    yield


@pytest.fixture
def client(monkeypatch):
    """Authenticated administrator client for functional API tests."""
    monkeypatch.setenv("AUCTARYN_API_KEY", "test-service-secret")
    monkeypatch.setenv("AUCTARYN_ADMIN_API_KEY", "test-admin-secret")
    return TestClient(app, headers={"Authorization": "Bearer test-admin-secret"})


@pytest.fixture
def sample_tool_call():
    return {
        "tool_name": "delete_emails", "action": "bulk",
        "parameters": {"count": 500, "folder": "inbox"},
        "target": "user@example.com",
        "agent_id": "agent-001", "session_id": "session-abc",
    }


@pytest.fixture
def safe_tool_call():
    return {
        "tool_name": "read_file", "action": "read",
        "parameters": {"path": "/documents/report.pdf"},
        "agent_id": "agent-001", "session_id": "session-abc",
    }
