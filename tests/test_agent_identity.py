"""
TwinGuard — Agent Identity & Privilege Module Tests (TDD)
Maps to OWASP ASI03:2026 — Agent Identity & Privilege Abuse.

Core principle (OWASP "Least Agency"): agents must have their own
managed identity with restricted, time-scoped permissions rather than
borrowing a user's session or holding standing admin access.

Written FIRST. Implementation follows.
"""

import pytest
import time
from datetime import datetime, timezone, timedelta


class TestAgentIdentityRegistration:
    """Every agent gets its own managed identity — never a borrowed user session."""

    def test_register_new_agent_identity(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        identity = mgr.register("openclone-agent-001", owner="user-42")
        assert identity.agent_id == "openclone-agent-001"
        assert identity.owner == "user-42"
        assert identity.identity_id != identity.agent_id  # distinct managed identity

    def test_duplicate_registration_returns_existing(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        i1 = mgr.register("agent-001", owner="user-1")
        i2 = mgr.register("agent-001", owner="user-1")
        assert i1.identity_id == i2.identity_id

    def test_each_agent_gets_unique_identity_id(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        i1 = mgr.register("agent-001", owner="user-1")
        i2 = mgr.register("agent-002", owner="user-1")
        assert i1.identity_id != i2.identity_id

    def test_identity_has_no_default_permissions(self):
        """Least Agency: zero permissions by default, must be explicitly scoped."""
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        identity = mgr.register("agent-001", owner="user-1")
        assert identity.scopes == set()

    def test_duplicate_registration_cannot_change_identity_owner(self, caplog):
        from modules.agent_identity.identity import AgentIdentityManager
        from core.exceptions import PolicyViolation

        mgr = AgentIdentityManager()
        original = mgr.register("agent-owner-bound", owner="tenant-a")

        with pytest.raises(PolicyViolation, match="identity_owner_conflict"):
            mgr.register("agent-owner-bound", owner="tenant-b")

        persisted = mgr.get_identity("agent-owner-bound")
        assert persisted is not None
        assert persisted.identity_id == original.identity_id
        assert persisted.owner == "tenant-a"
        assert any(
            getattr(record, "event", None) == "identity_owner_conflict"
            for record in caplog.records
        )


class TestScopedPermissions:
    """Permissions are explicit, minimal, and tied to specific tool/action patterns."""

    def test_grant_scope(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("agent-001", owner="user-1")
        mgr.grant_scope("agent-001", "read_file")
        identity = mgr.get_identity("agent-001")
        assert "read_file" in identity.scopes

    def test_revoke_scope(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("agent-001", owner="user-1")
        mgr.grant_scope("agent-001", "read_file")
        mgr.revoke_scope("agent-001", "read_file")
        identity = mgr.get_identity("agent-001")
        assert "read_file" not in identity.scopes

    def test_is_authorized_with_granted_scope(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("agent-001", owner="user-1")
        mgr.grant_scope("agent-001", "send_email")
        assert mgr.is_authorized("agent-001", "send_email") is True

    def test_is_not_authorized_without_scope(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("agent-001", owner="user-1")
        assert mgr.is_authorized("agent-001", "delete_database") is False

    def test_unknown_agent_is_never_authorized(self):
        """Confused-deputy prevention: unregistered agents have no implicit trust."""
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        assert mgr.is_authorized("ghost-agent-999", "read_file") is False

    def test_wildcard_scope_pattern_matching(self):
        """Scopes support prefix patterns like 'read_*' for grouped permissions."""
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("agent-001", owner="user-1")
        mgr.grant_scope("agent-001", "read_*")
        assert mgr.is_authorized("agent-001", "read_file") is True
        assert mgr.is_authorized("agent-001", "read_calendar") is True
        assert mgr.is_authorized("agent-001", "write_file") is False


class TestTimeScopedTokens:
    """Short-lived tokens prevent standing privilege accumulation across sessions."""

    def test_issue_scoped_token(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("agent-001", owner="user-1")
        mgr.grant_scope("agent-001", "send_email")
        token = mgr.issue_token("agent-001", ttl_seconds=300)
        assert token.agent_id == "agent-001"
        assert token.expires_at > datetime.now(timezone.utc)

    def test_token_validates_when_fresh(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("agent-001", owner="user-1")
        mgr.grant_scope("agent-001", "read_file")
        token = mgr.issue_token("agent-001", ttl_seconds=300)
        assert mgr.validate_token(token.token_id) is True

    def test_expired_token_fails_validation(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("agent-001", owner="user-1")
        mgr.grant_scope("agent-001", "read_file")
        token = mgr.issue_token("agent-001", ttl_seconds=1)
        token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert mgr.validate_token(token.token_id) is False

    def test_revoked_token_fails_validation(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("agent-001", owner="user-1")
        mgr.grant_scope("agent-001", "read_file")
        token = mgr.issue_token("agent-001", ttl_seconds=300)
        mgr.revoke_token(token.token_id)
        assert mgr.validate_token(token.token_id) is False

    def test_unknown_token_fails_validation(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        assert mgr.validate_token("nonexistent-token-id") is False



    def test_permission_change_invalidates_existing_token(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("agent-versioned", owner="user-1")
        mgr.grant_scope("agent-versioned", "read_file")
        token = mgr.issue_token("agent-versioned", scopes=["read_file"])
        assert mgr.is_authorized(
            "agent-versioned", "read_file", token_id=token.token_id, require_token=True
        )
        mgr.grant_scope("agent-versioned", "send_email")
        assert mgr.validate_token(token.token_id) is False
        assert mgr.is_authorized(
            "agent-versioned", "read_file", token_id=token.token_id, require_token=True
        ) is False

    def test_delegated_token_invalidated_when_delegator_permissions_change(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("manager-versioned", owner="user-1")
        mgr.register("sub-versioned", owner="user-1")
        mgr.grant_scope("manager-versioned", "read_file")
        token = mgr.delegate("manager-versioned", "sub-versioned", ["read_file"])
        assert mgr.is_authorized(
            "sub-versioned", "read_file", token_id=token.token_id, require_token=True
        )
        mgr.grant_scope("manager-versioned", "send_email")
        assert mgr.is_authorized(
            "sub-versioned", "read_file", token_id=token.token_id, require_token=True
        ) is False

class TestPrivilegeDelegation:
    """
    OWASP ASI03 example: 'Manager delegates task, full admin access persists.'
    Delegated scopes must be a SUBSET of the delegator's own scopes, and
    must not silently persist beyond the delegated task.
    """

    def test_delegate_subset_of_own_scopes(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("manager-agent", owner="user-1")
        mgr.grant_scope("manager-agent", "read_file")
        mgr.grant_scope("manager-agent", "send_email")
        mgr.grant_scope("manager-agent", "delete_database")

        mgr.register("sub-agent", owner="user-1")
        token = mgr.delegate("manager-agent", "sub-agent", scopes=["read_file"])

        assert mgr.is_authorized("sub-agent", "read_file") is False
        assert mgr.is_authorized(
            "sub-agent", "read_file", token_id=token.token_id, require_token=True
        ) is True
        assert mgr.is_authorized("sub-agent", "delete_database") is False

    def test_cannot_delegate_scope_you_do_not_have(self):
        """Confused-deputy prevention: cannot delegate privileges you were never granted."""
        from modules.agent_identity.identity import AgentIdentityManager
        from core.exceptions import PolicyViolation
        mgr = AgentIdentityManager()
        mgr.register("manager-agent", owner="user-1")
        mgr.grant_scope("manager-agent", "read_file")
        mgr.register("sub-agent", owner="user-1")

        with pytest.raises(PolicyViolation):
            mgr.delegate("manager-agent", "sub-agent", scopes=["delete_database"])

    def test_delegated_scopes_are_time_scoped(self):
        from modules.agent_identity.identity import AgentIdentityManager
        mgr = AgentIdentityManager()
        mgr.register("manager-agent", owner="user-1")
        mgr.grant_scope("manager-agent", "read_file")
        mgr.register("sub-agent", owner="user-1")

        token = mgr.delegate("manager-agent", "sub-agent", scopes=["read_file"], ttl_seconds=60)
        assert token.expires_at <= datetime.now(timezone.utc) + timedelta(seconds=61)


class TestGatewayIntegration:
    """The identity layer plugs into the Execution Gateway as an additional check."""

    def test_unauthorized_agent_action_is_denied(self):
        from modules.agent_identity.identity import AgentIdentityManager
        from core.models import ToolCall
        mgr = AgentIdentityManager()
        mgr.register("agent-001", owner="user-1")
        mgr.grant_scope("agent-001", "read_file")

        tc = ToolCall(tool_name="delete_database", action="drop", agent_id="agent-001")
        assert mgr.is_authorized(tc.agent_id, tc.tool_name) is False

    def test_unregistered_agent_in_tool_call_is_denied(self):
        from modules.agent_identity.identity import AgentIdentityManager
        from core.models import ToolCall
        mgr = AgentIdentityManager()

        tc = ToolCall(tool_name="read_file", action="read", agent_id="rogue-unregistered-agent")
        assert mgr.is_authorized(tc.agent_id, tc.tool_name) is False


def test_identity_manager_fails_closed_at_identity_capacity(monkeypatch):
    import modules.agent_identity.identity as identity_module
    from core.exceptions import PolicyViolation

    monkeypatch.setattr(identity_module, "MAX_AGENT_IDENTITIES", 1)
    manager = identity_module.AgentIdentityManager()
    manager.register("capacity-agent-1", "tenant-a")
    with pytest.raises(PolicyViolation, match="identity_capacity_exhausted"):
        manager.register("capacity-agent-2", "tenant-a")


def test_identity_manager_prunes_expired_tokens_before_capacity_check(monkeypatch):
    import modules.agent_identity.identity as identity_module

    monkeypatch.setattr(identity_module, "MAX_AGENT_TOKENS", 1)
    manager = identity_module.AgentIdentityManager()
    manager.register("token-capacity-agent", "tenant-a")
    manager.grant_scope("token-capacity-agent", "read_file")
    first = manager.issue_token("token-capacity-agent")
    first.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    second = manager.issue_token("token-capacity-agent")
    assert second.token_id != first.token_id
    assert manager.validate_token(first.token_id) is False
    assert manager.validate_token(second.token_id) is True


def test_identity_manager_bounds_scope_count(monkeypatch):
    import modules.agent_identity.identity as identity_module
    from core.exceptions import PolicyViolation

    monkeypatch.setattr(identity_module, "MAX_SCOPES_PER_IDENTITY", 1)
    manager = identity_module.AgentIdentityManager()
    manager.register("scope-capacity-agent", "tenant-a")
    manager.grant_scope("scope-capacity-agent", "read_file")
    with pytest.raises(PolicyViolation, match="scope_capacity_exhausted"):
        manager.grant_scope("scope-capacity-agent", "write_file")
