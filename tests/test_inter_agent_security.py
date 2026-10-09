"""Adversarial tests for authenticated inter-agent envelopes."""
import copy
from datetime import datetime, timedelta, timezone

import pytest

from modules.agent_identity.identity import AgentIdentityManager
from modules.inter_agent.messaging import AgentMessageBus


def _test_key(seed: str) -> str:
    return f"{seed}-A1b2C3d4E5f6G7h8J9k0L1m2N3p4Q5r6"


def _bus():
    bus = AgentMessageBus(allow_unbound_test_mode=True)
    bus.register_agent_key("agent-a", _test_key("a"))
    bus.register_agent_key("agent-b", _test_key("b"))
    return bus


def _message(bus):
    return bus.send("agent-a", "agent-b", {"task": "review", "priority": 1})


def test_message_verifies_once_and_is_removed_from_inbox():
    bus = _bus()
    message = _message(bus)
    assert len(bus.get_inbox("agent-b")) == 1
    assert bus.verify(message, recipient_id="agent-b") is True
    assert bus.verify(message, recipient_id="agent-b") is False
    assert bus.get_inbox("agent-b") == []


@pytest.mark.parametrize("field,value", [
    ("sender_id", "agent-b"),
    ("recipient_id", "agent-a"),
    ("signature", "0" * 64),
])
def test_envelope_tampering_is_rejected(field, value):
    bus = _bus()
    message = _message(bus)
    changed = copy.deepcopy(message)
    setattr(changed, field, value)
    assert bus.verify(changed) is False


def test_payload_and_expiry_are_covered_by_signature():
    bus = _bus()
    message = _message(bus)
    changed_payload = copy.deepcopy(message)
    changed_payload.payload["task"] = "delete"
    assert bus.verify(changed_payload) is False

    changed_expiry = copy.deepcopy(message)
    changed_expiry.expires_at += timedelta(seconds=1)
    assert bus.verify(changed_expiry) is False


def test_expired_and_future_messages_are_rejected():
    bus = _bus()
    now = datetime.now(timezone.utc)
    expired = bus.send("agent-a", "agent-b", {"task": "expired"}, now=now, ttl_seconds=10)
    assert bus.verify(expired, now=expired.expires_at) is False

    future = bus.send(
        "agent-a", "agent-b", {"task": "future"},
        now=now + timedelta(minutes=2),
    )
    assert bus.verify(future, now=now) is False


def test_wrong_recipient_cannot_consume_message():
    bus = _bus()
    message = _message(bus)
    assert bus.verify(message, recipient_id="agent-a") is False
    assert bus.verify(message, recipient_id="agent-b") is True


def test_unknown_recipient_and_invalid_key_are_rejected():
    bus = AgentMessageBus(allow_unbound_test_mode=True)
    bus.register_agent_key("agent-a", _test_key("a"))
    with pytest.raises(PermissionError):
        bus.send("agent-a", "missing-agent", {"task": "x"})
    with pytest.raises(ValueError):
        bus.register_agent_key("weak-key-agent", "short")


def test_payload_must_be_bounded_finite_json_object():
    bus = _bus()
    with pytest.raises(ValueError):
        bus.send("agent-a", "agent-b", {"not_json": object()})
    with pytest.raises(ValueError):
        bus.send("agent-a", "agent-b", {"number": float("nan")})
    with pytest.raises(ValueError):
        bus.send("agent-a", "agent-b", {"blob": "x" * (64 * 1024 + 1)})


def test_key_rotation_requires_explicit_flag_and_invalidates_pending_messages():
    bus = _bus()
    pending = _message(bus)
    with pytest.raises(ValueError, match="rotation"):
        bus.register_agent_key("agent-a", _test_key("z"))
    bus.register_agent_key("agent-a", _test_key("z"), rotate=True)
    assert bus.get_inbox("agent-b") == []
    assert bus.verify(pending) is False


def test_inbox_returns_copies_not_mutable_internal_messages():
    bus = _bus()
    _message(bus)
    copy_of_inbox = bus.get_inbox("agent-b")
    copy_of_inbox[0].payload["task"] = "tampered"
    assert bus.get_inbox("agent-b")[0].payload["task"] == "review"


def test_message_send_and_receive_require_scoped_identity_tokens():
    identities = AgentIdentityManager()
    identities.register("sender", owner="tenant-a")
    identities.register("receiver", owner="tenant-a")
    identities.grant_scope("sender", "inter_agent:send")
    identities.grant_scope("receiver", "inter_agent:receive")
    sender_token = identities.issue_token("sender", scopes=["inter_agent:send"])
    receiver_token = identities.issue_token("receiver", scopes=["inter_agent:receive"])

    bus = AgentMessageBus(identity_manager=identities, key_management_authorizer=lambda _agent_id, _operation: True)
    bus.register_agent_key("sender", _test_key("s"))
    bus.register_agent_key("receiver", _test_key("r"))
    message = bus.send("sender", "receiver", {"task": "handoff"}, token_id=sender_token.token_id)
    assert bus.verify(message, token_id=receiver_token.token_id) is True

    identities.revoke_scope("sender", "inter_agent:send")
    with pytest.raises(PermissionError):
        bus.send("sender", "receiver", {"task": "revoked"}, token_id=sender_token.token_id)


def test_agent_key_registration_requires_managed_identity_when_integrated():
    bus = AgentMessageBus(identity_manager=AgentIdentityManager())
    with pytest.raises(PermissionError):
        bus.register_agent_key("unknown-agent", _test_key("k"))



def test_expired_messages_are_pruned_and_inbox_capacity_is_bounded():
    from modules.inter_agent.messaging import MAX_INBOX_MESSAGES

    bus = _bus()
    now = datetime.now(timezone.utc)
    bus.send("agent-a", "agent-b", {"task": "short-lived"}, ttl_seconds=1, now=now)
    assert bus.clear_expired(now=now + timedelta(seconds=2)) == 1
    assert bus.get_inbox("agent-b") == []

    for index in range(MAX_INBOX_MESSAGES):
        bus.send("agent-a", "agent-b", {"sequence": index})
    with pytest.raises(RuntimeError, match="capacity"):
        bus.send("agent-a", "agent-b", {"sequence": MAX_INBOX_MESSAGES})



def test_envelope_not_in_recipient_queue_is_not_consumed():
    bus = _bus()
    message = _message(bus)
    bus._inboxes["agent-b"].clear()
    assert bus.verify(message, recipient_id="agent-b") is False



def test_cross_tenant_delivery_is_denied_without_explicit_policy():
    identities = AgentIdentityManager()
    identities.register("tenant-a-sender", owner="tenant-a")
    identities.register("tenant-b-receiver", owner="tenant-b")
    identities.grant_scope("tenant-a-sender", "inter_agent:send")
    identities.grant_scope("tenant-b-receiver", "inter_agent:receive")
    sender_token = identities.issue_token("tenant-a-sender", scopes=["inter_agent:send"])
    bus = AgentMessageBus(identity_manager=identities, key_management_authorizer=lambda _agent_id, _operation: True)
    bus.register_agent_key("tenant-a-sender", _test_key("a"))
    bus.register_agent_key("tenant-b-receiver", _test_key("b"))
    with pytest.raises(PermissionError, match="cross-tenant"):
        bus.send(
            "tenant-a-sender", "tenant-b-receiver", {"task": "handoff"},
            token_id=sender_token.token_id,
        )


def test_cross_tenant_delivery_requires_explicit_authorizer():
    identities = AgentIdentityManager()
    identities.register("tenant-a-sender", owner="tenant-a")
    identities.register("tenant-b-receiver", owner="tenant-b")
    identities.grant_scope("tenant-a-sender", "inter_agent:send")
    identities.grant_scope("tenant-b-receiver", "inter_agent:receive")
    sender_token = identities.issue_token("tenant-a-sender", scopes=["inter_agent:send"])
    receiver_token = identities.issue_token("tenant-b-receiver", scopes=["inter_agent:receive"])
    bus = AgentMessageBus(
        identity_manager=identities,
        cross_tenant_authorizer=lambda source, destination: (source, destination) == ("tenant-a", "tenant-b"),
        key_management_authorizer=lambda _agent_id, _operation: True,
    )
    bus.register_agent_key("tenant-a-sender", _test_key("a"))
    bus.register_agent_key("tenant-b-receiver", _test_key("b"))
    message = bus.send(
        "tenant-a-sender", "tenant-b-receiver", {"task": "approved handoff"},
        token_id=sender_token.token_id,
    )
    assert bus.verify(message, token_id=receiver_token.token_id) is True



def test_default_bus_requires_managed_identity_integration():
    bus = AgentMessageBus()
    with pytest.raises(PermissionError, match="managed identity"):
        bus.register_agent_key("agent-a", _test_key("a"))


def test_integrated_inbox_read_requires_recipient_token():
    identities = AgentIdentityManager()
    identities.register("sender", owner="tenant-a")
    identities.register("receiver", owner="tenant-a")
    identities.grant_scope("sender", "inter_agent:send")
    identities.grant_scope("receiver", "inter_agent:receive")
    sender_token = identities.issue_token("sender", scopes=["inter_agent:send"])
    receiver_token = identities.issue_token("receiver", scopes=["inter_agent:receive"])

    bus = AgentMessageBus(identity_manager=identities, key_management_authorizer=lambda _agent_id, _operation: True)
    bus.register_agent_key("sender", _test_key("s"))
    bus.register_agent_key("receiver", _test_key("r"))
    bus.send("sender", "receiver", {"task": "private handoff"}, token_id=sender_token.token_id)

    with pytest.raises(PermissionError, match="receive token"):
        bus.get_inbox("receiver")
    assert len(bus.get_inbox("receiver", token_id=receiver_token.token_id)) == 1


def test_global_inbox_capacity_is_bounded_across_recipients(monkeypatch):
    import modules.inter_agent.secure_messaging as secure_messaging

    bus = _bus()
    bus.register_agent_key("agent-c", _test_key("c"))
    monkeypatch.setattr(secure_messaging, "MAX_TOTAL_INBOX_MESSAGES", 1)
    bus.send("agent-a", "agent-b", {"task": "first"})
    with pytest.raises(RuntimeError, match="global message capacity"):
        bus.send("agent-a", "agent-c", {"task": "second"})


def test_empty_explicit_recipient_does_not_fall_back_to_signed_recipient():
    bus = _bus()
    message = _message(bus)
    assert bus.verify(message, recipient_id="") is False
    assert bus.verify(message, recipient_id="agent-b") is True


def test_managed_key_registration_requires_platform_authorizer():
    identities = AgentIdentityManager()
    identities.register("agent-a", owner="tenant-a")
    bus = AgentMessageBus(identity_manager=identities)
    with pytest.raises(PermissionError, match="key-management authorization"):
        bus.register_agent_key("agent-a", _test_key("agent-a"))


def test_key_rotation_requires_authorizer_even_with_rotate_flag():
    identities = AgentIdentityManager()
    identities.register("agent-a", owner="tenant-a")
    bus = AgentMessageBus(
        identity_manager=identities,
        key_management_authorizer=lambda _agent_id, _operation: True,
    )
    bus.register_agent_key("agent-a", _test_key("old-key"))
    bus.key_management_authorizer = None
    with pytest.raises(PermissionError, match="key-management authorization"):
        bus.register_agent_key("agent-a", _test_key("new-key"), rotate=True)



def test_cross_tenant_authorizer_requires_literal_boolean_true():
    identities = AgentIdentityManager()
    identities.register("tenant-a-sender", owner="tenant-a")
    identities.register("tenant-b-receiver", owner="tenant-b")
    identities.grant_scope("tenant-a-sender", "inter_agent:send")
    token = identities.issue_token("tenant-a-sender", scopes=["inter_agent:send"])
    bus = AgentMessageBus(
        identity_manager=identities,
        cross_tenant_authorizer=lambda _source, _destination: "yes",
        key_management_authorizer=lambda _agent_id, _operation: True,
    )
    bus.register_agent_key("tenant-a-sender", _test_key("a"))
    bus.register_agent_key("tenant-b-receiver", _test_key("b"))
    with pytest.raises(PermissionError, match="cross-tenant"):
        bus.send(
            "tenant-a-sender", "tenant-b-receiver", {"task": "handoff"},
            token_id=token.token_id,
        )



def test_key_revocation_requires_authorization_and_removes_pending_messages():
    identities = AgentIdentityManager()
    identities.register("sender", owner="tenant-a")
    identities.register("receiver", owner="tenant-a")
    identities.grant_scope("sender", "inter_agent:send")
    identities.grant_scope("receiver", "inter_agent:receive")
    sender_token = identities.issue_token("sender", scopes=["inter_agent:send"])
    receiver_token = identities.issue_token("receiver", scopes=["inter_agent:receive"])
    allowed = {"value": True}
    bus = AgentMessageBus(
        identity_manager=identities,
        key_management_authorizer=lambda _agent, _operation: allowed["value"] is True,
    )
    bus.register_agent_key("sender", _test_key("s"))
    bus.register_agent_key("receiver", _test_key("r"))
    bus.send("sender", "receiver", {"task": "pending"}, token_id=sender_token.token_id)
    assert bus._queued_count == 1

    allowed["value"] = False
    with pytest.raises(PermissionError, match="not authorized"):
        bus.revoke_agent_key("sender")

    allowed["value"] = True
    assert bus.revoke_agent_key("sender") is True
    assert bus._queued_count == 0
    assert bus.get_inbox("receiver", token_id=receiver_token.token_id) == []
    with pytest.raises(PermissionError):
        bus.send("sender", "receiver", {"task": "after-revoke"}, token_id=sender_token.token_id)


def test_unbound_test_mode_requires_a_boolean():
    with pytest.raises(ValueError, match="boolean"):
        AgentMessageBus(allow_unbound_test_mode=1)



def test_inbox_hides_messages_when_cross_tenant_permission_is_revoked():
    identities = AgentIdentityManager()
    identities.register("tenant-a-sender", owner="tenant-a")
    identities.register("tenant-b-receiver", owner="tenant-b")
    identities.grant_scope("tenant-a-sender", "inter_agent:send")
    identities.grant_scope("tenant-b-receiver", "inter_agent:receive")
    sender_token = identities.issue_token("tenant-a-sender", scopes=["inter_agent:send"])
    receiver_token = identities.issue_token("tenant-b-receiver", scopes=["inter_agent:receive"])
    policy = {"allowed": True}
    bus = AgentMessageBus(
        identity_manager=identities,
        cross_tenant_authorizer=lambda _source, _destination: policy["allowed"] is True,
        key_management_authorizer=lambda _agent, _operation: True,
    )
    bus.register_agent_key("tenant-a-sender", _test_key("a"))
    bus.register_agent_key("tenant-b-receiver", _test_key("b"))
    message = bus.send(
        "tenant-a-sender", "tenant-b-receiver", {"task": "private handoff"},
        token_id=sender_token.token_id,
    )
    policy["allowed"] = False
    assert bus.get_inbox("tenant-b-receiver", token_id=receiver_token.token_id) == []
    assert bus.verify(message, token_id=receiver_token.token_id) is False
    policy["allowed"] = True
    assert len(bus.get_inbox("tenant-b-receiver", token_id=receiver_token.token_id)) == 1
    assert bus.verify(message, token_id=receiver_token.token_id) is True
