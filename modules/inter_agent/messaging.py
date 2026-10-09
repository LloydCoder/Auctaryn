"""
TwinGuard — Agent Message Bus
Maps to OWASP ASI07:2026 — Insecure Inter-Agent Communication.

Every message between agents (delegation, task handoff, shared state
updates) is HMAC-signed using the sending agent's registered key.
Recipients verify the signature before trusting the payload. This
prevents one agent from impersonating another or injecting unsigned
instructions into a peer's task queue — the "unsigned agent card
injects hidden behavior" pattern OWASP calls out.

Not a transport layer (no actual network sockets) — this is the
signing/verification CONTRACT that any real transport (HTTP, message
queue, shared memory) must enforce.
"""

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from core.logging import get_logger

logger = get_logger("inter_agent.messaging")


@dataclass
class AgentMessage:
    message_id: str
    sender_id: str
    recipient_id: str
    payload: dict
    signature: str
    timestamp: datetime


def _canonical_payload(payload: dict) -> bytes:
    """Deterministic serialization so signing is reproducible."""
    return json.dumps(payload, sort_keys=True, default=str).encode("utf-8")


def _sign(payload: dict, key: str) -> str:
    return hmac.new(key.encode("utf-8"), _canonical_payload(payload), hashlib.sha256).hexdigest()


class AgentMessageBus:
    """
    In-memory signed message bus between registered agent identities.
    Pairs naturally with AgentIdentityManager (ASI03) — in production,
    the signing key would derive from the agent's managed identity
    rather than being registered separately.
    """

    def __init__(self):
        self._keys: dict[str, str] = {}
        self._inboxes: dict[str, list[AgentMessage]] = {}

    def register_agent_key(self, agent_id: str, signing_key: str) -> None:
        self._keys[agent_id] = signing_key

    def send(self, sender_id: str, recipient_id: str, payload: dict,
              signing_key: str | None = None) -> AgentMessage:
        """
        Sign and deliver a message. If signing_key is omitted, uses the
        sender's registered key. If a wrong key is supplied (impersonation
        attempt), raises PermissionError immediately — never delivers.
        """
        registered_key = self._keys.get(sender_id)
        if registered_key is None:
            raise PermissionError(f"No registered signing key for agent '{sender_id}'")

        key_to_use = signing_key if signing_key is not None else registered_key
        if key_to_use != registered_key:
            raise PermissionError(
                f"Signing key mismatch for '{sender_id}' — possible impersonation attempt"
            )

        message = AgentMessage(
            message_id=uuid.uuid4().hex[:12],
            sender_id=sender_id,
            recipient_id=recipient_id,
            payload=payload,
            signature=_sign(payload, registered_key),
            timestamp=datetime.now(timezone.utc),
        )

        self._inboxes.setdefault(recipient_id, []).append(message)
        logger.info(f"Agent message: {sender_id} -> {recipient_id}",
                   extra={"event": "agent_message_sent", "module_name": "inter_agent"})
        return message

    def verify(self, message: AgentMessage) -> bool:
        """Recompute the signature and compare — detects tampering or forgery."""
        key = self._keys.get(message.sender_id)
        if key is None:
            return False
        expected = _sign(message.payload, key)
        return hmac.compare_digest(expected, message.signature)

    def get_inbox(self, agent_id: str) -> list[AgentMessage]:
        return self._inboxes.get(agent_id, [])
