"""Bounded, authenticated inter-agent message envelope with replay protection."""
import copy
import hashlib
import hmac
import json
import re
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from core.logging import get_logger

logger = get_logger("inter_agent.messaging")

_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MESSAGE_ID = re.compile(r"^[0-9a-f]{32}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")
MAX_REGISTERED_AGENTS = 10000
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_INBOX_MESSAGES = 1000
MAX_TOTAL_INBOX_MESSAGES = 1024
MAX_CONSUMED_IDS = 10000
MAX_TTL_SECONDS = 3600
DEFAULT_TTL_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 30


@dataclass
class AgentMessage:
    message_id: str
    sender_id: str
    recipient_id: str
    payload: dict
    signature: str
    timestamp: datetime
    expires_at: datetime


def _canonical_envelope(message: AgentMessage) -> bytes:
    envelope = {
        "message_id": message.message_id,
        "sender_id": message.sender_id,
        "recipient_id": message.recipient_id,
        "payload": message.payload,
        "timestamp": message.timestamp.astimezone(timezone.utc).isoformat(),
        "expires_at": message.expires_at.astimezone(timezone.utc).isoformat(),
    }
    return json.dumps(
        envelope, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _sign(message: AgentMessage, key: str) -> str:
    return hmac.new(key.encode("utf-8"), _canonical_envelope(message), hashlib.sha256).hexdigest()


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


class AgentMessageBus:
    """In-memory envelope service; a production transport must preserve these checks."""

    def __init__(
        self,
        identity_manager=None,
        cross_tenant_authorizer=None,
        key_management_authorizer=None,
        *,
        allow_unbound_test_mode: bool = False,
    ):
        if not isinstance(allow_unbound_test_mode, bool):
            raise ValueError("allow_unbound_test_mode must be a boolean")
        self.identity_manager = identity_manager
        self.cross_tenant_authorizer = cross_tenant_authorizer
        self.key_management_authorizer = key_management_authorizer
        self.allow_unbound_test_mode = allow_unbound_test_mode
        self._keys: dict[str, str] = {}
        self._inboxes: dict[str, list[AgentMessage]] = {}
        self._consumed: dict[tuple[str, str], datetime] = {}
        self._queued_count = 0
        self._lock = threading.RLock()

    @staticmethod
    def _validate_agent_id(agent_id: str) -> None:
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            raise ValueError("invalid agent identifier")

    def _tenant_allowed(self, sender_id: str, recipient_id: str) -> bool:
        if self.identity_manager is None:
            return True
        sender = self.identity_manager.get_identity(sender_id)
        recipient = self.identity_manager.get_identity(recipient_id)
        if sender is None or recipient is None or not sender.owner or not recipient.owner:
            return False
        if sender.owner == recipient.owner:
            return True
        if self.cross_tenant_authorizer is None:
            return False
        try:
            return self.cross_tenant_authorizer(sender.owner, recipient.owner) is True
        except Exception:
            return False

    def register_agent_key(self, agent_id: str, signing_key: str, *, rotate: bool = False) -> None:
        self._validate_agent_id(agent_id)
        if not isinstance(signing_key, str) or len(signing_key.encode("utf-8")) < 32 or len(signing_key) > 512:
            raise ValueError("signing key must contain 32–512 UTF-8 bytes")
        if len(set(signing_key)) < 8:
            raise ValueError("signing key has insufficient character diversity; use a CSPRNG-generated secret")
        if self.identity_manager is None and not self.allow_unbound_test_mode:
            raise PermissionError("managed identity integration is required")
        if self.identity_manager is not None and self.identity_manager.get_identity(agent_id) is None:
            raise PermissionError("agent identity must exist before message key registration")
        with self._lock:
            previous = self._keys.get(agent_id)
            if previous is None and len(self._keys) >= MAX_REGISTERED_AGENTS:
                raise RuntimeError("agent message registry capacity reached")
            changed = previous is None or not hmac.compare_digest(previous, signing_key)
            if changed and self.identity_manager is not None:
                if self.key_management_authorizer is None:
                    raise PermissionError("platform key-management authorization is required")
                operation = "register" if previous is None else "rotate"
                try:
                    authorized = self.key_management_authorizer(agent_id, operation) is True
                except Exception:
                    authorized = False
                if not authorized:
                    raise PermissionError("platform key-management authorization is denied")
            if previous is not None and not hmac.compare_digest(previous, signing_key):
                if not rotate:
                    raise ValueError("key rotation requires explicit authorization")
                removed = 0
                for recipient, messages in self._inboxes.items():
                    active = [m for m in messages if m.sender_id != agent_id]
                    removed += len(messages) - len(active)
                    self._inboxes[recipient] = active
                self._queued_count = max(0, self._queued_count - removed)
            self._keys[agent_id] = signing_key

    def revoke_agent_key(self, agent_id: str) -> bool:
        self._validate_agent_id(agent_id)
        if self.identity_manager is None and not self.allow_unbound_test_mode:
            raise PermissionError("managed identity integration is required")
        if self.identity_manager is not None:
            if self.key_management_authorizer is None:
                raise PermissionError("key-management authorization is required")
            try:
                authorized = self.key_management_authorizer(agent_id, "revoke") is True
            except Exception:
                authorized = False
            if not authorized:
                raise PermissionError("key revocation is not authorized")

        with self._lock:
            if agent_id not in self._keys:
                return False
            del self._keys[agent_id]
            removed = len(self._inboxes.pop(agent_id, []))
            for recipient, messages in self._inboxes.items():
                remaining = [message for message in messages if message.sender_id != agent_id]
                removed += len(messages) - len(remaining)
                self._inboxes[recipient] = remaining
            self._queued_count = max(0, self._queued_count - removed)
            return True

    def send(
        self,
        sender_id: str,
        recipient_id: str,
        payload: dict,
        signing_key: str | None = None,
        *,
        token_id: str | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        now: datetime | None = None,
    ) -> AgentMessage:
        self._validate_agent_id(sender_id)
        self._validate_agent_id(recipient_id)
        if sender_id == recipient_id:
            raise ValueError("self-directed messages are not supported")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError("ttl_seconds must be between 1 and 3600")
        try:
            payload_bytes = json.dumps(
                payload, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("payload must be finite, JSON-serializable data") from exc
        if not isinstance(payload, dict) or len(payload_bytes) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload must be an object no larger than 64 KiB")
        payload_snapshot = json.loads(payload_bytes)

        with self._lock:
            key = self._keys.get(sender_id)
            if key is None:
                raise PermissionError("sender has no registered message identity")
            if recipient_id not in self._keys:
                raise PermissionError("recipient has no registered message identity")
            if signing_key is not None:
                if not isinstance(signing_key, str) or not hmac.compare_digest(signing_key, key):
                    raise PermissionError("sender signing key mismatch")
            if self.identity_manager is None and not self.allow_unbound_test_mode:
                raise PermissionError("managed identity integration is required")
            if self.identity_manager is not None:
                if not self.identity_manager.is_authorized(
                    sender_id, "inter_agent:send", token_id=token_id, require_token=True
                ):
                    raise PermissionError("sender lacks a valid inter-agent send token")
                if not self._tenant_allowed(sender_id, recipient_id):
                    raise PermissionError("cross-tenant message delivery is not authorized")
            issued_at = _aware_utc(now or datetime.now(timezone.utc))
            self._prune_expired_locked(issued_at)
            inbox = self._inboxes.setdefault(recipient_id, [])
            if len(inbox) >= MAX_INBOX_MESSAGES:
                raise RuntimeError("recipient inbox capacity reached")
            if self._queued_count >= MAX_TOTAL_INBOX_MESSAGES:
                raise RuntimeError("global message capacity reached")
            message = AgentMessage(
                message_id=uuid.uuid4().hex,
                sender_id=sender_id,
                recipient_id=recipient_id,
                payload=payload_snapshot,
                signature="",
                timestamp=issued_at,
                expires_at=issued_at + timedelta(seconds=ttl_seconds),
            )
            message.signature = _sign(message, key)
            inbox.append(copy.deepcopy(message))
            self._queued_count += 1
            logger.info(
                "Agent message queued",
                extra={"event": "agent_message_sent", "module_name": "inter_agent",
                       "message_id": message.message_id, "sender_id": sender_id,
                       "recipient_id": recipient_id},
            )
            return copy.deepcopy(message)

    def verify(
        self,
        message: AgentMessage,
        recipient_id: str | None = None,
        *,
        token_id: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Verify envelope, identity scope, expiry and one-time consumption atomically."""
        if not isinstance(message, AgentMessage) or not isinstance(message.payload, dict):
            return False
        if self.identity_manager is None and not self.allow_unbound_test_mode:
            return False
        if not isinstance(message.signature, str) or not _SIGNATURE.fullmatch(message.signature):
            return False
        try:
            self._validate_agent_id(message.sender_id)
            self._validate_agent_id(message.recipient_id)
            if not _MESSAGE_ID.fullmatch(message.message_id):
                return False
            issued_at = _aware_utc(message.timestamp)
            expires_at = _aware_utc(message.expires_at)
            current = _aware_utc(now or datetime.now(timezone.utc))
            if expires_at <= issued_at or expires_at - issued_at > timedelta(seconds=MAX_TTL_SECONDS):
                return False
            if issued_at > current + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS) or current >= expires_at:
                return False
            if len(json.dumps(message.payload, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False).encode("utf-8")) > MAX_PAYLOAD_BYTES:
                return False
            expected_recipient = message.recipient_id if recipient_id is None else recipient_id
            if expected_recipient != message.recipient_id:
                return False
            if self.identity_manager is not None:
                if not self.identity_manager.is_authorized(
                    expected_recipient, "inter_agent:receive", token_id=token_id, require_token=True
                ):
                    return False
                if not self._tenant_allowed(message.sender_id, expected_recipient):
                    return False
        except (ValueError, TypeError, AttributeError, RecursionError):
            return False

        with self._lock:
            key = self._keys.get(message.sender_id)
            if key is None or expected_recipient not in self._keys:
                return False
            if not any(item.message_id == message.message_id for item in self._inboxes.get(expected_recipient, [])):
                return False
            try:
                expected_signature = _sign(message, key)
            except (ValueError, TypeError, RecursionError):
                return False
            if not isinstance(message.signature, str) or not hmac.compare_digest(expected_signature, message.signature):
                return False

            self._prune_expired_locked(current)
            replay_key = (expected_recipient, message.message_id)
            if replay_key in self._consumed or len(self._consumed) >= MAX_CONSUMED_IDS:
                return False
            self._consumed[replay_key] = expires_at
            current_inbox = self._inboxes.get(expected_recipient, [])
            remaining = [item for item in current_inbox if item.message_id != message.message_id]
            self._queued_count -= len(current_inbox) - len(remaining)
            self._inboxes[expected_recipient] = remaining
            return True

    def _prune_expired_locked(self, current: datetime) -> int:
        removed = 0
        for recipient, messages in self._inboxes.items():
            active = [message for message in messages if current < message.expires_at]
            removed += len(messages) - len(active)
            self._inboxes[recipient] = active
        for key, expiry in list(self._consumed.items()):
            if current >= expiry:
                del self._consumed[key]
        self._queued_count = max(0, self._queued_count - removed)
        return removed

    def get_inbox(self, agent_id: str, *, token_id: str | None = None) -> list[AgentMessage]:
        self._validate_agent_id(agent_id)
        if self.identity_manager is not None and not self.identity_manager.is_authorized(
            agent_id, "inter_agent:receive", token_id=token_id, require_token=True
        ):
            raise PermissionError("recipient lacks a valid inter-agent receive token")
        with self._lock:
            self._prune_expired_locked(datetime.now(timezone.utc))
            messages = self._inboxes.get(agent_id, [])
            if self.identity_manager is None:
                return copy.deepcopy(messages)
            visible = []
            for message in messages:
                if message.recipient_id != agent_id or not self._tenant_allowed(message.sender_id, agent_id):
                    continue
                if (agent_id, message.message_id) in self._consumed:
                    continue
                key = self._keys.get(message.sender_id)
                if key is None or not isinstance(message.signature, str) or not _SIGNATURE.fullmatch(message.signature):
                    continue
                try:
                    expected = _sign(message, key)
                except (ValueError, TypeError, RecursionError):
                    continue
                if hmac.compare_digest(expected, message.signature):
                    visible.append(message)
            return copy.deepcopy(visible)

    def clear_expired(self, now: datetime | None = None) -> int:
        current = _aware_utc(now or datetime.now(timezone.utc))
        with self._lock:
            return self._prune_expired_locked(current)
