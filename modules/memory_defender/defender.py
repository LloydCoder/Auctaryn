"""Memory poisoning defense with provenance-bound, bounded in-process storage.

This module is a defense-in-depth component. Production persistence and
identity/tenant authority remain owned by the Tinlance Agent Platform.
"""
import copy
import hashlib
import json
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.logging import get_logger

logger = get_logger("memory_defender")

MAX_MEMORY_CONTENT_CHARS = 32_768
MAX_MEMORY_SOURCE_CHARS = 64
MAX_MEMORY_SESSION_CHARS = 128
MAX_MEMORY_AGENT_ID_CHARS = 128
MAX_MEMORY_ENTRIES = 5_000
MAX_MEMORY_SESSIONS = 5_000

POISONING_PATTERNS = [
    (r"ignore (all )?(previous|prior) instructions?", "instruction_override"),
    (r"disregard (all )?(prior|previous) (rules|instructions?)", "instruction_override"),
    (r"system\s*override", "role_hijack"),
    (r"you are now in (admin|root|unrestricted) mode", "role_hijack"),
    (r"\[agent instruction:", "hidden_directive"),
    (r"\[system:.*\]", "hidden_directive"),
    (r"grant (full|admin|root) access", "privilege_escalation"),
    (r"disable (all )?(safety|security) checks?", "safety_bypass"),
]
# Only these internal provenance labels are treated as trusted by the module API.
# Public API submissions are prefixed with "api:" and are always quarantined.
TRUSTED_SOURCES = {"user_conversation", "trusted_system", "approved_internal"}


@dataclass
class MemoryEntry:
    key: str
    content: str
    source: str
    integrity_hash: str
    session_id: str = ""
    agent_id: str = ""
    quarantined: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PoisoningScanResult:
    suspicious: bool
    matched_pattern: str = ""
    category: str = ""


@dataclass
class StorageDecision:
    allow_storage: bool
    quarantined: bool = False
    reason: str = ""
    entry_id: str | None = None


def _hash_content(content: str) -> str:
    """Compatibility helper for content-only checks."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _hash_entry(entry: MemoryEntry) -> str:
    """Bind the content and every security-relevant provenance field."""
    canonical = json.dumps(
        {
            "key": entry.key,
            "content": entry.content,
            "source": entry.source,
            "session_id": entry.session_id,
            "agent_id": entry.agent_id,
            "quarantined": entry.quarantined,
            "created_at": entry.created_at.astimezone(timezone.utc).isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_memory_fields(content: str, source: str, session_id: str, agent_id: str) -> None:
    if not isinstance(content, str) or not content or len(content) > MAX_MEMORY_CONTENT_CHARS:
        raise ValueError(f"content must contain 1–{MAX_MEMORY_CONTENT_CHARS} characters")
    if not isinstance(source, str) or not source.strip() or len(source) > MAX_MEMORY_SOURCE_CHARS:
        raise ValueError(f"source must contain 1–{MAX_MEMORY_SOURCE_CHARS} characters")
    if not isinstance(session_id, str) or len(session_id) > MAX_MEMORY_SESSION_CHARS:
        raise ValueError(f"session_id must be at most {MAX_MEMORY_SESSION_CHARS} characters")
    if not isinstance(agent_id, str) or len(agent_id) > MAX_MEMORY_AGENT_ID_CHARS:
        raise ValueError(f"agent_id must be at most {MAX_MEMORY_AGENT_ID_CHARS} characters")


def scan_for_poisoning(content: str) -> PoisoningScanResult:
    """Check bounded content against known adversarial instruction patterns."""
    if not isinstance(content, str):
        raise ValueError("content must be a string")
    if len(content) > MAX_MEMORY_CONTENT_CHARS:
        raise ValueError(f"content exceeds {MAX_MEMORY_CONTENT_CHARS} characters")
    lowered = content.lower()
    for pattern, category in POISONING_PATTERNS:
        if re.search(pattern, lowered):
            return PoisoningScanResult(suspicious=True, matched_pattern=pattern, category=category)
    return PoisoningScanResult(suspicious=False)


class MemoryStore:
    """Bounded in-process store with metadata-bound hashes and last-known-good snapshots.

    This is not durable storage and is not safe for multi-replica deployments.
    """
    def __init__(self, max_entries: int = MAX_MEMORY_ENTRIES):
        if not 1 <= max_entries <= MAX_MEMORY_ENTRIES:
            raise ValueError(f"max_entries must be between 1 and {MAX_MEMORY_ENTRIES}")
        self.max_entries = max_entries
        self._entries: dict[str, MemoryEntry] = {}
        self._last_known_good: dict[str, MemoryEntry] = {}
        self._lock = threading.RLock()

    def add(
        self,
        key: str,
        content: str,
        source: str,
        session_id: str = "",
        quarantined: bool = False,
        agent_id: str = "",
    ) -> MemoryEntry:
        _validate_memory_fields(content, source, session_id, agent_id)
        if not isinstance(key, str) or not key or len(key) > 128:
            raise ValueError("key must contain 1–128 characters")
        if not isinstance(quarantined, bool):
            raise ValueError("quarantined must be a boolean")
        with self._lock:
            if key in self._entries:
                raise ValueError("memory entry key already exists")
            if len(self._entries) >= self.max_entries:
                raise ValueError("memory store capacity reached")
            entry = MemoryEntry(
                key=key,
                content=content,
                source=source.strip().lower(),
                integrity_hash="",
                session_id=session_id,
                agent_id=agent_id,
                quarantined=quarantined,
            )
            entry.integrity_hash = _hash_entry(entry)
            self._entries[key] = entry
            self._last_known_good[key] = copy.deepcopy(entry)
            return copy.deepcopy(entry)

    def get(self, key: str) -> MemoryEntry | None:
        with self._lock:
            entry = self._entries.get(key)
            return copy.deepcopy(entry) if entry is not None else None

    def verify_integrity(self, key: str) -> bool:
        with self._lock:
            entry = self._entries.get(key)
            trusted_snapshot = self._last_known_good.get(key)
            if entry is None or trusted_snapshot is None:
                return False
            try:
                current_hash = _hash_entry(entry)
            except (AttributeError, TypeError, ValueError):
                return False
            return current_hash == trusted_snapshot.integrity_hash == entry.integrity_hash

    def rollback(self, key: str) -> bool:
        """Restore a trusted snapshot when content or provenance metadata was tampered."""
        with self._lock:
            good = self._last_known_good.get(key)
            if good is None:
                return False
            self._entries[key] = copy.deepcopy(good)
        logger.warning(
            "Rolled back tampered memory entry",
            extra={"event": "memory_rollback", "module_name": "memory_defender"},
        )
        return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class MemoryDefender:
    """Screen content, isolate sessions, quarantine untrusted sources and detect tampering."""
    def __init__(self):
        self.store = MemoryStore()
        self._sessions: dict[str, str] = {}
        self._session_lock = threading.RLock()

    def create_session(self, agent_id: str) -> str:
        if not isinstance(agent_id, str) or not agent_id or len(agent_id) > MAX_MEMORY_AGENT_ID_CHARS:
            raise ValueError("agent_id must contain 1–128 characters")
        with self._session_lock:
            if len(self._sessions) >= MAX_MEMORY_SESSIONS:
                raise ValueError("memory session capacity reached")
            session_id = uuid.uuid4().hex
            self._sessions[session_id] = agent_id
            return session_id

    def session_owned_by(self, session_id: str, agent_id: str) -> bool:
        with self._session_lock:
            return self._sessions.get(session_id) == agent_id

    def evaluate_for_storage(
        self,
        content: str,
        source: str,
        session_id: str = "",
        agent_id: str = "",
    ) -> StorageDecision:
        _validate_memory_fields(content, source, session_id, agent_id)
        normalized_source = source.strip().lower()
        scan = scan_for_poisoning(content)

        if scan.suspicious:
            logger.warning(
                "Blocked suspicious memory content",
                extra={
                    "event": "poisoning_blocked",
                    "module_name": "memory_defender",
                    "category": scan.category,
                },
            )
            return StorageDecision(
                allow_storage=False,
                reason=f"Adversarial pattern detected ({scan.category}): {scan.matched_pattern}",
            )

        quarantined = normalized_source not in TRUSTED_SOURCES
        entry_id = uuid.uuid4().hex
        try:
            self.store.add(
                key=entry_id,
                content=content,
                source=normalized_source,
                session_id=session_id,
                agent_id=agent_id,
                quarantined=quarantined,
            )
        except ValueError as exc:
            if "capacity reached" in str(exc):
                return StorageDecision(allow_storage=False, reason="Memory capacity reached")
            raise

        if quarantined:
            return StorageDecision(
                allow_storage=True,
                quarantined=True,
                reason="Untrusted or unverified provenance — quarantined pending review",
                entry_id=entry_id,
            )
        return StorageDecision(allow_storage=True, entry_id=entry_id)

    def is_readable_by_session(self, key: str, session_id: str, agent_id: str | None = None) -> bool:
        if not self.store.verify_integrity(key):
            if not self.store.rollback(key):
                return False
        entry = self.store.get(key)
        if entry is None:
            return False
        if entry.agent_id and agent_id != entry.agent_id:
            return False
        if entry.quarantined:
            return entry.session_id == session_id
        return True
