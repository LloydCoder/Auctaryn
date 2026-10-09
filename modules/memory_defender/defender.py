"""
TwinGuard — Memory Poisoning Defender
Maps to OWASP ASI06:2026 — Memory & Context Poisoning.

Protects an agent's accumulated long-term memory (summaries, learned
facts, prior-session notes) from adversarial content injected through
tool results, scraped documents, or untrusted conversation turns.

Distinct from Context Integrity Guardian: that module verifies explicitly
REGISTERED safety instructions survive compaction. This module screens
NEW content before it's allowed to become part of the agent's memory at
all, and detects tampering of content already stored.
"""

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.logging import get_logger

logger = get_logger("memory_defender")

# Known injection patterns — instruction override, role hijack, hidden
# directives smuggled inside otherwise-normal-looking content.
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

# Sources considered untrusted by default — content from these requires
# a clean poisoning scan before storage, and even then gets quarantined.
UNTRUSTED_SOURCES = {"scraped_webpage", "untrusted_document", "external_api", "third_party_tool"}


@dataclass
class MemoryEntry:
    key: str
    content: str
    source: str
    integrity_hash: str
    session_id: str = ""
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


def _hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def scan_for_poisoning(content: str) -> PoisoningScanResult:
    """Check content against known adversarial injection patterns."""
    lowered = content.lower()
    for pattern, category in POISONING_PATTERNS:
        if re.search(pattern, lowered):
            return PoisoningScanResult(suspicious=True, matched_pattern=pattern, category=category)
    return PoisoningScanResult(suspicious=False)


class MemoryStore:
    """
    Hashed, tamper-evident storage for agent memory entries.
    Not a database — in-memory for MVP, same pattern as other TwinGuard
    modules. Swap for Redis/Postgres when persistence is needed.
    """

    def __init__(self):
        self._entries: dict[str, MemoryEntry] = {}
        self._last_known_good: dict[str, MemoryEntry] = {}

    def add(self, key: str, content: str, source: str, session_id: str = "",
            quarantined: bool = False) -> MemoryEntry:
        entry = MemoryEntry(
            key=key, content=content, source=source,
            integrity_hash=_hash_content(content),
            session_id=session_id, quarantined=quarantined,
        )
        self._entries[key] = entry
        self._last_known_good[key] = MemoryEntry(
            key=key, content=content, source=source,
            integrity_hash=entry.integrity_hash, session_id=session_id,
            quarantined=quarantined,
        )
        return entry

    def get(self, key: str) -> MemoryEntry | None:
        return self._entries.get(key)

    def verify_integrity(self, key: str) -> bool:
        entry = self._entries.get(key)
        if entry is None:
            return False
        return _hash_content(entry.content) == entry.integrity_hash

    def rollback(self, key: str) -> bool:
        """Restore the last known-good version of a tampered entry."""
        good = self._last_known_good.get(key)
        if good is None:
            return False
        self._entries[key] = MemoryEntry(
            key=good.key, content=good.content, source=good.source,
            integrity_hash=good.integrity_hash, session_id=good.session_id,
            quarantined=good.quarantined,
        )
        logger.warning(f"Rolled back tampered memory entry: {key}",
                       extra={"event": "memory_rollback", "module_name": "memory_defender"})
        return True


class MemoryDefender:
    """
    Full defense pipeline: screens new content before storage, applies
    stricter scrutiny to untrusted sources, quarantines ambiguous
    content instead of silently dropping it, and blocks quarantined
    entries from propagating across agent sessions until cleared.
    """

    def __init__(self):
        self.store = MemoryStore()

    def evaluate_for_storage(self, content: str, source: str,
                              session_id: str = "") -> StorageDecision:
        scan = scan_for_poisoning(content)

        if scan.suspicious:
            logger.warning(
                f"Blocked poisoned content from source '{source}': category={scan.category}",
                extra={"event": "poisoning_blocked", "module_name": "memory_defender"},
            )
            return StorageDecision(
                allow_storage=False,
                reason=f"Adversarial pattern detected ({scan.category}): {scan.matched_pattern}",
            )

        is_untrusted = source in UNTRUSTED_SOURCES

        if is_untrusted:
            # Benign content from an untrusted source is still stored,
            # but quarantined — visible only to its own session until
            # a human or a trusted process clears it.
            self.store.add(
                key=source, content=content, source=source,
                session_id=session_id, quarantined=True,
            )
            return StorageDecision(allow_storage=True, quarantined=True,
                                   reason="Untrusted source — quarantined pending review")

        self.store.add(key=source, content=content, source=source, session_id=session_id)
        return StorageDecision(allow_storage=True)

    def is_readable_by_session(self, key: str, session_id: str) -> bool:
        """
        Quarantined entries are only readable by the session that
        produced them — prevents poisoned state from silently
        propagating to other agents/sessions sharing the same store.
        """
        entry = self.store.get(key)
        if entry is None:
            return False
        if not entry.quarantined:
            return True
        return entry.session_id == session_id
