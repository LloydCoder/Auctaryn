"""Append-only SQLite evidence chain with optional keyed authentication."""
from __future__ import annotations
import asyncio
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import sqlite3
import threading
from typing import Any
from uuid import uuid4

ZERO_HASH = "0" * 64
MAX_PAGE_SIZE = 500
ALLOWED_DETAIL_KEYS = {"decision", "action_fingerprint", "confidence", "risk_level", "receipt_hash", "runtime_adapter"}

# Per-database process-local locks serialize first-time schema initialization
# across distinct EvidenceStore instances. SQLite still provides cross-process
# locking; this avoids avoidable PRAGMA/schema races inside one worker process.
_INITIALIZATION_LOCKS: dict[str, threading.Lock] = {}
_INITIALIZATION_LOCKS_GUARD = threading.Lock()


def _initialization_lock(path: str) -> threading.Lock:
    if path == ":memory:":
        return threading.Lock()
    key = str(Path(path).expanduser().resolve())
    with _INITIALIZATION_LOCKS_GUARD:
        lock = _INITIALIZATION_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _INITIALIZATION_LOCKS[key] = lock
        return lock


class EvidenceStoreError(RuntimeError):
    """Evidence persistence or verification failed."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class EvidenceStore:
    """SQLite append-only chain. HMAC mode requires a separately managed 32-byte key."""

    def __init__(self, path: str | Path | None = None, signing_key: str | bytes | None = None):
        self.path = str(path if path is not None else os.getenv("AUCTARYN_EVIDENCE_DB", "data/evidence.sqlite3"))
        key = signing_key
        if key is None:
            key_file = os.getenv("AUCTARYN_EVIDENCE_HMAC_KEY_FILE")
            if key_file:
                try:
                    key = Path(key_file).read_text(encoding="utf-8").strip()
                except OSError as exc:
                    raise ValueError("Evidence key file could not be read") from exc
            else:
                key = os.getenv("AUCTARYN_EVIDENCE_HMAC_KEY")
        self.key = key.encode() if isinstance(key, str) and key else None
        if self.key is not None and len(self.key) < 32:
            raise ValueError("Evidence key must be at least 32 bytes")
        self._lock = asyncio.Lock()
        self._initialized = False

    @property
    def integrity_mode(self) -> str:
        return "sha256-chain+hmac-sha256" if self.key else "sha256-chain-only"

    def _connect(self):
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _init_sync(self):
        # Different EvidenceStore objects can initialize the same file concurrently.
        # Serialize WAL-mode negotiation and idempotent schema/trigger creation.
        with _initialization_lock(self.path):
            with closing(self._connect()) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("""CREATE TABLE IF NOT EXISTS evidence_records (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id TEXT NOT NULL UNIQUE,
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    hmac_signature TEXT NOT NULL DEFAULT ''
                )""")
                db.execute("""CREATE TRIGGER IF NOT EXISTS evidence_no_update
                    BEFORE UPDATE ON evidence_records BEGIN
                    SELECT RAISE(ABORT, 'append-only evidence'); END""")
                db.execute("""CREATE TRIGGER IF NOT EXISTS evidence_no_delete
                    BEFORE DELETE ON evidence_records BEGIN
                    SELECT RAISE(ABORT, 'append-only evidence'); END""")

    async def initialize(self):
        async with self._lock:
            if not self._initialized:
                try:
                    await asyncio.to_thread(self._init_sync)
                except (sqlite3.Error, OSError) as exc:
                    raise EvidenceStoreError("Evidence initialization failed") from exc
                self._initialized = True

    def _signature(self, digest: str) -> str:
        return hmac.new(self.key, digest.encode("ascii"), hashlib.sha256).hexdigest() if self.key else ""

    @staticmethod
    def _text(value: Any, limit: int = 256) -> str:
        return " ".join(str(value or "").split())[:limit]

    @classmethod
    def _identifier(cls, value: Any, limit: int = 128) -> str:
        text = cls._text(value, limit)
        if not text:
            return ""
        if re.fullmatch(r"[A-Za-z0-9._:@/-]+", text):
            return text
        return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _append_sync(self, event_type: str, *, correlation_id: str = "", actor_id: str = "",
                     tenant_id: str = "", decision_id: str = "", execution_id: str = "",
                     outcome: str = "", details: dict[str, Any] | None = None) -> dict[str, Any]:
        event_type = self._text(event_type, 96)
        if not event_type or any(ord(ch) < 32 for ch in event_type):
            raise ValueError("event_type must be a printable non-empty value")
        details = details or {}
        if not isinstance(details, dict) or len(details) > 32:
            raise ValueError("details must be an object with at most 32 fields")
        safe_details: dict[str, Any] = {}
        for key, value in details.items():
            safe_key = self._text(key, 64)
            if safe_key not in ALLOWED_DETAIL_KEYS:
                raise ValueError("detail key is not in the evidence allowlist")
            if safe_key in {"action_fingerprint", "receipt_hash"}:
                if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value.lower()):
                    raise ValueError("fingerprint details must be 64 hexadecimal characters")
                safe_details[safe_key] = value.lower()
            elif safe_key in {"decision", "risk_level", "runtime_adapter"}:
                if not isinstance(value, str) or len(value) > 128 or any(ord(ch) < 32 for ch in value):
                    raise ValueError("classification details must be short printable strings")
                safe_details[safe_key] = self._text(value, 128)
            elif safe_key == "confidence":
                if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0.0 <= float(value) <= 1.0:
                    raise ValueError("confidence must be between zero and one")
                safe_details[safe_key] = float(value)
            else:
                raise ValueError("unsupported evidence detail")
        occurred_at = datetime.now(timezone.utc).isoformat()
        payload = {
            "schema": "auctaryn.evidence-record.v1", "record_id": uuid4().hex,
            "occurred_at": occurred_at, "event_type": event_type,
            "correlation_id": self._identifier(correlation_id), "actor_id": self._identifier(actor_id),
            "tenant_id": self._identifier(tenant_id), "decision_id": self._identifier(decision_id),
            "execution_id": self._identifier(execution_id), "outcome": self._text(outcome, 96),
            "details": safe_details,
            "provenance": {"producer": "auctaryn", "source": "application_event"},
        }
        serialized = canonical_json(payload).decode("utf-8")
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT record_hash FROM evidence_records ORDER BY sequence DESC LIMIT 1").fetchone()
                previous_hash = row["record_hash"] if row else ZERO_HASH
                digest = hashlib.sha256(previous_hash.encode("ascii") + bytes([10]) + serialized.encode("utf-8")).hexdigest()
                signature = self._signature(digest)
                cursor = db.execute(
                    """INSERT INTO evidence_records
                    (record_id, occurred_at, event_type, payload_json, previous_hash, record_hash, hmac_signature)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (payload["record_id"], occurred_at, event_type, serialized, previous_hash, digest, signature),
                )
                sequence = int(cursor.lastrowid)
                db.commit()
            return {"sequence": sequence, **payload, "previous_hash": previous_hash,
                    "record_hash": digest, "hmac_signature": signature, "integrity_mode": self.integrity_mode}
        except (sqlite3.Error, OSError) as exc:
            raise EvidenceStoreError("Evidence append failed") from exc

    async def append(self, event_type: str, **kwargs: Any) -> dict[str, Any]:
        await self.initialize()
        return await asyncio.to_thread(self._append_sync, event_type, **kwargs)

    def _list_sync(self, limit: int) -> list[dict[str, Any]]:
        if not 1 <= limit <= MAX_PAGE_SIZE:
            raise ValueError("limit outside supported bounds")
        try:
            with closing(self._connect()) as db:
                rows = db.execute(
                    "SELECT * FROM evidence_records ORDER BY sequence DESC LIMIT ?", (limit,)
                ).fetchall()
            records = []
            for row in reversed(rows):
                payload = json.loads(row["payload_json"])
                payload.update({
                    "sequence": row["sequence"], "previous_hash": row["previous_hash"],
                    "record_hash": row["record_hash"], "hmac_signature": row["hmac_signature"],
                    "integrity_mode": self.integrity_mode,
                })
                records.append(payload)
            return records
        except (sqlite3.Error, OSError, json.JSONDecodeError) as exc:
            raise EvidenceStoreError("Evidence query failed") from exc

    async def list_records(self, limit: int = 100) -> list[dict[str, Any]]:
        await self.initialize()
        return await asyncio.to_thread(self._list_sync, limit)

    def _verify_sync(self) -> dict[str, Any]:
        try:
            with closing(self._connect()) as db:
                rows = db.execute("SELECT * FROM evidence_records ORDER BY sequence ASC").fetchall()
            previous_hash = ZERO_HASH
            checked = 0
            hmac_verified = bool(self.key)
            for row in rows:
                digest = hashlib.sha256(
                    previous_hash.encode("ascii") + bytes([10]) + row["payload_json"].encode("utf-8")
                ).hexdigest()
                if row["previous_hash"] != previous_hash or not hmac.compare_digest(digest, row["record_hash"]):
                    return {"valid": False, "records_checked": checked, "failed_sequence": row["sequence"],
                            "reason": "hash_chain_mismatch", "integrity_mode": self.integrity_mode}
                if self.key and not hmac.compare_digest(self._signature(digest), row["hmac_signature"]):
                    return {"valid": False, "records_checked": checked, "failed_sequence": row["sequence"],
                            "reason": "hmac_mismatch", "integrity_mode": self.integrity_mode}
                if not self.key and row["hmac_signature"]:
                    hmac_verified = False
                previous_hash = digest
                checked += 1
            if self.key:
                reason = "ok" if hmac_verified else "hmac_unverified"
            else:
                reason = "key_unavailable" if any(row["hmac_signature"] for row in rows) else "hash_chain_only"
            return {"valid": True, "records_checked": checked, "head_hash": previous_hash,
                    "hmac_verified": hmac_verified, "integrity_mode": self.integrity_mode,
                    "reason": reason}
        except (sqlite3.Error, OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise EvidenceStoreError("Evidence verification failed") from exc

    async def verify(self) -> dict[str, Any]:
        await self.initialize()
        return await asyncio.to_thread(self._verify_sync)


_default_store: EvidenceStore | None = None


def get_evidence_store() -> EvidenceStore:
    """Return the process-local store; SQLite serializes writes across processes."""
    global _default_store
    if _default_store is None:
        _default_store = EvidenceStore()
    return _default_store


async def record_evidence(event_type: str, **kwargs: Any) -> dict[str, Any]:
    return await get_evidence_store().append(event_type, **kwargs)
