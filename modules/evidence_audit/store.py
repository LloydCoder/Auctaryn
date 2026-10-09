"""Append-only SQLite evidence chain with optional keyed authentication."""
from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
from typing import Any
from uuid import uuid4

ZERO_HASH = "0" * 64
MAX_PAGE_SIZE = 500


class EvidenceStoreError(RuntimeError):
    """Evidence persistence or verification failed."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class EvidenceStore:
    """SQLite append-only chain. HMAC mode requires a separately managed 32-byte key."""

    def __init__(self, path: str | Path | None = None, signing_key: str | bytes | None = None):
        self.path = str(path if path is not None else os.getenv("AUCTARYN_EVIDENCE_DB", "data/evidence.sqlite3"))
        key = signing_key if signing_key is not None else os.getenv("AUCTARYN_EVIDENCE_HMAC_KEY")
        self.key = key.encode() if isinstance(key, str) and key else key
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
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def _init_sync(self):
        with self._connect() as db:
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
            if not safe_key or not isinstance(value, (str, int, float, bool, type(None))):
                raise ValueError("details must contain scalar values")
            if isinstance(value, str):
                safe_details[safe_key] = self._text(value, 512)
            elif isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
                raise ValueError("non-finite detail values are not allowed")
            else:
                safe_details[safe_key] = value
        occurred_at = datetime.now(timezone.utc).isoformat()
        payload = {
            "schema": "auctaryn.evidence-record.v1", "record_id": uuid4().hex,
            "occurred_at": occurred_at, "event_type": event_type,
            "correlation_id": self._text(correlation_id), "actor_id": self._text(actor_id),
            "tenant_id": self._text(tenant_id), "decision_id": self._text(decision_id),
            "execution_id": self._text(execution_id), "outcome": self._text(outcome, 96),
            "details": safe_details,
            "provenance": {"producer": "auctaryn", "source": "application_event"},
        }
        serialized = canonical_json(payload).decode("utf-8")
        try:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT record_hash FROM evidence_records ORDER BY sequence DESC LIMIT 1").fetchone()
                previous_hash = row["record_hash"] if row else ZERO_HASH
                digest = hashlib.sha256(previous_hash.encode("ascii") + b"\\n" + serialized.encode("utf-8")).hexdigest()
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
