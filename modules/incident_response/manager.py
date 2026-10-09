"""Durable local incident controls and alert lifecycle for Auctaryn."""
from __future__ import annotations
from contextlib import closing
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
from typing import Any
from uuid import uuid4

from modules.execution_gateway.runtime_adapter import RuntimeAdapterFailure


class IncidentResponseBlocked(RuntimeAdapterFailure):
    """Execution was stopped by an active incident-response control."""


class IncidentResponseManager:
    """Persistent emergency stop, per-agent quarantine, and alert state."""

    def __init__(self, path: str | None = None):
        self.path = path or os.getenv("AUCTARYN_EVIDENCE_DB", "data/evidence.sqlite3")
        self._initialized = False
        self._initialize()

    @staticmethod
    def _text(value: Any, limit: int = 256) -> str:
        return " ".join(str(value or "").split())[:limit]

    def _connect(self):
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def _initialize(self) -> None:
        if self._initialized:
            return
        with closing(self._connect()) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS incident_controls (
                control_id INTEGER PRIMARY KEY CHECK (control_id = 1),
                emergency_stop INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL DEFAULT '',
                updated_by TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 0
            )""")
            db.execute("""INSERT OR IGNORE INTO incident_controls
                (control_id, emergency_stop, reason, updated_by, updated_at, version)
                VALUES (1, 0, '', '', ?, 0)""", (datetime.now(timezone.utc).isoformat(),))
            db.execute("""CREATE TABLE IF NOT EXISTS agent_quarantine (
                agent_id TEXT PRIMARY KEY,
                quarantined INTEGER NOT NULL,
                reason TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS incident_alerts (
                alert_id TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                decision_id TEXT NOT NULL DEFAULT '',
                actor_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                acknowledged_by TEXT NOT NULL DEFAULT '',
                acknowledged_at TEXT NOT NULL DEFAULT '',
                resolved_by TEXT NOT NULL DEFAULT '',
                resolved_at TEXT NOT NULL DEFAULT ''
            )""")
        self._initialized = True

    def get_status(self) -> dict[str, Any]:
        self._initialize()
        with closing(self._connect()) as db:
            control = db.execute("SELECT * FROM incident_controls WHERE control_id = 1").fetchone()
            quarantined = db.execute(
                "SELECT agent_id, reason, updated_by, updated_at, version FROM agent_quarantine WHERE quarantined = 1 ORDER BY agent_id"
            ).fetchall()
            counts = db.execute(
                "SELECT status, COUNT(*) AS count FROM incident_alerts GROUP BY status"
            ).fetchall()
        return {
            "emergency_stop": bool(control["emergency_stop"]),
            "reason": control["reason"],
            "updated_by": control["updated_by"],
            "updated_at": control["updated_at"],
            "version": control["version"],
            "quarantined_agents": [dict(row) for row in quarantined],
            "alert_counts": {row["status"]: row["count"] for row in counts},
        }

    def set_emergency_stop(self, enabled: bool, actor: str, reason: str) -> dict[str, Any]:
        self._initialize()
        now = datetime.now(timezone.utc).isoformat()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """UPDATE incident_controls SET emergency_stop=?, reason=?, updated_by=?,
                updated_at=?, version=version+1 WHERE control_id=1""",
                (int(enabled), self._text(reason, 512), self._text(actor, 128), now),
            )
            db.commit()
        return self.get_status()

    def set_agent_quarantine(self, agent_id: str, enabled: bool, actor: str, reason: str) -> dict[str, Any]:
        self._initialize()
        agent_id = self._text(agent_id, 128)
        if not agent_id or any(ord(ch) < 32 for ch in agent_id):
            raise ValueError("agent_id is invalid")
        now = datetime.now(timezone.utc).isoformat()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """INSERT INTO agent_quarantine (agent_id, quarantined, reason, updated_by, updated_at, version)
                VALUES (?, ?, ?, ?, ?, 1)
                ON CONFLICT(agent_id) DO UPDATE SET quarantined=excluded.quarantined,
                reason=excluded.reason, updated_by=excluded.updated_by, updated_at=excluded.updated_at,
                version=agent_quarantine.version+1""",
                (agent_id, int(enabled), self._text(reason, 512), self._text(actor, 128), now),
            )
            db.commit()
        return {"agent_id": agent_id, "quarantined": enabled, "updated_by": self._text(actor, 128),
                "updated_at": now}

    def assert_execution_allowed(self, agent_id: str) -> None:
        self._initialize()
        with closing(self._connect()) as db:
            control = db.execute("SELECT emergency_stop, reason FROM incident_controls WHERE control_id=1").fetchone()
            quarantine = db.execute(
                "SELECT quarantined, reason FROM agent_quarantine WHERE agent_id=?", (self._text(agent_id, 128),)
            ).fetchone()
        if control and control["emergency_stop"]:
            raise IncidentResponseBlocked("Emergency stop is active; execution refused.")
        if quarantine and quarantine["quarantined"]:
            raise IncidentResponseBlocked("Agent is quarantined; execution refused.")

    def create_alert(self, severity: str, category: str, title: str, summary: str,
                     decision_id: str = "", actor_id: str = "") -> dict[str, Any]:
        self._initialize()
        if severity not in {"critical", "high", "medium", "low"}:
            raise ValueError("alert severity is invalid")
        alert = {
            "alert_id": uuid4().hex, "severity": severity,
            "category": self._text(category, 96), "title": self._text(title, 160),
            "summary": self._text(summary, 512), "decision_id": self._text(decision_id, 128),
            "actor_id": self._text(actor_id, 128), "status": "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "acknowledged_by": "", "acknowledged_at": "", "resolved_by": "", "resolved_at": "",
        }
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            if alert["decision_id"]:
                existing = db.execute(
                    """SELECT * FROM incident_alerts WHERE decision_id=? AND category=?
                    AND status != 'resolved' ORDER BY created_at DESC LIMIT 1""",
                    (alert["decision_id"], alert["category"]),
                ).fetchone()
                if existing is not None:
                    db.rollback()
                    return dict(existing)
            db.execute(
                """INSERT INTO incident_alerts
                (alert_id, severity, category, title, summary, decision_id, actor_id, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert["alert_id"], alert["severity"], alert["category"], alert["title"], alert["summary"],
                 alert["decision_id"], alert["actor_id"], alert["status"], alert["created_at"]),
            )
            db.commit()
        return alert

    def list_alerts(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        self._initialize()
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        if status is not None and status not in {"open", "acknowledged", "resolved"}:
            raise ValueError("alert status is invalid")
        with closing(self._connect()) as db:
            if status:
                rows = db.execute(
                    "SELECT * FROM incident_alerts WHERE status=? ORDER BY created_at DESC LIMIT ?", (status, limit)
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM incident_alerts ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(row) for row in rows]

    def transition_alert(self, alert_id: str, action: str, actor: str) -> dict[str, Any]:
        self._initialize()
        if action not in {"acknowledge", "resolve"}:
            raise ValueError("alert action is invalid")
        now = datetime.now(timezone.utc).isoformat()
        actor = self._text(actor, 128)
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM incident_alerts WHERE alert_id=?", (alert_id,)).fetchone()
            if row is None:
                db.rollback()
                raise KeyError("alert_not_found")
            if row["status"] == "resolved":
                db.rollback()
                raise ValueError("resolved alerts cannot transition")
            if action == "acknowledge":
                db.execute(
                    "UPDATE incident_alerts SET status='acknowledged', acknowledged_by=?, acknowledged_at=? WHERE alert_id=?",
                    (actor, now, alert_id),
                )
            else:
                db.execute(
                    "UPDATE incident_alerts SET status='resolved', resolved_by=?, resolved_at=? WHERE alert_id=?",
                    (actor, now, alert_id),
                )
            db.commit()
            updated = db.execute("SELECT * FROM incident_alerts WHERE alert_id=?", (alert_id,)).fetchone()
        return dict(updated)


_default_manager: IncidentResponseManager | None = None


def get_incident_response_manager() -> IncidentResponseManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = IncidentResponseManager()
    return _default_manager
