"""Phase 20 recovery and concurrency regressions."""
import asyncio
import sqlite3

import pytest

from modules.evidence_audit.store import EvidenceStore
from modules.incident_response.manager import IncidentResponseManager
from scripts.database_recovery import backup, restore, verify


@pytest.mark.asyncio
async def test_backup_and_restore_preserve_evidence_and_incident_controls(tmp_path):
    source = tmp_path / "live.sqlite3"
    snapshot = tmp_path / "backup.sqlite3"
    restored = tmp_path / "restored.sqlite3"
    evidence = EvidenceStore(source)
    await evidence.append("decision.created", actor_id="agent-a", outcome="approved")
    manager = IncidentResponseManager(str(source))
    manager.set_emergency_stop(True, "operator", "disaster recovery test")
    manager.create_alert("high", "test", "Test alert", "Safe summary", decision_id="decision-1")

    report = backup(source, snapshot)
    assert report["operation"] == "backup"
    assert report["sqlite"]["integrity"] == "ok"
    assert report["evidence"]["valid"] is True
    assert snapshot.stat().st_mode & 0o777 == 0o600

    restored_report = restore(snapshot, restored)
    assert restored_report["operation"] == "restore"
    assert restored_report["evidence"]["valid"] is True
    assert restored_report["evidence"]["records_checked"] == 1
    assert IncidentResponseManager(str(restored)).get_status()["emergency_stop"] is True
    assert len(IncidentResponseManager(str(restored)).list_alerts()) == 1


def test_restore_refuses_to_overwrite_without_explicit_flag(tmp_path):
    source = tmp_path / "backup.sqlite3"
    target = tmp_path / "live.sqlite3"
    source_store = EvidenceStore(source)
    asyncio.run(source_store.append("backup.created", outcome="ok"))
    target_store = EvidenceStore(target)
    asyncio.run(target_store.append("target.must_remain", outcome="unchanged"))

    with pytest.raises(FileExistsError):
        restore(source, target)
    result = asyncio.run(target_store.list_records())
    assert result[0]["event_type"] == "target.must_remain"


def test_restore_rejects_corrupt_snapshot_without_touching_target(tmp_path):
    source = tmp_path / "backup.sqlite3"
    target = tmp_path / "live.sqlite3"
    store = EvidenceStore(source)
    asyncio.run(store.append("backup.created", outcome="ok"))
    with sqlite3.connect(source) as db:
        db.execute("DROP TRIGGER evidence_no_update")
        db.execute("UPDATE evidence_records SET payload_json = ? WHERE sequence = 1", ('{"tampered":true}',))
    target_store = EvidenceStore(target)
    asyncio.run(target_store.append("target.must_remain", outcome="unchanged"))

    with pytest.raises(ValueError, match="Evidence chain invalid"):
        restore(source, target, overwrite=True)
    assert asyncio.run(target_store.list_records())[0]["event_type"] == "target.must_remain"


@pytest.mark.asyncio
async def test_concurrent_evidence_appends_remain_a_valid_ordered_chain(tmp_path):
    store = EvidenceStore(tmp_path / "concurrent.sqlite3")
    await asyncio.gather(*[
        store.append("load.test", actor_id=f"agent-{i}", outcome="accepted")
        for i in range(64)
    ])
    report = await store.verify()
    assert report["valid"] is True
    assert report["records_checked"] == 64
    rows = await store.list_records(limit=100)
    assert len(rows) == 64
    assert len({row["record_id"] for row in rows}) == 64


def test_verify_reports_sqlite_integrity_and_hash_chain(tmp_path):
    path = tmp_path / "evidence.sqlite3"
    store = EvidenceStore(path)
    asyncio.run(store.append("integrity.test", outcome="ok"))
    report = verify(path)
    assert report["sqlite"]["integrity"] == "ok"
    assert report["evidence"]["valid"] is True
    assert len(report["sha256"]) == 64


def test_hmac_signed_evidence_fails_closed_without_key(tmp_path, monkeypatch):
    path = tmp_path / "signed.sqlite3"
    monkeypatch.setenv("AUCTARYN_EVIDENCE_HMAC_KEY", "h" * 32)
    store = EvidenceStore(path)
    asyncio.run(store.append("signed.event", outcome="protected"))
    monkeypatch.delenv("AUCTARYN_EVIDENCE_HMAC_KEY", raising=False)

    with pytest.raises(ValueError, match="HMAC signatures"):
        verify(path)
    report = verify(path, allow_unverified_hmac=True)
    assert report["evidence"]["valid"] is True
    assert report["evidence"]["reason"] == "key_unavailable"
    assert report["evidence"]["hmac_verified"] is False
