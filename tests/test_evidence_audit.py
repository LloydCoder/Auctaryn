"""Tests for chained evidence persistence and operator inspection routes."""
import json
import sqlite3

import pytest

from modules.evidence_audit.store import EvidenceStore


@pytest.mark.asyncio
async def test_append_verify_and_list_preserve_order(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3", signing_key="k" * 32)
    first = await store.append(
        "decision.created", actor_id="agent-1", decision_id="decision-1",
        outcome="pending", details={"decision": "pending", "action_fingerprint": "a" * 64},
    )
    second = await store.append(
        "execution.receipt", actor_id="agent-1", decision_id="decision-1",
        execution_id="exec-1", outcome="succeeded", details={"receipt_hash": "b" * 64},
    )
    assert first["sequence"] == 1
    assert second["sequence"] == 2
    assert second["previous_hash"] == first["record_hash"]
    assert second["hmac_signature"]
    assert (await store.verify())["valid"] is True
    assert (await store.verify())["hmac_verified"] is True
    records = await store.list_records(limit=10)
    assert [item["event_type"] for item in records] == ["decision.created", "execution.receipt"]


@pytest.mark.asyncio
async def test_chain_detects_payload_tampering(tmp_path):
    path = tmp_path / "evidence.sqlite3"
    store = EvidenceStore(path, signing_key="s" * 32)
    await store.append("decision.created", outcome="pending")
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER evidence_no_update")
        db.execute("UPDATE evidence_records SET payload_json = ? WHERE sequence = 1", ('{"tampered":true}',))
    result = await store.verify()
    assert result["valid"] is False
    assert result["failed_sequence"] == 1
    assert result["reason"] == "hash_chain_mismatch"


@pytest.mark.asyncio
async def test_hmac_signature_tampering_is_detected(tmp_path):
    path = tmp_path / "evidence.sqlite3"
    store = EvidenceStore(path, signing_key="x" * 32)
    await store.append("decision.created", outcome="pending")
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER evidence_no_update")
        db.execute("UPDATE evidence_records SET hmac_signature = ? WHERE sequence = 1", ("0" * 64,))
    result = await store.verify()
    assert result["valid"] is False
    assert result["reason"] == "hmac_mismatch"


@pytest.mark.asyncio
async def test_key_must_be_long_enough_and_page_size_is_bounded(tmp_path):
    with pytest.raises(ValueError):
        EvidenceStore(tmp_path / "bad.sqlite3", signing_key="short")
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    with pytest.raises(ValueError):
        await store.list_records(limit=501)


@pytest.mark.asyncio
async def test_evidence_details_reject_unapproved_fields(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    with pytest.raises(ValueError):
        await store.append("decision.created", details={"raw_parameters": "must-not-be-stored"})
