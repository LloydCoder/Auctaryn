#!/usr/bin/env python3
"""Safe SQLite backup, integrity verification, and atomic restore for Auctaryn.

This utility protects local operational/evidence state. It does not replace
Platform audit storage, external key management, off-host backup retention, or
multi-replica coordination.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from typing import Any


def _path(value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_symlink():
        raise ValueError(f"Refusing symlink path: {path}")
    return path.resolve()


def _database_check(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"Database does not exist: {path}")
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)) as db:
            integrity = [row[0] for row in db.execute("PRAGMA integrity_check")]
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
    except sqlite3.Error as exc:
        raise ValueError("Database cannot be opened or checked") from exc
    if integrity != ["ok"]:
        raise ValueError("SQLite integrity_check failed")
    return {"integrity": "ok", "tables": sorted(tables)}


def _evidence_check(path: Path, allow_unverified_hmac: bool) -> dict[str, Any]:
    """Verify evidence rows read-only; never initialize or change the candidate DB."""
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)) as db:
        db.row_factory = sqlite3.Row
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        if "evidence_records" not in tables:
            return {"valid": True, "records_checked": 0, "reason": "no_evidence_table",
                    "hmac_verified": False, "integrity_mode": "not_present"}
        rows = db.execute("SELECT * FROM evidence_records ORDER BY sequence ASC").fetchall()

    key_value = os.getenv("AUCTARYN_EVIDENCE_HMAC_KEY")
    key_file = os.getenv("AUCTARYN_EVIDENCE_HMAC_KEY_FILE")
    if key_file:
        try:
            key_value = Path(key_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValueError("Evidence HMAC key file could not be read") from exc
    key = key_value.encode("utf-8") if key_value else None
    if key is not None and len(key) < 32:
        raise ValueError("Evidence HMAC key must be at least 32 bytes")

    previous_hash = "0" * 64
    checked = 0
    any_signature = any(row["hmac_signature"] for row in rows)
    hmac_verified = bool(key)
    for row in rows:
        digest = hashlib.sha256(
            previous_hash.encode("ascii") + bytes([10]) + row["payload_json"].encode("utf-8")
        ).hexdigest()
        if row["previous_hash"] != previous_hash or not hmac.compare_digest(digest, row["record_hash"]):
            raise ValueError(f"Evidence chain invalid at sequence {row['sequence']}: hash_chain_mismatch")
        signature = row["hmac_signature"]
        if key is not None:
            expected = hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()
            if not signature or not hmac.compare_digest(expected, signature):
                raise ValueError(f"Evidence chain invalid at sequence {row['sequence']}: hmac_mismatch")
        elif signature:
            hmac_verified = False
        previous_hash = digest
        checked += 1

    if key is not None:
        reason = "ok"
    elif any_signature:
        reason = "key_unavailable"
    else:
        reason = "hash_chain_only"
    if reason == "key_unavailable" and not allow_unverified_hmac:
        raise ValueError(
            "Evidence rows contain HMAC signatures but the verification key is unavailable; "
            "configure AUCTARYN_EVIDENCE_HMAC_KEY_FILE or explicitly pass "
            "--allow-unverified-hmac only for a documented recovery operation"
        )
    return {"valid": True, "records_checked": checked, "head_hash": previous_hash,
            "hmac_verified": hmac_verified, "integrity_mode": "sha256-chain+hmac-sha256" if key else "sha256-chain-only",
            "reason": reason}

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path, allow_unverified_hmac: bool = False) -> dict[str, Any]:
    database = _database_check(path)
    evidence = _evidence_check(path, allow_unverified_hmac)
    return {
        "database": str(path),
        "sqlite": database,
        "evidence": evidence,
        "sha256": _sha256(path),
    }


def backup(source: Path, destination: Path, allow_unverified_hmac: bool = False) -> dict[str, Any]:
    source = _path(str(source))
    destination = _path(str(destination))
    if source == destination:
        raise ValueError("Source and destination must differ")
    if not source.is_file():
        raise ValueError(f"Source database does not exist: {source}")
    if destination.exists():
        raise FileExistsError(f"Backup destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".auctaryn-backup-", suffix=".sqlite3", dir=destination.parent)
    os.close(fd)
    temp = Path(temp_name)
    try:
        # SQLite's backup API captures a consistent snapshot, including committed WAL data.
        src = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=10)
        dst = sqlite3.connect(temp, timeout=10)
        try:
            src.backup(dst)
            dst.commit()
            if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("SQLite integrity_check failed after backup")
        finally:
            dst.close()
            src.close()
        os.chmod(temp, 0o600)
        report = verify(temp, allow_unverified_hmac)
        # Hard-link creation is atomic and fails if another process created the
        # destination after our initial existence check (no accidental overwrite).
        os.link(temp, destination)
        temp.unlink()
        os.chmod(destination, 0o600)
        return {**report, "database": str(destination), "source": str(source), "operation": "backup"}
    finally:
        if temp.exists():
            temp.unlink()


def restore(source: Path, destination: Path, overwrite: bool = False,
            allow_unverified_hmac: bool = False) -> dict[str, Any]:
    source = _path(str(source))
    destination = _path(str(destination))
    if source == destination:
        raise ValueError("Backup and restore target must differ")
    if not source.is_file():
        raise ValueError(f"Backup does not exist: {source}")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Restore target exists; pass --overwrite to replace it: {destination}")
    if any(Path(str(destination) + suffix).exists() for suffix in ("-wal", "-shm")):
        raise ValueError("Restore target has SQLite -wal/-shm sidecars; stop all writers and handle them before restore")
    # Never replace the live target until the backup has passed both checks.
    verify(source, allow_unverified_hmac)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".auctaryn-restore-", suffix=".sqlite3", dir=destination.parent)
    os.close(fd)
    temp = Path(temp_name)
    try:
        with source.open("rb") as src, temp.open("wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        os.chmod(temp, 0o600)
        report = verify(temp, allow_unverified_hmac)
        if overwrite:
            os.replace(temp, destination)
        else:
            # Atomic no-clobber install closes the check/replace race.
            os.link(temp, destination)
            temp.unlink()
        os.chmod(destination, 0o600)
        return {**report, "database": str(destination), "source": str(source), "operation": "restore"}
    finally:
        if temp.exists():
            temp.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    backup_parser = sub.add_parser("backup", help="Create and verify a consistent SQLite snapshot")
    backup_parser.add_argument("source")
    backup_parser.add_argument("destination")
    restore_parser = sub.add_parser("restore", help="Verify then atomically restore a SQLite snapshot")
    restore_parser.add_argument("source")
    restore_parser.add_argument("destination")
    restore_parser.add_argument("--overwrite", action="store_true", help="Replace an existing target atomically")
    verify_parser = sub.add_parser("verify", help="Verify SQLite integrity and the evidence chain")
    verify_parser.add_argument("database")
    for command_parser in (backup_parser, restore_parser, verify_parser):
        command_parser.add_argument(
            "--allow-unverified-hmac", action="store_true",
            help="Allow recovery without the evidence HMAC key; records remain unauthenticated",
        )
    args = parser.parse_args()
    try:
        if args.command == "backup":
            result = backup(_path(args.source), _path(args.destination), args.allow_unverified_hmac)
        elif args.command == "restore":
            result = restore(_path(args.source), _path(args.destination), args.overwrite,
                             args.allow_unverified_hmac)
        else:
            result = verify(_path(args.database), args.allow_unverified_hmac)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, FileExistsError, OSError, sqlite3.Error) as exc:
        print(json.dumps({"error": str(exc), "operation": args.command}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
