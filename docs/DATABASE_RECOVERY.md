# Local database backup and recovery runbook

## Scope and safety boundary

Auctaryn stores the local evidence chain and incident-response controls in SQLite. This runbook provides a consistent single-database snapshot and verified restore. It does **not** make local identity/token/approval state durable, establish multi-replica consensus, replace Tinlance Agent Platform's authoritative audit, or satisfy off-site backup retention by itself.

The backup command uses Python's SQLite Online Backup API rather than copying a live database file. SQLite documents that this produces a consistent snapshot while allowing other connections to continue using the source database ([SQLite Online Backup API](https://www.sqlite.org/backup.html)). The process verifies SQLite integrity and the evidence chain before publishing a backup.

## Prerequisites

- Run from the repository root in the same Python environment as Auctaryn.
- Protect the backup directory with owner-only access and encrypted off-host storage.
- If records are HMAC-signed, provide the same separately managed key via `AUCTARYN_EVIDENCE_HMAC_KEY_FILE` (preferred) or `AUCTARYN_EVIDENCE_HMAC_KEY`. Never place key material in command-line arguments, backup manifests, logs, tickets or chat.
- Back up the database path configured by `AUCTARYN_EVIDENCE_DB`; Compose defaults to `/app/data/evidence.sqlite3`.

## Create and verify a backup

```bash
umask 077
python scripts/database_recovery.py backup \
  /path/to/evidence.sqlite3 \
  /secure-backups/auctaryn-evidence-$(date -u +%Y%m%dT%H%M%SZ).sqlite3
```

The command exits non-zero if the source cannot be read, SQLite integrity fails, the evidence chain is invalid, or HMAC signatures exist but the verification key is unavailable. It prints a JSON report with a SHA-256 digest; store that digest separately from the backup, preferably in a signed/immutable inventory.

Verify an existing snapshot before moving or restoring it:

```bash
python scripts/database_recovery.py verify /secure-backups/auctaryn-evidence-<timestamp>.sqlite3
sha256sum /secure-backups/auctaryn-evidence-<timestamp>.sqlite3
```

Compare the digest to the separately recorded value. A digest printed by the same machine is not an independent authenticity proof if that machine or its backup directory is compromised.

## Restore procedure

1. Declare an incident/change window; stop the Auctaryn API and all writers. Do not replace a database file while the application is running.
2. Preserve the current database and its `-wal`/`-shm` sidecars as incident artifacts when investigation or rollback requires them. Do not blindly delete sidecars from a live database.
3. Verify the candidate backup using the required HMAC key. If that key is unavailable, stop and recover the key through the approved secret-management process.
4. Restore to a **new path first** and review the JSON integrity report:

   ```bash
   python scripts/database_recovery.py restore \
     /secure-backups/auctaryn-evidence-<timestamp>.sqlite3 \
     /secure-restore/evidence-restore.sqlite3
   python scripts/database_recovery.py verify /secure-restore/evidence-restore.sqlite3
   ```

5. Compare expected evidence sequence/head, alert and emergency-stop state with incident records. Have an authorized operator approve the cutover.
6. During a maintenance window, move the verified restored database into the configured data location only after confirming all writers are stopped and handling any old SQLite sidecars. Keep the pre-restore copy until post-restore verification succeeds.
7. Start the service privately, check liveness and readiness, verify the evidence chain and incident controls, exercise a denied test action, and only then restore normal traffic.
8. Record the backup timestamp, selected snapshot, digest, evidence-chain result, approver, restoration time, observed data loss and follow-up actions in the incident record.

The utility refuses to overwrite an existing restore target unless `--overwrite` is supplied. Prefer restoring to a new path; reserve `--overwrite` for an explicitly approved, offline recovery.

### HMAC recovery exception

`--allow-unverified-hmac` allows inspection/restoration when signed evidence exists but the key is unavailable. This does **not** authenticate those records. It is an exceptional, documented recovery mode only; never interpret it as a clean forensic verification. Obtain the key and re-run verification before treating the evidence as authenticated.

## RPO, RTO, retention and production acceptance

Business owners must set and approve Recovery Point Objective (RPO), Recovery Time Objective (RTO), retention, encryption, off-site/immutable storage, restore-test cadence and access separation based on impact analysis. This repository does not invent those business targets. NIST SP 800-34 describes contingency planning and recovery priorities; use it as a planning reference ([NIST SP 800-34 Rev. 1](https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final)).

This utility is a single-host recovery mechanism, not a complete enterprise DR service. Production acceptance still requires scheduled off-host backups, independent monitoring of backup age and failures, automated restore drills, key escrow/rotation, storage-loss recovery, and a documented multi-replica/database migration strategy.
