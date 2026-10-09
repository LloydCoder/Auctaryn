# Phase 20 forensic audit — reliability, scale and disaster recovery

**Status:** Phase 20 implementation, forensic review, merge, and post-merge CI completed. Merged main commit: `64394df2adfc58964987d36ad010a0705f07c707`.  
**Scope:** Safe local SQLite backup/verification/restore and concurrency regressions for the evidence and incident-control database.

## Threats and invariants reviewed

1. A raw file copy of a live SQLite database may omit committed WAL state or produce an unusable snapshot.
2. A corrupted evidence chain must not be presented as a verified recovery point.
3. Signed evidence must not be called authenticated when the HMAC key is unavailable.
4. Restore must not silently overwrite a target or replace the target before the candidate backup passes validation.
5. Temporary backup/restore files must be restricted to owner read/write permissions.
6. Concurrent event writes must preserve a verifiable append-only hash chain.
7. Recovery documentation must distinguish a local utility from a complete enterprise disaster-recovery capability.

## Changes in this phase

- Added `scripts/database_recovery.py` with SQLite Online Backup API snapshots, SQLite `integrity_check`, SHA-256 digest reporting, evidence-chain verification, HMAC-key-unavailable fail-closed behavior, private file permissions and atomic restore publication.
- Added regression tests for evidence/incident-control preservation, no-overwrite behavior, corrupt-chain restore rejection, concurrent appends and verification reporting.
- Added `docs/DATABASE_RECOVERY.md` with operational backup/restore instructions, HMAC exception handling and explicit RPO/RTO ownership.
- Updated roadmap and README to describe capability and limitations without implying multi-replica or off-site DR is solved.

## CI acceptance evidence

- PR-head workflow: [Auctaryn CI run 37957625483](https://github.com/LloydCoder/Auctaryn/actions/runs/37957625483) on `9132b146f560dc1c4bc673eb24035e9f8b19e341`.
- Post-merge main workflow: [Auctaryn CI run 37957858071](https://github.com/LloydCoder/Auctaryn/actions/runs/37957858071) on `64394df2adfc58964987d36ad010a0705f07c707`.

- [x] Python 3.11: 487 tests passed; Ruff passed.
- [x] Python 3.12: 487 tests passed; Ruff passed; `pip-audit` reported no known vulnerabilities.
- [x] Dashboard production build and dependency audit passed.
- [x] Deployment-script syntax, Compose validation, container build and API liveness passed.
- [x] Merge completed and every required post-merge check passed.

The Python 3.11 dependency-audit step is intentionally skipped by the workflow; the required dependency audit runs and passed on Python 3.12.

## Production limitations intentionally not marked complete

- No scheduled backup service, backup-age alerting, off-host/immutable storage or encryption/key-management integration is introduced here.
- RPO/RTO, retention and restore-test intervals require business-owner approval and impact analysis; this repository does not invent targets.
- The tool restores one local SQLite database only. It does not make process-local identities, tokens, approvals, in-memory deduplication or circuit-breaker state durable.
- Replacing a live database is unsafe. Restore must be performed with all writers stopped and SQLite sidecars handled under the runbook.
- Local evidence storage is not the Tinlance Agent Platform audit of record.
- CI exercises a deterministic local database fixture; it is not a destructive production disaster-recovery drill.

## Research basis

- SQLite Online Backup API: https://www.sqlite.org/backup.html
- NIST SP 800-34 Rev. 1 contingency planning: https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final
- OWASP Agentic AI Threats and Mitigations: https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/

## Reviewer checklist

- Inspect every changed line and the generated workflow logs.
- Confirm restore never overwrites a target without explicit authorization.
- Confirm HMAC-signed evidence is rejected as unauthenticated when the key is absent.
- Confirm the roadmap and README do not overstate production readiness.
- Phase 20 exit gate satisfied for the repository implementation. Live DR acceptance gates remain explicitly listed above and must be completed before production release.
