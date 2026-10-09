# Phase 16 forensic audit — evidence and audit trail

**Scope:** append-only event chain, decision/approval/execution correlation, operator verification API and regression tests.

**CI evidence:** PR #24 exact head `c60acec2aa03e6da225ed96b8bdf618dfe3f4018` passed [workflow 37946732792](https://github.com/LloydCoder/Auctaryn/actions/runs/37946732792). Merge commit `ddb7aeaa6e8ee82814a918b2285dd7f4e50c750d` passed post-merge [workflow 37946956578](https://github.com/LloydCoder/Auctaryn/actions/runs/37946956578), including Python 3.11/3.12, Ruff, dependency audit, dashboard build, Compose, image build and liveness.

## Implemented

- SQLite-backed evidence records use a canonical JSON payload, sequence, previous-record digest and SHA-256 record digest.
- SQLite update/delete triggers reject ordinary mutation attempts; the verifier recomputes the complete chain and reports the first failing sequence.
- Optional HMAC-SHA-256 record authentication is enabled with `AUCTARYN_EVIDENCE_HMAC_KEY` (minimum 32 bytes). Without the key, the service explicitly reports hash-chain-only mode.
- Evidence records are bounded and contain correlation identifiers, decisions, action fingerprints and safe receipt hashes rather than raw action parameters, bearer credentials or stdout/stderr.
- Gateway records assessment, decision, approval resolution, execution request, execution decision and safe receipt events. The execution request is persisted before invoking the execution service.
- Administrator-only endpoints expose bounded record pages and chain verification.
- Regression tests cover ordering, keyed integrity, chain tampering, HMAC mismatch, bounds, administrator access and gateway correlation.

## Security invariants

1. Evidence endpoints do not create or grant authorization; Tinlance Agent Platform remains authoritative.
2. Raw action parameters, credentials and execution output are not intentionally persisted in evidence records.
3. An `execution.requested` event without a terminal decision/receipt is an incomplete operation requiring operator investigation, not proof that execution did or did not occur.
4. A hash chain alone cannot prevent an attacker with full database control from rewriting the entire database. HMAC requires a separately protected key; production deployments should export records/checkpoints to an independently administered immutable store.
5. SQLite is a local durable store, not a distributed consensus log. Multi-replica deployments require a shared, separately administered evidence service and explicit retention/backup policy.

## External acceptance gates

- Provision and rotate the evidence key through the approved secrets manager; prefer a mounted secret file and verify key rotation behavior.
- Validate file/volume permissions, backups, restore drills, retention, storage exhaustion and cross-process concurrent writers in the target deployment.
- Forward evidence records/checkpoints to independently controlled immutable storage and test tamper alerts.
- Correlate Auctaryn advisory findings with authoritative Platform decisions and execution receipts using Platform-issued IDs; do not treat local evidence as the Platform's audit of record.
- Exact final-head CI must pass before merge; live deployment acceptance remains separate.
