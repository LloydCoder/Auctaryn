# Phase 24 forensic audit — production release and ecosystem acceptance

**Repository:** `LloydCoder/Auctaryn`  
**Phase:** 24 of 24  
**Review date:** 2026-10-09  
**Scope:** release-evidence schema and validator, version-tag release workflow, OCI publication/attestation steps, tests, release runbook, supply-chain documentation, and roadmap reconciliation.

## Executive result

The repository implementation for Phase 24 is designed to fail closed. A valid pending manifest permits normal CI but does **not** authorize a release. Version-tag publication requires successful exact-commit CI, CodeQL and supply-chain runs, signed-off external evidence for independent security assessment, live Tinlance Agent Platform conformance, live OpenShell acceptance, and security-owner risk review. Post-deployment acceptance separately requires observed-vs-expected OCI digest equality and rollback-drill evidence.

This audit does not represent external gates as completed. No independent penetration-test report, live Platform conformance evidence, live OpenShell acceptance evidence, production deployment digest, or production rollback drill is fabricated or inferred from CI. The checked-in manifest intentionally remains pending, and release publication must remain blocked.

## Files reviewed

- `.github/workflows/release.yml`
- `scripts/verify_release_evidence.py`
- `tests/test_release_evidence.py`
- `release/release-evidence.json`
- `docs/PRODUCTION_RELEASE_ACCEPTANCE.md`
- `docs/SUPPLY_CHAIN.md`
- `docs/IMPLEMENTATION_ROADMAP.md`
- `.github/workflows/ci.yml`
- `.github/workflows/codeql.yml`
- `.github/workflows/supply-chain.yml`
- `scripts/deploy.sh` and `scripts/rollback.sh`
- `docker-compose.yml` and `docker-compose.production.yml`
- `.env.example`
- `README.md`, `site/index.html`, `site/about.html`, `site/docs.html`, `site/pricing.html`, `site/js/partials.js`
- `integrations/olvrix_widgets/twinguard_bridge_patch.py`
- `docs/DEMO_SCRIPT.md` and `docs/DEPLOYMENT_ROLLBACK.md`
- `LICENSE`

## Findings and remediation

### P24-01 — Workflow evidence could refer to the wrong successful run

**Risk:** a manifest could name a successful run for the same commit but not the required CI, CodeQL or supply-chain workflow. Run URL and run ID were not cryptographically or logically tied in the validator.

**Remediation:** the tag gate now checks each recorded run's database ID, exact workflow name, `main` branch, `push` event, exact tested commit, successful conclusion and exact recorded URL. The evidence validator rejects reused run IDs and URLs that do not identify their recorded run ID.

### P24-02 — Boolean finding counts could be treated as zero

**Risk:** in Python, `False == 0`; a malformed assessment could therefore pass the zero-findings comparison.

**Remediation:** assessment finding counts must be non-negative integers and explicitly cannot be booleans. A passed independent assessment must report zero unresolved critical and high findings and include a SHA-256 report digest.

### P24-03 — Review timestamps lacked a machine-validated timezone

**Risk:** ambiguous local timestamps could be accepted as release evidence.

**Remediation:** every passed gate requires an ISO-8601 review timestamp with an explicit timezone.

### P24-04 — Acceptance evidence did not require per-artifact integrity digests

**Risk:** a passed gate could reference an artifact without recording its expected content digest.

**Remediation:** each pre-release and post-deployment gate now requires an `evidence_sha256` digest when marked passed. This binds the reviewed evidence reference to an expected artifact hash; the reviewer/operator must still verify that the supplied artifact matches that hash.

### P24-05 — Published SBOM attestations were not all explicitly verified

**Risk:** verifying only the default OCI provenance did not explicitly verify the SPDX SBOM predicate or the local source-SBOM and release-manifest attestations.

**Remediation:** the release workflow verifies OCI provenance, the OCI image's SPDX SBOM predicate, the source SBOM attestation and the release-manifest attestation. It also checks that the registry's observed version-tag digest equals the digest returned by the image build.

### P24-06 — Operational collections could grow without bound

**Risk:** gateway decision history, pending approvals, identity/token/scope collections and runtime idempotency keys could grow without a hard memory bound under repeated requests.

**Remediation:** request ingress is bounded (2 MiB for ordinary API requests and a separate bounded PCAP allowance); gateway history is capped at 5,000 records, pending approvals at 1,000 with new pending actions denied at saturation, identity records at 100,000, token records at 250,000 with expired/revoked token pruning, per-identity scopes at 256, token/delegation scopes at 100, and execution/runtime idempotency records at 100,000. Capacity exhaustion denies or refuses further work rather than evicting replay guards. These in-process caps prevent unbounded growth but do not provide durable or multi-replica correctness.

### P24-07 — Public product pages overstated coverage and production validation

**Risk:** the static site advertised universal interception, a zero-percent production false-positive rate, stale test counts, live FusionOps metrics, and unapproved paid tiers/SLA claims. Those statements were not supported by the repository's current implementation or independent evidence.

**Remediation:** public pages now describe supported-path enforcement, label demo data as synthetic, distinguish mapped OWASP categories from certification, remove unverified production metrics and prices, and point to the canonical LloydCoder/Auctaryn repository. The reported February 2026 incident is described as a reported account with a source link and a qualification that it was not independently verified.

### P24-08 — Legacy Olvrix bridge was fail-open and hard-coded an endpoint

**Risk:** the reference patch used a hard-coded HTTP IP and allowed responses through when Auctaryn was unavailable. It also routed ordinary chat messages through an action-decision endpoint without a verified identity/context contract.

**Remediation:** replaced it with a draft action-only integration contract that requires HTTPS for remote endpoints, separate service and scoped-agent credentials, session-bound context-check evidence, and an exact `approved` decision. Any missing configuration, non-approved response or service error returns a blocked result. It is explicitly not represented as a tested live integration.

### P24-09 — Declared license file was missing

**Risk:** README and public pages described Apache-2.0 licensing, but the repository lacked a root license file.

**Remediation:** added the Apache License 2.0 text with Tinlance Limited copyright notice and added a regression test for the license file.

### P24-10 — Production deploy could bypass the release evidence chain

**Risk:** the previous helper built from a moving branch and used a mutable image reference; rollback attempted to retag a local image ID rather than restore a previously attested immutable digest.

**Remediation:** production deployment now requires a version tag, an exact GHCR digest, a verified release manifest, OCI provenance and SPDX SBOM attestations, HTTPS OpenShell gateway metadata, service-to-service OIDC credentials, and a mounted evidence HMAC key. The production Compose override pins the image digest. Rollback verifies the prior release and restores its immutable digest; deployment refuses missing/mismatched evidence and waits for readiness before exposing Nginx/TLS.

## Security and failure-mode coverage

The Phase 24 tests cover:

- pending template is schema-valid but cannot authorize promotion;
- valid pre-release evidence can pass schema/policy validation;
- unresolved high findings block production acceptance;
- mismatched deployed and expected digests block production acceptance;
- post-deployment digest verification and rollback evidence are mandatory for production acceptance;
- workflow evidence cannot reuse run IDs or mismatch its URL;
- boolean finding counts are rejected;
- passed gates require timezone-aware review timestamps;
- passed gates require evidence SHA-256 hashes;
- release workflow is version-tag-gated and verifies workflow identity and artifact attestations;
- API and PCAP ingress reject over-limit bodies before parsing;
- gateway history and approval queues remain bounded and pending actions are denied at queue saturation;
- identity, token, scope, execution-deduplication and runtime idempotency state have explicit fail-closed capacity guards;
- public pages avoid unsupported universal-mediation, production-metric and pricing claims;
- the Olvrix reference integration fails closed and does not use a hard-coded endpoint;
- production deployment and rollback require immutable digest and attestation verification;
- the repository contains the declared Apache-2.0 license.

The workflow-level checks remain authoritative for querying live GitHub run metadata. Unit tests cannot substitute for observing the required Actions jobs on the exact PR head.

## External production gates — still open by design

1. Independent security assessment report, independently reviewed and hashed, with zero unresolved critical/high findings.
2. Live Tinlance Agent Platform conformance evidence covering identity, tenant isolation, authorization, key rotation/revocation and deny behavior.
3. Live OpenShell acceptance proving effective policy, filesystem/workspace boundaries, egress restrictions, process limits and non-execution of denied actions.
4. Security-owner review of the current residual-risk register.
5. After an authorized deployment: expected and observed OCI digests must match, and a production rollback drill must be completed and evidenced.

These require real systems, authorized reviewers and operational evidence. GitHub-hosted CI cannot prove them. Do not populate the pending manifest with invented run IDs, test results, reviewers or evidence references.

## Required completion check

Before merging, verify all required jobs on the exact final PR head: Python 3.11 and 3.12 tests/Ruff, dependency audit, dashboard/container workflow, CodeQL, and secure-supply-chain workflow. A skipped release-publication job is expected on a pull request because publication is restricted to version tags; it is not evidence that a release was published. After merge, verify the post-merge workflows on the exact main commit.

## Standards references used

- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) — attestations provide provenance/integrity claims but do not by themselves certify the artifact as secure.
- [Generating and verifying artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) — required permissions and verification of OCI and SPDX attestations.
- [GitHub CLI `gh run view`](https://cli.github.com/manual/gh_run_view) — supported run metadata fields used to verify workflow name, branch, event, head SHA, conclusion, database ID and URL.

## Verdict

**Phase 24 implementation review: remediations applied; exact-head CI is the merge gate.**  
**Production release acceptance: NOT PASSED.** External evidence remains pending, so the release pipeline must refuse publication until real acceptance evidence is supplied. This is the intended safe state, not a reason to weaken the gate.
