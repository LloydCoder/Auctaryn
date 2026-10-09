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

### P24-10 — Weak API credentials could pass readiness outside the deployment helper

**Risk:** authentication accepted short service/admin keys, while only the deployment helper enforced a 32-character minimum. A manually configured deployment could therefore use weak keys and still appear configured.

**Remediation:** authentication now enables strong-key enforcement by default, rejects keys shorter than 32 characters and obvious placeholders, and readiness independently requires strong distinct credentials. Production Compose forces strong-key mode. Test fixtures explicitly disable the policy only for tests that exercise authentication error paths; readiness tests use strong test keys.

### P24-11 — Production deploy could bypass the release evidence chain

**Risk:** the previous helper built from a moving branch and used a mutable image reference; rollback attempted to retag a local image ID rather than restore a previously attested immutable digest.

**Remediation:** production deployment now requires a version tag, an exact GHCR digest, a verified release manifest, OCI provenance and SPDX SBOM attestations, HTTPS OpenShell gateway metadata, service-to-service OIDC credentials, and a mounted evidence HMAC key. The production Compose override pins the image digest. Rollback verifies the prior release and restores its immutable digest; deployment refuses missing/mismatched evidence and waits for readiness before exposing Nginx/TLS.

### P24-12 — Naive UTC model factories produced hundreds of deprecation warnings

**Risk:** repeated `datetime.utcnow` model defaults created naive timestamps and obscured the test signal with hundreds of Python deprecation warnings.

**Remediation:** replaced project-owned model timestamp factories with `datetime.now(timezone.utc)`. Exact implementation-head Python 3.11 and 3.12 CI each passed 552 tests with no pytest warning summary. No global warning suppression was added. Node/npm tooling still emits upstream deprecation notices; those are distinct from the resolved Python model warning.

### P24-13 — OpenShell system gateway metadata used the wrong endpoint field and allowed loopback HTTPS

**Risk:** the deploy helper expected `"endpoint"`, while current NVIDIA OpenShell gateway metadata uses `gateway_endpoint`. A legitimate registered gateway could be rejected. The old loopback guard checked only HTTP even though the preceding condition required HTTPS, so an HTTPS loopback endpoint could pass that check.

**Remediation:** added `scripts/verify_openshell_gateway_metadata.py`, accepts the current `gateway_endpoint` field (and the legacy `endpoint` key for compatibility), bounds metadata size, validates the HTTPS URL/hostname/port, rejects URL credentials/query/fragment, whitespace/backslashes, malformed numeric hosts, localhost, loopback and unspecified IPs, and fails closed. Production deployment invokes the validator before switching traffic; CI now uses the official `gateway_endpoint` field and tests rejection cases. This is contract validation, not proof of a live OpenShell connection.

### P24-14 — Synchronous runtime health probes could block or exhaust workers

**Risk:** invoking a synchronous adapter probe directly would block the event loop; running arbitrary blocking probes in a thread cannot safely cancel a hung function and repeated requests could exhaust worker threads.

**Remediation:** detailed health/readiness now require an asynchronous probe and apply a bounded timeout. Unsupported synchronous probes are rejected without invoking them. Regression tests cover timeout behavior and fail-closed handling.

### P24-15 — CI workflow token permissions were implicit

**Risk:** the primary CI workflow relied on repository defaults rather than declaring a least-privilege token contract.

**Remediation:** the primary CI workflow now explicitly sets `permissions: contents: read`. CodeQL and supply-chain workflows retain only the additional permissions needed for SARIF publication and artifact attestations.

#### P24-16 — Secret scanning did not reliably cover the full change set and used a deprecated action runtime

**Risk:** the prior Gitleaks Action v2 workflow ran on the deprecated Node 20 action runtime and its default commit selection did not reliably cover the complete squash-merge change set. A post-merge scan exposed a generic-api-key false positive in a prose row of the final audit, demonstrating that PR-only checks had not caught the same line.

**Remediation:** the workflow now installs checksum-pinned Gitleaks v8.30.1, scans the explicit `base..head` range for pull requests and `before..after` for pushes, scans all ancestors of the selected ref on weekly/manual runs, and uploads SARIF even on failure. The final audit wording was corrected. A single `.gitleaksignore` fingerprint is scoped to the immutable historical commit/line that contained the false positive; it does not ignore the rule, path or any future line. The exact-head scan on PR #34 reported no leaks. Full CI and post-merge verification remain required.

## External standards review — OWASP Agent Control Standard

The OWASP GenAI Security Project's [Agent Control Standard (ACS)](https://github.com/GenAI-Security-Project/agent-control-standard) v0.1.0 is a wire protocol with JSON-RPC envelopes, handshake/capability negotiation and pre-action hook requests; it is not the same thing as the OWASP ASI01–ASI10 risk taxonomy. Auctaryn currently exposes its own versioned REST contracts and **does not claim ACS conformance**. An ACS adapter is a future interoperability candidate, not an implemented capability or a current release blocker. Any future adapter requires schema validation, handshake, authentication/replay semantics, disposition mapping and live end-to-end mediation tests.

## Exact-head implementation CI evidence

Implementation head reviewed: `3da5a4f5a86f803545963a03a40a033c086ae566`.

- [Auctaryn CI — run 37978786024](https://github.com/LloydCoder/Auctaryn/actions/runs/37978786024): Python 3.11 and 3.12 each passed **552 tests**; lint, dependency audit, dashboard build, deployment/rollback syntax, Compose validation, container build and liveness passed.
- [Secure software supply chain — run 37978785991](https://github.com/LloydCoder/Auctaryn/actions/runs/37978785991): Gitleaks, npm audit, SBOM generation, fixable high/critical container gate, full Grype inventory audit and artifact upload passed. The full inventory reported 16 matches across 95 packages (3 ignored), with **0 high/critical and 0 actionable high/critical** findings.
- [CodeQL security analysis — run 37978785928](https://github.com/LloydCoder/Auctaryn/actions/runs/37978785928): SARIF reported **0 findings** across critical, high, medium and low/unrated severities.
- [Gated production release — run 37978786032](https://github.com/LloydCoder/Auctaryn/actions/runs/37978786032): release-evidence contract validation passed. OCI publication was skipped because this was a pull request, as intended; the release manifest remains pending external acceptance evidence.

These results apply to the implementation head above. The final audit/documentation commit must pass its own exact-head workflows before merge, and main must pass post-merge verification.

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
- authentication rejects weak/placeholder credentials by default and readiness requires strong distinct keys;
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

Implementation head `3da5a4f5a86f803545963a03a40a033c086ae566` passed all required exact-head checks listed above. The final audit/documentation commit must also pass Python 3.11/3.12, Ruff, dependency audit, dashboard/container, CodeQL and secure-supply-chain checks before merge. The tag-only publication job is expected to be skipped on a pull request; no release was published. After merge, verify the post-merge workflows on the exact main commit.

## Standards references used

- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) — attestations provide provenance/integrity claims but do not by themselves certify the artifact as secure.
- [Generating and verifying artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) — required permissions and verification of OCI and SPDX attestations.
- [GitHub CLI `gh run view`](https://cli.github.com/manual/gh_run_view) — supported run metadata fields used to verify workflow name, branch, event, head SHA, conclusion, database ID and URL.

## Verdict

**Phase 24 implementation review: remediations applied; exact-head CI is the merge gate.**  
**Production release acceptance: NOT PASSED.** External evidence remains pending, so the release pipeline must refuse publication until real acceptance evidence is supplied. This is the intended safe state, not a reason to weaken the gate.
