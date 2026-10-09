# Phase 22 forensic audit — secure software supply chain

**Status:** Implementation and exact-head CI are green on code head `a59d80aa08e5ae1713ea1f05a757a336c286b413`. The audit/documentation commit must pass the same required workflows before PR #31 is eligible to merge.

## Scope and acceptance criteria

This audit covers dependency reproducibility, immutable action references, source and container SBOMs, source-history secret scanning, static analysis, container vulnerability gates, artifact provenance and deployment install determinism. It does not claim that a green build proves production deployment identity or live runtime containment.

## Exact-head evidence

- [Auctaryn CI — run 37966794400](https://github.com/LloydCoder/Auctaryn/actions/runs/37966794400): Python 3.11 and 3.12 test matrices passed; each collected and passed 501 tests. Ruff, the Python 3.12 dependency audit, dashboard build, deployment/rollback shell syntax, Compose validation, container build and liveness checks passed.
- [Secure software supply chain — run 37966794385](https://github.com/LloydCoder/Auctaryn/actions/runs/37966794385): npm audit, historical/change-set Gitleaks scan, source and container SPDX SBOM generation, fixable high/critical vulnerability gate, complete Grype inventory audit and artifact upload passed. The complete inventory reported **0 high/critical findings and 0 actionable high/critical findings**.
- [CodeQL security analysis — run 37966794341](https://github.com/LloydCoder/Auctaryn/actions/runs/37966794341): Python and JavaScript/TypeScript security-extended analysis completed with **0 findings** (0 critical, 0 high, 0 medium, 0 low/unrated).

These workflow runs all target the same implementation head. The final audit/documentation commit is separately required to pass all workflows; PR #31 remains the source of truth for that exact-head result.

## Findings fixed in Phase 22

1. **Incomplete Grype inventory:** the “full inventory” scan used a `critical` cutoff, which could hide high-severity findings from the independent audit. The inventory scan now uses the lowest severity cutoff, does not filter to fixed vulnerabilities, and is checked independently. A separate blocking scan fails on fixable high/critical findings.
2. **Excessive Debian base-image attack surface:** the previous slim Debian image produced 55 high-severity package occurrences across 14 CVE IDs, all reported as unfixable by the scanned package metadata. The runtime image moved to the smaller official Python Alpine variant pinned to its multi-platform index digest. Grype then identified fixable `zlib` CVE-2026-85091; the image now pins the fixed Alpine package revision `zlib=1.3.2-r1`. The exact-head complete inventory now reports zero high/critical findings.
3. **Mutable deployment dependency resolution:** `scripts/deploy.sh` used `npm install`; it now uses `npm ci --no-audit --no-fund` against the committed `dashboard/package-lock.json`.
4. **Artifact-action runtime deprecation:** pinned `actions/upload-artifact` v7.0.2 and `actions/download-artifact` v8.0.2 at verified full commit SHAs. These releases use Node 24, avoiding the prior Node 20 compatibility warning.
5. **Starlette TestClient deprecation:** added hash-locked `httpx2==2.13.1`, `httpcore2==2.13.1` and `truststore==0.10.4`, including artifact hashes, so tests no longer fall back to the deprecated `httpx` implementation.
6. **Regression protection:** added tests for complete Grype inventory configuration, immutable base-image digest, the patched zlib revision, pinned artifact actions, lockfile integrity and `npm ci` deployment behavior.
7. **Documentation accuracy:** removed the claim that GitHub Dependency Review is configured. This repository instead uses `pip-audit`, `npm audit`, pinned lockfile diffs and the container scanner; no unconfigured GitHub Dependency Review action is represented as evidence.

## Controls now enforced

- Hash-locked Python direct and transitive dependencies; hash-locked npm graph.
- Immutable full-SHA GitHub Action references.
- Pinned multi-platform Python base-image index digest and fixed zlib revision.
- CodeQL security-extended analysis and high-severity SARIF gate.
- Gitleaks scanning across history and the change set.
- Python and npm dependency audits.
- A blocking scan for fixable high/critical container findings plus an independently parsed complete Grype report.
- SPDX SBOMs for source/dependencies and the built container.
- GitHub artifact attestations for SBOMs and the exact tested image archive on successful pushes to `main`.
- Locked `npm ci` deployment and rollback helper checks.

## Warnings and residual limits

- The suite passes 501 tests but still emits 279 warnings, predominantly repeated `datetime.utcnow()` deprecation warnings during model validation. The Starlette TestClient deprecation was removed; the remaining warning source must be traced rather than globally suppressed. Track this in Phase 23 assurance/test hygiene.
- GitHub Dependency Review is not enabled; the current alternative is documented above.
- The image archive is attested on `main` but is not published to a production OCI registry by this phase. No deployed-host digest verification or live rollback drill was performed.
- CI does not prove live OpenShell containment, Platform-side identity/key lifecycle, production network transport, multi-replica durability or external penetration-test results.
- The pinned Alpine base index digest and zlib revision require scheduled review as upstream security updates evolve.

## Research basis

- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) explain provenance claims and the need to verify attestations at consumption time; an attestation is not itself a security certification.
- [Docker Official Python image metadata](https://hub.docker.com/layers/library/python/3.12.15-alpine3.24/images/sha256-95f7584617ab7b4bdb100bb7f051749dbb9ad1f9bf29ad35b637e405e88c5092) provided the multi-platform index digest used to pin the base image.
- [Starlette TestClient documentation](https://www.starlette.io/testclient/) documents the `httpx2` migration and deprecation of the legacy `httpx` fallback.
- [HTTPX2 2.13.1 metadata](https://pypi.org/project/httpx2/2.13.1/) and [HTTPCore2 2.13.1 metadata](https://pypi.org/project/httpcore2/2.13.1/) were checked for current versions and artifact hashes.
- [CodeQL workflow configuration](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options) supports scanning on pushes and pull requests; this repository's workflow additionally audits exported SARIF severity.

## Exit decision

**Phase 22 implementation gate: PASS.** All three exact-head workflows were green and the container/CodeQL severity gates were clear. Merge remains blocked until the audit/documentation commit itself has all required workflows green. Production registry publication and deployed digest verification remain explicitly assigned to Phase 24.
