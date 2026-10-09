# Production release acceptance

## Purpose and current status

Auctaryn now has a fail-closed version-tag release workflow. It does not deploy to production and it does not manufacture acceptance evidence. The checked-in release-evidence manifest is intentionally pending, so no production release is authorized by the current repository state.

## Required pre-release evidence

1. Successful Auctaryn CI, CodeQL and secure-supply-chain workflows whose run IDs and head SHAs match the exact tested commit.
2. Independent security assessment report with report SHA-256, reviewer, date and zero unresolved critical/high findings.
3. Live Tinlance Agent Platform conformance evidence for identity, tenant isolation, authorization, key rotation/revocation and denial behavior.
4. Live OpenShell acceptance evidence for gateway identity, effective policy revision, filesystem/workspace boundaries, egress restrictions, process limits and denied-action non-execution.
5. Human security-owner review of the current risk register and explicit closure/acceptance of all release-blocking risks.

Update release/release-evidence.json with evidence references and reviewer metadata only after the evidence exists. Then set tested_commit to the exact commit that passed CI and record the successful workflow run IDs, conclusions, URLs and head SHAs. The release workflow re-queries GitHub for those run conclusions and rejects a release tag if any run is not green or does not match tested_commit.

## Version-tag release process

1. Complete the pre-release evidence manifest and commit only that manifest after the tested commit. The workflow rejects any intervening source/configuration change outside release/release-evidence.json.
2. Create a version tag (vX.Y.Z) on the evidence commit. Do not tag while any gate remains pending.
3. The workflow validates the manifest, verifies exact-head CI/CodeQL/supply-chain runs, builds the image using the pinned Docker base and security-patched zlib, publishes the version-tagged image to GHCR, generates source and image SPDX SBOMs, writes an immutable release manifest containing the image digest, tested commit, workflow run IDs and SBOM checksums, attests the manifest and image, verifies the published digest/attestations, and creates a GitHub release with the manifest and SBOM assets.
4. Verify image provenance independently before deployment with the GitHub CLI: gh attestation verify oci://ghcr.io/lloydcoder/auctaryn:vX.Y.Z -R LloydCoder/Auctaryn.

## Post-deployment acceptance

Production rollout is a separate operation and is not performed by this workflow. Before declaring production acceptance, record the expected immutable OCI digest and the observed deployed digest, prove they match, execute a rollback drill, and attach reviewer/evidence references. Validate with python scripts/verify_release_evidence.py release/release-evidence.json --require-production.

## Fail-closed behavior

- Pending/missing external assessment, Platform conformance, OpenShell acceptance or risk-review evidence blocks version-tag publication.
- A non-green or wrong-commit CI/CodeQL/supply-chain run blocks publication.
- Any unapproved source change after tested_commit blocks publication.
- Any unresolved critical/high external assessment finding blocks publication.
- A post-deployment digest mismatch or missing rollback evidence blocks production acceptance.
- A green CI run is not independent penetration testing, live runtime assurance or deployment verification.
