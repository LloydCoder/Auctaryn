# Auctaryn secure software supply chain

## Policy and evidence

Phase 22 adds continuous security checks to the existing test/build workflow. The repository is public, and the workflows are intentionally read-only except the main-branch attestation job.

- **Python dependencies:** `requirements.txt` remains the human-maintained, exact direct-dependency input. `requirements.lock` is generated with pinned transitive dependencies and package hashes. CI installs from the lock file; dependency updates must regenerate it deliberately and pass both supported Python test jobs plus `pip-audit`.
- **Dashboard dependencies:** `dashboard/package-lock.json` commits the complete npm resolution. CI and the production deployment helper use `npm ci`, not an unconstrained install, and the supply-chain workflow audits production and development dependencies at high severity.
- **Static analysis:** CodeQL security-extended queries cover Python and JavaScript/TypeScript. A SARIF audit summarizes findings and fails the workflow for high/critical security severity; SARIF is retained for 14 days for forensic review. Lower-severity findings still require triage, and a successful upload is not evidence that no alerts exist.
- **Secrets:** Gitleaks scans repository history and change sets. Any finding must be reviewed for real exposure; rotating a credential does not remove the need to remove it from repository history where feasible.
- **Dependency auditing:** the complete Python and npm lock graphs are audited on every pull request. GitHub's Dependency Review action is not supported because the repository's Dependency Graph/Advanced Security integration is not enabled; the blocking pip-audit and npm audit gates do not depend on that optional API.
- **Container security:** The runtime image uses the minimal official Python Alpine variant to reduce OS package surface. CI builds the API image and fails on fixable high/critical findings. A separate Grype JSON inventory uses the lowest severity cutoff and does not filter to fixed vulnerabilities, so the independent audit sees high/critical findings whether or not a fix exists. Fixable high/critical findings fail; unfixable and lower-severity findings are printed and retained as a 14-day artifact for explicit triage. This is not a blanket CVE suppression. Vulnerability databases and upstream packages change over time, so scheduled runs are required.
- **SBOM:** CI emits SPDX JSON SBOMs for the source/dependency tree and the built container. The exact tested image archive and both SBOMs are retained as workflow artifacts for 14 days.
- **Provenance:** on a successful push to `main`, GitHub artifact attestations are issued for the source SBOM, container SBOM and exact CI image archive. Action references are pinned to immutable commit SHAs rather than mutable major-version tags.

## Reproducible dependency updates

1. Edit `requirements.txt` or `dashboard/package.json` intentionally.
2. Regenerate `requirements.lock` with Python 3.12, `pip==25.2` and `pip-tools==7.5.2` using `pip-compile --generate-hashes --resolver=backtracking --output-file=requirements.lock requirements.txt`. Regenerate `dashboard/package-lock.json` with Node.js 22/npm using `npm install --package-lock-only --ignore-scripts --no-audit --no-fund`.
3. Review the complete transitive diff, including platform markers, package hashes, license metadata and transitive upgrades.
4. Run `pip-audit -r requirements.lock`, `npm audit --audit-level=high`, both Python test matrices, dashboard build and the container scan.
5. Merge only after all required checks are green and the phase-specific forensic audit is updated.

Do not add broad vulnerability suppressions. A necessary exception must identify the CVE/advisory, affected package and version, exploitability rationale, compensating control, owner, expiry date and follow-up issue. Expired exceptions fail acceptance.

## Artifact and release boundary

The workflow attests the CI-built image archive and SBOMs; it does **not** publish an OCI image to a production registry, sign a production release, or prove the deployed host runs that exact artifact. No production release should be described as provenance-verified until the release pipeline publishes immutable image digests, attaches/verifies attestations and SBOMs, and deployment verifies the expected digest. These are Phase 24 acceptance requirements.

GitHub-hosted CI also does not prove live OpenShell containment, Platform-side authorization/revocation, multi-replica durability, or independent penetration-test results. Those remain separately documented production gates.
