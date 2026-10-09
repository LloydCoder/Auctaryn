# Production deployment and rollback runbook

## Release prerequisites

Production deployment is allowed only for a version-tagged Auctaryn release with an attested release manifest and immutable OCI image digest. The release manifest must bind the release tag, tested source commit, image name and exact image digest. The production deployment script verifies the manifest attestation, OCI provenance, and SPDX SBOM attestation before switching the running service.

Required host tooling: Docker Engine with Compose v2, Git, GitHub CLI authenticated to the canonical repository, jq, curl, npm, Nginx and Certbot.

Required .env values:

- distinct high-entropy AUCTARYN_API_KEY and AUCTARYN_ADMIN_API_KEY;
- AUCTARYN_RELEASE_TAG and AUCTARYN_IMAGE=ghcr.io/lloydcoder/auctaryn@sha256:<digest> from the attested release manifest;
- a real HTTPS THREATFADE_SERVICE_URL and THREATFADE_SERVICE_TOKEN;
- AUCTARYN_RUNTIME_ADAPTER=openshell, sandbox/workspace settings, and OpenShell OIDC service credentials;
- OPENSHELL_SYSTEM_GATEWAY_DIR, pointing to host-side active gateway metadata with a remote HTTPS endpoint;
- AUCTARYN_EVIDENCE_HMAC_KEY_FILE, an absolute host path to a separate 32+ byte key file;
- AUCTARYN_DOMAIN, with DNS directed to the deployment host.

The production Compose override mounts the OpenShell gateway metadata read-only and the evidence HMAC key as a container secret. User credentials are prohibited. The deployment helper refuses a floating image tag, missing attestations, invalid release-manifest binding, missing runtime metadata, weak/missing credentials, and an unready runtime. It does not build the API from a moving branch.

## Deploy

After the independent assessment, live Platform conformance, live OpenShell acceptance and security-owner sign-off are complete:

    bash scripts/deploy.sh

The helper fetches the requested release tag, verifies the release manifest and image/SBOM attestations, checks that the tag is descended from the exact tested commit, pulls the immutable image digest, builds the dashboard from the same release tag, captures the prior running digest/tag, and only then replaces the API container. Nginx/TLS exposure happens only after liveness and readiness pass. If a failure occurs after switching and a verified prior deployment exists, the helper attempts automatic rollback.

A successful script run is not a substitute for recording the expected and observed deployed digests and completing a production rollback drill in the release acceptance evidence.

## Rollback

    bash scripts/rollback.sh

The rollback helper requires the previous image reference, image ID and release tag recorded before the last deployment. It verifies the previous release manifest and OCI/SBOM attestations, pulls the immutable digest, confirms the local image ID matches the recorded image, updates the active .env release reference, restarts the service without building source, and requires liveness/readiness to pass.

It deliberately does not retag an image ID as latest or bypass attestation checks. If the previous deployment was not digest-pinned or cannot be matched to a release manifest, rollback refuses and requires an operator-led recovery procedure. Do not restore public traffic if readiness or OpenShell policy validation fails.

## Evidence to retain

- release tag, tested commit, release source commit and exact OCI digest;
- release manifest, provenance and SBOM attestation verification output;
- deployment timestamp, operator identity and observed container digest;
- readiness response and live OpenShell/Platform acceptance evidence;
- rollback drill timestamp, prior/restored digest comparison and reviewer sign-off;
- evidence references with SHA-256 digests in release/release-evidence.json.

CI tests use mocked Docker/GitHub CLI commands. They verify orchestration and fail-closed behavior, but do not constitute a production-host deployment or rollback drill.
