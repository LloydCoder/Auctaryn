# Operator dashboard, deployment and rollback runbook

## Administrator dashboard

The dashboard requires the distinct administrator bearer credential. The browser holds it only in JavaScript memory; signing out clears the token and live WebSocket buffers, and stale sockets are prevented from reconnecting with the prior token. Never place service/admin credentials in Vite environment variables, URLs, query strings, browser local storage, screenshots or client bundles.

The **Incidents & Evidence** tab uses server-protected endpoints to display emergency-stop state, quarantined agents, alert lifecycle, a bounded recent evidence page and evidence-chain verification. The dashboard does not render raw request payloads. The API remains the authorization boundary: service credentials must receive 403 for incident administration, alert listing and evidence inspection even if client-side navigation is bypassed.

For incident response:
1. Inspect incident status and alert severity/category/summary.
2. Verify the evidence chain before using the local evidence page for forensic conclusions.
3. Enable the emergency stop with a specific reason if containment is required.
4. Acknowledge or resolve alerts only after recording the decision and rationale in the incident process.
5. Do not release an agent from quarantine merely because its alert was resolved; follow the incident-response runbook and Platform-side revocation process.

## Immutable-image deployment state

Compose uses `AUCTARYN_IMAGE` when supplied, otherwise `auctaryn:latest`. Before rebuilding, `scripts/deploy.sh` records the running container's immutable image ID in `.deploy-state/previous-image-id` with restrictive permissions. This metadata is local and ignored by Git. Do not manually edit it to point to an arbitrary image.

Deployment continues to fail closed if the API is live but readiness is false. Public reverse-proxy exposure must not be enabled until readiness and runtime enforcement are accepted.

## Rollback

Run from the deployment host after confirming the intended maintenance window:

```bash
cd /opt/auctaryn
bash scripts/rollback.sh
```

The script:
- Requires the deployment configuration and a previously recorded immutable image ID.
- Validates the image ID and verifies the image is present locally before retagging.
- Restarts only the API container with `docker compose up -d --no-build api`; persistent data volumes are not rolled back.
- Requires liveness and, by default, readiness before reporting success. `AUCTARYN_REQUIRE_READY=false` is an explicit emergency override for private diagnostics only; it must not be interpreted as authorization to restore public traffic.
- Fails closed if the prior image is missing or malformed. Restore it from the approved image registry using the trusted digest/provenance process; do not substitute an unverified image.

After rollback:
1. Keep external traffic disabled until readiness is true and the runtime policy is verified.
2. Verify `/health/ready`, the evidence chain, emergency-stop state, alert state and the image ID actually running.
3. Exercise a denied test action and confirm no unauthorized runtime call occurs.
4. Preserve logs and the failed release image digest for investigation.
5. Record the rollback approver, image digests, timestamps and outcome.

## Validation and limits

CI checks both shell scripts with `bash -n`, exercises rollback decision paths using mocked Docker/curl commands, validates Compose configuration, builds the container and checks API liveness. CI does not perform a production host rollback or prove a registry restore. Production acceptance still requires a staged rollback drill, protected registry access, immutable SBOM/provenance verification, and an operator-approved recovery procedure.
