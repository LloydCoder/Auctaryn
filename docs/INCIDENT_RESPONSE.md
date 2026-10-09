# Auctaryn incident response runbook

## Purpose and authority boundary

This runbook follows the Detect → Respond → Recover → Improve lifecycle described by [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final). Auctaryn provides local containment controls and signals; the Tinlance Agent Platform remains authoritative for policy, identity, approval and governed execution. The local incident database is not the Platform audit of record.

## Detection and triage

- Review `GET /api/v1/incident/alerts?status=open&limit=100` and `GET /api/v1/incident/status` using an administrator credential.
- Correlate each alert's decision ID with `GET /api/v1/evidence/records` and verify the chain using `GET /api/v1/evidence/verify`.
- Treat critical-risk, veto and trusted-runtime-failure alerts as triage signals, not proof that an external runtime was compromised. Confirm the action receipt and authoritative Platform logs.
- Do not copy credentials, prompts, raw parameters, customer data or command output into alert reasons or incident notes.

## Containment

1. Enable the global stop with `POST /api/v1/incident/emergency-stop` and body `{"enabled":true,"reason":"<brief incident rationale>"}`. The control is persistent in the local SQLite database and checked immediately before runtime invocation.
2. Quarantine a known affected agent with `POST /api/v1/incident/agents/{agent_id}/quarantine` and body `{"quarantined":true,"reason":"<brief rationale>"}`. This revokes that agent's current capabilities and blocks its future execution until explicitly released.
3. If broader credential compromise is suspected, revoke all tokens for the affected agent through `POST /api/v1/identity/{agent_id}/revoke-all-tokens`.
4. Acknowledge an alert only after an operator accepts ownership: `POST /api/v1/incident/alerts/{alert_id}/acknowledge`. Resolve only after containment and evidence preservation are confirmed.
5. Verify the global stop and quarantine status again. A 423 response from the gateway means an incident control blocked execution.

## Recovery

- Keep the stop enabled until the cause is understood, credentials are rotated, relevant capabilities are revoked, and the trusted runtime and Platform policy state are confirmed healthy.
- Release an agent quarantine with `POST /api/v1/incident/agents/{agent_id}/quarantine` and body `{"quarantined":false,"reason":"<recovery rationale>"}`. Reissue least-privilege tokens only after review; release does not recreate revoked capabilities.
- Disable the global stop with `POST /api/v1/incident/emergency-stop` and body `{"enabled":false,"reason":"<approved recovery rationale>"}` only after explicit operator review.
- Confirm evidence verification, capture the alert and decision IDs, validate runtime health, and document lessons learned and follow-up work.

## Operational limitations

- Emergency stop and quarantine state are persistent local SQLite controls, but identity/token state remains process-local. The Platform must independently revoke its own capabilities.
- A local database administrator can alter local control and alert tables. Use independent immutable evidence export and external key management in production.
- Multi-replica production requires a shared authoritative control service or equivalent coordination; local SQLite does not provide distributed consensus.
- The current policy uses explicit critical-risk/veto alert triggers. Tune thresholds with measured false-positive/false-negative data before production reliance.
- Recovery, key rotation, backup/restore, multi-worker stop propagation, and runtime termination must be exercised in the actual deployment environment.
