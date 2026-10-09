# Auctaryn Approval and Action-Intent Integrity

## Decision intent binding

Each gateway decision carries an internal SHA-256 fingerprint over the canonical JSON representation of:

- tool name and action;
- parameters;
- target resource;
- agent identity; and
- session identity.

Transient decision IDs, timestamps, and bearer capabilities are excluded. The fingerprint is not included in public API serialization.

## Enforcement points

1. The gateway creates the fingerprint after identity preflight and removal of the caller's identity token.
2. A pending approval is checked against its current tool-call intent before the approval transition.
3. If the intent has changed or the fingerprint is absent, the pending decision is removed, replaced with a terminal denial, and the approval request is rejected.
4. Immediately before runtime invocation, the execution service recomputes the fingerprint. A missing or mismatched fingerprint prevents adapter execution.
5. Existing expiry and at-most-once checks remain active. Approval state and execution claims are still process-local.

## Security properties and limits

This mechanism detects accidental or unauthorized mutation of a decision object between evaluation, approval, and execution within the application. It does not create a cryptographic signature, durable audit record, or distributed lock. An attacker able to alter both the decision object and its fingerprint in process memory can bypass this integrity check. The current in-memory approval state is not safe for multi-replica production deployment.

For production integration, Tinlance Agent Platform must remain authoritative for policy, approval, execution, and durable audit. Its adapter must bind the approval to its own immutable execution intent and enforce idempotency at the actual execution boundary. Auctaryn's local fingerprint is defense in depth, not a replacement for that authority.

## Verification

Phase 9 acceptance tests cover:
- fingerprint preservation across approval transitions;
- rejection of changed pending parameters;
- rejection of changed approved parameters before runtime invocation;
- no adapter call after an intent-integrity failure;
- existing approval expiry, one-time-use, and duplicate-execution behavior;
- non-exposure of the internal fingerprint in API serialization.

The full Python 3.11/3.12, lint, dependency, dashboard, Compose, container-build and liveness workflow must be green on the final phase commit.
