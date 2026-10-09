# Phase 14 — Forensic Audit: Inter-Agent Security

**Repository:** `LloydCoder/Auctaryn`  
**Branch:** `security/phase-14-inter-agent-security`  
**Implementation commit reviewed:** `65eaf1f004c9da8b490653dc644d39f1e9b942a6`  
**CI evidence:** [Run 37942375410](https://github.com/LloydCoder/Auctaryn/actions/runs/37942375410) — Python 3.11 and 3.12 tests, Ruff, dependency audit, dashboard build, deployment-script syntax, Compose validation, container build and liveness checks passed on the implementation head. Subsequent commits reconcile the audit and roadmap; the final documentation head must also pass all required workflows before merge.

## Scope

Reviewed the message envelope contract, compatibility imports, circuit-breaker state machine, ASI07/ASI08 regressions, new adversarial tests, and the inter-agent security documentation.

## Findings and remediation

1. **Envelope integrity:** HMAC-SHA-256 covers message ID, sender, recipient, payload, issue time and expiry. Signature comparison is constant-time; changes to envelope fields are rejected.
2. **Managed identity:** key registration, send, inbox reads and receive verification require managed identity integration by default. Unbound operation is an explicit test-only option. Send and receive require distinct scopes. Managed key registration/rotation requires an injected platform key-management authorizer returning literal boolean `True`; missing callbacks, exceptions and non-boolean grants deny the operation.
3. **Tenant isolation:** sender and recipient owner bindings must exist. Cross-owner delivery is denied unless an explicit authorization callback permits it.
4. **Replay protection:** messages have unique IDs, bounded expiry, explicit recipient binding and one-time consumption. Empty explicit recipients do not fall back to the signed recipient. A message must still be present in the recipient inbox to be consumed. Replay state is bounded and expired entries are pruned.
5. **Resource bounds:** payloads are finite JSON objects capped at 64 KiB; TTL is capped at one hour; per-recipient inboxes are capped at 1,000 messages and the aggregate queue at 1,024; registered identities, keys and replay entries are bounded. Queue accounting is adjusted on delivery, expiry and key rotation.
6. **Key lifecycle:** key length and low-diversity values are validated; this heuristic is not an entropy proof, so production keys must be CSPRNG-generated. Replacement requires both an explicit rotation flag and platform authorization; pending messages from the rotated sender are removed.
7. **Cascade containment:** dependency self-edges and cycles are rejected; dependency depth and state counts are bounded. After cooldown, only a direct probe of the tripped ancestor may run; descendants remain blocked until that probe succeeds. A failed probe trips the breaker again.
8. **Regression repair:** the legacy ASI07/ASI08 test module had an indentation/collection defect. It was rewritten into a valid test module aligned with the current API and is now collected by the full test suite.

## CI evidence

On the reviewed implementation commit, the Python 3.11 and Python 3.12 test jobs passed. The final audit/documentation commit has its own merge gate: all required tests, Ruff, dependency audit, dashboard build/audit, deployment-script syntax, Compose validation, container build and liveness checks must be green on that exact SHA. Queued, skipped, cancelled, or missing required checks do not count as green.

## Residual production gates

- The message bus is an in-process contract, not a deployed network/queue transport.
- Keys, inboxes, breaker state and replay state are in-memory and not durable or multi-replica safe.
- HMAC is a service-managed envelope integrity mechanism; the managed identity token authenticates the sender at send time. It is not a public-key signature produced by an external agent.
- Key provisioning/rotation, durable replay storage, tenant-bound delivery receipts and message audit records must be integrated with Tinlance Agent Platform.
- The cross-tenant authorizer must be implemented by the owning platform policy; absent an explicit callback, cross-tenant messages are denied.
- Production transport needs TLS, bounded request bodies, queue redelivery semantics, concurrency tests and independent security review.

## Reference basis

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — insecure inter-agent communication and cascading failures.
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html) — least privilege, sender constraints and replay considerations.

**Audit decision:** repository implementation passed the defined Phase 14 acceptance gate. The final documentation head must also pass the complete workflow before merge and progression to Phase 15.


Additional audit controls on the final implementation: key registration, rotation and revocation require the injected platform key-management authorizer when managed identity is enabled. Inbox reads recheck current tenant policy and envelope integrity before returning payloads; a non-boolean cross-tenant callback result is denied. The regression suite also verifies that revocation removes pending messages and keeps queue accounting consistent.
