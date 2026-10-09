# Auctaryn Security Model

## Authority boundaries

- **Tinlance Agent Platform** is the intended authoritative control plane for identity, policy, approval, governed execution, secrets, and durable audit.
- **Auctaryn** performs specialized agent-risk analysis, context/memory/tool-risk defenses, and runtime signal correlation. Its local policy result is not a substitute for the platform's authoritative authorization.
- **OpenShell** is the operating-system/runtime containment boundary for supported executions. Auctaryn must not weaken or replace the effective OpenShell policy.
- **ThreatFade Oracle** contributes threat intelligence. It cannot override a denial or turn an unapproved destructive action into an approval.

## Context-session enforcement

When protected instructions are configured, gateway actions require a session ID and the latest intact context-check ID for that session. The check ID participates in the action-intent fingerprint, and context integrity is revalidated immediately before the runtime adapter is invoked. Each check is bound to one action intent; replay for a different action is denied. Compromised sessions remain quarantined until an administrator clears them, after which a fresh clean check is mandatory. Tracked sessions are capped at 10,000, protected instructions at 1,000, and check/compaction histories at 5,000 each; capacity exhaustion fails closed. These controls are process-local, not durable or multi-replica safe. A submitted local check does not prove that the external agent consumed that exact context; trusted runtime/harness attestation remains necessary. See the [Phase 8 enforcement audit](../audits/PHASE-08-SESSION-BOUND-ENFORCEMENT.md).

## Decision and execution invariants

1. Every protected call passes the local data guard and identity/circuit-breaker preflight before Oracle enrichment or risk classification.
2. An unrecognized tool/action is low-confidence and requires operator review.
3. Oracle severity HIGH or CRITICAL can escalate an otherwise non-terminal decision to VETOED. Oracle timeout, invalid response, or unavailability preserves the conservative local decision; it never grants permission.
4. A policy VETOED or DENIED decision is not a runtime failure signal. Circuit-breaker counters are updated only after an actual runtime execution result or runtime execution exception.
5. Only APPROVED decisions can reach a configured runtime adapter. Pending, denied, vetoed, expired, or unknown decisions do not execute.
6. The OpenShell adapter uses a server-configured sandbox and workspace, accepts a bounded argv array, and does not invoke a host shell. A bounded supervisor runs inside the sandbox to cap runtime and captured output.
7. Runtime receipts correlate to the decision ID and expose output hashes plus truncation indicators, not raw stdout/stderr.
8. Pending approvals expire after 15 minutes by default and can be resolved once. The canonical action-intent fingerprint is rechecked when a pending action is approved and immediately before runtime execution; a changed intent is denied and never forwarded.
9. The fingerprint is an internal mutation-detection binding, not a signature or durable audit record. Approval state, identities, tokens, and execution deduplication remain in process memory in the current repository; they are not durable or multi-replica safe.

## Context-integrity trust boundary

- Protected instruction baselines are bounded and content-hashed; each check recomputes the stored content hash before trusting the baseline.
- Goal-hijack heuristics compare override-bearing sentences with protected instruction terms and produce a compromised/blocked finding when a relevant override is detected.
- Context text supplied to the API is caller-provided evidence. It is not proof of the actual runtime context unless it comes from a separately authenticated and trusted harness integration.
- Context findings and alerts are detection evidence. They must not be presented as proof that every external tool call is blocked. Phase 9 must bind trusted runtime context observations to immutable execution intent and the authoritative execution boundary.
- Heuristic prompt-injection detection is not complete semantic understanding and can have false negatives. Treat high-impact operations conservatively and retain independent policy, identity, approval, and runtime controls.

## Sensitive data

SensitiveDataGuard rejects raw credentials in sensitive parameter fields and known token/key formats before risk analysis or execution. It returns paths only. It is heuristic defense in depth and cannot detect every possible secret.

Recognized secret references (for example vault://...) are treated as opaque identifiers. Auctaryn does not resolve them. Production use must route resolution and injection through Tinlance Agent Platform's governed secret mechanism or a separately approved OpenShell provider profile. Never place raw credentials in tool-call arguments, logs, source files, or sandbox policy files.

## Fail-closed behavior

- If no runtime adapter is configured, governed execution returns HTTP 503 before evaluating or forwarding the tool call.
- If OpenShell initialization, authentication, or health verification fails, the application starts with governed execution disabled.
- Readiness requires a bounded live OpenShell gateway health probe with a non-empty version response; adapter construction or environment configuration alone does not establish readiness. The probe is tested with fake clients in CI, while production connectivity still requires live-environment acceptance.
- If the OpenShell execution envelope is malformed or the remote completion state is unknown, Auctaryn returns an execution failure and does not claim success.
- If a required authorization, policy, or runtime dependency is unavailable, no alternate direct execution path is permitted.

## Deployment acceptance

CI verifies unit and API behavior, the bounded supervisor script, dashboard build, container build, compose configuration, dependency audit, and liveness. Production readiness still requires a live OpenShell gateway integration test and verification of the effective sandbox policy, network restrictions, filesystem restrictions, service authentication, and operational recovery procedures.


## ThreatFade Oracle trust and failure boundary

ThreatFade is an advisory signal source, not an authorization authority. The upstream response is untrusted input: analysis responses must contain detection and triage objects, a recognized severity, finite numeric fields, and correctly typed control flags. Malformed or unavailable responses are treated as upstream failures; the gateway retains its conservative local decision and never turns a pending/destructive action into an approval because of a fallback.

Synthetic signals derived from tool-call parameters are not observed network telemetry. They are disabled by default and may only be enabled explicitly for demos or tests with `AUCTARYN_THREATFADE_ALLOW_SYNTHETIC_SIGNAL=true`. Do not cite synthetic-mode results as threat evidence or use them to certify detection performance.

The client disables redirects, validates the configured URL, applies bounded timeouts, constrains signal and event sizes, limits PCAP uploads to 10 MiB, rejects path-like filenames, validates JSON response structure, and supports a `THREATFADE_SERVICE_TOKEN` Bearer credential when the upstream service is configured to accept it. External deployments must use HTTPS. The optional token does not provide authentication unless the ThreatFade service verifies it.

The Oracle circuit breaker opens after repeated upstream failures and permits only a single half-open probe after its cooldown. Analysis history is capped in process memory. These are local resilience controls; they are not durable distributed rate limits, and the history is not a durable audit ledger.


## Memory integrity and poisoning boundary

- Memory API operations require a valid short-lived agent identity token with `memory:write` or `memory:read` scope and a server-issued session bound to that agent and the exact scoped token, with a maximum one-hour TTL. A caller-supplied session ID is not accepted as proof of ownership.
- Public API submissions cannot assert trusted provenance. The API prefixes source labels with `api:`, which always routes entries to quarantine pending review. Only a separately trusted internal ingestion path may use the module's trusted provenance labels.
- Memory entries use unique opaque IDs, bounded content/source/session/agent fields, and a bounded in-process store. The SHA-256 integrity digest binds content, source, session, agent, quarantine state, key and creation timestamp.
- Integrity verification compares the live entry with a separately held last-known-good snapshot. API metadata reads detect tampering and attempt rollback before returning the result; memory content is not returned by the metadata endpoint.
- Poisoning detection is heuristic and cannot detect every semantic prompt injection. Quarantine is a containment state, not a guarantee that content is benign.
- The store, session ownership map and last-known-good snapshots are process-local. They are not durable, distributed, or cryptographically tamper-proof against a compromised process. Production persistence and authoritative identity/tenant binding remain platform integration work.


Quarantined memory is not readable by any agent session, including the originating session. An operator-authenticated review endpoint exposes quarantined content for investigation; there is no API route that promotes quarantine to trusted memory in this phase. The quarantine queue and inspection route verify entry integrity and restore last-known-good metadata before using the quarantine flag.


## Skill and tool supply chain

Skill manifests are accepted only with an exact semantic version, valid SHA-256 artifact digest, trusted Ed25519 publisher signature and matching artifact bytes. Publisher trust mutation is administrator-only. Immutable name/version manifest pins detect changes and version rollback within the process. These pins and trust roots remain in-memory; they are not a durable multi-replica trust store. Passing vetting does not authorize execution, which remains governed by Tinlance Agent Platform and the configured runtime. See [Skill Supply-Chain Security](SKILL_SUPPLY_CHAIN.md).
