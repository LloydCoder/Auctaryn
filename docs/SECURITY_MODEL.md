# Auctaryn Security Model

## Authority boundaries

- **Tinlance Agent Platform** is the intended authoritative control plane for identity, policy, approval, governed execution, secrets, and durable audit.
- **Auctaryn** performs specialized agent-risk analysis, context/memory/tool-risk defenses, and runtime signal correlation. Its local policy result is not a substitute for the platform's authoritative authorization.
- **OpenShell** is the operating-system/runtime containment boundary for supported executions. Auctaryn must not weaken or replace the effective OpenShell policy.
- **ThreatFade Oracle** contributes threat intelligence. It cannot override a denial or turn an unapproved destructive action into an approval.

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
