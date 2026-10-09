# Auctaryn implementation roadmap

**Repository:** `LloydCoder/Auctaryn`  
**Product owner:** Tinlance Limited  
**Architecture:** Auctaryn is a Tinlance agent-security product. Tinlance Agent Platform remains authoritative for identity, tenant binding, policy, approvals, governed execution, secrets, durable evidence, and audit. Auctaryn provides specialized risk analysis, context/memory integrity, tool and skill risk, threat intelligence correlation, and adversarial validation. OpenShell or another explicitly supported runtime enforces operating-system/runtime containment.

## Phase status policy

A phase is complete only when its implementation and documentation are reconciled, regression and adversarial tests are added, the required GitHub Actions workflow is green on the exact final commit, and a phase-specific forensic review finds no unresolved blocker. A green CI run does not prove live production connectivity or independently certify security. Live-runtime acceptance and independent penetration testing remain separate release gates.

## Serial phases

| Phase | Scope | Acceptance evidence | Status |
|---|---|---|---|
| 1 | API authentication, administrator authorization, approval and identity-administration protection | Negative authorization tests; service/admin credential separation; CI green | Complete on main; CI verified |
| 2 | Agent identity ownership, scoped token lifecycle and delegation boundaries | Ownership-conflict audit test; scope and delegation regressions; CI green | Complete on main; CI verified |
| 3 | Versioned advisory risk contract for Tinlance Agent Platform | Schema/version tests; secret-safe response; no authorization grant in advisory response | Complete on main; CI verified |
| 4 | Centralized authentication/authorization dependencies | Shared security module; route-level regression coverage; CI green | Complete on main; CI verified |
| 5 | Sensitive-data guard across classification, interception, Oracle and execution ingress | Secret-pattern and redaction tests; no raw secret in findings or decision history; CI green | Complete on main; CI verified |
| 6 | Evidence-based health/readiness semantics | Liveness separated from readiness; credentials and runtime dependencies reported separately; CI green | Core change on main; remediation tracked in Phase 7 |
| 7 | Real bounded OpenShell health probe and truthful readiness | Active gateway health call with timeout; non-empty version required; unavailable/invalid probe fails readiness; tests and docs reconciled | Complete on main; PR #8 full CI green and phase audit passed |
| 8 | Context-integrity detector hardening and session-bound enforcement | Stored-baseline tamper detection; protected-context compaction fingerprint; session/check binding in action intent; runtime-boundary revalidation; admin-only quarantine clearance; bounded session, instruction and history state | Implementation merged in PR #21; exact-head Python 3.11/3.12, Ruff, dependency audit, dashboard/container, Compose, image-build and liveness checks passed. Trusted runtime attestation and durable multi-replica state remain production gates. Audit: [Phase 8 session-bound enforcement](../audits/PHASE-08-SESSION-BOUND-ENFORCEMENT.md) |
| 9 | Execution mediation and approval lifecycle hardening | Canonical action-intent fingerprint; altered pending or approved actions are refused; expiry, replay and duplicate execution rejected; CI green | Implementation and forensic audit complete; full required CI green. Audit: [Phase 9 forensic report](audits/PHASE-09-FORENSIC-AUDIT.md) |
| 10 | Runtime containment and policy verification | Restrictive baseline validated at startup; operator verifier checks a reviewed effective-policy hash; live filesystem/network/process restrictions still require deployment acceptance | Repository implementation and CI complete; live gateway acceptance remains a production release gate. Audit: [Phase 10 forensic report](audits/PHASE-10-FORENSIC-AUDIT.md) |
| 11 | ThreatFade Oracle resilience and evidence handling | Bounded ingress/PCAP inputs; validated upstream schema; required external service Bearer credential; circuit breaker; synthetic telemetry disabled by default; conservative fallback | Repository controls documented and forensic audit recorded; live upstream authentication/telemetry acceptance remains a production gate. See [Phase 11 forensic audit](../audits/PHASE-11-FORENSIC-AUDIT.md) |
| 12 | Memory integrity and poisoning defense | Scoped agent/token sessions; provenance quarantine; metadata-bound integrity hashes; rollback; bounded storage; operator-only quarantine inspection; poisoning regression suite | Repository implementation and forensic audit complete; CI run 687 green on commit 6fde77d; durable persistence and trusted quarantine-promotion integration remain production gates |
| 13 | Tool, skill, MCP and dependency supply-chain defense | Cryptographic Ed25519 publisher verification; artifact-byte SHA-256 verification; exact semantic versions; immutable manifest pins; rollback/change detection; administrator-only publisher trust; bounded artifact ingress | Implementation and forensic audit complete; final documentation-head workflow #754 passed. See [Phase 13 forensic audit](../audits/PHASE-13-FORENSIC-AUDIT.md) |
| 14 | Inter-agent identity, communication and delegation | HMAC envelope integrity; managed-identity scoped send, inbox-read and receive; platform-authorized key lifecycle; expiry and replay protection; 1,024-message aggregate cap; cycle-safe cascade containment with ancestor-only half-open recovery probes | Implementation and forensic audit complete; merge was gated on all required workflows being green on the exact PR head. Live Platform key-management integration, durable/multi-replica state and production network transport remain acceptance gates. Audit: [Phase 14 forensic audit](../audits/PHASE-14-FORENSIC-AUDIT.md) |
| 15 | Unified explainable risk findings | Deterministic bounded findings with provenance, confidence, rationale, rule/control references and evidence references; additive versioned schema; no advisory-to-authorization escalation | Implementation and forensic audit complete; final exact-head CI acceptance pending. Audit: [Phase 15 forensic audit](../audits/PHASE-15-FORENSIC-AUDIT.md) |
| 16 | Evidence, audit and forensic investigation | Tamper-evident records, correlation identifiers, execution receipts and reconstructable incident timelines | Planned |
| 17 | Detection operations and incident response | Alerts, quarantine, emergency stop, revocation, recovery and failure-mode exercises | Planned |
| 18 | Adversarial red-team and regression benchmark | Repeatable attacks mapped to OWASP Agentic Applications and MITRE ATLAS; every finding becomes a regression test | Planned |
| 19 | Enterprise tenancy and administrative boundaries | Tenant isolation and authorization conformance; no competing identity authority | Planned |
| 20 | Reliability, scale and disaster recovery | Load, concurrency, resource exhaustion, backup/restore and recovery objectives | Planned |
| 21 | Operator dashboard and deployment compatibility | Backend-enforced permissions, accessible evidence, tested deployment and rollback paths | Planned |
| 22 | Secure software supply chain | Dependency/SAST/secret/container scans, SBOM, artifact provenance and release integrity | Planned |
| 23 | Standards mapping and independent assurance | Control-to-test traceability; external security review and penetration testing; risk register | Planned |
| 24 | Production release and ecosystem acceptance | Exact-commit CI green, live runtime acceptance, Platform integration conformance, operations documentation and release sign-off | Planned |

## Required phase exit gate

For every phase:

1. Inspect the relevant source, tests, configuration, deployment files and existing docs before editing.
2. Implement the smallest coherent change that closes the identified blocker.
3. Add negative, regression and failure-mode tests for security-sensitive behavior.
4. Update the README and affected architecture/security/deployment documents in the same phase.
5. Run the repository's full required CI matrix: Python 3.11/3.12 tests, Ruff, dependency audit, dashboard build/audit, deployment-script syntax, Compose validation, container build and liveness check.
6. Inspect the exact workflow jobs and logs for the final commit; do not treat queued, cancelled, skipped, or missing checks as green.
7. Conduct a phase-specific forensic audit and fix any gap before beginning the next phase.

## Current known release limitations

- Identity, scoped tokens, pending approvals, decision history and execution deduplication are currently process-local and are not durable or multi-replica safe.
- CI uses fake OpenShell clients; it does not prove live gateway connectivity or the effective sandbox policy.
- Auctaryn's advisory risk contract is not a live Tinlance Agent Platform integration until a separately versioned Platform-side adapter and conformance tests are implemented.
- SensitiveDataGuard is heuristic defense in depth, not complete DLP.
- Auctaryn does not prove universal mediation of every external agent tool unless that tool is routed through a supported, configured enforcement adapter.

Additional Phase 8 boundary: context checks analyze the context text submitted to Auctaryn. Without a trusted runtime/harness attestation, submitted text cannot prove which context the agent actually consumed. Phase 8 therefore hardens detection and provenance; Phase 9 must bind trusted runtime observations to immutable execution intent before any context finding is described as an execution-enforcement guarantee.

These limitations must remain visible in documentation until resolved and independently verified.
