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
| 8 | Context-integrity detector hardening and baseline provenance | Stored-baseline tamper detection; bounded inputs; goal-hijack detection and false-positive tests; blocked findings alert correctly; no claim that caller-supplied context is a trusted execution attestation | Implementation and forensic audit complete; full CI green on final PR #10 head (run 425). Audit: [Phase 8 forensic report](audits/PHASE-08-FORENSIC-AUDIT.md) |
| 9 | Execution mediation and approval lifecycle hardening | Canonical action-intent fingerprint; altered pending or approved actions are refused; expiry, replay and duplicate execution rejected; CI green | Implementation and forensic audit complete; full required CI green. Audit: [Phase 9 forensic report](audits/PHASE-09-FORENSIC-AUDIT.md) |
| 10 | Runtime containment and policy verification | Restrictive baseline validated at startup; operator verifier checks a reviewed effective-policy hash; live filesystem/network/process restrictions still require deployment acceptance | Repository implementation and CI complete; live gateway acceptance remains a production release gate. Audit: [Phase 10 forensic report](audits/PHASE-10-FORENSIC-AUDIT.md) |
| 11 | ThreatFade Oracle resilience and evidence handling | Bounded ingress/PCAP inputs; validated upstream schema; required external service Bearer credential; circuit breaker; synthetic telemetry disabled by default; conservative fallback | Repository implementation and forensic audit complete; code CI run 597 and final PR-head CI run 602 green; live upstream authentication/telemetry acceptance remains a production gate |
| 12 | Memory integrity and poisoning defense | Scoped agent/token sessions; provenance quarantine; metadata-bound integrity hashes; rollback; bounded storage; operator-only quarantine inspection; poisoning regression suite | Repository implementation and forensic audit complete; CI run 687 green on commit 6fde77d; durable persistence and trusted quarantine-promotion integration remain production gates |
| 13 | Tool, skill, MCP and dependency supply-chain defense | Cryptographic Ed25519 publisher verification; artifact-byte SHA-256 verification; exact semantic versions; immutable manifest pins; rollback/change detection; administrator-only publisher trust; bounded artifact ingress | Implementation committed on phase branch; awaiting full CI and forensic acceptance |
| 14 | Inter-agent identity, communication and delegation | Authenticated messages, replay prevention, scoped delegation and cascade containment | Planned |
| 15 | Unified explainable risk findings | Correlated risk signals with provenance; deterministic schema; no advisory-to-authorization escalation | Planned |
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
