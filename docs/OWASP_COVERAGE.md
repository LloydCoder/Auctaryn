# Auctaryn — OWASP Top 10 for Agentic Applications 2026 coverage

This is an engineering assurance map, not a claim of OWASP certification. The machine-readable control-to-test registry is linked from STANDARDS_TRACEABILITY.md; the open risk register is SECURITY_RISK_REGISTER.md, and external review scope is defined in INDEPENDENT_ASSURANCE_PLAN.md. “Represented in code” means a module or control exists; it does not mean every attack in a category is prevented, every external execution path is mediated, or production controls have been independently verified.

## Coverage and assurance status

| OWASP category | Current implementation evidence | Assurance status and remaining gap |
|---|---|---|
| ASI01 — Agent Goal Hijack | Context Integrity Guardian hashes registered instructions, checks for missing instruction text, and uses heuristic override-language detection. | **Partial / MVP.** Detection is heuristic and is not a semantic guarantee. Context checks are not proven to gate every external agent execution path. |
| ASI02 — Tool Misuse & Exploitation | Risk classifier, veto engine, gateway decisions, approval lifecycle and a trusted runtime adapter contract. | **Partial / MVP.** The classifier is not a substitute for authorization. Universal mediation of every external tool is not proven; only supported configured adapter paths are governed. |
| ASI03 — Agent Identity & Privilege Abuse | Agent identities, scoped expiring tokens, permission-version invalidation, delegation subset checks and mandatory gateway preflight. | **Implemented locally; enterprise gaps remain.** State is in process memory, not durable or multi-replica safe. Tinlance Agent Platform remains the intended authoritative identity and capability owner. |
| ASI04 — Agentic Supply Chain Compromise | `SecureSkillVettingService` verifies Ed25519 signatures over canonical manifests, SHA-256 against actual artifact bytes, exact semantic versions, permissions, rollback and same-version changes. | **Artifact verification implemented locally; enterprise gaps remain.** Publisher pins and trust state are process-local; this does not prove runtime behavior integrity or durable, multi-replica trust. See Phase 13 audit and red-team benchmark. |
| ASI05 — Unexpected Code Execution | OpenShell adapter restricts the supported operation to a server-selected sandbox/workspace and bounded argv wrapper; OpenShell provides runtime isolation. | **Integration implemented; live assurance outstanding.** CI uses fake clients. Live gateway identity, effective policy, filesystem isolation, egress denial and execution-path mediation require deployment acceptance tests. |
| ASI06 — Memory & Context Poisoning | Memory Defender scans content, considers source trust and tracks integrity-related state. | **Partial / MVP.** In-process state and heuristic detection do not guarantee protection of every external or persistent memory system. |
| ASI07 — Insecure Inter-Agent Communication | Agent Message Bus signs and verifies messages with HMAC keys and separates recipient inboxes. | **Partial / MVP.** Key distribution, durable identity binding, transport security and production key rotation/PKI are not established by the in-memory module alone. |
| ASI08 — Cascading Agent Failures | Per-agent circuit breaker, cooldown and dependency-aware isolation are wired into the gateway. | **Partial / MVP.** Local in-memory breaker state does not provide distributed fleet-wide containment or durable recovery evidence. |
| ASI09 — Human-Agent Trust Exploitation | A step-up authenticator module tests freshness, one-time challenge consumption and replay rejection. | **Integration not yet proven.** The existence of a standalone module is not evidence that every privileged API approval or runtime execution is bound to a fresh challenge. |
| ASI10 — Rogue Agents | The combined context, identity, gateway, threat-intelligence and runtime-control architecture provides building blocks for rogue-agent containment. | **Architecture direction / partial.** There is no evidence that the platform detects and contains every rogue-agent behavior or that every agent path is mediated. |

## Security and architecture boundaries

- Tinlance Agent Platform remains authoritative for tenant binding, identity, capabilities, policy, approvals, governed execution, secrets, durable evidence and audit.
- Auctaryn contributes specialized agent-risk analysis and security findings. Advisory risk responses are not authorization grants and must not independently authorize execution.
- OpenShell is the runtime containment boundary for supported operations. Auctaryn must not weaken its effective policy.
- ThreatFade Oracle contributes threat intelligence; an Oracle result must never override a platform denial or silently approve a pending/destructive action.
- SensitiveDataGuard is heuristic defense in depth, not complete DLP.
- The readiness endpoint requires configured credentials, mandatory identity enforcement, a configured trusted adapter and a successful live gateway health probe. CI tests the probe contract with fakes; it does not prove production connectivity.

## Evidence required before production claims

1. Full required CI matrix is green on the exact release commit.
2. Live OpenShell acceptance proves the intended authenticated gateway, effective policy revision, sandbox/workspace, denied egress and filesystem restrictions.
3. Negative end-to-end tests prove denied, pending, expired, replayed and unauthorized actions never reach the runtime.
4. Approval and identity state are durable and safe under restart, concurrent requests and multiple replicas, or deployment is explicitly constrained to a single instance.
5. Independent adversarial testing covers each mapped OWASP category and turns findings into regression tests.
6. Residual risks, false-positive/false-negative limits, and unsupported integration paths remain documented.
7. Phase 18's repeatable benchmark must execute its registered ASI01–ASI10 scenarios; tactic-level MITRE ATLAS mappings must not be represented as technique-level validation.
8. The independent-assurance plan and risk register must be reviewed against the actual deployment topology. External penetration-test results are required before production security claims.

Do not describe the project as “10/10 covered,” “fully secure,” or production-certified based only on module presence or unit tests. Update this document when new implementation evidence changes a category's status.
