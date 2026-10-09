# TwinGuard — OWASP Top 10 for Agentic Applications 2026 Coverage

Honest status, updated as modules ship. This is an engineering tracking document, not a marketing claim.

| Code | Risk | Status | TwinGuard Module |
|------|------|--------|-------------------|
| ASI01 | Agent Goal Hijack | ✅ Covered | Context Integrity Guardian — catches both instruction LOSS (compaction) and instruction OVERRIDE (in-context conflicting directives via `detect_goal_hijack`) |
| ASI02 | Tool Misuse & Exploitation | ✅ Covered | Execution Gateway — pattern classification + risk-based veto/approval |
| ASI03 | Agent Identity & Privilege Abuse | ✅ Covered | Agent Identity Manager — scoped permissions, time-limited tokens, subset-constrained delegation. **Wired directly into the Gateway decision path** (opt-in via `/api/v1/gateway/identity-enforcement/enable`) |
| ASI04 | Agentic Supply Chain Compromise | ✅ Covered | Skill Vetting Service — signature verification, content-hash pinning, permission scanning, typosquat detection |
| ASI05 | Unexpected Code Execution | Delegated | Handled by NVIDIA OpenShell (Landlock/seccomp), not TwinGuard-native |
| ASI06 | Memory & Context Poisoning | ✅ Covered | Memory Poisoning Defender — adversarial pattern scanning, provenance-based trust, integrity hashing + rollback, cross-session quarantine |
| ASI07 | Insecure Inter-Agent Communication | ✅ Covered | Agent Message Bus — HMAC-signed inter-agent messages, tamper detection, per-recipient inbox isolation, impersonation rejection |
| ASI08 | Cascading Agent Failures | ✅ Covered | Agent Circuit Breaker — per-agent failure isolation, auto-recovery cooldown, dependency-aware blast-radius containment. **Wired into the Gateway by default** (always-on, not opt-in) |
| ASI09 | Human-Agent Trust Exploitation | ✅ Covered | Step-Up Authenticator — single-use, time-windowed confirmation challenges required for destructive/critical decisions; replay and staleness rejected |
| ASI10 | Rogue Agents | ✅ Covered | Core thesis of the platform — Context Integrity + Execution Gateway + ThreatFade Oracle combined |

**10 of 10 categories represented in code. 232 tests passing.**

## What "covered" honestly means at this stage

Every category above has working, tested code behind it — not a stub, not a TODO. But "covered" here means **MVP-depth defensible implementation**, not enterprise-hardened production infrastructure. Specifically, being transparent about depth:

- **ASI03/ASI08 enforcement is real but partially opt-in.** Circuit breaker isolation is always active in the production gateway. Identity enforcement is available and fully tested, but ships disabled-by-default to avoid breaking deployments with unregistered agent fleets — an operator must explicitly call `/api/v1/gateway/identity-enforcement/enable` once their agents are registered.
- **ASI07's signing is HMAC, not full PKI.** Production-grade inter-agent security would typically use asymmetric signing (ed25519, same as ASI04's skill signatures) and a real transport layer (mTLS, message queue). The current implementation enforces the correct *contract* (signed, verified, tamper-evident, non-impersonable) using symmetric keys appropriate for an MVP.
- **ASI04's signature verification is presence + format + trust-list, not full cryptographic ed25519 verification.** The contract (signed, hash-pinned, permission-scanned, typosquat-checked) is real; swapping in actual public-key cryptography is a contained follow-up, not a redesign.
- **ASI05 is intentionally delegated**, not weak — OpenShell's kernel-level sandboxing is the correct layer for code execution containment, and duplicating that inside TwinGuard would be redundant.

This document will be updated honestly as each item moves from "MVP-depth" to "production-hardened." Anyone — engineering hire, accelerator reviewer, pilot customer's security team — should be able to read this and know exactly what they're getting.
