# Phase 18 forensic audit — adversarial red-team benchmark

**Scope:** repeatable OWASP ASI01–ASI10 attack scenarios, MITRE ATLAS traceability, regression binding and honest assurance reporting.

## CI evidence

**Exact-head CI:** PR head `ca1cf15d30dd92edc2f9f200b0b52e00a36e5dab` passed [workflow 37954433869](https://github.com/LloydCoder/Auctaryn/actions/runs/37954433869). The Python 3.12 run collected 473 tests; all 473 passed, Ruff and dependency audit passed, and the dashboard/container job validated dashboard build, deployment syntax, Compose, image build and liveness.  
**Post-merge CI:** merge commit `8b5864f1806268a1d7fea73f020b713021f63504` passed [workflow 37954650272](https://github.com/LloydCoder/Auctaryn/actions/runs/37954650272) with the same required jobs green.


## Implemented

- Added a machine-readable scenario manifest with all ten ASI 2026 categories and named executable tests.
- Added registry validation that fails if an ASI category, named test, expected outcome or ATLAS tactic mapping is missing.
- The first CI attempt exposed an invalid low-diversity static HMAC fixture; replaced it with cryptographically random signing keys and reran the complete matrix. Final result: 473 tests passed.
- Added deterministic tests for goal hijack, unknown-tool fail-closed behavior, scope escalation, signed-manifest tampering, invalid runtime command shape, memory poisoning, inter-agent payload tampering, circuit-breaker containment, step-up challenge replay and emergency-stop enforcement.
- Reconciled OWASP coverage to reflect actual Ed25519 manifest verification and actual artifact-byte digest verification from Phase 13.
- Documented tactic-level ATLAS mapping only; no unverified technique IDs are claimed.
- Explicitly records ASI09 as contract-only because the local step-up challenge is not bound to a real IdP/MFA assertion at the approval endpoint.

## Security findings and release gates

1. A passing local regression scenario is evidence for only the tested path, not universal mediation of external agent tools.
2. ASI09 needs authoritative identity-provider/Platform proof binding to approval intent before production claims.
3. In-process identity, memory, message and breaker state require durable authoritative storage before multi-replica claims.
4. OpenShell and runtime cancellation/fencing require live deployment acceptance; the benchmark uses no live external runtime.
5. Independent red-team and penetration testing remains a separate assurance activity.

## CI evidence

Exact-head and post-merge CI passed for the implementation commit. The audit and roadmap were reconciled after the successful implementation and post-merge runs. The current final documentation commit is subject to the same full CI gate; passing it closes the repository phase, not the external production acceptance gates. This audit is not a certification.
