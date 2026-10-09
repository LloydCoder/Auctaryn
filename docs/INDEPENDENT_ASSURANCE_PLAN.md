# Independent assurance plan

**Purpose:** prepare Auctaryn for an external security assessment without representing internal tests as independent assurance.  
**Status:** readiness package defined; external penetration test not yet performed.

## Assessment objectives

1. Verify authorization boundaries and confirm Auctaryn's advisory risk response cannot grant execution authority.
2. Find bypasses around gateway mediation, approvals, session-bound context checks and emergency-stop/quarantine controls.
3. Test cross-tenant isolation, identity ownership, scoped tokens, delegation, revocation and step-up challenge binding.
4. Validate live OpenShell sandbox/workspace selection, effective policy, filesystem boundaries, network egress restrictions, process limits and behavior after gateway failure.
5. Test inter-agent HMAC envelope tampering, replay, expiry, recipient isolation, key rotation/revocation and cascade recovery.
6. Assess skill/artifact signature verification, version pinning, content digest checks, rollback attacks and dependency/supply-chain poisoning.
7. Probe sensitive-data exposure, logs, error paths, evidence APIs, dashboard authorization, WebSocket session revocation and incident-response controls.
8. Test persistence, restart behavior, concurrent requests and multi-replica deployment assumptions.
9. Validate image provenance, SBOM correspondence, release digest pinning and rollback evidence.

## Required review artifacts

- Exact repository commit SHA and deployment configuration digest.
- Architecture/data-flow diagram identifying Tinlance Agent Platform as the authority plane, Auctaryn as the advisory/security-analysis plane, and OpenShell as the runtime boundary.
- Machine-readable standards traceability, threat model, OWASP coverage, red-team benchmark, API authorization matrix and relevant phase audits.
- Exact-head CI, CodeQL, Gitleaks, pip/npm audit, Grype inventory, SPDX SBOM and artifact-attestation evidence.
- Live test environment topology, tenant/agent identities, policy revision, secrets handling procedure and sanitized logs.
- Explicit limitations: local-only state, unsupported external agent paths, heuristic detectors and any unavailable live integrations.

## Required independent report format

For each finding record: unique ID; severity and rationale; affected component and exact commit; preconditions; reproducible steps or safe proof-of-concept; impact; evidence; remediation recommendation; owner; target date; fix commit; regression test; independent retest result; final disposition.

The assessor must state the environment, test window, scope exclusions, access level and whether the result was black-box, gray-box or white-box. A report that omits excluded attack paths must not be interpreted as comprehensive coverage.

## Release acceptance

- No unresolved critical findings.
- No unresolved high finding unless the accountable security owner records a time-bounded exception with compensating controls and the release approver explicitly accepts it.
- Every remediated finding has a regression test and independent retest evidence.
- Live OpenShell and Platform integration tests pass in the intended deployment topology.
- Deployed image digest matches the verified immutable release digest and its provenance/SBOM.
- Risk register and roadmap reflect the assessor's findings.
- The external report must be delivered by an independent assessor. Internal CI and local red-team tests do not satisfy this requirement.