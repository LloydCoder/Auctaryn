# Phase 19 forensic audit — enterprise tenancy and administrative boundaries

## Findings and changes

- Restricted sensitive gateway decision history, pending approvals, protected-context check/compaction history and skill-vetting history to administrator credentials.
- Added a fail-closed local execution switch: direct execution routes return 503 unless `AUCTARYN_ALLOW_DIRECT_EXECUTION` is explicitly enabled.
- Required the distinct administrator credential for local direct execution, even when enabled.
- Added negative tests for service-key access to sensitive history and direct-execution routes.
- Added an API authorization matrix and reconciled the Platform integration boundary to state that local service/admin keys do not establish tenant membership or human MFA.

## Authority and tenant isolation

Tinlance Agent Platform remains the sole authority for authenticated principal, tenant binding, capability authorization, policy, approvals and consequential execution. Auctaryn's risk endpoint is an advisory signal. A live Platform-side adapter must bind its assessment to the authenticated tenant, subject, agent and exact action intent; this repository does not claim that a live adapter or external identity provider is configured.

## Residual production gates

- Static service/admin credentials do not provide per-human attribution or tenant isolation.
- Process-local agent identity and token state is not durable or multi-replica safe.
- Direct execution must remain disabled in the Platform-integrated production profile until an independently verified authority boundary and runtime deployment are accepted.
- Live Platform conformance, enterprise IdP/MFA, durable state and runtime acceptance remain release gates.

## CI evidence

Exact-head and post-merge required workflows must pass on the final implementation and documentation commits before Phase 19 is closed.
