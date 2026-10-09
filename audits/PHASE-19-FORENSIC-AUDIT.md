# Phase 19 forensic audit — enterprise tenancy and administrative boundaries

## CI evidence

**Exact-head CI:** PR head `7135b3c5bcf7ecf3a91e91bc5b4313e6d0248228` passed [workflow 37956021802](https://github.com/LloydCoder/Auctaryn/actions/runs/37956021802): 481 tests passed, Ruff and dependency audit passed, dashboard build, deployment syntax, Compose, container build and liveness passed.  
**Post-merge CI:** merge commit `7162505b397e7d1a442e967005c323904463aac9` passed [workflow 37956239758](https://github.com/LloydCoder/Auctaryn/actions/runs/37956239758) with all required jobs green.

## Findings and changes

- Restricted sensitive gateway decision history, pending approvals, protected-context check/compaction history and skill-vetting history to administrator credentials.
- Added a fail-closed local execution switch: direct execution routes return 503 unless `AUCTARYN_ALLOW_DIRECT_EXECUTION` is explicitly enabled.
- Rejected unknown request fields on the advisory risk contract so a caller-supplied `tenant_id` cannot be silently accepted as trusted identity context.
- CI initially exposed an existing evidence-before-runtime test that needed to opt into the explicit local execution profile; updated the test to state that mode and reran the full matrix.
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

## Final gate

The implementation's exact-head and post-merge workflows passed. The final audit/roadmap documentation commit remains subject to the same required CI gate. This does not claim that a live Platform adapter or enterprise IdP is configured.
