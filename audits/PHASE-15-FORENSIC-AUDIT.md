# Phase 15 forensic audit — explainable risk findings

Status: implementation and forensic audit complete. PR #23 exact-head workflow passed all required checks; the merged commit's post-merge Python 3.11/3.12, dependency-audit, dashboard, Compose, container-build and liveness checks also passed.

## Implemented

- Added deterministic finding identifiers derived from risk level, rule identifier and request fingerprint.
- Added severity, confidence, bounded rationale, rule identifier, control references, recommendations, evidence references and explicit provenance.
- Identified the source as caller-supplied action metadata and set runtime_observed to false.
- Kept the existing auctaryn-risk-assessment.v1 fields and added fields only.
- Kept action parameters out of finding objects and bounded rationale/rule text.
- Added regression tests for determinism, provenance, bounds, unknown actions and advisory-only behavior.

## Invariants

1. Findings do not authorize, approve or execute actions.
2. Platform identity, tenant, capability, policy and approval checks remain authoritative.
3. The unkeyed SHA-256 request fingerprint is correlation metadata, not a signature or confidentiality control.
4. Control references are explanatory crosswalk tags, not certification.
5. Caller-supplied metadata and classifier output are not proof of actual runtime behavior.

## Remaining limitations

- Pattern-based explanations are heuristic and do not guarantee semantic completeness or detection accuracy.
- Findings are not yet linked to immutable evidence-store records or signed Platform decisions; those belong to Phase 16.
- Live Platform/runtime integration and durable multi-replica state require separate acceptance tests.
- Final completion requires all required workflows to pass on the exact final commit.
