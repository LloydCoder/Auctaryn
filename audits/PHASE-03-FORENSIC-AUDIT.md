# Phase 3 forensic audit — versioned advisory risk contract

**Review date:** 2026-10-09  
**Scope:** `api/routes/risk.py`, `docs/integration/TINLANCE_AGENT_PLATFORM.md`, and `tests/test_platform_risk_contract.py`.

## Verified implementation

- The endpoint is `POST /api/v1/risk/assess` and uses the explicit `auctaryn-risk-assessment.v1` contract.
- Requests reject unknown fields and bound the primary identifier/target fields.
- Responses are advisory-only: they return risk level, confidence, safe rationale, correlation fingerprint and structured findings; they do not return an allow/deny decision or execute an action.
- Raw parameters and identity tokens are not returned. Recognized sensitive data is rejected before classification.
- Findings mark caller-supplied action metadata and `runtime_observed: false`; the fingerprint is documented as correlation metadata, not an authorization proof.
- The Platform integration document explicitly states that the stable Platform SDK does not expose this operation and that a versioned Platform-side adapter plus conformance tests are required.

## Residual limitations

The contract is not a live Platform integration. Auctaryn's local classifier and findings must never grant authority or bypass Platform policy. Request-body limits bound total ingress, but the endpoint remains an advisory signal and requires caller-side timeout, tenant binding, rate limiting and audit correlation.

## Verdict

Contract and boundary documentation are reviewed. Exact-head CI must pass; live Platform adapter/conformance acceptance remains open.
