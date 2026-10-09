# Phase 10 — Runtime Containment and Policy Verification Audit

**Repository:** LloydCoder/Auctaryn  
**Pull request:** [#13 — Validate restrictive OpenShell baseline before runtime startup](https://github.com/LloydCoder/Auctaryn/pull/13)  
**Implementation commit:** 78a5ffc0e1fcd178b4f49e3420541eaa85aa5800  
**CI evidence:** [Auctaryn CI run 509](https://github.com/LloydCoder/Auctaryn/actions/runs/37932946315)  
**Outcome:** Code implementation and CI passed. Live gateway acceptance remains an explicit production release gate and is not claimed as complete.

## Files reviewed

- modules/execution_gateway/policy_validation.py
- modules/execution_gateway/openshell_adapter.py
- scripts/verify_openshell_policy.py
- deploy/openshell/auctaryn-policy.yaml
- tests/test_openshell_policy_validation.py
- tests/test_openshell_policy_verifier.py
- tests/test_openshell_adapter.py
- docs/OPEN_SHELL_RUNTIME.md
- docs/IMPLEMENTATION_ROADMAP.md

## Findings and remediation

1. **Restrictive baseline validation — implemented.** The policy validator requires version 1, required read-only system paths, only the approved writable paths, include_workdir=true, landlock.compatibility=hard_requirement, and an empty default network policy.
2. **Policy ambiguity — mitigated.** The YAML loader rejects duplicate mapping keys, merge-expanded duplicates, and unreviewed top-level or filesystem/Landlock settings.
3. **Startup fail-closed behavior — implemented.** Environment-based OpenShell adapter initialization validates the repository-owned baseline before creating the SDK client and fails closed if the baseline is missing or unsafe.
4. **Baseline provenance — implemented.** The SHA-256 of the validated source file is retained on the adapter for diagnostics.
5. **Sandbox identifier safety — implemented.** Sandbox identifiers are bounded and restricted to a conservative character set before they reach the SDK or CLI.
6. **Live effective-policy drift check — implemented as an operator tool.** The verifier runs the documented OpenShell command using an argv array, shell=False, a 10-second timeout, and an independently reviewed SHA-256 pin. It rejects missing pins, CLI errors, and digest mismatch.
7. **Regression coverage — passed.** Tests cover baseline acceptance, unsafe filesystem/network mutations, unreviewed policy sections, malformed/duplicate YAML, startup failure, policy match/drift, CLI failures and invalid identifiers.

## CI evidence

Full CI passed on implementation commit 78a5ffc0e1fcd178b4f49e3420541eaa85aa5800:
- Python 3.11: 341 passed; Ruff passed.
- Python 3.12: 341 passed; Ruff passed; Python dependency audit passed.
- Dashboard build and npm audit passed.
- Deployment script syntax passed.
- Compose validation passed.
- API container build passed.
- Container liveness check passed.

## Production blocker — live runtime acceptance not performed

The current CI uses a fake OpenShell client. It does not prove:
- the configured SDK and CLI are connected to the intended authenticated gateway;
- the active sandbox's effective policy equals the reviewed pinned revision;
- filesystem writes outside approved paths fail in the live sandbox;
- unapproved network egress is blocked;
- process isolation and the Landlock requirement are actually enforced by the deployed host/runtime;
- a denied or pending Auctaryn decision cannot reach the live OpenShell execution endpoint.

Before production enablement, run the live checks in the OpenShell Runtime guide against the intended gateway and retain the output as deployment evidence. Do not describe this phase as live-runtime certified until that evidence exists.

## Verdict

Phase 10's repository implementation, static policy checks, operator verifier, documentation and CI are complete. Production readiness remains blocked on the external live OpenShell acceptance gate; no live integration or containment certification is claimed.
