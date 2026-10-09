# Standards-to-evidence traceability

This is the human-readable entry point to the machine-readable manifest at config/standards_traceability.json. The manifest is validated by scripts/audit_standards_traceability.py and the test suite; it records implementation paths, exact test functions, evidence level, residual risk and release-gate status for OWASP ASI01–ASI10, selected NIST SSDF practices, the NIST AI RMF Govern/Map/Measure/Manage functions, and tactic-level MITRE ATLAS mappings.

Run validation with python scripts/audit_standards_traceability.py and pytest tests/test_standards_traceability.py -q.

**Interpretation rule:** a mapping means there is a traceable local artifact or test—not that the standard is certified, the control is universally effective, or the runtime has been independently assessed. OWASP categories with heuristic or in-process controls remain partial. MITRE ATLAS mappings in the red-team manifest remain tactic-level. See OWASP_COVERAGE.md, SECURITY_RISK_REGISTER.md and INDEPENDENT_ASSURANCE_PLAN.md.


## Interoperability standards assessed but not implemented

The [OWASP Agent Control Standard (ACS) v0.1.0](https://github.com/GenAI-Security-Project/agent-control-standard) was reviewed during the Phase 24 final audit. ACS defines a JSON-RPC runtime-control wire contract (handshake and pre-action hooks), rather than a control taxonomy. Auctaryn does not currently implement that protocol and makes no ACS conformance claim. This absence is tracked as a future interoperability candidate, not as evidence of ASI01–ASI10 coverage or a current release blocker. Reassess if ACS interoperability becomes a product requirement.
