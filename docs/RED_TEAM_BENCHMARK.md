# Auctaryn adversarial red-team benchmark

**Version:** `auctaryn-redteam-manifest.v1`  
**Scope:** deterministic regression scenarios for the OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10).  
**Run:** `python -m pytest tests/redteam -v`

## Method

The JSON manifest is the scenario registry. Every entry names a concrete test, an expected security outcome, and a tactic-level MITRE ATLAS mapping. The registry test fails if a category or named test is missing. Each test exercises a local control path, not a simulated claim of full end-to-end protection.

The benchmark follows OWASP's current ASI01–ASI10 taxonomy and MITRE ATLAS's living threat matrix. Mapping is deliberately at the tactic level: this suite does not claim that each case has a verified technique identifier or that a single tactic mapping exhausts an attack chain. Review the [OWASP 2026 taxonomy](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and [MITRE ATLAS matrix](https://atlas.mitre.org/) before adding technique-level claims.

## Scenario registry

| ID | Attack class | Regression assertion | Evidence |
|---|---|---|---|
| ASI01 | Goal hijack | Contradictory override directive is detected | `test_asi01_goal_hijack_is_detected` |
| ASI02 | Tool misuse | Unknown operation is held for review, not auto-approved | `test_asi02_unknown_tool_action_is_not_auto_approved` |
| ASI03 | Identity/privilege abuse | Scoped token cannot exceed granted capability | `test_asi03_token_cannot_exceed_granted_scope` |
| ASI04 | Supply-chain compromise | Signed manifest mutation invalidates Ed25519 verification | `test_asi04_signed_manifest_tampering_is_rejected` |
| ASI05 | Unexpected code execution | Free-form shell command string is rejected where argv is required | `test_asi05_shell_command_string_is_rejected_by_runtime_adapter` |
| ASI06 | Memory/context poisoning | Poisoning pattern is detected; explicitly quarantined memory remains marked | `test_asi06_poisoning_pattern_is_detected_and_quarantined` |
| ASI07 | Inter-agent communication | Payload tampering fails HMAC verification | `test_asi07_tampered_message_payload_is_rejected` |
| ASI08 | Cascading failure | Tripped circuit breaker blocks the affected agent | `test_asi08_open_circuit_breaker_fails_closed` |
| ASI09 | Human-agent trust | Step-up challenge replay is rejected | `test_asi09_step_up_challenge_is_single_use` |
| ASI10 | Rogue agent | Persistent emergency stop blocks the agent execution guard | `test_asi10_emergency_stop_blocks_agent_execution` |

## Assurance limits and findings

- ASI09 is **contract-only**: the local challenge module enforces freshness and single-use, but a real IdP/MFA assertion is not yet bound to the gateway approval endpoint. Do not claim this benchmark proves MFA-protected approval. The authoritative identity and approval integration must be addressed in the ecosystem integration/release gates.
- Local identity, memory, breaker and message state remain in-process; the suite does not prove durability or multi-replica enforcement.
- The emergency stop blocks new execution checks; it is not proof that an already-running external process is terminated.
- OpenShell tests validate adapter input contracts, not a live sandbox's kernel enforcement, filesystem isolation or network egress policy.
- The tests use generated cryptographic keys and synthetic payloads. They do not constitute an independent penetration test or certify production security.

Every confirmed benchmark finding must be retained as a regression case or tracked as a release-blocking integration gate. Do not turn a tactic-level mapping or passing unit test into a claim of full OWASP/ATLAS coverage.
