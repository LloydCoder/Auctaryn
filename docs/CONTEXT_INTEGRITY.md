# Auctaryn Context Integrity

## Purpose

Auctaryn's Context Integrity Guardian checks whether registered protected instructions remain present in a submitted context snapshot and detects selected goal-hijack patterns. It is a detection and evidence component, not a model-verification oracle.

## Baseline handling

- Instruction tags must be non-empty and at most 128 characters.
- Instruction content must be non-empty and at most 32,768 characters.
- Context-check input is bounded at the API boundary.
- The guardian recomputes SHA-256 over each stored instruction before trusting it. A baseline whose content no longer matches its registered hash produces a blocked, compromised result.
- Instruction content is not copied into alert messages. Findings should contain only necessary metadata and bounded explanations.

## Detection semantics

A check can report degraded or compromised context when protected instructions are missing or a relevant override pattern is detected. Goal-hijack detection compares the sentence containing the override phrase with meaningful terms from the protected instruction to reduce false positives caused by unrelated override language elsewhere in the context.

These are deterministic heuristics. They do not provide complete semantic prompt-injection detection and can produce false negatives. Treat findings as one security signal among independent identity, policy, approval, data-protection, and runtime controls.

## Trust boundary

Context text sent to an API is caller-provided evidence. A successful check cannot establish that the submitted snapshot is exactly the context an external agent actually consumed. Until a trusted runtime/harness adapter supplies authenticated provenance and binds the observation to immutable execution intent, the result must not be described as proof that an action is safe or that execution has been prevented.

Phase 9 must connect trusted runtime observations to the authoritative execution boundary. Auctaryn findings remain advisory until that integration is implemented and tested end to end.

## Verification

Phase 8 acceptance requires regression tests for:
- empty and oversized instruction registration;
- stored-baseline tampering;
- missing instruction degradation;
- relevant goal-hijack detection when the original instruction is still present;
- unrelated override language that should not trigger a hijack finding;
- API response and alert behavior for blocked findings.

The full required GitHub Actions matrix must be green on the final commit. CI tests do not replace live-runtime acceptance or independent penetration testing.
