# Tinlance Agent Platform integration boundary

## Status

This document defines Auctaryn's **advisory risk contract**. It does not claim that a live Tinlance Agent Platform deployment has been configured to call it.

The Tinlance Agent Platform remains authoritative for agent identity, tenant binding, capabilities, policy, approvals, execution, sandboxing, secrets, evidence, and audit. The Platform SDK is a typed consumer surface; it does not grant authority locally.

## Auctaryn contract

- Endpoint: `POST /api/v1/risk/assess`
- Contract: `auctaryn-risk-assessment.v1`
- Authentication: configured Auctaryn service/admin Bearer credential
- Output: risk level, confidence, reason, matched pattern, timestamp, assessment ID, a SHA-256 request fingerprint, and additive structured `findings` plus `evidence_quality` fields
- The response deliberately excludes raw parameters and identity tokens.
- `input_fingerprint` is an unkeyed SHA-256 correlation value, not an authorization proof or confidentiality control; low-entropy inputs may be guessable. The Platform must compute its own authoritative execution-intent binding and must not trust this fingerprint for approval or access decisions.
- The endpoint does not return an allow/deny/approval decision and does not execute a tool.
- SensitiveDataGuard rejects recognized raw-secret patterns before classification. This is defense in depth, not a complete DLP guarantee.

## Explainable finding semantics

Each finding contains a stable finding identifier, severity, confidence, bounded rationale, rule identifier, explanatory control references, a recommendation, evidence-reference labels and provenance. Current provenance explicitly says `caller_supplied_action_metadata`, `local_pattern_classifier`, and `runtime_observed: false`. These fields explain Auctaryn's classification; they are not runtime telemetry, immutable evidence, a cryptographic attestation, or a Platform authorization decision. Existing v1 response fields remain unchanged; the added fields are additive. Consumers must tolerate absent/unknown optional finding fields and must never use the finding ID or request fingerprint as an approval token.

## Required Platform-side behavior

1. Treat the response as an untrusted risk signal, not an authorization grant.
2. Bind the assessment to the exact action, resource, agent, tenant, and execution intent on the Platform side.
3. Re-evaluate identity, capability, policy, and approval at the actual execution boundary.
4. Fail closed or apply a documented conservative policy if Auctaryn is unavailable, the response is malformed, or the contract version is unsupported.
5. Do not infer approval from a low risk level. Auctaryn's risk classifier is not the Platform policy engine.
6. Preserve correlation IDs and evidence references without copying raw secrets into logs.

## SDK and contract compatibility

The current Tinlance Agent Platform SDK v1.0 contract exposes Platform API 1.1 through `POST /v1/agent-platform` and lists a fixed set of operations, including `tools.execute` and `approvals.request`. The Auctaryn risk endpoint is **not** one of those SDK operations. A live integration therefore requires a separately versioned Platform-side adapter/extension and executable conformance tests; do not invent an SDK operation or treat this endpoint as part of the stable SDK surface.

## Evidence correlation boundary

Auctaryn's local evidence chain records application events and safe hashes for assessment, decision, approval, execution request and receipt. These records can help correlate incidents, but they are not the Platform's authoritative audit records. The Platform must persist its own identity/policy/approval decision and execution receipt, link the advisory assessment by a correlation identifier, and retain evidence in independently administered durable storage. Local SQLite and optional HMAC are a defense-in-depth mechanism, not a distributed immutable ledger.

## Production acceptance gates

- Verify service authentication, TLS, tenant isolation, request/response schema validation, timeouts, rate limits, and bounded payload size.
- Verify unsupported contract versions and malformed responses fail closed.
- Test that a low-risk response cannot bypass Platform policy and that high-risk findings can only tighten controls.
- Test behavior during Auctaryn outage, latency, replay, and conflicting assessments.
- Verify Platform audit evidence links the advisory finding to the authoritative policy decision and actual execution result.
- Keep the local Auctaryn gateway disabled for direct production execution unless the configured trusted runtime and the Platform authority boundary have both been independently verified.
