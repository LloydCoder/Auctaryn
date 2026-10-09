# ThreatFade Oracle Resilience and Evidence Handling

## Trust boundary

ThreatFade Oracle is a threat-intelligence signal provider, not an authorization authority. Its severity can escalate a non-terminal local decision, but its response cannot override a local denial or authorize a destructive operation. If the Oracle is unavailable or its response is invalid, Auctaryn preserves the conservative local decision path; Oracle failure must not be interpreted as a safe verdict.

## HTTP client controls

- Endpoint configuration rejects embedded credentials, query parameters and fragments; external endpoints require HTTPS unless an explicit isolated-test override is configured. Remote endpoints also require THREATFADE_API_KEY, sent as a bearer credential; the local Docker service name may run without a key for isolated development.
- Request timeout is bounded to 1–60 seconds.
- JSON responses must be objects; analysis responses must include detection, triage and remediation mappings with bounded numeric values and valid severity/decision fields.
- Non-finite input numbers, out-of-order timestamps, excessive sample counts, oversized triage payloads, oversized response bodies, invalid event limits, oversized PCAP files and unsafe filenames are rejected.
- PCAP uploads are limited to 25 MiB and are read with a bounded read in the API route.
- Upstream errors are logged with error type and returned to API clients as generic service-unavailable responses; raw upstream exception text is not exposed.
- Oracle result and raw-result histories are bounded to 1,000 records per instance.
- The Oracle circuit breaker opens after five consecutive transport/schema failures, remains open for 30 seconds, and permits only one half-open probe. A successful probe closes the breaker; failures return to the open state. Circuit state is included in the status response.

## Evidence semantics

A validated Oracle response is an external observation. It is not proof that a threat occurred, that a runtime action was blocked, or that the upstream service is uncompromised. Auctaryn preserves source labels and result fields for correlation, while malformed or unavailable responses produce an INFO fallback for the execution-analysis path and do not grant additional authority.

Synthetic signals derived from a ToolCall are heuristics; they are not captured network telemetry or a PCAP. UI and reports must label them accordingly.

## Circuit-breaker boundary

The execution gateway's circuit breaker governs actual runtime execution failures. Oracle transport or schema failures are not runtime execution failures and must not increment runtime failure counters. Oracle calls have bounded timeouts; the local decision remains authoritative if enrichment fails.

## Live acceptance still required

CI uses mocked HTTP responses. Before production enablement, verify authenticated upstream transport, TLS configuration, service identity, real response schema compatibility, rate limits, timeout behavior, and fail-safe behavior against the deployed ThreatFade service. CI does not certify the live upstream.
