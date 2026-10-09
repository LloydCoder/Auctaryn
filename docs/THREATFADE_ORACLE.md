# ThreatFade Oracle Resilience and Evidence Contract

## Trust boundary

ThreatFade is an advisory signal source. Its response can increase scrutiny or risk, but it cannot authorize an action, reverse a local denial, approve a destructive operation, or execute a tool. Tinlance Agent Platform remains authoritative for policy, approval, and governed execution.

## Client-side controls

The current client implementation in `modules/threatfade_oracle/client.py` applies these controls:

- External endpoints must use HTTPS and require `THREATFADE_SERVICE_TOKEN`; the token is sent as a Bearer credential. Plain HTTP is limited to recognized local/Docker hosts unless the explicit insecure-testing override is enabled.
- Requests use bounded timeouts and do not follow redirects, preventing credentials from being forwarded through an untrusted redirect.
- Signal inputs, labels, scenarios, JSON responses, and PCAP uploads are bounded. PCAP ingress is limited to 10 MiB and checks recognized PCAP/PCAPNG magic headers.
- JSON responses must be objects; analysis responses require the expected detection and triage objects and validate severity, numeric fields, and boolean flags.
- Invalid schemas, oversized payloads, transport errors, and upstream unavailability are treated as unavailable analysis. Error details are sanitized before they reach API clients.
- The Oracle circuit breaker is process-local, opens after repeated upstream failures, and permits a bounded recovery probe after its cooldown.
- Synthetic action-derived telemetry is disabled by default. Enabling `AUCTARYN_THREATFADE_ALLOW_SYNTHETIC_SIGNAL=true` is for isolated demonstrations/tests only; it is not observed network telemetry.

## Decision semantics

- Oracle findings are advisory and cannot override a terminal local denial or create an approval.
- An unavailable or malformed Oracle response must not grant authority. Existing local policy and approval requirements remain in force.
- Oracle transport failure is not evidence that the runtime action itself failed.
- Raw credentials and sensitive request values must not be copied into logs, histories, or public error responses.

## Required tests

Regression coverage should exercise missing/invalid service credentials, HTTP-vs-HTTPS policy, redirects, timeout and transport failures, malformed or oversized JSON, invalid severity/numeric/boolean fields, PCAP limits and magic headers, sanitized errors, circuit-breaker open/half-open recovery, and the invariant that Oracle output cannot approve an action.

The CI workflow uses mocked upstream behavior. A green workflow therefore validates repository behavior, not live ThreatFade authentication, upstream telemetry correctness, production rate limits, DNS, TLS certificates, or availability.

## Production acceptance gates

Before relying on a live upstream:

1. Verify HTTPS certificate validation and service-to-service Bearer authentication against the intended endpoint.
2. Verify upstream authorization, rate limits, timeouts, and payload limits under expected traffic.
3. Confirm that upstream telemetry represents observed data and is not synthesized from the action being evaluated.
4. Exercise outage, malformed response, latency, replay, and recovery scenarios.
5. Trace the advisory finding to the authoritative Platform policy decision and runtime receipt without logging raw secrets.
6. Record the tested upstream version, environment, date, and evidence artifact.

Do not describe mocked CI as live integration acceptance or independent security certification.
