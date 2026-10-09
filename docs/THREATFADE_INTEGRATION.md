# ThreatFade Oracle Integration and Failure Semantics

## Trust boundary

ThreatFade/FusionOps is an advisory analysis service. Its responses are untrusted input and may add risk or preserve an existing conservative decision; they never grant authorization, approve an action, or invoke a tool. Tinlance Agent Platform remains authoritative for production identity, policy, approval, execution, secrets and durable audit.

## Telemetry quality

The current Auctaryn integration can generate a synthetic entropy signal from action metadata. Such data is not a network capture or observed agent telemetry and cannot support a claim of actual network-threat detection. Synthetic analysis is disabled by default. Set `AUCTARYN_THREATFADE_ALLOW_SYNTHETIC_SIGNAL=true` only in isolated demos/tests; do not enable it in production. Real telemetry ingestion and provenance-bound correlation remain separate implementation work.

## Client configuration

- `THREATFADE_SERVICE_URL`: absolute HTTPS URL for an external service; plain HTTP is accepted only for loopback/Docker service names unless the explicit isolated-testing override is set.
- `THREATFADE_SERVICE_TOKEN`: required for external HTTPS endpoints and sent as a Bearer token. The upstream ThreatFade service must validate it; Auctaryn sending a token does not itself authenticate the upstream service. Local Docker/loopback services may run without it for development.
- `AUCTARYN_ALLOW_INSECURE_THREATFADE_HTTP=true`: isolated testing only; never use for external production endpoints.
- Requests disable redirects and use bounded timeouts. Credentials must not be placed in URLs.

## Input and response limits

- Signal requests require 10–10,000 finite numeric points, matching timestamp/value lengths, and a bounded source label.
- Events queries are limited to 1–200.
- PCAP uploads are capped at 10 MiB; filenames are restricted to a safe basename character set and file contents must begin with a recognized PCAP/PCAPNG magic header.
- Analysis responses must be JSON objects with `detection` and `triage` objects, recognized severity values, finite numeric fields, and correctly typed boolean flags. Malformed, invalid or unavailable responses are upstream failures, not benign findings.

The current response-size guard checks Content-Length and the received response body after HTTPX has materialized it. It is defense in depth, not a hard transport-memory cap; production service and reverse-proxy limits must also enforce response sizes.

## Circuit breaker and failure behavior

The Oracle circuit breaker opens after three consecutive upstream failures, remains open for 30 seconds, and permits one half-open probe after cooldown. Successful upstream analysis resets it. Analysis history is capped at 500 in-memory records and is not a durable audit ledger.

When analysis fails or the breaker is open, Auctaryn returns an informational fallback to the local gateway integration. The gateway must preserve its local decision: an existing pending, denied or vetoed action cannot become approved because ThreatFade is unavailable. The fallback means “no usable ThreatFade signal,” not “the action is safe.”

## Production acceptance

Before production use, verify:
1. TLS and upstream authentication are enforced by the actual ThreatFade service.
2. Request/response limits are enforced at the service and reverse proxy.
3. A malformed or oversized response cannot crash the gateway or leak payloads/secrets.
4. Circuit-breaker opening, half-open probing and recovery behave under concurrency.
5. Oracle outage preserves the local decision and never authorizes an action.
6. Real observed telemetry, its source identity and timestamp are bound to the relevant agent/action before describing an Oracle finding as runtime evidence.
7. Synthetic mode remains disabled in the production deployment environment.
