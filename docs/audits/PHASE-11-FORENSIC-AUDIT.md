# Phase 11 Forensic Audit — ThreatFade Oracle Resilience

**Repository:** `LloydCoder/Auctaryn`  
**Phase branch:** `security/phase-11-threatfade-resilience`  
**Audited commit:** `30d28932737d2864eb92016c50a9ef65befbe94c`  
**CI run:** [Auctaryn CI #597](https://github.com/LloydCoder/Auctaryn/actions/runs/37934425427)  
**Disposition:** Repository-level phase acceptance passed; external production integration remains gated.

## Scope reviewed

- `modules/threatfade_oracle/client.py`
- `modules/threatfade_oracle/oracle.py`
- `api/routes/threatfade.py`
- `api/main.py` (route-specific ingress body limiter)
- `tests/test_threatfade_resilience.py`
- `tests/test_threatfade_oracle.py`
- `tests/conftest.py`
- `README.md`
- `docs/SECURITY_MODEL.md`
- `docs/THREATFADE_INTEGRATION.md`
- `docs/IMPLEMENTATION_ROADMAP.md`

## Implemented and verified

1. External ThreatFade endpoints require a configured Bearer token; local loopback/Docker endpoints can be used without one for development. The upstream service must validate the token for authentication to be effective.
2. Remote requests use bounded timeouts, disable redirects, reject embedded URL credentials/query strings/fragments, and require HTTPS for non-local endpoints unless an explicit isolated-testing override is used.
3. Analysis requests validate matching, finite timestamp/value arrays, cap point count, and bound the source label.
4. Upstream analysis responses must be JSON objects with detection/triage objects, a recognized severity, finite numeric fields and correctly typed boolean flags. Invalid responses become upstream failures.
5. Events queries and response payload acceptance are bounded; PCAP filenames are constrained and file bytes must begin with a recognized PCAP/PCAPNG magic header.
6. PCAP request bodies are capped by ASGI middleware before multipart parsing, including requests without a Content-Length header. The endpoint reads no more than the file cap plus one byte.
7. The Oracle circuit breaker supports open/half-open/closed behavior, one half-open probe, bounded cooldown, recovery, and cancellation cleanup. Invalid caller scenarios do not count as upstream failures.
8. Synthetic action-derived signals are disabled by default because they are not observed network telemetry. Tests opt into demo mode explicitly.
9. Oracle failures and breaker-open outcomes produce an informational “no usable signal” fallback; the local gateway decision remains authoritative. History is capped at 500 records.

## CI evidence

Run #597 completed successfully on the audited commit:

- Python 3.11: **357 passed**, 1 warning.
- Python 3.12: **357 passed**, 238 warnings.
- Ruff lint check: passed on both matrix legs.
- Python dependency audit: passed; no known vulnerabilities reported.
- Dashboard build: passed.
- Deployment script syntax: passed.
- Compose validation: passed.
- API container build: passed.
- API liveness check: passed.

The Python 3.12 warnings are non-failing but should be reduced before a final production release. The observed categories include Starlette TestClient/httpx deprecation and `datetime.utcnow()` deprecation.

## Residual risks and release gates

- The response-size guard validates Content-Length and body size after HTTPX has materialized the response. It is not a hard transport-memory cap; configure response limits at the upstream service and reverse proxy, and consider a streaming capped reader before production.
- Auctaryn sends the configured service token, but the actual upstream ThreatFade service's token verification was not available to validate in this repository-only CI run. Verify it with a live authenticated integration test.
- Real network telemetry capture and provenance binding are not implemented by this phase. Synthetic analysis remains demo/test-only and must not be used as production threat evidence.
- Circuit-breaker state and result history are process-local. They are not distributed rate controls or durable audit evidence.
- CI does not substitute for live OpenShell/runtime acceptance, external ThreatFade integration testing, or independent penetration testing.

## Conclusion

Phase 11's repository implementation passes the required CI matrix and regression checks. This is **not** a claim of production certification. The listed live-integration and transport-level limitations remain explicit release gates and must not be hidden by the green CI result.
