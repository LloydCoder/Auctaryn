# Auctaryn — Security Demo Script

**Duration:** 6–8 minutes  
**Audience:** CISOs, security engineers, pilot customers  
**Purpose:** Demonstrate context-integrity detection and its session-bound gateway enforcement. This script demonstrates the configured local environment; it is not proof of universal mediation or a live OpenShell production deployment.

## Setup

1. Start the API using the repository's documented Compose configuration.
2. Set two distinct, high-entropy credentials in the local environment. Do not paste secrets into slides, logs, or a shared terminal recording.
3. Set the local API base URL and authenticate requests:

```bash
export AUCTARYN_ADMIN_API_KEY='your-local-admin-key'
export AUCTARYN_API_URL='http://localhost:8400'
```

Use the Authorization header on every API call below. The configured local port may differ by deployment.

## Part 1 — Register a protected instruction

```bash
curl -sS -X POST "$AUCTARYN_API_URL/api/v1/context/register" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tag":"customer_delete_safety","content":"Never delete customer records without explicit confirmation."}'
```

Explain that Auctaryn stores a fingerprint of the registered instruction. Current detection checks for missing instruction text and known override-language patterns; it is heuristic and does not guarantee semantic understanding of every prompt injection.

## Part 2 — Check a clean session

```bash
curl -sS -X POST "$AUCTARYN_API_URL/api/v1/context/check" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"session_id":"demo-session","context":"Never delete customer records without explicit confirmation.\\nUser asks for a customer report."}'
```

Expected result: status `intact`, `blocked: false`, and `session_id: demo-session`.

## Part 3 — Simulate instruction loss

```bash
curl -sS -X POST "$AUCTARYN_API_URL/api/v1/context/check" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"session_id":"demo-session","context":"[Conversation summary]\\nUser asks to delete every customer record."}'
```

Expected result: a compromised/blocked session and a context-integrity alert. The session is quarantined until an administrator clears it; a subsequent clean check alone does not remove the quarantine.

## Part 4 — Prove the gateway rejects the quarantined session

```bash
curl -sS -X POST "$AUCTARYN_API_URL/api/v1/gateway/intercept" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"search_web","action":"search","parameters":{"query":"customer records"},"agent_id":"demo-agent","session_id":"demo-session"}'
```

Expected result: decision `denied`, with `decided_by: context_integrity_guard`. This proves the tested gateway decision path rejects the quarantined session. It does not prove every external tool in every agent framework is automatically mediated.

## Part 5 — Operator recovery

Register an agent, grant only the required tool scope, and issue a short-lived identity capability using the administrator-protected identity endpoints. Then clear the session quarantine:

```bash
curl -sS -X POST "$AUCTARYN_API_URL/api/v1/context/sessions/demo-session/clear" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY"
```

The endpoint should report that a fresh integrity check is required. Submit a clean, session-bound context check before retrying a gateway action with the issued identity token. The gateway should reject the action if the session is unchecked, degraded, compromised, or quarantined.

## Part 6 — Explain the defense boundaries

- The gateway's session-bound check is one control within Auctaryn's supported path; external agent frameworks must explicitly route actions through that path.
- The configured runtime adapter is opt-in. Without a trusted runtime adapter, governed execution returns HTTP 503.
- ThreatFade Oracle enrichment is available only when its service is correctly configured and reachable. Its signal cannot grant authorization or override a denial.
- OpenShell enforces its own effective sandbox policy. CI with fake clients does not prove a live gateway's network, filesystem, or process restrictions.
- Identity, quarantine, approval and history state are currently in-process. Multi-replica durability is a known enterprise-readiness gap.

Do not claim a perfect detection rate, universal prevention, a zero false-positive rate, or production certification without current, reproducible evidence and independent review.
