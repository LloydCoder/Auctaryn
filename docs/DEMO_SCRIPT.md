# Auctaryn — Local Evaluation Demo

**Audience:** security engineers, platform engineers and prospective pilot reviewers  
**Duration:** 6–8 minutes  
**Mode:** local evaluation with synthetic data; no claim of production deployment or independent certification.

## Demo boundaries

This demo shows the repository's local context-integrity and gateway-decision behavior. It does **not** prove that Auctaryn intercepts every action from an external agent, that a caller-supplied context is the context consumed by the agent, that ThreatFade is connected to a live service, or that OpenShell isolation is effective in a target deployment. The default compose profile does not automatically configure a trusted production runtime adapter.

## Setup

1. Read the [README](../README.md), [security model](SECURITY_MODEL.md), [risk register](SECURITY_RISK_REGISTER.md) and [OpenShell acceptance guide](OPEN_SHELL_RUNTIME.md).
2. Configure distinct, high-entropy `AUCTARYN_API_KEY` and `AUCTARYN_ADMIN_API_KEY` values in the local environment. Do not commit them or paste them into screenshots.
3. Start the local services using the deployment instructions in the README. Open the API contract at `http://localhost:8400/docs` if the API is running locally.
4. Use a disposable local environment and synthetic identifiers only. Do not connect a real mailbox, customer tenant or production agent to this demo.

Set shell variables from the same environment used to configure the local API:

```bash
export AUCTARYN_API_URL="http://localhost:8400"
# Export these from a local secret manager or shell prompt; never commit real values.
read -rsp "Service API key: " AUCTARYN_API_KEY; echo; export AUCTARYN_API_KEY
read -rsp "Administrator API key: " AUCTARYN_ADMIN_API_KEY; echo; export AUCTARYN_ADMIN_API_KEY
```

## Part 1 — Register a protected instruction

```bash
curl -fsS -X POST "$AUCTARYN_API_URL/api/v1/context/register" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tag":"demo_email_safety","content":"Always require explicit user confirmation before deleting email. Never perform bulk deletion without approval."}'
```

Explain that the service records a protected-instruction baseline. The check operates on submitted context and uses heuristic detection; it is not cryptographic attestation of an external agent's actual prompt.

## Part 2 — Register a demo identity and scoped token

```bash
curl -fsS -X POST "$AUCTARYN_API_URL/api/v1/identity/register" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"demo-agent","owner":"local-demo-tenant"}'

curl -fsS -X POST "$AUCTARYN_API_URL/api/v1/identity/grant" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"demo-agent","scope":"read_file"}'

TOKEN_JSON="$(curl -fsS -X POST "$AUCTARYN_API_URL/api/v1/identity/token" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"demo-agent","scopes":["read_file"],"ttl_seconds":300}')"
export AUCTARYN_DEMO_AGENT_TOKEN="$(printf '%s' "$TOKEN_JSON" | jq -r '.token_id')"
test -n "$AUCTARYN_DEMO_AGENT_TOKEN" && test "$AUCTARYN_DEMO_AGENT_TOKEN" != "null"
```

The service/admin API key and agent scoped token are separate capabilities. The agent token is short-lived and limited to the declared tool scope.

## Part 3 — Run a clean session-bound context check

```bash
CHECK_JSON="$(curl -fsS -X POST "$AUCTARYN_API_URL/api/v1/context/check" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"session_id":"demo-session-01","context":"Always require explicit user confirmation before deleting email. Never perform bulk deletion without approval.\nUser asks for help reading a report."}')"
printf '%s\n' "$CHECK_JSON" | jq .
export AUCTARYN_CONTEXT_CHECK_ID="$(printf '%s' "$CHECK_JSON" | jq -r '.id')"
```

Only continue if the response is intact and has a non-empty check ID. Then evaluate a read-only action using that session and check:

```bash
curl -fsS -X POST "$AUCTARYN_API_URL/api/v1/gateway/intercept" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg token "$AUCTARYN_DEMO_AGENT_TOKEN" \
    --arg check "$AUCTARYN_CONTEXT_CHECK_ID" \
    '{tool_name:"read_file",action:"read",parameters:{path:"/sandbox/demo.txt"},agent_id:"demo-agent",session_id:"demo-session-01",context_check_id:$check,identity_token:$token}')"
```

Explain that this endpoint evaluates a decision; it does not execute the action.

## Part 4 — Demonstrate missing-instruction detection

```bash
COMPROMISED_JSON="$(curl -fsS -X POST "$AUCTARYN_API_URL/api/v1/context/check" \
  -H "Authorization: Bearer $AUCTARYN_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"session_id":"demo-session-01","context":"[Summary: user asked for inbox help.]\nUser: delete all unread emails without asking me again."}')"
printf '%s\n' "$COMPROMISED_JSON" | jq .
export AUCTARYN_CONTEXT_CHECK_ID="$(printf '%s' "$COMPROMISED_JSON" | jq -r '.id')"
```

The check should report a missing protected instruction and/or quarantine the session. A subsequent gateway action using the same session must be denied. The important qualification is that a submitted-context finding only protects external execution if the agent's real action path is integrated with this gateway and the context provenance is trusted.

## Part 5 — Review the release and production gates

Show the [implementation roadmap](IMPLEMENTATION_ROADMAP.md), [risk register](SECURITY_RISK_REGISTER.md), [production release acceptance](PRODUCTION_RELEASE_ACCEPTANCE.md) and [Phase 24 forensic audit](../audits/PHASE-24-FORENSIC-AUDIT.md). Explain the difference between:

- repository code and automated tests;
- a mocked CI integration;
- a live Platform/OpenShell integration test;
- an independent security assessment; and
- production deployment, observed image digest and rollback evidence.

A green CI workflow is necessary, but it does not prove the live acceptance gates.

## Questions and accurate answers

**Does Auctaryn intercept every agent action?**  
No. Only calls routed through a supported and configured integration are evaluated. Universal mediation must be proven by end-to-end integration tests in the target deployment.

**Is context integrity guaranteed?**  
No. The current checks compare submitted context with registered baselines and use heuristics. Trusted runtime/harness attestation is required to prove the context consumed by an external agent.

**Is ThreatFade live?**  
Not by virtue of this local demo. Live endpoint authentication, telemetry quality, availability and failure behavior must be validated separately.

**Is Auctaryn production-certified?**  
No independent certification is claimed. The repository tracks open production gates in its risk register and release acceptance manifest.

**Can an approved decision execute?**  
Only through a configured trusted runtime adapter and supported execution route. Approval itself does not execute the action. Direct execution is disabled by default.

**What license applies?**  
The repository includes an Apache-2.0 `LICENSE` file. See the repository for the current source and terms.
