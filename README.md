# Auctaryn

**Runtime authority and containment for autonomous AI agents**

Built on [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) — defense-in-depth for autonomous AI agents.

Auctaryn helps control autonomous agent actions from going rogue by adding context integrity monitoring, execution gating, and network threat intelligence on top of OpenShell's kernel-level sandbox.

## Why Auctaryn?

On February 23, 2026, an OpenClaw agent deleted a user's entire email inbox after a context compaction event stripped its safety instructions. OpenShell provides kernel-level isolation — but it doesn't monitor what happens *inside* the agent's reasoning. Auctaryn is designed to complement runtime isolation with context integrity, action policy, and threat intelligence.

## MVP Modules

1. **Context Integrity Guardian** — Checks registered instructions for integrity changes
2. **Execution Gateway** — Evaluates submitted tool calls and applies risk-based decisions; direct tool execution must still be connected to a trusted runtime adapter
3. **ThreatFade Oracle** — Network threat intelligence via [ThreatFade](https://github.com/LloydCoder/tinlance-threatfade)
4. **React Dashboard** — Real-time visibility into agent behavior

## Quick Start

```bash
# Clone
git clone https://github.com/LloydCoder/Auctaryn.git
cd Auctaryn

# Setup
chmod +x scripts/setup.sh
./scripts/setup.sh

# Run
cp .env.example .env
# Edit .env: set two independent high-entropy API keys and a reachable HTTPS
# THREATFADE_SERVICE_URL. Do not commit .env.
docker compose --env-file .env up -d --build api

# Dashboard (local dev; run in another terminal)
cd dashboard
npm install
npm run dev -- --host 0.0.0.0
# Open the Vite URL shown in the terminal (normally http://localhost:5173).
```

## Implementation roadmap

Auctaryn follows a serial 24-phase security and enterprise-readiness roadmap with explicit CI and forensic acceptance gates. See [docs/IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md) for phase status and known limitations. A green CI run is necessary but does not certify live runtime security or production readiness.

## Tinlance Agent Platform integration

Auctaryn exposes the versioned advisory risk contract `POST /api/v1/risk/assess` (`auctaryn-risk-assessment.v1`). It returns risk signals only; it does not grant permission, approve an action, or execute tools. Tinlance Agent Platform remains authoritative for identity, tenant binding, policy, approvals, governed execution, secrets, and audit. A live Platform-side adapter and conformance tests are still required before claiming production integration. See [the integration boundary](docs/integration/TINLANCE_AGENT_PLATFORM.md).

## Production

The deployment scripts and domain configuration may still reference legacy TwinGuard infrastructure. Verify DNS, TLS, runtime integration, and authentication before exposing a deployment.
- `/` — marketing site (`site/`)
- `/dashboard` — operational console (built React app)
- `/api/` — REST API
- `/ws/` — WebSocket live streams
- `/docs` — interactive Swagger API reference

The dashboard requires an administrator API key at sign-in. REST API clients use `Authorization: Bearer <key>`; general clients use `AUCTARYN_API_KEY`, while identity administration and approval operations require `AUCTARYN_ADMIN_API_KEY`.

## Security configuration

- Generate two different secrets, for example with `openssl rand -hex 32`, and set `AUCTARYN_API_KEY` and `AUCTARYN_ADMIN_API_KEY` in `.env`.
- All `/api/v1/*` HTTP endpoints require a Bearer credential. Identity management, approval, pending-decision, and decision-history endpoints require the administrator credential.
- Before intercepting actions, an administrator registers an agent, grants tool scopes, and issues a short-lived token via `POST /api/v1/identity/token`. Gateway interception requests must include both `agent_id` and `identity_token`. Tokens expire within one hour maximum. Any permission change increments the identity's permission version and invalidates existing issued capabilities; delegated capabilities also become invalid when the delegator's permission version changes. Reissue capabilities after any scope change.
- Agent registration is idempotent only for the same owner. Re-registering an existing `agent_id` under a different owner is rejected with a policy violation; resolve ownership conflicts through an explicit, audited administrative workflow rather than silently reassigning the identity.
- WebSocket clients must send `{"type":"authenticate","token":"..."}` as their first frame. The dashboard prompts for the administrator key and keeps it in memory rather than local storage.
- SensitiveDataGuard runs before classification, interception, Oracle-backed interception, advisory risk assessment, and execution. It blocks recognized raw-secret patterns and redacts values from error responses; it is defense in depth, not a guarantee of complete DLP coverage.
- When protected instructions are registered, the gateway requires a session ID and a session-bound context-integrity check. Missing, degraded, compromised, or quarantined sessions are denied by the supported gateway path. A compromised session remains quarantined until an administrator clears it and a fresh clean check is submitted. This does not prove that every external agent tool path is mediated.
- The ThreatFade service implementation is not bundled in this repository; Compose requires a reachable `THREATFADE_SERVICE_URL`. Use HTTPS for external ThreatFade endpoints; plain HTTP is accepted only for local/Docker service names unless the explicit insecure override is set for isolated testing. The dashboard is run with Vite in development and served as static assets by the deployment script; this repository does not define a dashboard Dockerfile.
- `/health` is a liveness endpoint, not evidence that OpenShell is connected or that all security controls are ready.
- `/health/ready` reports distinct API credentials, identity enforcement, trusted runtime adapter configuration, probe availability/result, and OpenShell connectivity separately. It remains false unless a configured adapter reports a successful live health probe and identifies itself as the OpenShell runtime.
- Pending approvals expire after 15 minutes by default, cannot be approved after expiry, and can be resolved only once. Decision identifiers use 128-bit UUIDs. Agent identities, scoped tokens, pending approvals, and execution deduplication are currently held in process memory. This is a single-process MVP limitation, not an enterprise multi-instance persistence design; do not rely on them across restarts or replicas.
- `POST /api/v1/gateway/execute` is the governed execution entry point. It fails with HTTP 503 before evaluating the action if no trusted runtime adapter is configured. With an adapter configured, only an `APPROVED` decision is forwarded to it; pending, denied, vetoed, or timed-out actions are never executed.
- Destructive actions remain pending until an administrator approves them with `POST /api/v1/gateway/approve`. Approval changes the decision state but does not execute the action; execution then uses `POST /api/v1/gateway/execute/approved/{decision_id}`. Runtime receipts expose output hashes rather than raw stdout/stderr.
- The restrictive OpenShell baseline is `deploy/openshell/auctaryn-policy.yaml`; it requires Landlock `hard_requirement` and denies network egress until explicit rules are added. See `docs/OPEN_SHELL_RUNTIME.md` for setup and production acceptance.
- The OpenShell adapter is opt-in through `AUCTARYN_RUNTIME_ADAPTER=openshell` and a configured sandbox/workspace. Production requires service-to-service OIDC credentials and the active OpenShell CLI gateway/TLS context; user credentials are allowed only through an explicit local-development override. Execution timeout is bounded to 1–3600 seconds. Only bounded argv arrays are accepted; shell command strings and caller-selected sandbox names are rejected. OpenShell sandbox policy remains mandatory and must be independently configured and verified.
- This release does not yet prove that every external agent tool execution is forcibly mediated by Auctaryn. Do not treat an API decision alone as an execution sandbox.

## Requirements

- Linux (kernel >= 5.13 for Landlock)
- Docker + Docker Compose
- Python 3.11+
- Node.js 18+
- NVIDIA OpenShell v0.1.0+

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Runtime | NVIDIA OpenShell (Landlock, seccomp, namespaces) |
| Backend | Python / FastAPI |
| Frontend | React 19 / Vite / Tailwind CSS |
| AI | Claude API (Anthropic) |
| Threat Intel | ThreatFade v0.2.0-beta |
| Database | SQLite (MVP) |

## Architecture

```
┌─────────────────────────────────────────────┐
│              React Dashboard                │
│  (Context | Gateway | ThreatFade | Health)  │
└──────────────────┬──────────────────────────┘
                   │ WebSocket + REST
┌──────────────────┴──────────────────────────┐
│              FastAPI Backend                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐│
│  │ Context  │ │Execution │ │  ThreatFade  ││
│  │Integrity │ │ Gateway  │ │   Oracle     ││
│  │ Guardian │ │  + Veto  │ │  (Docker)    ││
│  └──────────┘ └──────────┘ └──────────────┘│
└──────────────────┬──────────────────────────┘
                   │ Policy Engine
┌──────────────────┴──────────────────────────┐
│         NVIDIA OpenShell Runtime            │
│  (Landlock | seccomp | namespaces | proxy)  │
└─────────────────────────────────────────────┘
```

## License

Apache 2.0 — open-core base.

## Author

**Tinlance Limited** (RC: 7962164)
Built by [Chinaemerem Nkwachukwu](https://github.com/LloydCoder)

---

*Securing AI agents. Nigeria-1. World-0.* 💚
