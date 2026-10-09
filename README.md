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
# Edit .env and replace AUCTARYN_API_KEY and AUCTARYN_ADMIN_API_KEY
# with independent, high-entropy secrets. Do not commit .env.
docker compose --env-file .env up -d --build

# Dashboard (local dev)
open http://localhost:3000
```

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
- WebSocket clients must send `{"type":"authenticate","token":"..."}` as their first frame. The dashboard prompts for the administrator key and keeps it in memory rather than local storage.
- The ThreatFade service is not published on the host by Compose. Use HTTPS for external ThreatFade endpoints; plain HTTP is accepted only for local/Docker service names unless the explicit insecure override is set for isolated testing.
- `/health` is a liveness endpoint, not evidence that OpenShell is connected or that all security controls are ready.
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
