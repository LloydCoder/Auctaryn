# TwinGuard

**AI Agent Containment & Security Platform**

Built on [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) — defense-in-depth for autonomous AI agents.

TwinGuard prevents AI agents from going rogue by adding context integrity monitoring, execution gating, and network threat intelligence on top of OpenShell's kernel-level sandbox.

## Why TwinGuard?

On February 23, 2026, an OpenClaw agent deleted a user's entire email inbox after a context compaction event stripped its safety instructions. OpenShell provides kernel-level isolation — but it doesn't monitor what happens *inside* the agent's reasoning. TwinGuard fills that gap.

## MVP Modules

1. **Context Integrity Guardian** — Detects instruction loss during context compaction
2. **Execution Gateway** — Intercepts and classifies every tool call by risk level
3. **ThreatFade Oracle** — Network threat intelligence via [ThreatFade](https://github.com/LloydCoder/tinlance-threatfade)
4. **React Dashboard** — Real-time visibility into agent behavior

## Quick Start

```bash
# Clone
git clone https://github.com/Tinlance/twinguard.git
cd twinguard

# Setup
chmod +x scripts/setup.sh
./scripts/setup.sh

# Run
docker-compose up -d

# Dashboard (local dev)
open http://localhost:3000
```

## Production

Live at **twinguard.tinlance.com**:
- `/` — marketing site (`site/`)
- `/dashboard` — operational console (built React app)
- `/api/` — REST API
- `/ws/` — WebSocket live streams
- `/docs` — interactive Swagger API reference

Deploy with `./scripts/deploy.sh` (set `TWINGUARD_DOMAIN` to override the default domain).

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
