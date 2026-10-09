> **Historical planning document — not current implementation status.** This file preserves the original TwinGuard MVP proposal. Its proposed modules, deployment claims, false-positive targets, pricing, and statements such as “intercepts every tool call” are not evidence of current capability. The canonical project is **Auctaryn**; use [the current implementation roadmap](docs/IMPLEMENTATION_ROADMAP.md), [security risk register](docs/SECURITY_RISK_REGISTER.md), and [production release acceptance](docs/PRODUCTION_RELEASE_ACCEPTANCE.md) for verified status and open gates.

---

# TwinGuard MVP — Implementation Plan

**Version:** 1.0  
**Date:** April 19, 2026  
**Author:** Claude (Anthropic) + Chinaemerem Nkwachukwu (Tinlance Limited)  
**Status:** APPROVED

---

## 1. Executive Summary

TwinGuard is an AI agent containment and security platform built on NVIDIA's NemoClaw/OpenShell runtime. It adds defense-in-depth modules that prevent autonomous AI agents from going rogue — addressing real-world failures like the Summer Yue/OpenClaw email deletion incident (Feb 23, 2026) and SandboxEscapeBench findings (~49-50% escape rates for frontier models).

The MVP targets 4 priority modules, leverages ThreatFade v0.2.0-beta as a network threat oracle, and ships within 8 weeks on a budget under $60.

---

## 2. Approved Decisions

| Decision | Choice |
|----------|--------|
| VPS | Contabo — 4 vCPU / 8GB RAM / 200GB SSD (~$7-12/mo) |
| Domain | twinguard.ai (Namecheap, ~$25-30/yr) |
| GUI Framework | React (aligns with GiftMode/Next.js experience) |
| AI API (MVP) | Claude API (already owned) |
| AI API (Phase 2) | Grok API as second Parliament member |
| ThreatFade Integration | v0.2.0-beta — JSON severity + confidence scoring ready |
| Timeline | 8 weeks |
| Total Cash Cost | ~$50-60 to start |
| Entity | Tinlance Limited (RC: 7962164) |

---

## 3. MVP Scope — 4 Priority Modules

### Module 1: Context Integrity Guardian

**Why first:** Directly solves the Summer Yue problem. Best demo story for investors. OpenShell does not currently protect against context compaction failures.

**What it does:**

- Monitors the AI agent's context window for instruction loss during compaction
- Maintains a cryptographic hash of critical instructions (system prompts, safety rules, user-defined policies)
- Before any compaction event, validates that protected instructions survive intact
- If instructions are lost or altered, blocks the agent and alerts the operator
- Logs every compaction event with before/after integrity scores

**Technical approach:**

- Python service running alongside the OpenShell sandbox
- SHA-256 hashing of protected instruction blocks
- Hook into OpenShell's policy engine via YAML policy extensions
- FastAPI endpoint exposing integrity status to the dashboard
- SQLite for compaction event logging (lightweight, no external DB needed for MVP)

**Key files:**

```
twinguard/
├── modules/
│   └── context_integrity/
│       ├── __init__.py
│       ├── guardian.py          # Core logic — hash, compare, block
│       ├── compaction_hook.py   # Intercepts compaction events
│       ├── policy.yaml          # OpenShell policy extension
│       └── tests/
│           ├── test_guardian.py
│           └── test_compaction.py
```

**Estimated effort:** 25-35 hours

---

### Module 2: Execution Gateway with Destructive Action Veto

**Why second:** Visible, tangible safety layer. The thing that actually stops an agent from bulk-deleting emails, dropping databases, or executing unauthorized API calls.

**What it does:**

- Intercepts every tool call the agent makes before execution
- Classifies actions by risk level: safe / moderate / destructive / critical
- Safe actions pass through automatically
- Moderate actions get logged with full context
- Destructive actions (bulk delete, file system writes, API calls to external services) require explicit operator approval or automatic veto
- Critical actions (privilege escalation, config changes, network exfiltration) are always blocked
- Maintains an allowlist/blocklist of tool patterns configurable via YAML

**Technical approach:**

- Sits as a middleware layer between the OpenShell sandbox and external tools
- Pattern matching on tool call signatures (regex + semantic classification via Claude API)
- Action queue with approval/deny workflow exposed via WebSocket to the React dashboard
- Configurable risk thresholds per deployment context (e.g., fintech = stricter than dev)

**Key files:**

```
twinguard/
├── modules/
│   └── execution_gateway/
│       ├── __init__.py
│       ├── gateway.py           # Core interception + classification
│       ├── risk_classifier.py   # Action risk scoring
│       ├── veto_engine.py       # Approval/deny logic
│       ├── action_patterns.yaml # Allowlist/blocklist config
│       └── tests/
│           ├── test_gateway.py
│           ├── test_classifier.py
│           └── test_veto.py
```

**Estimated effort:** 30-40 hours

---

### Module 3: ThreatFade Oracle Integration

**Why third:** Leverages your existing validated work. Adds network-level threat intelligence to TwinGuard's decision engine. Differentiator — no other agent containment platform has a built-in network threat oracle.

**What ThreatFade already provides (v0.2.0-beta):**

- Direct PCAP ingestion
- Confidence scoring (critical / high / medium / low / info)
- 0% false positive baseline
- 22 unit tests passing
- JSON + PNG export
- SIEM export (JSON, Splunk HEC, CEF, CSV)
- MITRE TTP mapping (T1027, T1071.001, T1095)
- Validated: Merlin QUIC C2 (z-score 14.76), Cobalt Strike (7.01), IcedID (3.89)
- Detection weights: drop=0.50, entropy=0.30, zscore=0.20

**What we build:**

- A thin FastAPI wrapper around ThreatFade's `core/fade_engine.py`
- REST endpoints: `POST /analyze` (PCAP upload), `GET /status`, `GET /results/{id}`
- WebSocket endpoint for real-time streaming results to the dashboard
- Integration adapter that feeds ThreatFade severity scores into the Parliament Ensemble voting system (Phase 2 module, but the adapter interface ships now)
- Docker container packaging ThreatFade as a standalone microservice

**Key files:**

```
twinguard/
├── modules/
│   └── threatfade_oracle/
│       ├── __init__.py
│       ├── api_wrapper.py       # FastAPI wrapper around fade_engine
│       ├── parliament_adapter.py # Feeds scores to Parliament (interface only for MVP)
│       ├── Dockerfile           # Containerized ThreatFade service
│       ├── docker-compose.yml   # Orchestration with main TwinGuard
│       └── tests/
│           ├── test_api.py
│           └── test_adapter.py
```

**Estimated effort:** 20-25 hours (ThreatFade is already built; this is wrapping + connecting)

---

### Module 4: React Dashboard (Basic GUI)

**Why fourth:** Investors and CISOs need to see something. A CLI-only tool doesn't win funding. The dashboard makes TwinGuard real.

**What it shows:**

- **Context Integrity Panel** — real-time status of protected instructions, hash comparison history, compaction event log with timestamps
- **Execution Gateway Panel** — live action queue, approve/deny buttons for pending destructive actions, action history with risk classifications
- **ThreatFade Panel** — network threat severity scores, confidence levels, MITRE TTP mapping display, mini-timeline visualization
- **System Health** — OpenShell sandbox status, module health indicators, alert feed

**Technical approach:**

- React 19 with Tailwind CSS (dark-first theme, security product aesthetic)
- Vite as build tool
- WebSocket connections to each module's real-time endpoints
- Recharts for data visualization (already available in artifact environment, familiar library)
- Mobile-responsive (secondary priority, desktop-first for CISO demos)

**Key files:**

```
twinguard/
├── dashboard/
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   ├── src/
│   │   ├── App.jsx
│   │   ├── index.css
│   │   ├── components/
│   │   │   ├── ContextIntegrityPanel.jsx
│   │   │   ├── ExecutionGatewayPanel.jsx
│   │   │   ├── ThreatFadePanel.jsx
│   │   │   ├── SystemHealth.jsx
│   │   │   ├── ActionApproval.jsx
│   │   │   └── AlertFeed.jsx
│   │   ├── hooks/
│   │   │   ├── useWebSocket.js
│   │   │   └── useModuleStatus.js
│   │   └── utils/
│   │       ├── api.js
│   │       └── constants.js
│   └── public/
│       └── favicon.ico
```

**Estimated effort:** 40-50 hours

---

## 4. Full Project Architecture

```
twinguard/
├── README.md
├── LICENSE                      # Apache 2.0 open-core
├── docker-compose.yml           # Full stack orchestration
├── .env.example
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI/CD
│
├── core/
│   ├── __init__.py
│   ├── config.py                # Central config loader (YAML)
│   ├── logging.py               # Structured logging (JSON format)
│   ├── exceptions.py            # Custom exception hierarchy
│   └── models.py                # Shared data models (Pydantic)
│
├── api/
│   ├── __init__.py
│   ├── main.py                  # FastAPI app entry point
│   ├── routes/
│   │   ├── context.py           # Context Integrity endpoints
│   │   ├── gateway.py           # Execution Gateway endpoints
│   │   ├── threatfade.py        # ThreatFade Oracle endpoints
│   │   └── health.py            # System health endpoints
│   └── websockets/
│       ├── actions.py           # Real-time action stream
│       └── alerts.py            # Real-time alert stream
│
├── modules/
│   ├── context_integrity/       # Module 1
│   ├── execution_gateway/       # Module 2
│   └── threatfade_oracle/       # Module 3
│
├── dashboard/                   # Module 4 — React app
│
├── policies/
│   ├── default.yaml             # Base security policy
│   ├── fintech.yaml             # Industry seed — financial
│   ├── health.yaml              # Industry seed — healthcare
│   └── strict.yaml              # Maximum restriction policy
│
├── tests/
│   ├── conftest.py              # Shared fixtures
│   ├── integration/
│   │   ├── test_full_pipeline.py
│   │   └── test_yue_scenario.py # Summer Yue recreation test
│   └── e2e/
│       └── test_demo_flow.py    # Full demo scenario
│
├── scripts/
│   ├── setup.sh                 # One-command setup
│   ├── demo.sh                  # Run demo scenario
│   └── deploy.sh                # Production deployment
│
├── config/
│   ├── twinguard.yaml           # Main config
│   └── openshell_policy.yaml    # OpenShell integration policy
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── API.md
│   ├── DEPLOYMENT.md
│   └── DEMO_SCRIPT.md           # Investor demo walkthrough
│
└── Dockerfile
```

---

## 5. Tech Stack

| Layer | Technology | Reason |
|-------|-----------|--------|
| Runtime Base | NVIDIA OpenShell v0.1.0 | Kernel-level sandbox (Landlock, seccomp, namespaces). Apache 2.0. Rust binary, Linux kernel >= 5.13 |
| Backend | Python 3.11+ / FastAPI | ThreatFade is Python. FastAPI for async + WebSockets |
| Frontend | React 19 / Vite / Tailwind | Matches your GiftMode stack. Fast, modern, dark-theme ready |
| Database | SQLite (MVP) | Zero config, embedded, sufficient for single-node MVP |
| AI API | Claude API (Haiku for speed) | Action classification in Execution Gateway |
| Containerization | Docker + Docker Compose | OpenShell requires Docker. Compose orchestrates all services |
| CI/CD | GitHub Actions | Free for public repos. Runs tests on every push |
| Monitoring | Structured JSON logs | Simple, parseable, SIEM-compatible |

---

## 6. OpenShell Integration Details

Based on research of NVIDIA/OpenShell (4.3k stars, Apache 2.0, Rust-based):

**OpenShell provides:**

- Gateway (control plane) + Sandbox (data plane) architecture
- Declarative YAML policies for filesystem, network, process, and inference
- Landlock filesystem restrictions (kernel >= 5.13)
- seccomp syscall filtering
- Network namespace isolation
- Privacy-enforcing HTTP CONNECT proxy
- Hot-reloadable network and inference policies
- K3s Kubernetes cluster inside a single Docker container
- Python SDK (`pip install openshell`)

**TwinGuard extends OpenShell by:**

- Adding context integrity monitoring (OpenShell doesn't track context compaction)
- Adding action-level gating (OpenShell operates at syscall/network level, not semantic action level)
- Adding network threat intelligence (ThreatFade oracle feeding into policy decisions)
- Adding a human-readable dashboard (OpenShell is CLI-only)

**Contabo VPS requirements for OpenShell:**

- Linux kernel >= 5.13 (Ubuntu 22.04+ satisfies this)
- Docker Desktop or Docker daemon
- 4 vCPU / 8GB RAM is sufficient for single-gateway, single-sandbox MVP

---

## 7. Build Phases (8 Weeks)

### Phase 1: Foundation (Weeks 1-2)

**Goal:** Project scaffold, OpenShell running on Contabo, basic API skeleton

- Set up Contabo VPS (Ubuntu 22.04 LTS, Docker installed)
- Install OpenShell (`curl -LO` from NVIDIA releases)
- Configure base OpenShell policy (default.yaml)
- Create project repository structure
- Set up FastAPI skeleton with health endpoints
- Set up React dashboard skeleton with Vite + Tailwind
- Configure GitHub Actions CI pipeline
- Write shared data models (Pydantic schemas for actions, alerts, integrity reports)
- Domain setup (twinguard.ai → Contabo VPS)

**Deliverable:** Running OpenShell sandbox + API skeleton + empty dashboard shell

**Tests:** Health endpoint tests, OpenShell connectivity test

---

### Phase 2: Context Integrity Guardian (Weeks 3-4)

**Goal:** Working context monitoring with hash verification and compaction detection

- Implement SHA-256 instruction hashing in guardian.py
- Build compaction hook that intercepts context window changes
- Implement before/after integrity comparison logic
- Build alert system for integrity violations
- Create OpenShell policy extension for context protection
- Build Context Integrity Panel in React dashboard
- Connect via WebSocket for real-time integrity status
- Write Summer Yue recreation test (simulates the email deletion scenario)

**Deliverable:** Context Integrity Guardian detecting and blocking instruction loss

**Tests:** Unit tests for hashing, compaction detection, alert triggering. Integration test recreating the Yue scenario.

---

### Phase 3: Execution Gateway + ThreatFade Oracle (Weeks 5-6)

**Goal:** Action interception working, ThreatFade feeding severity scores

- Implement action interception middleware (gateway.py)
- Build risk classifier with pattern matching + Claude API semantic classification
- Implement veto engine with approve/deny workflow
- Build action approval WebSocket stream
- Create action_patterns.yaml with default risk classifications
- Build FastAPI wrapper around ThreatFade's fade_engine.py
- Containerize ThreatFade as Docker service
- Build Parliament adapter interface (for Phase 2 Grok integration)
- Build Execution Gateway Panel + ThreatFade Panel in React dashboard
- Connect approve/deny buttons to gateway WebSocket

**Deliverable:** Working action gating + ThreatFade threat scoring displayed on dashboard

**Tests:** Action classification tests, veto logic tests, ThreatFade API wrapper tests, integration tests for full action pipeline.

---

### Phase 4: Integration, Polish, Demo (Weeks 7-8)

**Goal:** Everything connected, demo-ready, deployment scripts working

- End-to-end integration testing (all 4 modules working together)
- Build demo script that walks through a realistic attack scenario
- Polish React dashboard (animations, error states, loading states)
- Write deployment scripts (setup.sh, demo.sh, deploy.sh)
- SSL/TLS setup (Let's Encrypt via Certbot)
- Write documentation (ARCHITECTURE.md, API.md, DEMO_SCRIPT.md)
- Create investor demo walkthrough document
- Performance testing under load
- Security review of TwinGuard itself (eating our own dog food)
- Create industry policy seeds (fintech.yaml, health.yaml)
- Final cleanup, README, and public repo preparation

**Deliverable:** Demo-ready TwinGuard MVP with documentation and deployment scripts

**Tests:** Full E2E test suite, demo flow test, load test.

---

## 8. Testing Strategy

**Approach:** Tests first for every module (TDD). No code merges without passing tests.

| Level | Tool | Coverage Target |
|-------|------|----------------|
| Unit | pytest | Core logic: hashing, classification, scoring |
| Integration | pytest + Docker | Module-to-module communication |
| E2E | pytest + Selenium (dashboard) | Full demo scenario |
| Security | Manual + automated | Self-audit against OWASP Top 10:2025 |
| Performance | locust | API response times under load |

**Critical test scenarios:**

1. **Summer Yue Recreation** — Simulate context compaction that strips safety instructions → verify TwinGuard blocks the agent before destructive action
2. **Bulk Delete Veto** — Agent attempts to delete 500+ emails → verify Execution Gateway vetoes and alerts operator
3. **C2 Detection** — Feed Merlin QUIC PCAP → verify ThreatFade Oracle returns critical severity → verify dashboard displays alert
4. **Policy Bypass Attempt** — Agent attempts to modify its own policy YAML → verify system blocks and logs

---

## 9. Security Considerations

TwinGuard is a security product. It must be secure itself.

- All API endpoints require authentication (API key in MVP, OAuth2 in production)
- WebSocket connections authenticated on handshake
- YAML policy files are read-only at runtime (Landlock enforced)
- ThreatFade Oracle runs in isolated Docker container
- No secrets in code — all via environment variables
- Dashboard served over HTTPS only
- Action approval tokens are single-use and time-limited
- Structured logging with no sensitive data exposure
- CORS restricted to dashboard origin only

---

## 10. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| OpenShell is alpha-quality, APIs may change | High | Medium | Pin to specific release. Abstract behind our own interfaces |
| Contabo VPS kernel < 5.13 | Low | High | Verify kernel version before purchase. Ubuntu 22.04 ships 5.15+ |
| Claude API costs exceed budget | Low | Low | Use Haiku model for classification. Cache repeat patterns |
| ThreatFade integration complexity | Low | Medium | ThreatFade already outputs structured JSON. Wrapper is thin |
| 8-week timeline slips | Medium | Medium | Phases are independent. Can ship 3 modules and add 4th later |
| OpenShell doesn't support our hooks | Medium | High | Build hooks as external watchers, not internal patches |

---

## 11. Post-MVP Roadmap (Phase 2+)

After MVP ships, the remaining 18 modules from the full TwinGuard architecture get built in priority order:

1. **Parliament Ensemble** — Add Grok API as second voter. Multi-model consensus.
2. **Dynamic Self-Hardening Loop** — Offline distillation from synthetic near-miss data.
3. **Memory Poisoning Defender** — Detect and clean adversarial memory entries.
4. **Verifiable Proofs Layer** — Signed immutable logs, zk-SNARK stubs.
5. **Built-in Red-Teaming Simulator** — Automated SandboxEscapeBench testing.
6. **Industry Policy Seed Manager** — Hot-reloadable YAML seeds for regulated industries.
7. **Remaining 12 advanced protection modules** — Config integrity, WebSocket defender, tool stream injection, etc.

**Revenue model:** Usage-based SaaS. Per-agent, per-month pricing. Free tier for open-source/research.

**Target accelerators:** CyRise, Cicada, 8200 EISP.

---

## 12. Estimated Hours Summary

| Phase | Module | Hours |
|-------|--------|-------|
| Phase 1 | Foundation + Setup | 20-25 |
| Phase 2 | Context Integrity Guardian | 25-35 |
| Phase 3a | Execution Gateway | 30-40 |
| Phase 3b | ThreatFade Oracle Integration | 20-25 |
| Phase 4a | React Dashboard | 40-50 |
| Phase 4b | Integration + Polish + Docs | 20-30 |
| **Total** | | **155-205 hours** |

At ~25 hours/week focused work = **6-8 weeks**.

---

## 13. First Implementation Step

When you're ready to start building, we begin with **Phase 1, Day 1:**

1. Set up Contabo VPS (Ubuntu 22.04)
2. Install Docker + OpenShell
3. Create the `twinguard/` repository with the full folder structure
4. Initialize FastAPI with a `/health` endpoint
5. Initialize React dashboard with Vite + Tailwind
6. Push to GitHub
7. Configure GitHub Actions CI

Say **"START BUILDING"** and we write the first code.

---

*Plan prepared by Claude (Anthropic) for Tinlance Limited.*  
*All technical decisions verified against NVIDIA OpenShell documentation and ThreatFade v0.2.0-beta source.*
