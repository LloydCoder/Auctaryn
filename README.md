# Auctaryn

**Supported-path governance and runtime integration for autonomous AI agents**

Designed to integrate with [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) as a defense-in-depth runtime boundary.

Auctaryn adds heuristic context checks and risk-based decisions to supported agent paths, with optional ThreatFade advisory signals and a configured OpenShell runtime adapter. Tinlance Agent Platform remains authoritative for identity, tenant binding, policy, approvals and governed execution.

## Why Auctaryn?

On February 23, 2026, Summer Yue publicly reported that OpenClaw began deleting email after a large-inbox workflow and context compaction. TechCrunch reported the account but noted it could not independently verify the event. Auctaryn explores defense-in-depth controls that complement runtime isolation; submitted-context checks do not prove what an external agent consumed.

## MVP Modules

1. **Context Integrity Guardian** — Checks registered instructions for integrity changes
2. **Execution Gateway** — Evaluates submitted tool calls and applies risk-based decisions; direct tool execution must still be connected to a trusted runtime adapter
3. **ThreatFade Oracle** — Advisory network threat intelligence via [ThreatFade](https://github.com/LloydCoder/tinlance-threatfade); see the [Oracle security contract](docs/THREATFADE_ORACLE.md)
4. **React Dashboard** — Real-time visibility into agent behavior
5. **Skill Supply-Chain Vetting** — Ed25519 publisher verification, artifact digest validation, exact version pins, and tool-change detection

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
# Local evaluation only: no trusted runtime adapter is configured by default.
# /health/ready remains false until OpenShell and all required runtime settings are verified.

# Dashboard (local dev; run in another terminal)
cd dashboard
npm ci
npm run dev -- --host 0.0.0.0
# Open the Vite URL shown in the terminal (normally http://localhost:5173).
```

## Implementation roadmap

Auctaryn follows a serial 24-phase security and enterprise-readiness roadmap with explicit CI and forensic acceptance gates. See [docs/IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md) for phase status and known limitations. A green CI run is necessary but does not certify live runtime security or production readiness.

## Tinlance Agent Platform integration

Auctaryn exposes the versioned advisory risk contract `POST /api/v1/risk/assess` (`auctaryn-risk-assessment.v1`). It returns risk signals and additive structured findings with confidence, bounded rationale, control references and provenance (`runtime_observed: false` for the current caller-metadata classifier); it does not grant permission, approve an action, or execute tools. The SHA-256 request fingerprint is correlation metadata, not a signature or confidentiality control. Tinlance Agent Platform remains authoritative for identity, tenant binding, policy, approvals, governed execution, secrets, and audit. A live Platform-side adapter and conformance tests are still required before claiming production integration. See [the integration boundary](docs/integration/TINLANCE_AGENT_PLATFORM.md) and [Phase 15 forensic audit](audits/PHASE-15-FORENSIC-AUDIT.md).

## Evidence and forensic audit

Gateway assessments, decisions, approvals, execution requests and safe receipt hashes are recorded in a local SQLite hash chain. Administrator-only inspection endpoints are `GET /api/v1/evidence/records` and `GET /api/v1/evidence/verify`. Set `AUCTARYN_EVIDENCE_DB` for the database path and configure a separately managed value of at least 32 bytes for keyed record authentication using `AUCTARYN_EVIDENCE_HMAC_KEY` or, preferably, a mounted secret file via `AUCTARYN_EVIDENCE_HMAC_KEY_FILE`. Without the key, the service reports hash-chain-only mode. This local store is not the Platform audit of record; production requires external key management, immutable export, retention and restore validation. See [Phase 16 forensic audit](audits/PHASE-16-FORENSIC-AUDIT.md).

## Local database recovery

Auctaryn includes a verified single-host SQLite backup and restore utility for its local evidence and incident-control database. Use `python scripts/database_recovery.py backup SOURCE DESTINATION` to create a consistent snapshot and verify SQLite integrity plus the evidence hash chain; use `verify DATABASE` before a restore. If evidence records are HMAC-signed, configure the same separately managed verification key. See the [database recovery runbook](docs/DATABASE_RECOVERY.md) and [Phase 20 forensic audit](audits/PHASE-20-FORENSIC-AUDIT.md).

This is not a complete enterprise DR service: off-host/immutable backup retention, backup monitoring, approved RPO/RTO, scheduled restore drills, multi-replica coordination and durable identity/approval state remain production gates.

## Operator dashboard and rollback

The administrator dashboard includes an **Incidents & Evidence** view for server-authorized emergency-stop status, incident alerts, bounded evidence metadata and evidence-chain verification. The backend remains the authorization boundary; hiding a dashboard tab is not access control. See the [operator dashboard and deployment rollback runbook](docs/DEPLOYMENT_ROLLBACK.md).

Production deployment is separate from local Compose. `scripts/deploy.sh` requires a version tag and exact GHCR image digest from the attested release manifest, verifies the manifest and image/SBOM attestations, mounts OpenShell gateway metadata and the evidence HMAC key, and refuses to expose the service until liveness/readiness pass. It records the previous digest/tag for verified rollback through `scripts/rollback.sh`. CI tests do not replace a production-host rollback drill.

## Enterprise authorization boundary

See [`docs/API_AUTHORIZATION_MATRIX.md`](docs/API_AUTHORIZATION_MATRIX.md) for service/admin route permissions. Direct execution is disabled by default; controlled local execution requires `AUCTARYN_ALLOW_DIRECT_EXECUTION=true` plus the distinct administrator credential. In the Platform-integrated production profile, keep it disabled.

## Incident response and containment

Administrators can inspect `GET /api/v1/incident/status`, list alerts with `GET /api/v1/incident/alerts`, activate the persistent global stop with `POST /api/v1/incident/emergency-stop`, quarantine/release an agent with `POST /api/v1/incident/agents/{agent_id}/quarantine`, and acknowledge/resolve alerts through the incident API. Critical-risk and veto decisions create durable alerts; the execution service checks stop/quarantine state before runtime invocation. Agent-wide capability revocation is available at `POST /api/v1/identity/{agent_id}/revoke-all-tokens`. These local controls do not replace Platform-side revocation or multi-replica coordination. Follow the [incident response runbook](docs/INCIDENT_RESPONSE.md) and [Phase 17 forensic audit](audits/PHASE-17-FORENSIC-AUDIT.md).

## Skill supply-chain security

Skill vetting requires a trusted publisher's Ed25519 signature and the actual artifact bytes matching the signed SHA-256 digest. Publisher trust mutation requires the administrator credential. Version and manifest pins currently remain process-local; see [the supply-chain security contract](docs/SKILL_SUPPLY_CHAIN.md) before deployment.

## Context-session enforcement

When protected instructions are configured, gateway actions require a current session-bound context check; the check ID is bound into action intent and revalidated immediately before runtime execution. Compromised sessions remain quarantined until an administrator clears them and a fresh clean check is supplied. Session state is bounded and fail-closed. This local binding is not a cryptographic attestation of the context consumed by an external agent. See the [Phase 8 enforcement audit](audits/PHASE-08-SESSION-BOUND-ENFORCEMENT.md).

## Context-integrity trust boundary

Auctaryn bounds protected-instruction inputs, verifies stored baseline hashes, and detects selected context/goal-hijack patterns. These checks are heuristic. Context submitted by an API caller is not proof of the exact context consumed by an external agent; do not treat a context finding as an execution guarantee until a trusted runtime/harness adapter binds authenticated context provenance to immutable execution intent. See [Context Integrity](docs/CONTEXT_INTEGRITY.md).

## Production

No production domain is preconfigured. Production uses the `docker-compose.production.yml` override and only a digest-pinned versioned release; `scripts/deploy.sh` validates the DNS hostname, GitHub release attestations, service/admin secrets, OpenShell OIDC credentials and mounted gateway metadata before exposing Nginx/TLS.
- `/` — marketing site (`site/`)
- `/dashboard` — operational console (built React app)
- `/api/` — REST API
- `/ws/` — WebSocket live streams
- `/docs` — interactive Swagger API reference

The dashboard requires an administrator API key at sign-in. REST API clients use `Authorization: Bearer <key>`; general clients use `AUCTARYN_API_KEY`, while identity administration and approval operations require `AUCTARYN_ADMIN_API_KEY`.

## Security configuration

- Generate two different secrets, for example with `openssl rand -hex 32`, and set `AUCTARYN_API_KEY` and `AUCTARYN_ADMIN_API_KEY` in `.env`.
- All `/api/v1/*` HTTP endpoints require a Bearer credential. Strong-key mode is enabled by default and rejects distinct service/admin keys shorter than 32 characters, low-diversity values and obvious placeholders; production Compose forces it on. Ordinary API request bodies are capped at 2 MiB before parsing; PCAP ingress has a separate bounded allowance. Identity management, approval, pending-decision, and decision-history endpoints require the administrator credential.
- Before intercepting actions, an administrator registers an agent, grants tool scopes, and issues a short-lived token via `POST /api/v1/identity/token`. Gateway interception requests must include both `agent_id` and `identity_token`. Tokens expire within one hour maximum. Any permission change increments the identity's permission version and invalidates existing issued capabilities; delegated capabilities also become invalid when the delegator's permission version changes. Reissue capabilities after any scope change.
- Gateway decisions carry an internal canonical fingerprint of the action intent (tool, action, parameters, target, agent and session). A pending action is denied if its intent changes before approval, and execution rechecks the fingerprint immediately before calling the trusted runtime adapter. The fingerprint is excluded from public serialization; it is mutation detection, not a signature or durable audit guarantee. Approval and execution-deduplication state remain in process memory. See [Approval Lifecycle](docs/APPROVAL_LIFECYCLE.md).
- Agent registration is idempotent only for the same owner. Re-registering an existing `agent_id` under a different owner is rejected with a policy violation; resolve ownership conflicts through an explicit, audited administrative workflow rather than silently reassigning the identity.
- WebSocket clients must send `{"type":"authenticate","token":"..."}` as their first frame. The dashboard prompts for the administrator key and keeps it in memory rather than local storage.
- SensitiveDataGuard runs before classification, interception, Oracle-backed interception, advisory risk assessment, and execution. It blocks recognized raw-secret patterns and redacts values from error responses; it is defense in depth, not a guarantee of complete DLP coverage.
- Memory Defender requires a scoped agent token and a server-issued, agent-and-token-bound memory session that expires within one hour. Public API submissions are always treated as untrusted and quarantined; agents cannot read quarantined content, while operators have an authenticated inspection queue. Integrity hashes bind content and provenance metadata, with rollback to a trusted in-process snapshot on tampering. Storage is bounded but still process-local and not durable/multi-replica safe. See [Memory Defender](docs/MEMORY_DEFENDER.md).
- The ThreatFade service implementation is not bundled in this repository; Compose requires a reachable `THREATFADE_SERVICE_URL`. Use HTTPS for external ThreatFade endpoints; plain HTTP is accepted only for local/Docker service names unless the explicit insecure override is set for isolated testing. The dashboard is run with Vite in development and served as static assets by the deployment script; this repository does not define a dashboard Dockerfile.
- Synthetic ThreatFade signals are disabled by default because action-derived synthetic values are not observed network telemetry. `AUCTARYN_THREATFADE_ALLOW_SYNTHETIC_SIGNAL=true` is demo/test-only. External HTTPS endpoints require `THREATFADE_SERVICE_TOKEN`, and the upstream must validate it. Local Docker/loopback services may run without it for development. PCAP requests are capped at ingress, files are limited to 10 MiB and checked for PCAP/PCAPNG magic headers; malformed or invalid upstream analysis is treated as unavailable and cannot grant approval. See [ThreatFade integration security contract](docs/THREATFADE_INTEGRATION.md).
- `/health` is a liveness endpoint, not evidence that OpenShell is connected or that all security controls are ready.
- `/health/ready` reports distinct API credentials, identity enforcement, trusted runtime adapter configuration, probe availability/result, and OpenShell connectivity separately. It remains false unless a configured adapter reports a successful live health probe and identifies itself as the OpenShell runtime.
- Pending approvals expire after 15 minutes by default, cannot be approved after expiry, and can be resolved only once. Decision identifiers use 128-bit UUIDs. Agent identities, scoped tokens, pending approvals, context sessions, and execution deduplication are held in bounded process memory. Capacity exhaustion fails closed, but this is still a single-process limitation, not an enterprise multi-instance persistence design; do not rely on this state across restarts or replicas.
- `POST /api/v1/gateway/execute` is the governed execution entry point. It fails with HTTP 503 before evaluating the action if no trusted runtime adapter is configured. With an adapter configured, only an `APPROVED` decision is forwarded to it; pending, denied, vetoed, or timed-out actions are never executed.
- Destructive actions remain pending until an administrator approves them with `POST /api/v1/gateway/approve`. Approval changes the decision state but does not execute the action; execution then uses `POST /api/v1/gateway/execute/approved/{decision_id}`. Runtime receipts expose output hashes rather than raw stdout/stderr.
- The restrictive OpenShell baseline is `deploy/openshell/auctaryn-policy.yaml`; it requires Landlock `hard_requirement` and denies network egress until explicit rules are added. See `docs/OPEN_SHELL_RUNTIME.md` for setup and production acceptance.
- The OpenShell adapter is opt-in through `AUCTARYN_RUNTIME_ADAPTER=openshell` and a configured sandbox/workspace. Production requires service-to-service OIDC credentials and read-only active-gateway metadata mounted at `/etc/openshell`; user credentials are prohibited in the production deployment script. Execution timeout is bounded to 1–3600 seconds. Only bounded argv arrays are accepted; shell command strings and caller-selected sandbox names are rejected. OpenShell sandbox policy remains mandatory and must be independently configured and verified.
- This release does not yet prove that every external agent tool execution is forcibly mediated by Auctaryn. Do not treat an API decision alone as an execution sandbox.

## Adversarial security benchmark

Run `python -m pytest tests/redteam -v` for the repeatable OWASP ASI01–ASI10 red-team regression suite. Scenario coverage is documented in [`docs/RED_TEAM_BENCHMARK.md`](docs/RED_TEAM_BENCHMARK.md); a passing suite is not certification and does not prove live Platform/IdP or runtime integration.

## Requirements

- Linux (kernel >= 5.13 for Landlock)
- Docker + Docker Compose
- Python 3.11+
- Node.js 22+ (dashboard dependency-lock generation and CI)
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


## Secure software supply chain

Auctaryn's supply-chain gates run through [CodeQL](.github/workflows/codeql.yml) and [the supply-chain workflow](.github/workflows/supply-chain.yml). Python direct dependencies are declared in `requirements.txt` and hash-locked in `requirements.lock`; dashboard dependencies are committed in `dashboard/package-lock.json`. CI installs the npm graph with `npm ci`, audits dependencies, scans secrets and the built container, generates SPDX SBOMs, and attests tested artifacts on pushes to `main`. See [the supply-chain policy](docs/SUPPLY_CHAIN.md), [Phase 22 forensic audit](audits/PHASE-22-FORENSIC-AUDIT.md) and [production release acceptance](docs/PRODUCTION_RELEASE_ACCEPTANCE.md) for exact-head evidence, scope, exception handling and fail-closed release gates.
