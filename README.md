# Auctaryn

**Auctaryn adds context-integrity checks and advisory risk assessments to supported autonomous-agent paths, while leaving identity, policy, approvals, and governed execution authoritative in Tinlance Agent Platform.**

[![CI](https://github.com/LloydCoder/Auctaryn/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/LloydCoder/Auctaryn/actions/workflows/ci.yml)
[![CodeQL](https://github.com/LloydCoder/Auctaryn/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/LloydCoder/Auctaryn/actions/workflows/codeql.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

> **Demo status:** A real, current screenshot or recording has not yet been committed. The [local evaluation demo script](docs/DEMO_SCRIPT.md) describes a synthetic-data walkthrough. No mockup is presented as proof of a running system.

## Why Auctaryn?

Agent applications need defense in depth, but a risk classifier is not an authorization system and submitted context is not proof of the context an external agent actually consumed. Auctaryn provides bounded checks and structured advisory signals for supported paths; it does not claim universal interception or independently enforce actions outside an integrated trusted runtime.

| Auctaryn provides | It does not replace |
| --- | --- |
| Context-integrity checks over registered and submitted content | Cryptographic attestation of an external agent's effective prompt |
| Risk assessments and structured findings for supported requests | Tinlance Agent Platform identity, policy, approvals, or governed execution |
| Execution-gateway and runtime-adapter integration surfaces | A trusted runtime connection that has not been configured and verified |
| Local evidence-chain storage and verification utilities | The Platform's authoritative audit record or an immutable enterprise evidence service |
| Optional ThreatFade advisory signals | A live ThreatFade service unless endpoint, credentials, and connectivity are configured |

## Quick start

This path is for **local evaluation**, not production. It requires Docker Engine and the Docker Compose plugin.

1. Clone the repository:

   ```bash
   git clone https://github.com/LloydCoder/Auctaryn.git
   cd Auctaryn
   ```

2. Create a local environment file:

   ```bash
   cp .env.example .env
   ```

3. Generate two independent high-entropy secrets with `openssl rand -hex 32`. Set them as `AUCTARYN_API_KEY` and `AUCTARYN_ADMIN_API_KEY` in `.env`; do not reuse the same value. Review other settings before starting.

4. Build and start the API:

   ```bash
   docker compose --env-file .env up -d --build api
   ```

5. Check liveness:

   ```bash
   curl -fsS http://localhost:8400/health
   ```

   When running, open the API schema at [http://localhost:8400/docs](http://localhost:8400/docs).

[!WARNING]
The default local evaluation configuration does **not** establish a trusted OpenShell runtime integration. A healthy liveness endpoint is not production readiness; `/health/ready` should remain false until required runtime and deployment settings are verified. Do not connect real mailboxes, customer data, or production agents during the demo.

## Installation

| Component | Requirement |
| --- | --- |
| API and tests | Python 3.11 or 3.12, matching the CI matrix |
| Python dependencies | Hash-pinned `requirements.lock` |
| Container path | Docker Engine and Docker Compose plugin |
| Dashboard development | Node.js 22 as used by CI; npm and `dashboard/package-lock.json` |
| Optional integrations | Separately configured OpenShell gateway and/or reachable ThreatFade service |

### Reproducible Python environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.lock
```

If dependency declarations change, regenerate and review the lock file rather than editing transitive pins manually.

### Dashboard development

```bash
cd dashboard
npm ci
npm run dev
```

Vite prints the development URL. The dashboard is an operator interface; hiding controls in the UI is not an authorization boundary.

## Usage

### Risk assessment API

The versioned advisory contract is `POST /api/v1/risk/assess`, identified as `auctaryn-risk-assessment.v1`. Use the running API's OpenAPI document at `/docs` for the exact request schema and authentication requirements for the checked-out revision.

The response provides risk signals and structured findings with bounded rationale, confidence, control references, and provenance. For the current caller-metadata classifier, `runtime_observed: false` is an explicit boundary: it is not evidence that an external runtime action was observed.

### Run tests and lint checks

```bash
python -m pytest tests/ -v --cov=core --cov=api --cov=modules --cov-report=term-missing
ruff check --select E4,E7,E9,F core/ api/ modules/
```

Install `ruff` in the active development environment if needed. CI also performs dependency auditing, dashboard builds, container checks, Compose validation, and supply-chain checks.

### Evidence store and recovery

The local SQLite evidence store can record gateway assessments and related decision metadata. Configure `AUCTARYN_EVIDENCE_DB` and a separately managed key for keyed record authentication using `AUCTARYN_EVIDENCE_HMAC_KEY_FILE` (preferred) or `AUCTARYN_EVIDENCE_HMAC_KEY`. Without the key, the service reports hash-chain-only mode.

Follow [Database recovery](docs/DATABASE_RECOVERY.md) for backup, integrity verification, and restore boundaries. This is a single-host utility, not a complete enterprise disaster-recovery service.

## Configuration

The canonical environment template is [.env.example](.env.example). The default application configuration is [config/twinguard.yaml](config/twinguard.yaml); check active Compose files and runtime-adapter configuration rather than assuming every YAML key controls every deployment mode.

| Variable | Purpose | Notes |
| --- | --- | --- |
| `AUCTARYN_API_KEY` | Service API credential | Unique high-entropy secret |
| `AUCTARYN_ADMIN_API_KEY` | Administrative API credential | Must differ from the service key |
| `AUCTARYN_REQUIRE_STRONG_API_KEYS` | Enforce strong-key validation | Template sets `true` |
| `AUCTARYN_DB_PATH` | Application SQLite path | Template: `data/auctaryn.db` |
| `AUCTARYN_EVIDENCE_DB` | Local evidence database | Template: `data/evidence.sqlite3` |
| `AUCTARYN_EVIDENCE_HMAC_KEY_FILE` | Mounted evidence-authentication key | Preferred for production |
| `THREATFADE_SERVICE_URL` | ThreatFade endpoint | Production requires reachable HTTPS |
| `THREATFADE_SERVICE_TOKEN` | ThreatFade credential | Keep secret |
| `AUCTARYN_RUNTIME_ADAPTER` | Runtime adapter selection | Trusted runtime disabled in local evaluation |
| `OPENSHELL_SYSTEM_GATEWAY_DIR` | OpenShell gateway metadata | Validate against target environment |
| `AUCTARYN_PORT` | API port setting | Template: `8400`; confirm Compose mapping |

The template is not a guarantee every variable is consumed in every deployment mode. Consult [OpenShell runtime acceptance](docs/OPEN_SHELL_RUNTIME.md), [deployment rollback](docs/DEPLOYMENT_ROLLBACK.md), and the [security model](docs/SECURITY_MODEL.md) before production configuration.

## Features

| Area | Repository capability | Boundary |
| --- | --- | --- |
| Context integrity | Registered-instruction baseline and heuristic checks | Does not prove external prompt consumption |
| Execution gateway | Risk classification, policy-validation, and runtime-adapter interfaces | End-to-end enforcement depends on trusted integration |
| Agent identity | Identity and scoped-token modules | Platform identity remains authoritative for production governance |
| Inter-agent security | Secure messaging and circuit-breaker modules | Validate against target topology and threat model |
| Skill supply chain | Publisher/signature and artifact-integrity checks | Key trust and update policy must be configured |
| ThreatFade Oracle | Advisory integration adapter | External availability and credentials are deployment-dependent |
| Evidence and incidents | Local evidence chain, verification, incident endpoints, and dashboard | Not the authoritative Platform audit system |
| Release assurance | CI, CodeQL, supply-chain, and release-evidence workflows | Workflow definitions alone do not prove successful current runs |

## Documentation

| Document | Purpose |
| --- | --- |
| [Implementation roadmap](docs/IMPLEMENTATION_ROADMAP.md) | Phase sequence, acceptance gates, and limitations |
| [Security model](docs/SECURITY_MODEL.md) | Trust boundaries and threat model |
| [Security risk register](docs/SECURITY_RISK_REGISTER.md) | Known risks and mitigations |
| [OpenShell runtime acceptance](docs/OPEN_SHELL_RUNTIME.md) | Runtime integration requirements |
| [Tinlance Agent Platform integration](docs/integration/TINLANCE_AGENT_PLATFORM.md) | Advisory contract and authority separation |
| [API authorization matrix](docs/API_AUTHORIZATION_MATRIX.md) | Route authorization reference |
| [Approval lifecycle](docs/APPROVAL_LIFECYCLE.md) | Approval and decision states |
| [Context integrity](docs/CONTEXT_INTEGRITY.md) | Context-check model and limitations |
| [ThreatFade Oracle contract](docs/THREATFADE_ORACLE.md) | External intelligence integration |
| [Skill supply chain](docs/SKILL_SUPPLY_CHAIN.md) | Skill provenance and vetting |
| [Incident response](docs/INCIDENT_RESPONSE.md) | Incident handling guidance |
| [Database recovery](docs/DATABASE_RECOVERY.md) | Local SQLite backup and restore |
| [Deployment rollback](docs/DEPLOYMENT_ROLLBACK.md) | Deployment and rollback gates |
| [Production release acceptance](docs/PRODUCTION_RELEASE_ACCEPTANCE.md) | Release acceptance evidence |
| [Standards traceability](docs/STANDARDS_TRACEABILITY.md) | Security-control mapping |
| [Local demo script](docs/DEMO_SCRIPT.md) | Synthetic-data walkthrough |
| [Audit index](audits/README.md) | Canonical audit report map |
| [Final repository audit](audits/FINAL-REPOSITORY-FORENSIC-AUDIT.md) | Cross-phase audit; verify its tested SHA before relying on it |

## Architecture and authority boundaries

Auctaryn is a supporting component in the Tinlance ecosystem, not a replacement for its control plane:

- **Tinlance Agent Platform** remains authoritative for identity, tenant binding, policy, approvals, governed execution, secrets, and audit.
- **TADL (Tinlance Agent Developer Layer)** is the developer-facing layer. Auctaryn must not silently assume ownership of developer SDK contracts or duplicate Platform authority.
- **Agent OS** owns workspace, environment, lifecycle, fleet, and user-facing agent-operation concerns above the Platform.
- **Auctaryn** contributes supported-path context checks, advisory risk findings, and runtime integration components. It is not the source of truth for permissions or execution decisions.

See [the integration contract](docs/integration/TINLANCE_AGENT_PLATFORM.md). A live Platform-side adapter and conformance tests are required before claiming production integration.

## Contributing

Contributions should preserve the trust boundaries above and include tests and documentation for behavior changes. Start with [CONTRIBUTING.md](CONTRIBUTING.md), follow the [Code of Conduct](CODE_OF_CONDUCT.md), and use the pull-request template.

## License and acknowledgements

Auctaryn is licensed under [Apache License 2.0](LICENSE). Third-party dependencies remain subject to their own licenses.

Auctaryn is developed by Tinlance Limited. It is designed to integrate with [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) as a defense-in-depth runtime boundary and may consume advisory signals from [ThreatFade](https://github.com/LloydCoder/tinlance-threatfade). These integrations do not imply endorsement by those projects.

<details>
<summary>Roadmap and release readiness</summary>

Auctaryn follows a serial 24-phase security and enterprise-readiness roadmap. Use the [roadmap](docs/IMPLEMENTATION_ROADMAP.md), [audit index](audits/README.md), and [production release acceptance](docs/PRODUCTION_RELEASE_ACCEPTANCE.md) for current status. Historical audit reports are evidence snapshots, not proof the current branch passes every gate. Green CI alone does not certify production security.

</details>

<details>
<summary>Troubleshooting</summary>

- **API does not start:** inspect `docker compose --env-file .env logs api`; verify keys and environment values.
- **Readiness is false:** expected for local evaluation until trusted runtime settings are verified.
- **ThreatFade checks fail:** verify the endpoint and service token; a placeholder URL is not a working service.
- **Dashboard cannot reach the API:** check `VITE_API_URL`, `VITE_WS_URL`, port mappings, and browser console errors.
- **Evidence verification fails:** follow [Database recovery](docs/DATABASE_RECOVERY.md) and preserve the original database before attempting repair.

</details>

<details>
<summary>Support</summary>

For usage and documentation questions, search the existing documentation and use GitHub Issues. For suspected vulnerabilities, do not open a public issue; follow [SECURITY.md](SECURITY.md). Support is best-effort.

</details>
