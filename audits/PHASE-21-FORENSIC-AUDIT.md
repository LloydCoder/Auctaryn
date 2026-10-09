# Phase 21 forensic audit — operator dashboard and deployment compatibility

**Status:** Pre-merge forensic review completed. Exact-head CI passed on `18ac0a2e979e51b05f430f02c1cb8bfcfb037166`; merge and post-merge verification remain required before phase closure.  
**Scope:** Administrator incident/evidence UI, correct rendering of durable incident alert envelopes, session credential cleanup, server-side authorization regressions, immutable image rollback and deployment documentation.

## Findings addressed

1. The overview alert feed only recognized legacy `type=alert` frames and legacy fields; Phase 17 broadcasts `type=incident_alert` with a nested durable incident object. The dashboard now accepts both and normalizes fields.
2. Incident response and evidence endpoints were not directly accessible through a dedicated dashboard view. The new Incidents & Evidence panel shows emergency-stop status, quarantined agents, alerts, bounded evidence metadata and evidence-chain verification, with acknowledgement/resolution controls.
3. Dashboard navigation lacked explicit tab semantics and keyboard arrow/Home/End navigation. Navigation now exposes accessible tab semantics, keyboard movement and visible focus indicators.
4. The dashboard had no explicit sign-out control and its WebSocket hook could attempt a stale reconnect after credentials changed. Sign-out clears the in-memory token; token changes clear live buffers; stale socket close handlers cannot reconnect.
5. Deployment rebuilt a mutable image tag without preserving a reliable rollback reference. The deploy script now records the previous container's immutable image ID; the rollback script validates that ID, refuses missing/malformed targets, restores the tag and checks liveness/readiness without reverting persistent data.
6. The API authorization matrix requires server-side access checks. Regression tests assert service credentials cannot read incident or evidence surfaces, while administrators can list/verify bounded evidence and transition alerts.

## Implementation

- `dashboard/src/components/IncidentEvidencePanel.jsx`: administrator incident and evidence UI; payloads are not rendered.
- `dashboard/src/components/AlertFeed.jsx` and `dashboard/src/App.jsx`: legacy/new alert normalization, new tab, session sign-out and keyboard navigation.
- `dashboard/src/hooks/useWebSocket.js`: credential-change cleanup and stale socket protection.
- `dashboard/src/utils/api.js`: typed incident/evidence API helpers and safe header merging.
- `docker-compose.yml`, `scripts/deploy.sh`, `scripts/rollback.sh`: immutable image tag and guarded rollback.
- `tests/test_phase21_operator_console.py`, `tests/test_deployment_rollback.py`: backend authorization, lifecycle and rollback safety tests.
- `docs/DEPLOYMENT_ROLLBACK.md`, README and roadmap: operator procedure and limitations.

## Exact-head CI acceptance evidence

- Workflow: [Auctaryn CI run 37958990855](https://github.com/LloydCoder/Auctaryn/actions/runs/37958990855) on `18ac0a2e979e51b05f430f02c1cb8bfcfb037166`.
- [x] Python 3.11: 492 tests passed; Ruff passed.
- [x] Python 3.12: 492 tests passed; Ruff passed; `pip-audit` reported no known vulnerabilities.
- [x] Dashboard production build and dependency audit passed.
- [x] Both deployment scripts passed `bash -n`.
- [x] Compose validation, container build and API liveness passed.
- [ ] Merge and verify the resulting main commit's full workflow before closing Phase 21.

**Non-blocking test warning:** Python 3.12 emitted 280 warnings, including Starlette's deprecation warning for using `httpx` with `starlette.testclient`. Tests still pass, but this dependency compatibility warning is retained for Phase 22 dependency/toolchain hardening rather than hidden with a warning filter.

## Production limitations

- The dashboard uses a static administrator API credential, not enterprise SSO/MFA or individual human attribution. Tinlance Agent Platform and an enterprise IdP remain authoritative.
- The local evidence store is not the Platform audit of record; the UI shows bounded local metadata only.
- Rollback restores an image, not database state or external Platform state. A staged production-host rollback, immutable registry provenance verification, runtime-policy verification and operator approval remain mandatory.
- This phase does not claim WCAG conformance from a successful frontend build. Manual assistive-technology and contrast/focus audits remain release assurance tasks.

## Research basis

- WCAG 2.2: https://www.w3.org/TR/WCAG22/
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- Docker Compose deployment specification: https://docs.docker.com/reference/compose-file/deploy/

## Reviewer checklist

- Inspect the React component and ensure no secret or raw request payload is rendered.
- Confirm server-side admin checks reject service credentials independent of client navigation.
- Confirm logout cannot trigger a stale authenticated WebSocket reconnect.
- Confirm the rollback script never substitutes an unverified image and fails closed when state is missing.
- Close Phase 21 only after merge and a green post-merge main workflow; retain the test-client deprecation as a tracked Phase 22 dependency-hardening item.
