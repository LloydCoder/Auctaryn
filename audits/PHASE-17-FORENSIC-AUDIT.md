# Phase 17 forensic audit — detection operations and incident response

**Scope:** persistent emergency stop, per-agent quarantine, agent-wide capability revocation, durable alert lifecycle, alert WebSocket acknowledgement, evidence correlation and operational runbook.

## Implemented controls

- Global emergency stop and per-agent quarantine are persisted in SQLite and checked by the execution service immediately before runtime invocation, including the approved-decision path.
- Incident controls return HTTP 423 when they block execution. A global stop does not depend on the dashboard or WebSocket connection being available.
- Quarantining an agent revokes its current in-process capabilities; releasing quarantine does not restore tokens.
- Added agent-wide token revocation that invalidates the identity permission version and marks direct/delegated tokens revoked.
- Critical-risk and veto decisions create durable alerts with bounded metadata and are broadcast to connected alert clients. Trusted runtime execution failures also create durable alerts; unresolved duplicate signals for the same decision/category are deduplicated.
- Alert state persists across process restarts and supports open → acknowledged → resolved transitions; resolved alerts cannot be reopened through the transition API.
- Alert acknowledgement over WebSocket requires the administrator credential and persists state rather than claiming unsupported success.
- State changes and alert transitions are correlated with the Phase 16 evidence chain; a failed terminal record is explicitly surfaced as `terminal_record_failed`.
- Added regression tests for restart persistence, stop enforcement, scoped quarantine, token revocation, alert lifecycle, alert creation and service-vs-admin authorization.
- Added an operator runbook aligned with NIST SP 800-61 Rev. 3.

## Security invariants

1. Every actual runtime invocation checks emergency-stop and agent-quarantine state at the execution service boundary.
2. Dashboard/WebSocket outage cannot disable the local execution guard.
3. Only administrator credentials can change incident controls or acknowledge/resolve alerts.
4. Quarantine release is not token reissuance; least-privilege capability issuance remains a separate operator action.
5. Alerts are triage signals and do not claim confirmed compromise or replace Platform audit evidence.

## Remaining deployment gates

- Local SQLite state is persistent on a single host but does not provide distributed consensus; multi-replica stop propagation requires a shared authoritative control plane.
- Identity and token state remain process-local. Auctaryn's local revocation must be paired with authoritative Platform-side revocation.
- The local alert/control tables are not protected against a privileged database operator; production requires external key management, immutable export and backup/restore testing.
- Runtime process termination, stop propagation under worker concurrency, alert false-positive tuning and recovery drills require validation in the deployed environment.
- Exact final-head CI and post-merge CI must be green before phase acceptance.
