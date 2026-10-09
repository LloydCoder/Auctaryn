# Memory Defender — Security Contract

## Purpose and limits

Memory Defender screens new content before it can enter agent memory, quarantines untrusted content, verifies integrity, and restores a last-known-good snapshot when tampering is detected. It is a heuristic defense layer, not a semantic prompt-injection oracle.

## API identity and sessions

All `/api/v1/memory/*` calls still require the Auctaryn service credential. In addition, the memory API requires:
- `X-Agent-ID`: registered agent identity;
- `X-Agent-Identity-Token`: valid short-lived token with the required `memory:write` or `memory:read` scope.

Create a server-issued session with `POST /api/v1/memory/sessions`. The session ID is bound to the authenticated agent; clients cannot establish ownership merely by choosing a session string. Storage and readability checks reject sessions owned by a different agent.

## Provenance and quarantine

The public `POST /api/v1/memory/evaluate` endpoint treats caller-supplied provenance as untrusted. It prefixes source labels with `api:`, so even a caller claiming `user_conversation` is quarantined. Suspicious instruction override, role-hijack, hidden-directive, privilege-escalation and safety-bypass patterns are blocked before storage. Unknown internal source labels are quarantined by default.

A trusted source label is meaningful only when assigned by a trusted internal ingestion path; do not expose that path directly to untrusted callers.

## Integrity and rollback

Each entry receives a unique opaque ID. The SHA-256 digest binds:
- entry key and content;
- source label and session/agent binding;
- quarantine state;
- creation timestamp.

A separately held last-known-good snapshot anchors integrity verification. Metadata tampering, including changing `quarantined` to false or rewriting the source label, is detected. The metadata API attempts rollback and reports `tamper_detected`, `rolled_back`, and `integrity_ok` without returning memory content. The scoped content endpoint returns content only to an authorized agent/session; quarantined content is restricted to its originating session.

This is tamper detection against accidental or ordinary in-process mutation, not a cryptographic guarantee against a compromised process that can modify both live state and the snapshot.

## Resource limits

- Content: 1–32,768 characters.
- Source label: at most 64 characters internally; public source label at most 48 before the `api:` prefix.
- Session and agent IDs: at most 128 characters.
- In-process entries: at most 5,000.
- Aggregate stored content: at most 8 Mi characters (the live entry and trusted snapshot together use approximately twice this amount, excluding object overhead).
- Server-issued sessions: at most 5,000.

Capacity exhaustion denies further storage/session creation rather than growing the process without bound.

## Operational limitations

The current implementation stores entries, session ownership and trusted snapshots in process memory. State is lost on restart and is not shared across replicas. Production must integrate a durable store and authoritative tenant/identity binding through Tinlance Agent Platform. Do not treat the local SHA-256 digest as a signed audit record or an external provenance attestation.

The poisoning scanner is regex-based and can have false positives and false negatives. High-impact decisions still require independent policy, scoped identity, approval and runtime enforcement controls.
