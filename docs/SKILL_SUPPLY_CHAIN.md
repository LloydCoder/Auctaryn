# Skill and Tool Supply-Chain Security Contract

## Security boundary

Auctaryn vets artifacts before a deployment or agent runtime makes a skill available. Vetting is a decision signal, not a sandbox: approved code must still execute only inside the configured, least-privilege runtime. Publisher trust is administrator-managed and must not be writable with a service credential.

## Manifest and signature

The verifier accepts an exact semantic version and lowercase 64-character SHA-256 digest. It rejects version ranges, malformed permission lists, duplicate permissions, unknown publishers, invalid signatures, and absent artifact bytes.

The Ed25519 signature is base64 encoded after the `ed25519:` prefix. It signs UTF-8 canonical JSON with sorted keys and compact separators over exactly these fields:

- `name`
- `version`
- `content_hash`
- `permissions`
- `publisher`

The signature field and transport-only `artifact_b64` field are excluded. The artifact bytes are base64 encoded for the API transport and must match the signed digest. The API limits decoded artifacts to 1 MiB. The public key is the base64 encoding of the raw 32-byte Ed25519 public key.

## Publisher trust and rotation

Only the administrator credential may register a publisher public key. Publisher keys are trust roots; registering an existing publisher with a different key is rejected. Key rotation must be an explicit, separately reviewed and audited workflow. The current in-process trust store is not durable and must not be represented as a multi-replica production trust service.

## Immutable version pins and tool-change detection

On the first approved artifact, the service pins the canonical signed manifest fingerprint for the exact `name@version` and records the latest approved version. A different manifest for an already pinned name/version is rejected. A lower version than the latest approved version is rejected as rollback. A new version must be re-signed by a trusted publisher and pass artifact, permission and typo-squat checks.

Pin state is currently process-local. Production deployment must persist pins in the authoritative, audited control plane before relying on them across restarts or replicas.

## Least privilege and threat checks

Permission scanning rejects critical capabilities and high-risk private-data/network-egress combinations. Typosquat detection is heuristic and does not establish package identity. Passing a permission heuristic does not grant authorization; the Tinlance Agent Platform remains authoritative for capabilities and execution approvals.

## API

- `POST /api/v1/skills/trust-publisher`: administrator only; body includes `publisher` and base64 raw Ed25519 `public_key`.
- `POST /api/v1/skills/vet`: requires a signed manifest and base64 `artifact_b64`; returns a vetting verdict, never an execution authorization.
- `GET /api/v1/skills/history`: bounded verdict history; history is process-local.

## Remaining production gates

- Persist publisher trust roots, key rotations, immutable pins and vetting evidence in a durable, tenant-bound control plane.
- Bind vetting verdicts to the exact runtime-loaded artifact digest and refuse to load any other bytes.
- Add signed build provenance verification (for example SLSA/in-toto) where producers supply provenance; this module currently verifies publisher signatures and artifact hashes, not SLSA attestations.
- Independently review the trust bootstrap and recovery process, including compromise and revocation of publisher keys.


## Registry operations

Publisher trust and the canonical skill-name registry are administrator-only operations. Unknown permission names require an explicit code change before acceptance. The registry is currently process-local; durable storage and audit-backed changes remain production requirements.
