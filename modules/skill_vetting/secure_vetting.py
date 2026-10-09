"""Strict artifact-level skill verification for Auctaryn."""
import base64
import hashlib
import hmac
import json
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from modules.skill_vetting.vetting import (
    PermissionScanResult,
    VettingVerdict,
    detect_typosquat,
    scan_permissions,
)

_HASH = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_MAX_ARTIFACT_BYTES = 1024 * 1024
_MAX_HISTORY = 500
_REQUIRED = {"name", "version", "content_hash", "signature", "permissions", "publisher"}


def canonical_manifest(manifest: dict) -> bytes:
    fields = {key: manifest[key] for key in ("name", "version", "content_hash", "permissions", "publisher") if key in manifest}
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def valid_manifest(manifest: object) -> bool:
    if not isinstance(manifest, dict) or not _REQUIRED.issubset(manifest):
        return False
    if any(not isinstance(manifest.get(k), str) or not manifest[k].strip() for k in ("name", "version", "content_hash", "signature", "publisher")):
        return False
    if len(manifest["name"]) > 128 or len(manifest["publisher"]) > 256:
        return False
    if not _VERSION.fullmatch(manifest["version"]) or not _HASH.fullmatch(manifest["content_hash"]):
        return False
    permissions = manifest.get("permissions")
    return (
        isinstance(permissions, list)
        and len(permissions) <= 100
        and all(isinstance(p, str) and 0 < len(p) <= 128 for p in permissions)
        and len(set(permissions)) == len(permissions)
    )


def verify_signature(manifest: dict, trusted_keys: dict[str, str]) -> bool:
    publisher = manifest.get("publisher") if isinstance(manifest, dict) else None
    signature = manifest.get("signature") if isinstance(manifest, dict) else None
    encoded_key = trusted_keys.get(publisher) if isinstance(publisher, str) else None
    if not isinstance(encoded_key, str) or not isinstance(signature, str) or not signature.startswith("ed25519:"):
        return False
    try:
        key = base64.b64decode(encoded_key, validate=True)
        sig = base64.b64decode(signature[8:], validate=True)
        if len(key) != 32 or len(sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(key).verify(sig, canonical_manifest(manifest))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def verify_artifact(content: bytes, expected_hash: str) -> bool:
    return (
        isinstance(content, bytes)
        and len(content) <= _MAX_ARTIFACT_BYTES
        and isinstance(expected_hash, str)
        and _HASH.fullmatch(expected_hash) is not None
        and hmac.compare_digest(hashlib.sha256(content).hexdigest(), expected_hash)
    )


def _version_tuple(value: str) -> tuple:
    match = _VERSION.fullmatch(value)
    if not match:
        raise ValueError("exact semantic version required")
    core = tuple(int(match.group(i)) for i in (1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        return (*core, 1, ())
    identifiers = tuple(
        (0, int(part)) if part.isdigit() else (1, part)
        for part in prerelease.split(".")
    )
    return (*core, 0, identifiers)


class SecureSkillVettingService:
    """Verifies publisher signatures, artifact bytes, permissions, and version pins."""

    def __init__(self, trusted_keys: dict[str, str] | None = None, known_skills: set[str] | None = None):
        self.trusted_keys = dict(trusted_keys or {})
        self.known_skills = set(known_skills or ())
        self.history: list[VettingVerdict] = []
        self._pins: dict[tuple[str, str], str] = {}
        self._latest: dict[str, str] = {}

    def trust_publisher(self, publisher: str, public_key: str) -> None:
        if not isinstance(publisher, str) or not publisher.strip() or len(publisher) > 256:
            raise ValueError("invalid publisher")
        try:
            raw = base64.b64decode(public_key, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("public key must be base64 encoded") from exc
        if len(raw) != 32:
            raise ValueError("Ed25519 public key must contain 32 bytes")
        previous = self.trusted_keys.get(publisher)
        if previous is not None and not hmac.compare_digest(previous, public_key):
            raise ValueError("publisher key rotation requires an audited rotation workflow")
        self.trusted_keys[publisher] = public_key

    def vet(self, manifest: dict, artifact_content: bytes | None) -> VettingVerdict:
        name = manifest.get("name", "unknown") if isinstance(manifest, dict) else "unknown"
        reasons: list[str] = []
        if not valid_manifest(manifest):
            reasons.append("Manifest is malformed; exact semantic version and SHA-256 pin are required")
        if not isinstance(artifact_content, bytes):
            reasons.append("Artifact bytes are required")
        elif not isinstance(manifest, dict) or not verify_artifact(artifact_content, manifest.get("content_hash", "")):
            reasons.append("Artifact digest does not match the pinned SHA-256 hash")
        if not isinstance(manifest, dict) or not verify_signature(manifest, self.trusted_keys):
            reasons.append("Publisher signature is invalid or publisher is not trusted")
        permissions = manifest.get("permissions", []) if isinstance(manifest, dict) else []
        permission_result: PermissionScanResult = scan_permissions(permissions)
        if permission_result.risk_level in ("high", "critical"):
            reasons.append(f"Permission risk {permission_result.risk_level}: {permission_result.reason}")
        if self.known_skills:
            match = detect_typosquat(name, self.known_skills)
            if match:
                reasons.append(f"Possible typosquat of known skill '{match}'")

        if valid_manifest(manifest):
            name, version = manifest["name"], manifest["version"]
            current = self._latest.get(name)
            if current and _version_tuple(version) < _version_tuple(current):
                reasons.append("Version rollback detected")
            pin = self._pins.get((name, version))
            fingerprint = hashlib.sha256(canonical_manifest(manifest)).hexdigest()
            if pin and not hmac.compare_digest(pin, fingerprint):
                reasons.append("Tool-change detected for an already pinned name/version")

        verdict = VettingVerdict(skill_name=name, approved=not reasons, reasons=reasons)
        self.history.append(verdict)
        if len(self.history) > _MAX_HISTORY:
            del self.history[:-_MAX_HISTORY]
        if verdict.approved:
            name, version = manifest["name"], manifest["version"]
            self._pins[(name, version)] = hashlib.sha256(canonical_manifest(manifest)).hexdigest()
            if name not in self._latest or _version_tuple(version) > _version_tuple(self._latest[name]):
                self._latest[name] = version
        return verdict
