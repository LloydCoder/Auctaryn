"""Cryptographic skill and dependency vetting.

The vetter never executes skill code. It verifies a publisher's Ed25519
signature over a canonical manifest, hashes the exact artifact bytes,
checks declared permissions, and rejects same-version artifact changes.
"""
import base64
import binascii
import difflib
import hashlib
import hmac
import json
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.logging import get_logger

logger = get_logger("skill_vetting")

MAX_ARTIFACT_BYTES = 1_048_576
MAX_ARTIFACT_BASE64_CHARS = 4 * ((MAX_ARTIFACT_BYTES + 2) // 3)
MAX_MANIFEST_PERMISSIONS = 32
MAX_TRUSTED_PUBLISHERS = 500
MAX_KNOWN_SKILLS = 10_000
MAX_APPROVED_PINS = 1_000
MAX_VETTING_HISTORY = 1_000

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
PUBLISHER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
PERMISSION_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
REQUIRED_MANIFEST_FIELDS = {"name", "version", "content_hash", "signature", "permissions", "publisher"}

# Permissions which always represent high-impact authority.
ALWAYS_CRITICAL_PERMISSIONS = {
    "delete_database", "exfiltrate_data", "escalate_privileges", "modify_policy",
    "modify_config", "disable_security", "disable_guard", "execute_code",
    "spawn_process", "read_credentials", "read_secrets", "shell_exec",
    "install_package", "write_env",
}
PRIVATE_DATA_PERMS = {
    "read_email", "read_file", "read_database", "read_contacts", "read_credentials",
    "read_secrets", "access_filesystem", "read_env", "read_browser",
}
NETWORK_EGRESS_PERMS = {
    "send_email", "http_request", "webhook_call", "network_access", "send_message",
}
KNOWN_PERMISSIONS = (
    ALWAYS_CRITICAL_PERMISSIONS
    | PRIVATE_DATA_PERMS
    | NETWORK_EGRESS_PERMS
    | {
        "list_email", "write_file", "write_database", "calendar_read", "calendar_write",
        "read_calendar", "write_calendar", "write_contacts", "delete_file",
        "browser_access", "use_mcp", "invoke_tool",
    }
)
TYPOSQUAT_SIMILARITY_THRESHOLD = 0.82


@dataclass
class PermissionScanResult:
    risk_level: str
    flagged_permissions: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class VettingVerdict:
    skill_name: str
    approved: bool
    reasons: list[str] = field(default_factory=list)
    verdict_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    publisher: str = ""
    version: str = ""
    artifact_hash: str = ""


def canonical_manifest_payload(manifest: dict) -> bytes:
    """Return the one canonical byte representation publishers must sign."""
    payload = {
        "name": manifest["name"],
        "version": manifest["version"],
        "content_hash": manifest["content_hash"].lower(),
        "permissions": sorted(manifest["permissions"]),
        "publisher": manifest["publisher"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_manifest_structure(manifest: dict) -> bool:
    if not isinstance(manifest, dict) or set(manifest.keys()) != REQUIRED_MANIFEST_FIELDS:
        return False
    name = manifest.get("name")
    version = manifest.get("version")
    content_hash = manifest.get("content_hash")
    signature = manifest.get("signature")
    permissions = manifest.get("permissions")
    publisher = manifest.get("publisher")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        return False
    if not isinstance(version, str) or not SEMVER_RE.fullmatch(version):
        return False
    if not isinstance(content_hash, str) or not SHA256_RE.fullmatch(content_hash):
        return False
    if not isinstance(publisher, str) or not PUBLISHER_RE.fullmatch(publisher):
        return False
    if not isinstance(signature, str) or not signature.startswith("ed25519:") or len(signature) > 200:
        return False
    try:
        signature_bytes = base64.b64decode(signature.removeprefix("ed25519:"), validate=True)
    except (ValueError, binascii.Error):
        return False
    if len(signature_bytes) != 64:
        return False
    if not isinstance(permissions, list) or len(permissions) > MAX_MANIFEST_PERMISSIONS:
        return False
    if any(not isinstance(permission, str) or not PERMISSION_RE.fullmatch(permission) for permission in permissions):
        return False
    if len(set(permissions)) != len(permissions):
        return False
    return True


def has_valid_signature(manifest: dict, trusted_publishers: Mapping[str, bytes | str]) -> bool:
    """Verify the Ed25519 signature over the canonical manifest payload."""
    if not validate_manifest_structure(manifest) or not isinstance(trusted_publishers, Mapping):
        return False
    signature = manifest.get("signature")
    publisher = manifest.get("publisher")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        return False
    if not isinstance(publisher, str):
        return False
    key_value = trusted_publishers.get(publisher)
    if key_value is None:
        return False
    try:
        if isinstance(key_value, str):
            public_key_bytes = base64.b64decode(key_value, validate=True)
        elif isinstance(key_value, bytes):
            public_key_bytes = key_value
        else:
            return False
        if len(public_key_bytes) != 32:
            return False
        signature_bytes = base64.b64decode(signature.removeprefix("ed25519:"), validate=True)
        if len(signature_bytes) != 64:
            return False
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, canonical_manifest_payload(manifest))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError, AttributeError, binascii.Error):
        return False


def has_pinned_hash(manifest: dict) -> bool:
    content_hash = manifest.get("content_hash") if isinstance(manifest, dict) else None
    return isinstance(content_hash, str) and bool(SHA256_RE.fullmatch(content_hash))


def verify_content_hash(content: bytes, expected_hash: str) -> bool:
    if not isinstance(content, bytes) or not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
        return False
    return hmac.compare_digest(hashlib.sha256(content).hexdigest(), expected_hash.lower())


def scan_permissions(permissions: list[str]) -> PermissionScanResult:
    if (
        not isinstance(permissions, list)
        or len(permissions) > MAX_MANIFEST_PERMISSIONS
        or any(not isinstance(p, str) or not PERMISSION_RE.fullmatch(p) for p in permissions)
    ):
        return PermissionScanResult("critical", reason="Malformed permission list")
    unknown = [permission for permission in permissions if permission not in KNOWN_PERMISSIONS]
    if unknown:
        return PermissionScanResult("critical", reason="Unknown permissions cannot be verified")
    flagged = [permission for permission in permissions if permission in ALWAYS_CRITICAL_PERMISSIONS]
    if flagged:
        return PermissionScanResult(
            "critical", flagged, f"Requests always-critical permissions: {', '.join(flagged)}"
        )
    has_private_data = any(permission in PRIVATE_DATA_PERMS for permission in permissions)
    has_network = any(permission in NETWORK_EGRESS_PERMS for permission in permissions)
    if has_private_data and has_network:
        return PermissionScanResult(
            "high",
            [p for p in permissions if p in PRIVATE_DATA_PERMS or p in NETWORK_EGRESS_PERMS],
            "Lethal Trifecta pattern: private data access combined with network egress",
        )
    if len(permissions) > 3:
        return PermissionScanResult("medium", reason="Requests more than 3 permissions")
    return PermissionScanResult("low")


def detect_typosquat(skill_name: str, known_skills: set[str]) -> str | None:
    if not isinstance(skill_name, str) or not NAME_RE.fullmatch(skill_name):
        return None
    if skill_name in known_skills:
        return None
    best_match = None
    best_score = 0.0
    for known in known_skills:
        if not isinstance(known, str) or not NAME_RE.fullmatch(known):
            continue
        score = difflib.SequenceMatcher(None, skill_name, known).ratio()
        if score > best_score:
            best_score = score
            best_match = known
    return best_match if best_match and best_score >= TYPOSQUAT_SIMILARITY_THRESHOLD else None


class SkillVettingService:
    """Bounded, thread-safe skill supply-chain vetting and version-pin tracking."""
    def __init__(
        self,
        trusted_publishers: Mapping[str, bytes | str] | None = None,
        known_skills: set[str] | None = None,
    ):
        if len(trusted_publishers or {}) > MAX_TRUSTED_PUBLISHERS:
            raise ValueError("trusted publisher capacity reached")
        if len(known_skills or set()) > MAX_KNOWN_SKILLS:
            raise ValueError("known skill registry capacity reached")
        self.trusted_publishers: dict[str, bytes] = {}
        for publisher, key in (trusted_publishers or {}).items():
            self.trusted_publishers[publisher] = self._decode_public_key(key)
        self.known_skills: set[str] = set(known_skills or set())
        self.approved_pins: dict[tuple[str, str], tuple[str, str]] = {}
        self.history: list[VettingVerdict] = []
        self._lock = threading.RLock()

    @staticmethod
    def _decode_public_key(public_key: bytes | str) -> bytes:
        if isinstance(public_key, str):
            try:
                public_key = base64.b64decode(public_key, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("public key must be valid base64") from exc
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValueError("Ed25519 public key must be exactly 32 bytes")
        Ed25519PublicKey.from_public_bytes(public_key)
        return public_key

    @staticmethod
    def _validate_publisher_name(publisher: str) -> None:
        if not isinstance(publisher, str) or not PUBLISHER_RE.fullmatch(publisher):
            raise ValueError("invalid publisher name")

    def trust_publisher(self, publisher: str, public_key: bytes | str, replace: bool = False) -> str:
        self._validate_publisher_name(publisher)
        public_key_bytes = self._decode_public_key(public_key)
        with self._lock:
            existing = self.trusted_publishers.get(publisher)
            if existing is not None and existing != public_key_bytes and not replace:
                raise ValueError("publisher key already exists; explicit rotation is required")
            if existing is None and len(self.trusted_publishers) >= MAX_TRUSTED_PUBLISHERS:
                raise ValueError("trusted publisher capacity reached")
            self.trusted_publishers[publisher] = public_key_bytes
        return hashlib.sha256(public_key_bytes).hexdigest()

    def revoke_publisher(self, publisher: str) -> bool:
        with self._lock:
            return self.trusted_publishers.pop(publisher, None) is not None

    def register_known_skill(self, name: str) -> bool:
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise ValueError("invalid skill name")
        with self._lock:
            if name in self.known_skills:
                return False
            if len(self.known_skills) >= MAX_KNOWN_SKILLS:
                raise ValueError("known skill registry capacity reached")
            self.known_skills.add(name)
            return True

    def remove_known_skill(self, name: str) -> bool:
        with self._lock:
            if name not in self.known_skills:
                return False
            self.known_skills.remove(name)
            return True

    def vet(self, manifest: dict, artifact: bytes | None = None) -> VettingVerdict:
        reasons: list[str] = []
        manifest_is_valid = validate_manifest_structure(manifest)
        safe_manifest = manifest if isinstance(manifest, dict) else {}
        skill_name = safe_manifest.get("name", "invalid-manifest")
        if not isinstance(skill_name, str) or not NAME_RE.fullmatch(skill_name):
            skill_name = "invalid-manifest"
        publisher = safe_manifest.get("publisher", "")
        version = safe_manifest.get("version", "")
        content_hash = safe_manifest.get("content_hash", "")
        if not manifest_is_valid:
            reasons.append("Manifest is malformed or missing required fields")
        if not has_pinned_hash(safe_manifest):
            reasons.append("Missing or invalid SHA-256 content hash")
        if artifact is None:
            reasons.append("Artifact bytes are required for content verification")
        elif not isinstance(artifact, bytes) or len(artifact) > MAX_ARTIFACT_BYTES:
            reasons.append("Artifact exceeds the allowed size or is not bytes")
        elif not verify_content_hash(artifact, content_hash):
            reasons.append("Artifact content does not match the pinned SHA-256 hash")
        if not has_valid_signature(safe_manifest, self.trusted_publishers):
            reasons.append("Ed25519 signature invalid or publisher key is not trusted")

        permissions = safe_manifest.get("permissions", [])
        perm_scan = scan_permissions(permissions)
        if perm_scan.risk_level != "low":
            reasons.append(f"Permission risk {perm_scan.risk_level}: {perm_scan.reason}")

        with self._lock:
            known_skills = set(self.known_skills)
            trusted_publishers = dict(self.trusted_publishers)
        if known_skills and isinstance(skill_name, str) and skill_name != "invalid-manifest":
            typosquat_match = detect_typosquat(skill_name, known_skills)
            if typosquat_match:
                reasons.append(f"Possible typosquat of known skill '{typosquat_match}'")

        pin_key = (skill_name, version) if isinstance(version, str) else (skill_name, "")
        manifest_fingerprint = (
            hashlib.sha256(canonical_manifest_payload(safe_manifest)).hexdigest()
            if manifest_is_valid else ""
        )
        with self._lock:
            prior_pin = self.approved_pins.get(pin_key)
            current_pin = (content_hash.lower(), manifest_fingerprint) if has_pinned_hash(safe_manifest) else None
            if current_pin and prior_pin and prior_pin != current_pin:
                reasons.append("Artifact or manifest changed without a version bump; publish a new version")
            if prior_pin is None and len(self.approved_pins) >= MAX_APPROVED_PINS:
                reasons.append("Approved artifact pin capacity reached")

            approved = not reasons
            if approved and current_pin is not None:
                self.approved_pins[pin_key] = current_pin
            verdict = VettingVerdict(
                skill_name=skill_name,
                approved=approved,
                reasons=reasons,
                publisher=publisher if isinstance(publisher, str) else "",
                version=version if isinstance(version, str) else "",
                artifact_hash=content_hash.lower() if isinstance(content_hash, str) else "",
            )
            self.history.append(verdict)
            if len(self.history) > MAX_VETTING_HISTORY:
                del self.history[: len(self.history) - MAX_VETTING_HISTORY]

        if not verdict.approved:
            logger.warning(
                "Skill vetting rejected",
                extra={
                    "event": "skill_rejected",
                    "module_name": "skill_vetting",
                    "skill_name": skill_name,
                    "verdict_id": verdict.verdict_id,
                },
            )
        else:
            logger.info(
                "Skill vetting approved",
                extra={
                    "event": "skill_approved",
                    "module_name": "skill_vetting",
                    "skill_name": skill_name,
                    "verdict_id": verdict.verdict_id,
                },
            )
        return verdict
