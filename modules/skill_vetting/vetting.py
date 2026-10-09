"""Compatibility facade for the strict artifact-level skill vetting service."""
import re

from modules.skill_vetting.common import (
    PermissionScanResult,
    VettingVerdict,
    detect_typosquat,
    scan_permissions,
)


def validate_manifest_structure(manifest: dict) -> bool:
    from modules.skill_vetting.secure_vetting import valid_manifest
    return valid_manifest(manifest)


def has_valid_signature(
    manifest: dict,
    trusted_publishers: set[str],
    publisher_keys: dict[str, str] | None = None,
) -> bool:
    if not isinstance(manifest, dict) or manifest.get("publisher") not in trusted_publishers:
        return False
    from modules.skill_vetting.secure_vetting import verify_signature
    return verify_signature(manifest, publisher_keys or {})


def has_pinned_hash(manifest: dict) -> bool:
    value = manifest.get("content_hash", "") if isinstance(manifest, dict) else ""
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def verify_content_hash(content: bytes, expected_hash: str) -> bool:
    from modules.skill_vetting.secure_vetting import verify_artifact
    return verify_artifact(content, expected_hash)


class SkillVettingService:
    """Backwards-compatible wrapper; approval requires keys and actual artifact bytes."""

    def __init__(
        self,
        trusted_publishers: set[str] | None = None,
        known_skills: set[str] | None = None,
        publisher_keys: dict[str, str] | None = None,
    ):
        from modules.skill_vetting.secure_vetting import SecureSkillVettingService
        trusted = set(trusted_publishers or ())
        keys = dict(publisher_keys or {})
        if trusted:
            keys = {name: key for name, key in keys.items() if name in trusted}
        self.trusted_publishers = trusted or set(keys)
        self.publisher_keys = keys
        self.known_skills = set(known_skills or ())
        self._service = SecureSkillVettingService(trusted_keys=keys, known_skills=self.known_skills)
        self.history = self._service.history

    def trust_publisher(self, publisher: str, public_key: str) -> None:
        self._service.trust_publisher(publisher, public_key)
        self.trusted_publishers.add(publisher)
        self.publisher_keys[publisher] = public_key

    def vet(self, manifest: dict, artifact_content: bytes | None = None) -> VettingVerdict:
        return self._service.vet(manifest, artifact_content)
