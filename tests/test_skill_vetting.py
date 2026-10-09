"""Regression coverage for the strict skill-vetting compatibility facade."""
import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modules.skill_vetting.secure_vetting import canonical_manifest, SecureSkillVettingService
from modules.skill_vetting.vetting import (
    SkillVettingService,
    detect_typosquat,
    has_pinned_hash,
    has_valid_signature,
    scan_permissions,
    validate_manifest_structure,
    verify_content_hash,
)


def signed_fixture(name="email-organizer", version="1.2.0", permissions=None, content=b"skill bytes"):
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode("ascii")
    manifest = {
        "name": name,
        "version": version,
        "content_hash": hashlib.sha256(content).hexdigest(),
        "signature": "",
        "permissions": permissions or ["read_file"],
        "publisher": "trusted-dev",
    }
    manifest["signature"] = "ed25519:" + base64.b64encode(
        private.sign(canonical_manifest(manifest))
    ).decode("ascii")
    return private, public, manifest, content


def test_manifest_requires_exact_version_and_sha256():
    _, _, manifest, _ = signed_fixture()
    assert validate_manifest_structure(manifest) is True
    assert validate_manifest_structure(dict(manifest, version="^1.2.0")) is False
    assert validate_manifest_structure(dict(manifest, content_hash="z" * 64)) is False


def test_signature_requires_trusted_public_key_and_real_signature():
    _, public, manifest, _ = signed_fixture()
    assert has_valid_signature(manifest, {"trusted-dev"}) is False
    assert has_valid_signature(manifest, {"trusted-dev"}, {"trusted-dev": public}) is True
    changed = dict(manifest, permissions=["write_file"])
    assert has_valid_signature(changed, {"trusted-dev"}, {"trusted-dev": public}) is False


def test_content_hash_verification_checks_exact_bytes():
    _, _, manifest, content = signed_fixture()
    assert has_pinned_hash(manifest) is True
    assert verify_content_hash(content, manifest["content_hash"]) is True
    assert verify_content_hash(b"different", manifest["content_hash"]) is False


def test_permission_scan_rejects_high_risk_combinations():
    result = scan_permissions(["read_email", "http_request"])
    assert result.risk_level == "high"
    critical = scan_permissions(["exfiltrate_data"])
    assert critical.risk_level == "critical"


def test_typosquat_detection_against_known_registry():
    assert detect_typosquat("gmial-organizer", {"gmail-organizer"}) == "gmail-organizer"
    assert detect_typosquat("gmail-organizer", {"gmail-organizer"}) is None


def test_compatibility_service_fails_closed_without_artifact_bytes():
    _, public, manifest, content = signed_fixture()
    service = SkillVettingService(
        trusted_publishers={"trusted-dev"},
        publisher_keys={"trusted-dev": public},
    )
    assert service.vet(manifest).approved is False
    assert service.vet(manifest, content).approved is True


def test_compatibility_service_tracks_approved_verdicts():
    _, public, manifest, content = signed_fixture()
    service = SkillVettingService(
        trusted_publishers={"trusted-dev"},
        publisher_keys={"trusted-dev": public},
    )
    service.vet(manifest, content)
    assert len(service.history) == 1


def test_secure_service_rejects_unknown_publisher():
    _, _, manifest, content = signed_fixture()
    service = SecureSkillVettingService()
    verdict = service.vet(manifest, content)
    assert verdict.approved is False
    assert any("publisher" in reason.lower() for reason in verdict.reasons)
