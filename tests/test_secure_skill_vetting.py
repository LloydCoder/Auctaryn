"""Adversarial tests for signed skill artifact verification."""
import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modules.skill_vetting.secure_vetting import SecureSkillVettingService, canonical_manifest


def make_manifest(private_key, artifact=b"safe artifact", version="1.0.0", permissions=None):
    manifest = {
        "name": "trusted-skill",
        "version": version,
        "content_hash": hashlib.sha256(artifact).hexdigest(),
        "signature": "",
        "permissions": permissions or ["read_file"],
        "publisher": "publisher-a",
    }
    manifest["signature"] = "ed25519:" + base64.b64encode(
        private_key.sign(canonical_manifest(manifest))
    ).decode("ascii")
    return manifest, artifact


def configured_service():
    private_key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode("ascii")
    service = SecureSkillVettingService()
    service.trust_publisher("publisher-a", public_key)
    return service, private_key


def test_real_ed25519_signature_and_artifact_are_required():
    service, key = configured_service()
    manifest, artifact = make_manifest(key)
    assert service.vet(manifest, artifact).approved is True


def test_signature_tampering_is_rejected():
    service, key = configured_service()
    manifest, artifact = make_manifest(key)
    manifest["permissions"] = ["read_file", "write_file"]
    verdict = service.vet(manifest, artifact)
    assert verdict.approved is False
    assert any("signature" in reason.lower() for reason in verdict.reasons)


def test_artifact_digest_mismatch_is_rejected():
    service, key = configured_service()
    manifest, _ = make_manifest(key, artifact=b"signed artifact")
    verdict = service.vet(manifest, b"different bytes")
    assert verdict.approved is False
    assert any("digest" in reason.lower() for reason in verdict.reasons)


def test_missing_artifact_is_rejected():
    service, key = configured_service()
    manifest, _ = make_manifest(key)
    assert service.vet(manifest, None).approved is False


def test_version_ranges_and_duplicate_permissions_are_rejected():
    service, key = configured_service()
    manifest, artifact = make_manifest(key, version="^1.2.3")
    assert service.vet(manifest, artifact).approved is False
    manifest, artifact = make_manifest(key, version="1.2.3", permissions=["read_file", "read_file"])
    assert service.vet(manifest, artifact).approved is False


def test_same_name_and_version_cannot_change_signed_manifest():
    service, key = configured_service()
    manifest, artifact = make_manifest(key)
    assert service.vet(manifest, artifact).approved is True
    changed, same_artifact = make_manifest(key, artifact=artifact, permissions=["read_file", "write_file"])
    verdict = service.vet(changed, same_artifact)
    assert verdict.approved is False
    assert any("tool-change" in reason.lower() for reason in verdict.reasons)


def test_version_rollback_is_rejected():
    service, key = configured_service()
    current, artifact = make_manifest(key, version="2.0.0")
    assert service.vet(current, artifact).approved is True
    old, old_artifact = make_manifest(key, artifact=b"older", version="1.0.0")
    verdict = service.vet(old, old_artifact)
    assert verdict.approved is False
    assert any("rollback" in reason.lower() for reason in verdict.reasons)


def test_publisher_key_cannot_be_silently_replaced():
    service, _ = configured_service()
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    with pytest.raises(ValueError, match="rotation"):
        service.trust_publisher("publisher-a", base64.b64encode(other).decode("ascii"))


def test_untrusted_publisher_cannot_approve_artifact():
    _, key = configured_service()
    service = SecureSkillVettingService()
    manifest, artifact = make_manifest(key)
    verdict = service.vet(manifest, artifact)
    assert verdict.approved is False
    assert any("publisher signature" in reason.lower() for reason in verdict.reasons)
