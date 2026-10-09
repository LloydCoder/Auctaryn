"""Edge cases for risk and exact version identity."""
import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modules.skill_vetting.secure_vetting import SecureSkillVettingService, canonical_manifest


def _configured():
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode("ascii")
    service = SecureSkillVettingService()
    service.trust_publisher("publisher-edge", public)
    return service, private


def _manifest(private, version, content, permissions):
    manifest = {
        "name": "edge-skill",
        "version": version,
        "content_hash": hashlib.sha256(content).hexdigest(),
        "signature": "",
        "permissions": permissions,
        "publisher": "publisher-edge",
    }
    manifest["signature"] = "ed25519:" + base64.b64encode(
        private.sign(canonical_manifest(manifest))
    ).decode("ascii")
    return manifest


def test_medium_permission_set_is_rejected():
    service, private = _configured()
    artifact = b"permission edge artifact"
    manifest = _manifest(private, "1.0.0", artifact, ["read_file", "write_file", "list_files", "memory:read"])
    result = service.vet(manifest, artifact)
    assert not result.approved
    assert any("medium" in reason.lower() for reason in result.reasons)


def test_different_build_metadata_for_same_precedence_is_rejected():
    service, private = _configured()
    artifact = b"version edge artifact"
    first = _manifest(private, "1.0.0+build.1", artifact, ["read_file"])
    assert service.vet(first, artifact).approved
    second = _manifest(private, "1.0.0+build.2", artifact, ["read_file"])
    result = service.vet(second, artifact)
    assert not result.approved
    assert any("version identity" in reason.lower() for reason in result.reasons)
