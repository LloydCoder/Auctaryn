"""Cryptographic skill supply-chain vetting tests."""
import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modules.skill_vetting.vetting import canonical_manifest_payload

TEST_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
TEST_PUBLIC_KEY = TEST_PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw,
)
TEST_PUBLIC_KEY_B64 = base64.b64encode(TEST_PUBLIC_KEY).decode("ascii")
TRUSTED_PUBLISHERS = {"trusted-dev-001": TEST_PUBLIC_KEY_B64}

SAFE_ARTIFACT = b"the actual skill bytes"
MALICIOUS_ARTIFACT = b"malicious skill bytes"
UNSIGNED_ARTIFACT = b"unsigned skill bytes"
TYPOSQUAT_ARTIFACT = b"typosquatted skill bytes"


def _signed_manifest(name, version, permissions, artifact, publisher="trusted-dev-001", private_key=TEST_PRIVATE_KEY):
    manifest = {
        "name": name,
        "version": version,
        "content_hash": hashlib.sha256(artifact).hexdigest(),
        "signature": "",
        "permissions": list(permissions),
        "publisher": publisher,
    }
    signature = private_key.sign(canonical_manifest_payload(manifest))
    manifest["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return manifest


SAFE_MANIFEST = _signed_manifest(
    "email-organizer", "1.2.0", ["read_email", "list_email"], SAFE_ARTIFACT,
)
MALICIOUS_MANIFEST = _signed_manifest(
    "totally-safe-skill", "1.0.0",
    ["read_email", "send_email", "delete_database", "escalate_privileges", "exfiltrate_data"],
    MALICIOUS_ARTIFACT,
)
UNSIGNED_MANIFEST = _signed_manifest(
    "mystery-skill", "2.0.0", ["read_file"], UNSIGNED_ARTIFACT,
)
UNSIGNED_MANIFEST["signature"] = ""
TYPOSQUAT_MANIFEST = _signed_manifest(
    "gmial-organizer", "1.0.0", ["read_email"], TYPOSQUAT_ARTIFACT,
)


class TestManifestValidation:
    def test_valid_manifest_passes_structure_check(self):
        from modules.skill_vetting.vetting import validate_manifest_structure
        assert validate_manifest_structure(SAFE_MANIFEST) is True

    def test_missing_content_hash_fails_structure_check(self):
        from modules.skill_vetting.vetting import validate_manifest_structure
        assert validate_manifest_structure(dict(MALICIOUS_MANIFEST, content_hash="")) is False

    def test_missing_required_field_fails(self):
        from modules.skill_vetting.vetting import validate_manifest_structure
        assert validate_manifest_structure({"name": "x"}) is False

    def test_unsigned_extra_manifest_fields_are_rejected(self):
        from modules.skill_vetting.vetting import validate_manifest_structure
        assert validate_manifest_structure({**SAFE_MANIFEST, "unsigned_metadata": "changed"}) is False

    def test_version_ranges_and_non_semver_versions_are_rejected(self):
        from modules.skill_vetting.vetting import validate_manifest_structure
        assert validate_manifest_structure({**SAFE_MANIFEST, "version": "^1.2.0"}) is False
        assert validate_manifest_structure({**SAFE_MANIFEST, "version": "latest"}) is False


class TestSignatureVerification:
    def test_valid_ed25519_signature_passes(self):
        from modules.skill_vetting.vetting import has_valid_signature
        assert has_valid_signature(SAFE_MANIFEST, TRUSTED_PUBLISHERS) is True

    def test_unsigned_skill_fails_signature_check(self):
        from modules.skill_vetting.vetting import has_valid_signature
        assert has_valid_signature(UNSIGNED_MANIFEST, TRUSTED_PUBLISHERS) is False

    def test_signed_but_untrusted_publisher_fails(self):
        from modules.skill_vetting.vetting import has_valid_signature
        manifest = _signed_manifest(
            "email-organizer", "1.2.0", ["read_email"], SAFE_ARTIFACT,
            publisher="random-unverified-account",
        )
        assert has_valid_signature(manifest, TRUSTED_PUBLISHERS) is False

    def test_manifest_tampering_invalidates_signature(self):
        from modules.skill_vetting.vetting import has_valid_signature
        tampered = dict(SAFE_MANIFEST, permissions=["read_email", "send_email"])
        assert has_valid_signature(tampered, TRUSTED_PUBLISHERS) is False

    def test_malformed_signature_fails_closed(self):
        from modules.skill_vetting.vetting import has_valid_signature
        malformed = dict(SAFE_MANIFEST, signature="ed25519:not-base64")
        assert has_valid_signature(malformed, TRUSTED_PUBLISHERS) is False


class TestContentHashPinning:
    def test_hash_pinned_manifest_passes(self):
        from modules.skill_vetting.vetting import has_pinned_hash
        assert has_pinned_hash(SAFE_MANIFEST) is True

    def test_empty_or_short_hash_fails(self):
        from modules.skill_vetting.vetting import has_pinned_hash
        assert has_pinned_hash(dict(SAFE_MANIFEST, content_hash="")) is False
        assert has_pinned_hash(dict(SAFE_MANIFEST, content_hash="a" * 32)) is False

    def test_hash_mismatch_detected(self):
        from modules.skill_vetting.vetting import verify_content_hash
        assert verify_content_hash(SAFE_ARTIFACT, "0" * 64) is False

    def test_hash_match_verified(self):
        from modules.skill_vetting.vetting import verify_content_hash
        assert verify_content_hash(SAFE_ARTIFACT, hashlib.sha256(SAFE_ARTIFACT).hexdigest()) is True


class TestPermissionManifestScanning:
    def test_minimal_permissions_pass(self):
        from modules.skill_vetting.vetting import scan_permissions
        assert scan_permissions(SAFE_MANIFEST["permissions"]).risk_level == "low"

    def test_dangerous_permissions_are_critical(self):
        from modules.skill_vetting.vetting import scan_permissions
        result = scan_permissions(MALICIOUS_MANIFEST["permissions"])
        assert result.risk_level == "critical"
        assert "escalate_privileges" in result.flagged_permissions

    def test_exfiltration_permission_always_critical(self):
        from modules.skill_vetting.vetting import scan_permissions
        assert scan_permissions(["exfiltrate_data"]).risk_level == "critical"

    def test_unknown_permissions_are_critical(self):
        from modules.skill_vetting.vetting import scan_permissions
        assert scan_permissions(["vendor_specific_unknown_permission"]).risk_level == "critical"

    def test_private_data_plus_network_egress_is_high_risk(self):
        from modules.skill_vetting.vetting import scan_permissions
        assert scan_permissions(["read_email", "send_email"]).risk_level == "high"

    def test_excessive_permission_count_is_medium_and_not_approvable(self):
        from modules.skill_vetting.vetting import scan_permissions
        assert scan_permissions(["read_email", "list_email", "calendar_read", "write_file"]).risk_level == "medium"


class TestTyposquatDetection:
    def test_typosquat_detected_against_known_skills(self):
        from modules.skill_vetting.vetting import detect_typosquat
        assert detect_typosquat("gmial-organizer", {"gmail-organizer", "calendar-sync"}) == "gmail-organizer"

    def test_exact_match_is_not_a_typosquat(self):
        from modules.skill_vetting.vetting import detect_typosquat
        assert detect_typosquat("gmail-organizer", {"gmail-organizer"}) is None

    def test_unrelated_name_is_not_flagged(self):
        from modules.skill_vetting.vetting import detect_typosquat
        assert detect_typosquat("completely-different-tool", {"gmail-organizer"}) is None


class TestSkillVettingService:
    def _service(self, known_skills=None):
        from modules.skill_vetting.vetting import SkillVettingService
        return SkillVettingService(
            trusted_publishers=TRUSTED_PUBLISHERS,
            known_skills=set(known_skills or {"email-organizer"}),
        )

    def test_vet_safe_skill_approves_with_real_artifact(self):
        verdict = self._service().vet(SAFE_MANIFEST, SAFE_ARTIFACT)
        assert verdict.approved is True
        assert verdict.publisher == "trusted-dev-001"
        assert verdict.version == "1.2.0"
        assert verdict.artifact_hash == hashlib.sha256(SAFE_ARTIFACT).hexdigest()

    def test_vet_malicious_skill_rejects(self):
        verdict = self._service().vet(MALICIOUS_MANIFEST, MALICIOUS_ARTIFACT)
        assert verdict.approved is False
        assert any("critical" in reason.lower() for reason in verdict.reasons)

    def test_vet_unsigned_skill_rejects(self):
        verdict = self._service().vet(UNSIGNED_MANIFEST, UNSIGNED_ARTIFACT)
        assert verdict.approved is False
        assert any("signature" in reason.lower() for reason in verdict.reasons)

    def test_vet_typosquat_against_known_registry_rejects(self):
        verdict = self._service({"gmail-organizer"}).vet(TYPOSQUAT_MANIFEST, TYPOSQUAT_ARTIFACT)
        assert verdict.approved is False
        assert any("typosquat" in reason.lower() for reason in verdict.reasons)

    def test_vet_requires_artifact_bytes(self):
        verdict = self._service().vet(SAFE_MANIFEST)
        assert verdict.approved is False
        assert any("artifact bytes" in reason.lower() for reason in verdict.reasons)

    def test_vet_rejects_artifact_hash_mismatch(self):
        verdict = self._service().vet(SAFE_MANIFEST, b"different bytes")
        assert verdict.approved is False
        assert any("does not match" in reason.lower() for reason in verdict.reasons)

    def test_same_version_artifact_change_is_rejected(self):
        service = self._service()
        assert service.vet(SAFE_MANIFEST, SAFE_ARTIFACT).approved is True
        changed_artifact = b"changed bytes but same semantic version"
        changed_manifest = _signed_manifest(
            "email-organizer", "1.2.0", ["read_email", "list_email"], changed_artifact,
        )
        verdict = service.vet(changed_manifest, changed_artifact)
        assert verdict.approved is False
        assert any("without a version bump" in reason.lower() for reason in verdict.reasons)

    def test_same_version_permission_manifest_change_is_rejected(self):
        service = self._service()
        assert service.vet(SAFE_MANIFEST, SAFE_ARTIFACT).approved is True
        changed_manifest = _signed_manifest(
            "email-organizer", "1.2.0", ["read_email", "list_email", "calendar_read"], SAFE_ARTIFACT,
        )
        verdict = service.vet(changed_manifest, SAFE_ARTIFACT)
        assert verdict.approved is False
        assert any("manifest changed" in reason.lower() for reason in verdict.reasons)

    def test_new_version_can_pin_new_artifact(self):
        service = self._service()
        assert service.vet(SAFE_MANIFEST, SAFE_ARTIFACT).approved is True
        artifact = b"new version artifact"
        manifest = _signed_manifest("email-organizer", "1.2.1", ["read_email"], artifact)
        assert service.vet(manifest, artifact).approved is True

    def test_vetting_history_is_bounded(self, monkeypatch):
        import modules.skill_vetting.vetting as vetting_module
        monkeypatch.setattr(vetting_module, "MAX_VETTING_HISTORY", 2)
        service = self._service()
        for _ in range(3):
            service.vet(UNSIGNED_MANIFEST, UNSIGNED_ARTIFACT)
        assert len(service.history) == 2

    def test_publisher_key_rotation_requires_explicit_replace(self):
        from modules.skill_vetting.vetting import SkillVettingService
        second_private_key = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
        second_public_key = second_private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        service = self._service()
        with pytest.raises(ValueError, match="explicit rotation"):
            service.trust_publisher("trusted-dev-001", second_public_key)
        fingerprint = service.trust_publisher("trusted-dev-001", second_public_key, replace=True)
        assert fingerprint == hashlib.sha256(second_public_key).hexdigest()
