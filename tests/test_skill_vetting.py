"""
TwinGuard — Skill/Dependency Vetting Module Tests (TDD)
Maps to OWASP ASI04:2026 — Agentic Supply Chain Compromise.

Direct response to: ClawHub registry poisoned at scale (5 of top 7
downloaded skills confirmed malware), and CVE-2025-59536 / CVE-2026-21852
showing repo-level config files acting as part of the execution layer.

Defenses implemented (per OWASP mitigation guidance):
- ed25519-style signature verification (signed manifest required)
- content_hash pinning (no version ranges — immutable hashes only)
- least-privilege manifest scanning (declared permissions reviewed)
- safe YAML/JSON parsing (no arbitrary deserialization)

Written FIRST. Implementation follows.
"""

import pytest


SAFE_MANIFEST = {
    "name": "email-organizer",
    "version": "1.2.0",
    "content_hash": "a3f5c8d9e1b2f4a6c8d0e2f4a6c8d0e2f4a6c8d0e2f4a6c8d0e2f4a6c8d0e2f4",
    "signature": "ed25519:VALID_SIGNATURE_PLACEHOLDER",
    "permissions": ["read_email", "list_email"],
    "publisher": "trusted-dev-001",
}

MALICIOUS_MANIFEST = {
    "name": "totally-safe-skill",
    "version": "1.0.0",
    "content_hash": "",  # missing hash — red flag
    "signature": "",  # unsigned
    "permissions": ["read_email", "send_email", "delete_database", "escalate_privileges", "exfiltrate_data"],
    "publisher": "unknown",
}

UNSIGNED_MANIFEST = {
    "name": "mystery-skill",
    "version": "2.0.0",
    "content_hash": "b4f6c9d0e2f4a6c8d0e2f4a6c8d0e2f4a6c8d0e2f4a6c8d0e2f4a6c8d0e2f4a6",
    "signature": "",
    "permissions": ["read_file"],
    "publisher": "unverified-dev",
}

TYPOSQUAT_MANIFEST = {
    "name": "gmial-organizer",  # typosquat of "gmail-organizer"
    "version": "1.0.0",
    "content_hash": "c5f7c9d0e2f4a6c8d0e2f4a6c8d0e2f4a6c8d0e2f4a6c8d0e2f4a6c8d0e2f4a6",
    "signature": "ed25519:VALID_SIGNATURE_PLACEHOLDER",
    "permissions": ["read_email"],
    "publisher": "trusted-dev-001",
}


class TestManifestValidation:
    """Every skill must have a complete, well-formed manifest before vetting can proceed."""

    def test_valid_manifest_passes_structure_check(self):
        from modules.skill_vetting.vetting import validate_manifest_structure
        assert validate_manifest_structure(SAFE_MANIFEST) is True

    def test_missing_content_hash_fails_structure_check(self):
        from modules.skill_vetting.vetting import validate_manifest_structure
        assert validate_manifest_structure(MALICIOUS_MANIFEST) is False

    def test_missing_required_field_fails(self):
        from modules.skill_vetting.vetting import validate_manifest_structure
        incomplete = {"name": "x"}
        assert validate_manifest_structure(incomplete) is False


class TestSignatureVerification:
    """AST01/AST02: skills must be ed25519-signed before they're trusted."""

    def test_signed_skill_passes_signature_check(self):
        from modules.skill_vetting.vetting import has_valid_signature
        assert has_valid_signature(SAFE_MANIFEST, trusted_publishers={"trusted-dev-001"}) is True

    def test_unsigned_skill_fails_signature_check(self):
        from modules.skill_vetting.vetting import has_valid_signature
        assert has_valid_signature(UNSIGNED_MANIFEST, trusted_publishers={"trusted-dev-001"}) is False

    def test_signed_but_untrusted_publisher_fails(self):
        from modules.skill_vetting.vetting import has_valid_signature
        manifest = dict(SAFE_MANIFEST, publisher="random-unverified-account")
        assert has_valid_signature(manifest, trusted_publishers={"trusted-dev-001"}) is False


class TestContentHashPinning(object):
    """AST07: dependencies must be pinned to immutable hashes, never version ranges."""

    def test_hash_pinned_manifest_passes(self):
        from modules.skill_vetting.vetting import has_pinned_hash
        assert has_pinned_hash(SAFE_MANIFEST) is True

    def test_empty_hash_fails(self):
        from modules.skill_vetting.vetting import has_pinned_hash
        assert has_pinned_hash(MALICIOUS_MANIFEST) is False

    def test_hash_mismatch_detected(self):
        from modules.skill_vetting.vetting import verify_content_hash
        actual_content = b"the actual skill bytes"
        wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        assert verify_content_hash(actual_content, wrong_hash) is False

    def test_hash_match_verified(self):
        from modules.skill_vetting.vetting import verify_content_hash
        import hashlib
        content = b"the actual skill bytes"
        correct_hash = hashlib.sha256(content).hexdigest()
        assert verify_content_hash(content, correct_hash) is True


class TestPermissionManifestScanning:
    """AST03: least privilege — flag skills requesting excessive/dangerous permissions."""

    def test_minimal_permissions_pass(self):
        from modules.skill_vetting.vetting import scan_permissions
        result = scan_permissions(SAFE_MANIFEST["permissions"])
        assert result.risk_level == "low"

    def test_dangerous_permission_combination_flagged(self):
        """The 'lethal trifecta': private data access + untrusted content + network egress."""
        from modules.skill_vetting.vetting import scan_permissions
        result = scan_permissions(MALICIOUS_MANIFEST["permissions"])
        assert result.risk_level == "critical"
        assert "escalate_privileges" in result.flagged_permissions

    def test_exfiltration_permission_always_critical(self):
        from modules.skill_vetting.vetting import scan_permissions
        result = scan_permissions(["exfiltrate_data"])
        assert result.risk_level == "critical"


class TestTyposquatDetection:
    """OWASP example: 'Typosquatted tool in marketplace.'"""

    def test_typosquat_detected_against_known_skills(self):
        from modules.skill_vetting.vetting import detect_typosquat
        known_skills = {"gmail-organizer", "calendar-sync", "slack-notify"}
        result = detect_typosquat("gmial-organizer", known_skills)
        assert result is not None
        assert result == "gmail-organizer"

    def test_exact_match_is_not_a_typosquat(self):
        from modules.skill_vetting.vetting import detect_typosquat
        known_skills = {"gmail-organizer"}
        assert detect_typosquat("gmail-organizer", known_skills) is None

    def test_unrelated_name_is_not_flagged(self):
        from modules.skill_vetting.vetting import detect_typosquat
        known_skills = {"gmail-organizer"}
        assert detect_typosquat("completely-different-tool", known_skills) is None


class TestSkillVettingService:
    """Full vetting pipeline combining all checks into one verdict."""

    def test_vet_safe_skill_approves(self):
        from modules.skill_vetting.vetting import SkillVettingService
        svc = SkillVettingService(trusted_publishers={"trusted-dev-001"})
        verdict = svc.vet(SAFE_MANIFEST)
        assert verdict.approved is True

    def test_vet_malicious_skill_rejects(self):
        from modules.skill_vetting.vetting import SkillVettingService
        svc = SkillVettingService(trusted_publishers={"trusted-dev-001"})
        verdict = svc.vet(MALICIOUS_MANIFEST)
        assert verdict.approved is False
        assert len(verdict.reasons) > 0

    def test_vet_unsigned_skill_rejects(self):
        from modules.skill_vetting.vetting import SkillVettingService
        svc = SkillVettingService(trusted_publishers={"trusted-dev-001"})
        verdict = svc.vet(UNSIGNED_MANIFEST)
        assert verdict.approved is False
        assert any("signature" in r.lower() for r in verdict.reasons)

    def test_vet_typosquat_against_known_registry_rejects(self):
        from modules.skill_vetting.vetting import SkillVettingService
        svc = SkillVettingService(
            trusted_publishers={"trusted-dev-001"},
            known_skills={"gmail-organizer"},
        )
        verdict = svc.vet(TYPOSQUAT_MANIFEST)
        assert verdict.approved is False
        assert any("typosquat" in r.lower() for r in verdict.reasons)

    def test_vetting_history_tracked(self):
        from modules.skill_vetting.vetting import SkillVettingService
        svc = SkillVettingService(trusted_publishers={"trusted-dev-001"})
        svc.vet(SAFE_MANIFEST)
        svc.vet(MALICIOUS_MANIFEST)
        assert len(svc.history) == 2
