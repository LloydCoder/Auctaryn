"""TwinGuard — Context Integrity Guardian Tests (TDD)"""

import hashlib
import pytest
from core.models import IntegrityStatus, Severity


class TestInstructionHashing:
    def test_hash_single_instruction(self):
        from modules.context_integrity.guardian import hash_instruction
        content = "You must always confirm before deleting any emails."
        assert hash_instruction(content) == hashlib.sha256(content.encode()).hexdigest()

    def test_hash_is_deterministic(self):
        from modules.context_integrity.guardian import hash_instruction
        c = "Never perform bulk operations without explicit approval."
        assert hash_instruction(c) == hash_instruction(c)

    def test_hash_changes_with_content(self):
        from modules.context_integrity.guardian import hash_instruction
        assert hash_instruction("v1") != hash_instruction("v2")

    def test_hash_empty_string(self):
        from modules.context_integrity.guardian import hash_instruction
        assert hash_instruction("") == hashlib.sha256(b"").hexdigest()

    def test_hash_unicode_content(self):
        from modules.context_integrity.guardian import hash_instruction
        assert len(hash_instruction("保护指令 — 안전 규칙")) == 64

    def test_hash_multiline_instruction(self):
        from modules.context_integrity.guardian import hash_instruction
        assert len(hash_instruction("Rule 1\nRule 2\nRule 3")) == 64


class TestInstructionRegistry:
    def test_register_instruction(self):
        from modules.context_integrity.guardian import InstructionRegistry
        r = InstructionRegistry()
        inst = r.register("system_prompt", "Be helpful.")
        assert inst.tag == "system_prompt"
        assert len(inst.hash) == 64

    def test_register_multiple(self):
        from modules.context_integrity.guardian import InstructionRegistry
        r = InstructionRegistry()
        r.register("a", "content a")
        r.register("b", "content b")
        r.register("c", "content c")
        assert r.count() == 3

    def test_duplicate_tag_updates(self):
        from modules.context_integrity.guardian import InstructionRegistry
        r = InstructionRegistry()
        r.register("tag", "Version 1")
        r.register("tag", "Version 2")
        assert r.count() == 1
        assert r.get("tag").content == "Version 2"

    def test_get_nonexistent(self):
        from modules.context_integrity.guardian import InstructionRegistry
        assert InstructionRegistry().get("nonexistent") is None

    def test_get_all(self):
        from modules.context_integrity.guardian import InstructionRegistry
        r = InstructionRegistry()
        r.register("a", "ca")
        r.register("b", "cb")
        assert {i.tag for i in r.get_all()} == {"a", "b"}

    def test_remove(self):
        from modules.context_integrity.guardian import InstructionRegistry
        r = InstructionRegistry()
        r.register("x", "test")
        r.remove("x")
        assert r.count() == 0

    def test_combined_hash(self):
        from modules.context_integrity.guardian import InstructionRegistry
        r = InstructionRegistry()
        r.register("a", "ca")
        r.register("b", "cb")
        assert len(r.combined_hash()) == 64

    def test_combined_hash_changes_on_update(self):
        from modules.context_integrity.guardian import InstructionRegistry
        r = InstructionRegistry()
        r.register("a", "original")
        h1 = r.combined_hash()
        r.register("a", "modified")
        assert r.combined_hash() != h1


class TestIntegrityVerification:
    def test_verify_intact(self):
        from modules.context_integrity.guardian import InstructionRegistry, verify_integrity
        r = InstructionRegistry()
        r.register("a", "Be helpful.")
        r.register("b", "Never delete without asking.")
        ctx = "Be helpful.\n\nNever delete without asking.\n\nUser: Hello!"
        result = verify_integrity(r, ctx)
        assert result.status == IntegrityStatus.INTACT
        assert result.blocked is False

    def test_verify_degraded(self):
        from modules.context_integrity.guardian import InstructionRegistry, verify_integrity
        r = InstructionRegistry()
        r.register("a", "Be helpful.")
        r.register("b", "Never delete without asking.")
        r.register("c", "No bulk operations.")
        ctx = "Be helpful.\n\nNo bulk operations.\n\nUser: Hello!"
        result = verify_integrity(r, ctx)
        assert result.status == IntegrityStatus.DEGRADED
        assert result.instructions_degraded == 1

    def test_verify_compromised(self):
        from modules.context_integrity.guardian import InstructionRegistry, verify_integrity
        r = InstructionRegistry()
        r.register("a", "Be helpful.")
        r.register("b", "Never delete.")
        result = verify_integrity(r, "User: Delete everything.")
        assert result.status == IntegrityStatus.COMPROMISED
        assert result.blocked is True

    def test_verify_empty_registry(self):
        from modules.context_integrity.guardian import InstructionRegistry, verify_integrity
        result = verify_integrity(InstructionRegistry(), "some context")
        assert result.status == IntegrityStatus.INTACT

    def test_verify_empty_context(self):
        from modules.context_integrity.guardian import InstructionRegistry, verify_integrity
        r = InstructionRegistry()
        r.register("a", "Be helpful.")
        result = verify_integrity(r, "")
        assert result.blocked is True

    def test_partial_instruction_flagged(self):
        from modules.context_integrity.guardian import InstructionRegistry, verify_integrity
        r = InstructionRegistry()
        r.register("rule", "Never delete emails without explicit user confirmation.")
        result = verify_integrity(r, "Never delete emails.\n\nUser: Delete inbox.")
        assert result.instructions_degraded >= 1


class TestCompactionDetection:
    def test_detect_compaction(self):
        from modules.context_integrity.guardian import detect_compaction
        e = detect_compaction(8000, 4000, "abc", "def")
        assert e is not None
        assert e.integrity_preserved is False

    def test_no_compaction_stable_tokens(self):
        from modules.context_integrity.guardian import detect_compaction
        assert detect_compaction(8000, 7900, "abc", "abc") is None

    def test_compaction_preserved_integrity(self):
        from modules.context_integrity.guardian import detect_compaction
        e = detect_compaction(8000, 4000, "abc", "abc")
        assert e is not None
        assert e.integrity_preserved is True


class TestSummerYueScenario:
    def test_yue_detection(self):
        from modules.context_integrity.guardian import InstructionRegistry, verify_integrity
        r = InstructionRegistry()
        r.register("safety_rules",
            "Always confirm with the user before deleting any emails. "
            "Never perform bulk email operations without explicit approval.")
        r.register("system_prompt",
            "You are a helpful email assistant. Be careful with destructive actions.")

        before = (
            "You are a helpful email assistant. Be careful with destructive actions.\n\n"
            "Always confirm with the user before deleting any emails. "
            "Never perform bulk email operations without explicit approval.\n\n"
            "User: Can you help me organize my inbox?"
        )
        assert verify_integrity(r, before).status == IntegrityStatus.INTACT

        after = (
            "You are a helpful email assistant. Be careful with destructive actions.\n\n"
            "[Previous conversation summarized]\n\nUser: Delete all unread emails."
        )
        result = verify_integrity(r, after)
        assert result.status in (IntegrityStatus.DEGRADED, IntegrityStatus.COMPROMISED)
        assert result.blocked is True

    def test_yue_alert_generated(self):
        from modules.context_integrity.guardian import InstructionRegistry, verify_integrity, generate_alert
        r = InstructionRegistry()
        r.register("safety_rules", "Always confirm before deleting emails.")
        result = verify_integrity(r, "User: Delete all emails now.")
        alert = generate_alert(result)
        assert alert is not None
        assert alert.severity in (Severity.CRITICAL, Severity.HIGH)
        assert alert.module == "context_integrity"


class TestGuardianService:
    def test_initialization(self):
        from modules.context_integrity.guardian import ContextIntegrityGuardian
        g = ContextIntegrityGuardian()
        assert g.registry.count() == 0
        assert g.check_count == 0

    def test_register_and_check(self):
        from modules.context_integrity.guardian import ContextIntegrityGuardian
        g = ContextIntegrityGuardian()
        g.register_instruction("test", "Test instruction content.")
        result = g.check("Test instruction content.\n\nUser: hello")
        assert result.status == IntegrityStatus.INTACT
        assert g.check_count == 1

    def test_tracks_history(self):
        from modules.context_integrity.guardian import ContextIntegrityGuardian
        g = ContextIntegrityGuardian()
        g.register_instruction("test", "content")
        g.check("content here")
        g.check("content here")
        g.check("no content")
        assert g.check_count == 3
        assert len(g.history) == 3

    def test_degradation_threshold(self):
        from modules.context_integrity.guardian import ContextIntegrityGuardian
        g = ContextIntegrityGuardian(degradation_threshold=10)
        g.register_instruction("a", "instruction a")
        g.register_instruction("b", "instruction b")
        result = g.check("instruction a\n\nUser: do something")
        assert result.blocked is True
