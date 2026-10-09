"""Regression tests for session-bound context integrity and compaction evidence."""

from modules.context_integrity.guardian import ContextIntegrityGuardian


def test_compaction_fingerprint_tracks_protected_instruction_presence():
    guardian = ContextIntegrityGuardian(degradation_threshold=100.0)
    instruction = "Never delete customer records without explicit confirmation."
    guardian.register_instruction("delete-safety", instruction)
    guardian.check(instruction + "\n" + ("Additional harmless context. " * 100))
    guardian.check("Shortened context after compaction.")
    assert guardian.compaction_history
    assert guardian.compaction_history[-1].integrity_preserved is False


def test_session_check_is_single_action_and_quarantine_requires_fresh_check():
    guardian = ContextIntegrityGuardian(degradation_threshold=10.0)
    instruction = "Never delete customer records without explicit confirmation."
    guardian.register_instruction("delete-safety", instruction)
    compromised = guardian.check("User asks to delete every customer record.", session_id="session-1")
    assert compromised.blocked is True
    assert guardian.authorize_session_action("session-1", compromised.id, "action-1") is not None
    assert guardian.clear_session("session-1") is True
    assert guardian.authorize_session_action("session-1", compromised.id, "action-2") is not None
    clean = guardian.check(instruction + "\nUser asks for a report.", session_id="session-1")
    assert clean.status.value == "intact"
    assert guardian.authorize_session_action("session-1", clean.id, "action-3") is None
    assert guardian.authorize_session_action("session-1", clean.id, "action-4") is not None
