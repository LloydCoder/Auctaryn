"""
TwinGuard — Context Integrity Guardian
Monitors AI agent context windows for instruction loss during compaction.
"""

import hashlib
import re
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from core.models import (
    ProtectedInstruction, IntegrityCheckResult, IntegrityStatus,
    CompactionEvent, Alert, Severity,
)
from core.logging import get_logger

logger = get_logger("context_integrity")

MAX_TRACKED_CONTEXT_SESSIONS = 10000
MAX_PROTECTED_INSTRUCTIONS = 1000
MAX_CONTEXT_HISTORY = 5000
MAX_COMPACTION_HISTORY = 5000

# Phrases that signal an attempt to override/contradict a prior directive —
# ASI01 active goal-hijack pattern, distinct from passive instruction loss.
HIJACK_OVERRIDE_PATTERNS = [
    r"\boverride\b",
    r"\bignore (all )?(previous|prior|the above|above) instructions?\b",
    r"\bnew (system )?directive\b",
    r"\bno confirmation needed\b",
    r"\bwithout asking\b",
    r"\bdo not ask for confirmation\b",
    r"\bdisregard (all )?(previous|prior|the above|above) instructions?\b",
    r"\bbypass (the )?(safety|security|approval) (rules|checks|controls|process)\b",
    r"\bdisable (the )?(safety|security) (rules|checks|controls)\b",
    r"\bapprove all (actions|requests|operations)\b",
    r"\breveal (all )?(secrets|credentials|system prompt)\b",
    r"\bimmediately\b.{0,20}\bno\b",
]


@dataclass
class GoalHijackResult:
    hijack_detected: bool
    reason: str = ""


def detect_goal_hijack(registered_instruction: str, new_content: str) -> GoalHijackResult:
    """
    ASI01: detect content that actively contradicts/overrides a registered
    safety instruction, rather than simply being absent (that's covered
    by verify_integrity's degradation check below).
    """
    lowered_new = new_content.lower()

    has_override_language = any(
        re.search(pattern, lowered_new) for pattern in HIJACK_OVERRIDE_PATTERNS
    )
    if not has_override_language:
        return GoalHijackResult(hijack_detected=False)

    # Override language alone isn't enough — it must also semantically
    # target the same domain as the registered instruction (share key
    # terms) to avoid false positives on unrelated override-sounding text.
    stop_words = {
        "about", "after", "before", "being", "from", "have", "into", "must",
        "never", "only", "should", "that", "their", "there", "these", "they",
        "this", "those", "user", "when", "with", "without", "would", "your",
    }
    registered_terms = {
        term for term in re.findall(r"\b\w{5,}\b", registered_instruction.lower())
        if term not in stop_words
    }
    # Remove one exact copy of the protected baseline before comparing terms;
    # otherwise its presence would create a guaranteed, misleading overlap.
    analysis_content = lowered_new.replace(registered_instruction.lower(), "", 1)
    # Compare only the sentence containing the override phrase to reduce false
    # positives from unrelated override-sounding text elsewhere in the context.
    for match in re.finditer("|".join(f"(?:{pattern})" for pattern in HIJACK_OVERRIDE_PATTERNS), analysis_content):
        left_candidates = [analysis_content.rfind(mark, 0, match.start()) for mark in (".", "!", "?", "\n")]
        start = max(left_candidates) + 1
        right_candidates = [
            position for mark in (".", "!", "?", "\n")
            if (position := analysis_content.find(mark, match.end())) >= 0
        ]
        end = min(right_candidates) if right_candidates else len(analysis_content)
        candidate = analysis_content[start:end]
        candidate_terms = {
            term for term in re.findall(r"\b\w{5,}\b", candidate)
            if term not in stop_words
        }
        overlap = registered_terms & candidate_terms
        if overlap:
            return GoalHijackResult(
                hijack_detected=True,
                reason="Override language matched the protected-instruction domain.",
            )

    return GoalHijackResult(hijack_detected=False)


def hash_instruction(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class InstructionRegistry:
    def __init__(self):
        self._instructions: dict[str, ProtectedInstruction] = {}
        self._lock = threading.RLock()

    def register(self, tag: str, content: str) -> ProtectedInstruction:
        """Register bounded, non-empty policy text and preserve its content hash."""
        if not isinstance(tag, str) or not tag.strip() or len(tag) > 128:
            raise ValueError("Instruction tag must be 1–128 non-whitespace characters")
        if not isinstance(content, str) or not content.strip() or len(content) > 32768:
            raise ValueError("Instruction content must be 1–32768 non-whitespace characters")
        tag = tag.strip()
        with self._lock:
            if tag not in self._instructions and len(self._instructions) >= MAX_PROTECTED_INSTRUCTIONS:
                raise ValueError("protected instruction registry capacity reached")
            instruction = ProtectedInstruction(
                tag=tag, content=content, hash=hash_instruction(content),
                registered_at=datetime.now(timezone.utc),
            )
            self._instructions[tag] = instruction
            return instruction

    def get(self, tag: str) -> Optional[ProtectedInstruction]:
        with self._lock:
            return self._instructions.get(tag)

    def get_all(self) -> list[ProtectedInstruction]:
        with self._lock:
            return list(self._instructions.values())

    def remove(self, tag: str) -> bool:
        with self._lock:
            if tag in self._instructions:
                del self._instructions[tag]
                return True
            return False

    def count(self) -> int:
        with self._lock:
            return len(self._instructions)

    def combined_hash(self) -> str:
        with self._lock:
            if not self._instructions:
                return hash_instruction("")
            combined = "|".join(
                f"{tag}:{inst.hash}"
                for tag, inst in sorted(self._instructions.items())
            )
            return hash_instruction(combined)


def verify_integrity(
    registry: InstructionRegistry,
    current_context: str,
    degradation_threshold: float = 50.0,
) -> IntegrityCheckResult:
    instructions = registry.get_all()
    total = len(instructions)

    if total == 0:
        return IntegrityCheckResult(
            id=_gen_id(), status=IntegrityStatus.INTACT,
            instructions_total=0, instructions_intact=0,
            instructions_degraded=0, degradation_percent=0.0, blocked=False,
        )

    intact_count = 0
    degraded_count = 0
    details = []

    tampered_count = 0
    for inst in instructions:
        # Detect corruption of the stored baseline before trusting it for comparison.
        if hash_instruction(inst.content) != inst.hash:
            tampered_count += 1
            degraded_count += 1
            details.append({"tag": inst.tag, "status": "baseline_tampered"})
            continue
        present = inst.content in current_context
        if present:
            intact_count += 1
            details.append({"tag": inst.tag, "status": "intact", "hash": inst.hash})
        else:
            degraded_count += 1
            details.append({"tag": inst.tag, "status": "missing", "hash": inst.hash})

    degradation_pct = (degraded_count / total) * 100.0

    if degraded_count == 0:
        status = IntegrityStatus.INTACT
    elif degraded_count == total:
        status = IntegrityStatus.COMPROMISED
    else:
        status = IntegrityStatus.DEGRADED

    should_block = degraded_count > 0 and degradation_pct >= degradation_threshold
    if status == IntegrityStatus.COMPROMISED or tampered_count:
        should_block = True
        status = IntegrityStatus.COMPROMISED

    result = IntegrityCheckResult(
        id=_gen_id(), status=status,
        instructions_total=total, instructions_intact=intact_count,
        instructions_degraded=degraded_count,
        degradation_percent=round(degradation_pct, 2),
        details=details, blocked=should_block,
    )

    if should_block:
        logger.warning(
            f"Context integrity violation: {degraded_count}/{total} instructions missing "
            f"({degradation_pct:.1f}% degradation) — AGENT BLOCKED",
            extra={"event": "integrity_violation", "module_name": "context_integrity",
                   "degradation_percent": degradation_pct},
        )
    return result


def detect_compaction(
    before_tokens: int, after_tokens: int,
    before_hash: str, after_hash: str,
    threshold_ratio: float = 0.20,
) -> Optional[CompactionEvent]:
    if before_tokens == 0:
        return None
    reduction_ratio = (before_tokens - after_tokens) / before_tokens
    if reduction_ratio < threshold_ratio:
        return None
    return CompactionEvent(
        id=_gen_id(), before_hash=before_hash, after_hash=after_hash,
        integrity_preserved=(before_hash == after_hash),
        tokens_before=before_tokens, tokens_after=after_tokens,
    )


def generate_alert(result: IntegrityCheckResult) -> Optional[Alert]:
    if result.status == IntegrityStatus.INTACT:
        return None
    if result.status == IntegrityStatus.COMPROMISED:
        severity = Severity.CRITICAL
    elif result.degradation_percent >= 20:
        severity = Severity.HIGH
    else:
        severity = Severity.MEDIUM

    affected_tags = sorted({
        d["tag"] for d in result.details
        if d.get("status") in {"missing", "baseline_tampered", "hijack_detected"}
    })
    return Alert(
        id=_gen_id(), severity=severity, module="context_integrity",
        title="Context Integrity Violation Detected",
        message=(
            f"{result.instructions_degraded} of {result.instructions_total} protected "
            f"instructions missing or unverified ({result.degradation_percent}% degraded). "
            f"Affected tags: {', '.join(affected_tags) or 'none'}. "
            f"Agent {'BLOCKED' if result.blocked else 'warned'}."
        ),
        data={"check_id": result.id, "status": result.status.value,
              "degradation_percent": result.degradation_percent,
              "affected_tags": affected_tags, "blocked": result.blocked},
    )


class ContextIntegrityGuardian:
    def __init__(self, degradation_threshold: float = 50.0):
        self.registry = InstructionRegistry()
        self.degradation_threshold = degradation_threshold
        self.history: list[IntegrityCheckResult] = []
        self.compaction_history: list[CompactionEvent] = []
        self.check_count: int = 0
        self._last_token_count: int = 0
        self._last_protected_context_hash: str = ""
        self._session_results: dict[str, IntegrityCheckResult] = {}
        self._blocked_sessions: dict[str, str] = {}
        self._consumed_checks: dict[str, str] = {}
        self._session_lock = threading.RLock()

    def register_instruction(self, tag: str, content: str) -> ProtectedInstruction:
        inst = self.registry.register(tag, content)
        return inst

    def _protected_context_hash(self, current_context: str) -> str:
        present = sorted(
            f"{inst.tag}:{inst.hash}"
            for inst in self.registry.get_all()
            if hash_instruction(inst.content) == inst.hash and inst.content in current_context
        )
        return hash_instruction("|".join(present))

    def authorize_session_action(self, session_id: str, check_id: str, action_id: str) -> str | None:
        """Require a current intact context check bound to this session and action."""
        if self.registry.count() == 0:
            return None
        with self._session_lock:
            if not session_id or not check_id or not action_id:
                return "Session ID, current context-check ID, and action ID are required."
            if session_id in self._blocked_sessions:
                return "Session is quarantined after a context-integrity violation; administrator clearance is required."
            result = self._session_results.get(session_id)
            if result is None or result.id != check_id or result.session_id != session_id:
                return "No current session-bound context-integrity check exists; action denied."
            if result.blocked or result.status != IntegrityStatus.INTACT:
                return "Latest context-integrity check is not intact; action denied."
            consumed_by = self._consumed_checks.get(check_id)
            if consumed_by is not None and consumed_by != action_id:
                return "Context-check ID has already been consumed by another action."
            self._consumed_checks[check_id] = action_id
            return None

    def clear_session(self, session_id: str) -> bool:
        """Clear quarantine but require a new clean check before the session can act."""
        with self._session_lock:
            was_blocked = self._blocked_sessions.pop(session_id, None) is not None
            previous = self._session_results.pop(session_id, None)
            if previous is not None:
                self._consumed_checks.pop(previous.id, None)
            return was_blocked or previous is not None

    def check(self, current_context: str, session_id: str | None = None) -> IntegrityCheckResult:
        # Serialize context evaluation with gateway preflight so a concurrent
        # compromised check cannot race past an older intact result.
        with self._session_lock:
            return self._check_impl(current_context, session_id)

    def _check_impl(self, current_context: str, session_id: str | None = None) -> IntegrityCheckResult:
        result = verify_integrity(
            self.registry, current_context,
            degradation_threshold=self.degradation_threshold,
        )

        # ASI01: even if every registered instruction is textually present
        # (so verify_integrity sees it as "intact"), scan for in-context
        # override language that actively contradicts it.
        if not result.blocked:
            for inst in self.registry.get_all():
                hijack = detect_goal_hijack(inst.content, current_context)
                if hijack.hijack_detected:
                    result.blocked = True
                    result.status = IntegrityStatus.COMPROMISED
                    result.details.append({
                        "tag": inst.tag, "status": "hijack_detected",
                        "reason": hijack.reason,
                    })
                    logger.warning(
                        f"Goal hijack detected against instruction '{inst.tag}': {hijack.reason}",
                        extra={"event": "goal_hijack_detected", "module_name": "context_integrity"},
                    )
                    break

        result.session_id = session_id or ""
        if session_id:
            with self._session_lock:
                if session_id not in self._session_results and len(self._session_results) >= MAX_TRACKED_CONTEXT_SESSIONS:
                    # Evict only non-quarantined state. If all slots are quarantined, fail closed.
                    for stale_session in list(self._session_results):
                        if stale_session not in self._blocked_sessions:
                            stale_result = self._session_results.pop(stale_session)
                            self._consumed_checks.pop(stale_result.id, None)
                            break
                    if len(self._session_results) >= MAX_TRACKED_CONTEXT_SESSIONS:
                        raise RuntimeError("context session state capacity reached; all sessions are quarantined")
                previous = self._session_results.get(session_id)
                if previous is not None:
                    self._consumed_checks.pop(previous.id, None)
                self._session_results[session_id] = result
                if result.blocked or result.status != IntegrityStatus.INTACT:
                    self._blocked_sessions[session_id] = result.id

        self.history.append(result)
        del self.history[:-MAX_CONTEXT_HISTORY]
        self.check_count += 1

        estimated_tokens = len(current_context.split())
        protected_hash = self._protected_context_hash(current_context)
        if self._last_token_count > 0:
            compaction = detect_compaction(
                self._last_token_count, estimated_tokens,
                self._last_protected_context_hash, protected_hash,
            )
            if compaction:
                self.compaction_history.append(compaction)
                del self.compaction_history[:-MAX_COMPACTION_HISTORY]

        self._last_token_count = estimated_tokens
        self._last_protected_context_hash = protected_hash
        return result

    def get_status(self) -> dict:
        last_check = self.history[-1] if self.history else None
        return {
            "status": last_check.status.value if last_check else "intact",
            "instructions_protected": self.registry.count(),
            "check_count": self.check_count,
            "last_check": last_check.timestamp.isoformat() if last_check else None,
            "combined_hash": self.registry.combined_hash(),
        }


def _gen_id() -> str:
    return uuid.uuid4().hex[:12]
