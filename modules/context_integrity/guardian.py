"""
TwinGuard — Context Integrity Guardian
Monitors AI agent context windows for instruction loss during compaction.
"""

import hashlib
import re
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
    # Compare only the sentence containing the override phrase. Comparing the
    # whole context would always overlap with a protected instruction that is
    # still present, producing false positives for unrelated quoted content.
    for match in re.finditer("|".join(f"(?:{pattern})" for pattern in HIJACK_OVERRIDE_PATTERNS), lowered_new):
        left_candidates = [lowered_new.rfind(mark, 0, match.start()) for mark in (".", "!", "?", "\n")]
        start = max(left_candidates) + 1
        right_candidates = [
            position for mark in (".", "!", "?", "\n")
            if (position := lowered_new.find(mark, match.end())) >= 0
        ]
        end = min(right_candidates) if right_candidates else len(lowered_new)
        candidate = lowered_new[start:end]
        candidate_terms = {
            term for term in re.findall(r"\b\w{5,}\b", candidate)
            if term not in stop_words
        }
        overlap = registered_terms & candidate_terms
        if overlap:
            return GoalHijackResult(
                hijack_detected=True,
                reason="Override language targets protected instruction terms: "
                + ", ".join(sorted(overlap)),
            )

    return GoalHijackResult(hijack_detected=False)


def hash_instruction(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class InstructionRegistry:
    def __init__(self):
        self._instructions: dict[str, ProtectedInstruction] = {}

    def register(self, tag: str, content: str) -> ProtectedInstruction:
        """Register bounded, non-empty policy text and preserve its content hash."""
        if not isinstance(tag, str) or not tag.strip() or len(tag) > 128:
            raise ValueError("Instruction tag must be 1–128 non-whitespace characters")
        if not isinstance(content, str) or not content.strip() or len(content) > 32768:
            raise ValueError("Instruction content must be 1–32768 non-whitespace characters")
        tag = tag.strip()
        instruction = ProtectedInstruction(
            tag=tag, content=content, hash=hash_instruction(content),
            registered_at=datetime.now(timezone.utc),
        )
        self._instructions[tag] = instruction
        return instruction

    def get(self, tag: str) -> Optional[ProtectedInstruction]:
        return self._instructions.get(tag)

    def get_all(self) -> list[ProtectedInstruction]:
        return list(self._instructions.values())

    def remove(self, tag: str) -> bool:
        if tag in self._instructions:
            del self._instructions[tag]
            return True
        return False

    def count(self) -> int:
        return len(self._instructions)

    def combined_hash(self) -> str:
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

    missing_tags = [d["tag"] for d in result.details if d.get("status") == "missing"]
    return Alert(
        id=_gen_id(), severity=severity, module="context_integrity",
        title="Context Integrity Violation Detected",
        message=(
            f"{result.instructions_degraded} of {result.instructions_total} protected "
            f"instructions missing ({result.degradation_percent}% degradation). "
            f"Missing: {', '.join(missing_tags)}. "
            f"Agent {'BLOCKED' if result.blocked else 'warned'}."
        ),
        data={"check_id": result.id, "status": result.status.value,
              "degradation_percent": result.degradation_percent,
              "missing_tags": missing_tags, "blocked": result.blocked},
    )


class ContextIntegrityGuardian:
    def __init__(self, degradation_threshold: float = 50.0):
        self.registry = InstructionRegistry()
        self.degradation_threshold = degradation_threshold
        self.history: list[IntegrityCheckResult] = []
        self.compaction_history: list[CompactionEvent] = []
        self.check_count: int = 0
        self._last_token_count: int = 0
        self._last_combined_hash: str = ""

    def register_instruction(self, tag: str, content: str) -> ProtectedInstruction:
        inst = self.registry.register(tag, content)
        self._last_combined_hash = self.registry.combined_hash()
        return inst

    def check(self, current_context: str) -> IntegrityCheckResult:
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

        self.history.append(result)
        self.check_count += 1

        estimated_tokens = len(current_context.split())
        if self._last_token_count > 0:
            current_hash = self.registry.combined_hash()
            compaction = detect_compaction(
                self._last_token_count, estimated_tokens,
                self._last_combined_hash, current_hash,
            )
            if compaction:
                self.compaction_history.append(compaction)

        self._last_token_count = estimated_tokens
        self._last_combined_hash = self.registry.combined_hash()
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
