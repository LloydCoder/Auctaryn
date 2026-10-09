"""
TwinGuard — Step-Up Authentication
Maps to OWASP ASI09:2026 — Human-Agent Trust Exploitation.

OWASP mitigation guidance: "When an agent suggests something irreversible
... trigger a fresh MFA challenge. This forces a period where the human
has to step outside the chat and confirm the action."

This module doesn't implement actual MFA (that's an identity-provider
integration, out of scope for TwinGuard core) — it implements the
freshness/single-use CONTRACT that any MFA integration must honor:
a challenge issued for one decision can't be silently reused, replayed,
or confirmed outside its freshness window.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from core.logging import get_logger

logger = get_logger("step_up_auth")

DEFAULT_FRESHNESS_WINDOW_SECONDS = 120

# Risk levels that require step-up confirmation before an approval is honored.
STEP_UP_REQUIRED_LEVELS = {"destructive", "critical"}


@dataclass
class StepUpChallenge:
    challenge_id: str
    decision_id: str
    issued_at: datetime
    expires_at: datetime
    consumed: bool = False


@dataclass
class StepUpResult:
    valid: bool
    reason: str = ""


def requires_step_up(risk_level: str) -> bool:
    """Irreversible/high-risk decisions require step-up confirmation."""
    return risk_level in STEP_UP_REQUIRED_LEVELS


class StepUpAuthenticator:
    """
    Issues single-use, time-windowed confirmation challenges tied to a
    specific gateway decision. An approval is only honored if it arrives
    via a freshly-confirmed challenge — not a stale or replayed one.
    """

    def __init__(self, freshness_window_seconds: int = DEFAULT_FRESHNESS_WINDOW_SECONDS):
        self.freshness_window_seconds = freshness_window_seconds
        self._challenges: dict[str, StepUpChallenge] = {}

    def issue_challenge(self, decision_id: str) -> StepUpChallenge:
        now = datetime.now(timezone.utc)
        challenge = StepUpChallenge(
            challenge_id=uuid.uuid4().hex,
            decision_id=decision_id,
            issued_at=now,
            expires_at=now + timedelta(seconds=self.freshness_window_seconds),
        )
        self._challenges[challenge.challenge_id] = challenge
        logger.info(f"Step-up challenge issued for decision {decision_id}",
                   extra={"event": "step_up_issued", "module_name": "step_up_auth"})
        return challenge

    def confirm(self, challenge_id: str, confirmed_at: datetime) -> StepUpResult:
        challenge = self._challenges.get(challenge_id)
        if challenge is None:
            return StepUpResult(valid=False, reason="Unknown or invalid challenge")

        if challenge.consumed:
            return StepUpResult(valid=False, reason="Challenge already consumed")

        if confirmed_at > challenge.expires_at:
            return StepUpResult(valid=False, reason="Confirmation outside freshness window — stale")

        challenge.consumed = True
        logger.info(f"Step-up challenge confirmed: {challenge_id}",
                   extra={"event": "step_up_confirmed", "module_name": "step_up_auth"})
        return StepUpResult(valid=True)
