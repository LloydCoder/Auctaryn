"""
TwinGuard — Agent Circuit Breaker
Maps to OWASP ASI08:2026 — Cascading Agent Failures.

A repeatedly-failing or erratic agent must be isolated before it can
flood the Execution Gateway, corrupt shared state, or — per OWASP's
"failure propagation patterns" — drag dependent sub-agents down with it.

Each agent has its own independent breaker (per-agent isolation — one
agent tripping never blocks an unrelated agent). Dependency edges allow
a parent's trip to cascade to children it spawned/delegated to, which
is the intentional, contained version of cascade: stopping the blast
radius from spreading further, not letting it spread uncontrolled.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from core.logging import get_logger

logger = get_logger("inter_agent.circuit_breaker")

DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_COOLDOWN_SECONDS = 60


@dataclass
class _BreakerState:
    failure_count: int = 0
    tripped_at: datetime | None = None


class AgentCircuitBreaker:
    """
    Per-agent failure tracking with automatic cooldown recovery and
    dependency-aware cascade isolation.
    """

    def __init__(self, failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
                 cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._states: dict[str, _BreakerState] = {}
        self._dependencies: dict[str, str] = {}  # child_agent_id -> parent_agent_id

    def _get_state(self, agent_id: str) -> _BreakerState:
        return self._states.setdefault(agent_id, _BreakerState())

    def record_failure(self, agent_id: str) -> None:
        state = self._get_state(agent_id)
        state.failure_count += 1
        if state.failure_count >= self.failure_threshold and state.tripped_at is None:
            state.tripped_at = datetime.now(timezone.utc)
            logger.warning(f"Circuit breaker TRIPPED for agent {agent_id}",
                           extra={"event": "breaker_tripped", "module_name": "inter_agent"})

    def record_success(self, agent_id: str) -> None:
        """A successful action resets the failure streak — recovery signal."""
        state = self._get_state(agent_id)
        state.failure_count = 0
        state.tripped_at = None

    def register_dependency(self, child_agent_id: str, parent: str) -> None:
        """Mark child_agent_id as spawned/delegated-from parent — for cascade isolation."""
        self._dependencies[child_agent_id] = parent

    def is_open(self, agent_id: str, now: datetime | None = None) -> bool:
        """
        True if the breaker is OPEN (agent should be isolated/blocked).
        Auto-recovers after cooldown_seconds — moves to a half-open
        retry state, which for this MVP simply means "closed again".
        """
        current_time = now or datetime.now(timezone.utc)
        state = self._get_state(agent_id)

        if state.tripped_at is not None:
            elapsed = (current_time - state.tripped_at).total_seconds()
            if elapsed >= self.cooldown_seconds:
                # Cooldown elapsed — allow a fresh attempt (half-open -> closed)
                state.failure_count = 0
                state.tripped_at = None
                return False
            return True

        # Not directly tripped — check if a parent's trip cascades down
        parent = self._dependencies.get(agent_id)
        if parent is not None:
            return self.is_open(parent, now=current_time)

        return False
