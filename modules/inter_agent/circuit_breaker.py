"""Bounded per-agent circuit breaker with cycle-safe dependency containment."""
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from core.logging import get_logger

logger = get_logger("inter_agent.circuit_breaker")

DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_COOLDOWN_SECONDS = 60
MAX_FAILURE_THRESHOLD = 1000
MAX_COOLDOWN_SECONDS = 3600
MAX_AGENT_STATES = 10000
MAX_DEPENDENCIES = 10000
MAX_DEPENDENCY_DEPTH = 64
_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass
class _BreakerState:
    failure_count: int = 0
    tripped_at: datetime | None = None
    half_open: bool = False
    probe_in_flight: bool = False
    probe_started_at: datetime | None = None


class AgentCircuitBreaker:
    """A trip blocks an agent and its descendants until cooldown recovery."""

    def __init__(
        self,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS,
        probe_timeout_seconds: int = 30,
    ):
        if not isinstance(failure_threshold, int) or isinstance(failure_threshold, bool) or not 1 <= failure_threshold <= MAX_FAILURE_THRESHOLD:
            raise ValueError("failure_threshold must be between 1 and 1000")
        if not isinstance(cooldown_seconds, int) or isinstance(cooldown_seconds, bool) or not 1 <= cooldown_seconds <= MAX_COOLDOWN_SECONDS:
            raise ValueError("cooldown_seconds must be between 1 and 3600")
        if not isinstance(probe_timeout_seconds, int) or isinstance(probe_timeout_seconds, bool) or not 1 <= probe_timeout_seconds <= 300:
            raise ValueError("probe_timeout_seconds must be between 1 and 300")
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.probe_timeout_seconds = probe_timeout_seconds
        self._states: dict[str, _BreakerState] = {}
        self._dependencies: dict[str, str] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _validate_agent_id(agent_id: str) -> None:
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            raise ValueError("invalid agent identifier")

    def _get_state(self, agent_id: str) -> _BreakerState:
        self._validate_agent_id(agent_id)
        state = self._states.get(agent_id)
        if state is None:
            if len(self._states) >= MAX_AGENT_STATES:
                raise RuntimeError("circuit breaker state capacity reached")
            state = _BreakerState()
            self._states[agent_id] = state
        return state

    def record_failure(self, agent_id: str) -> None:
        with self._lock:
            state = self._get_state(agent_id)
            if state.half_open and state.probe_in_flight:
                state.failure_count = self.failure_threshold
                state.tripped_at = datetime.now(timezone.utc)
                state.half_open = False
                state.probe_in_flight = False
                state.probe_started_at = None
                logger.warning(
                    "Agent circuit breaker re-tripped after failed probe",
                    extra={"event": "breaker_retripped", "module_name": "inter_agent", "agent_id": agent_id},
                )
                return
            state.failure_count = min(state.failure_count + 1, self.failure_threshold)
            if state.failure_count >= self.failure_threshold and state.tripped_at is None:
                state.tripped_at = datetime.now(timezone.utc)
                logger.warning(
                    "Agent circuit breaker tripped",
                    extra={"event": "breaker_tripped", "module_name": "inter_agent", "agent_id": agent_id},
                )

    def record_success(self, agent_id: str) -> None:
        with self._lock:
            state = self._get_state(agent_id)
            state.failure_count = 0
            state.tripped_at = None
            state.half_open = False
            state.probe_in_flight = False
            state.probe_started_at = None

    def register_dependency(self, child_agent_id: str, parent_agent_id: str) -> None:
        self._validate_agent_id(child_agent_id)
        self._validate_agent_id(parent_agent_id)
        if child_agent_id == parent_agent_id:
            raise ValueError("an agent cannot depend on itself")
        with self._lock:
            if child_agent_id not in self._dependencies and len(self._dependencies) >= MAX_DEPENDENCIES:
                raise RuntimeError("dependency registry capacity reached")
            cursor = parent_agent_id
            visited: set[str] = set()
            depth = 0
            while cursor in self._dependencies:
                if cursor == child_agent_id or cursor in visited:
                    raise ValueError("dependency cycle rejected")
                visited.add(cursor)
                cursor = self._dependencies[cursor]
                depth += 1
                if depth > MAX_DEPENDENCY_DEPTH:
                    raise ValueError("dependency chain exceeds maximum depth")
            if cursor == child_agent_id:
                raise ValueError("dependency cycle rejected")
            self._dependencies[child_agent_id] = parent_agent_id

    def _is_open(
        self, agent_id: str, current_time: datetime, visited: set[str],
        *, allow_half_open_probe: bool = True,
    ) -> bool:
        if agent_id in visited:
            return True
        visited.add(agent_id)
        parent = self._dependencies.get(agent_id)
        # A descendant cannot use its own request as a probe for a failed ancestor.
        # The ancestor must recover through its own single half-open probe first.
        if parent is not None and self._is_open(
            parent, current_time, visited, allow_half_open_probe=False
        ):
            return True

        state = self._states.get(agent_id)
        if state is None or state.tripped_at is None:
            return False
        elapsed = (current_time - state.tripped_at).total_seconds()
        if elapsed < self.cooldown_seconds:
            return True
        if not allow_half_open_probe:
            return True
        state.half_open = True
        if state.probe_in_flight and state.probe_started_at is not None:
            probe_elapsed = (current_time - state.probe_started_at).total_seconds()
            if probe_elapsed < self.probe_timeout_seconds:
                return True
        state.probe_in_flight = True
        state.probe_started_at = current_time
        return False

    def is_open(self, agent_id: str, now: datetime | None = None) -> bool:
        try:
            self._validate_agent_id(agent_id)
            current_time = now or datetime.now(timezone.utc)
            if current_time.tzinfo is None or current_time.utcoffset() is None:
                return True
            current_time = current_time.astimezone(timezone.utc)
        except (ValueError, TypeError, AttributeError):
            return True
        with self._lock:
            return self._is_open(agent_id, current_time, set())
