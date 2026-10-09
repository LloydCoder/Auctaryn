"""
TwinGuard — Agent Identity & Privilege Manager
Maps to OWASP ASI03:2026 — Agent Identity & Privilege Abuse.

Core principle (OWASP "Least Agency"): every agent gets its own managed
identity with explicit, minimal, time-scoped permissions. Agents never
inherit or borrow a user's session — that's the confused-deputy pattern
OWASP specifically calls out: "Manager delegates task, full admin access
persists. Memory retains prior user secrets. Agent-to-agent confused
deputy attack."

This module is intentionally simple and dependency-free (in-memory,
no external IAM) so it can be wired into the Execution Gateway as an
additional check without adding infrastructure for the MVP.
"""

import fnmatch
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from core.exceptions import PolicyViolation
from core.logging import get_logger

logger = get_logger("agent_identity")


@dataclass
class AgentIdentity:
    agent_id: str
    identity_id: str
    owner: str
    scopes: set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ScopedToken:
    token_id: str
    agent_id: str
    scopes: set[str]
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False
    delegator_agent_id: str | None = None


class AgentIdentityManager:
    """
    Manages agent identities, scoped permissions, and short-lived tokens.
    In-memory for MVP — swap the dicts for a real store (Redis/Postgres)
    when multi-instance deployment is needed.
    """

    def __init__(self):
        self._identities: dict[str, AgentIdentity] = {}
        self._tokens: dict[str, ScopedToken] = {}

    # --- Identity registration ---

    def register(self, agent_id: str, owner: str) -> AgentIdentity:
        """Register a new agent with its own managed identity. Idempotent."""
        if agent_id in self._identities:
            return self._identities[agent_id]

        identity = AgentIdentity(
            agent_id=agent_id,
            identity_id=uuid.uuid4().hex,
            owner=owner,
        )
        self._identities[agent_id] = identity
        logger.info(f"Registered agent identity: {agent_id} (owner={owner})",
                   extra={"event": "identity_registered", "module_name": "agent_identity"})
        return identity

    def get_identity(self, agent_id: str) -> AgentIdentity | None:
        return self._identities.get(agent_id)

    # --- Scoped permissions ---

    def grant_scope(self, agent_id: str, scope: str) -> None:
        identity = self._identities.get(agent_id)
        if identity is None:
            raise PolicyViolation("unknown_agent", agent_id)
        identity.scopes.add(scope)
        logger.info(f"Granted scope '{scope}' to {agent_id}",
                   extra={"event": "scope_granted", "module_name": "agent_identity"})

    def revoke_scope(self, agent_id: str, scope: str) -> None:
        identity = self._identities.get(agent_id)
        if identity is not None:
            identity.scopes.discard(scope)
            for token in self._tokens.values():
                if token.agent_id == agent_id or token.delegator_agent_id == agent_id:
                    token.scopes.discard(scope)
                    if not token.scopes:
                        token.revoked = True
            logger.info(f"Revoked scope '{scope}' from {agent_id}",
                       extra={"event": "scope_revoked", "module_name": "agent_identity"})

    def is_authorized(
        self,
        agent_id: str,
        tool_name: str,
        token_id: str | None = None,
        require_token: bool = False,
    ) -> bool:
        """Check identity and tool scope; runtime gateway calls require a scoped token."""
        identity = self._identities.get(agent_id)
        if identity is None:
            return False

        if require_token:
            token = self._tokens.get(token_id or "")
            if (
                token is None
                or token.revoked
                or token.agent_id != agent_id
                or datetime.now(timezone.utc) >= token.expires_at
            ):
                return False
            return any(fnmatch.fnmatch(tool_name, scope) for scope in token.scopes)

        return any(fnmatch.fnmatch(tool_name, scope) for scope in identity.scopes)

    # --- Time-scoped tokens ---

    def issue_token(self, agent_id: str, ttl_seconds: int = 300) -> ScopedToken:
        identity = self._identities.get(agent_id)
        if identity is None:
            raise PolicyViolation("unknown_agent", agent_id)
        if not 1 <= ttl_seconds <= 3600:
            raise PolicyViolation("invalid_token_ttl", str(ttl_seconds))

        now = datetime.now(timezone.utc)
        token = ScopedToken(
            token_id=uuid.uuid4().hex,
            agent_id=agent_id,
            scopes=set(identity.scopes),
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        self._tokens[token.token_id] = token
        return token

    def validate_token(self, token_id: str) -> bool:
        token = self._tokens.get(token_id)
        if token is None:
            return False
        if token.revoked:
            return False
        if datetime.now(timezone.utc) >= token.expires_at:
            return False
        return True

    def revoke_token(self, token_id: str) -> None:
        token = self._tokens.get(token_id)
        if token is not None:
            token.revoked = True

    # --- Delegation ---

    def delegate(self, delegator_agent_id: str, delegate_agent_id: str,
                 scopes: list[str], ttl_seconds: int = 300) -> ScopedToken:
        """
        Delegate a SUBSET of the delegator's own scopes to another agent.
        Cannot delegate scopes the delegator doesn't hold — this is the
        direct fix for OWASP's confused-deputy example: "Manager delegates
        task, full admin access persists."
        """
        delegator = self._identities.get(delegator_agent_id)
        delegate_identity = self._identities.get(delegate_agent_id)

        if delegator is None:
            raise PolicyViolation("unknown_delegator", delegator_agent_id)
        if delegate_identity is None:
            raise PolicyViolation("unknown_delegate", delegate_agent_id)

        if not 1 <= ttl_seconds <= 3600:
            raise PolicyViolation("invalid_token_ttl", str(ttl_seconds))
        requested = set(scopes)
        if not requested:
            raise PolicyViolation("empty_delegation", delegate_agent_id)
        not_held = requested - delegator.scopes
        if not_held:
            raise PolicyViolation(
                f"delegator_lacks_scope:{','.join(not_held)}", delegator_agent_id
            )

        # Delegated scopes live only in this expiring token; never mutate
        # the delegate's durable identity scopes.
        now = datetime.now(timezone.utc)
        token = ScopedToken(
            token_id=uuid.uuid4().hex,
            agent_id=delegate_agent_id,
            scopes=requested,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            delegator_agent_id=delegator_agent_id,
        )
        self._tokens[token.token_id] = token

        logger.info(
            f"Delegated {scopes} from {delegator_agent_id} to {delegate_agent_id} "
            f"(ttl={ttl_seconds}s)",
            extra={"event": "scope_delegated", "module_name": "agent_identity"},
        )
        return token
