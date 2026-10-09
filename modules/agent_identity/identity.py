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

MAX_AGENT_IDENTITIES = 100_000
MAX_AGENT_TOKENS = 250_000
MAX_SCOPES_PER_IDENTITY = 256
MAX_SCOPES_PER_TOKEN = 100


@dataclass
class AgentIdentity:
    agent_id: str
    identity_id: str
    owner: str
    scopes: set[str] = field(default_factory=set)
    permissions_version: int = 0
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
    identity_version: int = 0
    delegator_identity_version: int | None = None


class AgentIdentityManager:
    """
    Manages agent identities, scoped permissions, and short-lived tokens.
    In-memory for MVP — swap the dicts for a real store (Redis/Postgres)
    when multi-instance deployment is needed.
    """

    def __init__(self):
        self._identities: dict[str, AgentIdentity] = {}
        self._tokens: dict[str, ScopedToken] = {}
        self._last_token_prune_at = datetime.now(timezone.utc)

    # --- Identity registration ---

    def register(self, agent_id: str, owner: str) -> AgentIdentity:
        """Register a new agent with its own managed identity. Idempotent."""
        if not isinstance(agent_id, str) or not agent_id.strip() or len(agent_id) > 128:
            raise PolicyViolation("invalid_agent_id", "Agent ID must contain 1–128 characters")
        if not isinstance(owner, str) or not owner.strip() or len(owner) > 256:
            raise PolicyViolation("invalid_agent_owner", "Agent owner must contain 1–256 characters")
        if agent_id in self._identities:
            existing = self._identities[agent_id]
            if existing.owner != owner:
                # An idempotent retry by the same owner is safe; silently
                # accepting a different owner would create an identity
                # ownership-confusion / takeover primitive.
                logger.warning(
                    "Rejected agent identity registration with conflicting owner",
                    extra={"event": "identity_owner_conflict", "agent_id": agent_id},
                )
                raise PolicyViolation("identity_owner_conflict", agent_id)
            return existing

        if len(self._identities) >= MAX_AGENT_IDENTITIES:
            raise PolicyViolation("identity_capacity_exhausted", "Agent identity capacity reached")

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
        if not isinstance(scope, str) or not scope.strip() or len(scope) > 256:
            raise PolicyViolation("invalid_scope", "Scope must contain 1–256 characters")
        if scope not in identity.scopes and len(identity.scopes) >= MAX_SCOPES_PER_IDENTITY:
            raise PolicyViolation("scope_capacity_exhausted", "Agent scope capacity reached")
        if scope not in identity.scopes:
            identity.scopes.add(scope)
            identity.permissions_version += 1
        logger.info(f"Granted scope '{scope}' to {agent_id}",
                   extra={"event": "scope_granted", "module_name": "agent_identity"})

    def revoke_scope(self, agent_id: str, scope: str) -> None:
        identity = self._identities.get(agent_id)
        if identity is None:
            raise PolicyViolation("unknown_agent", agent_id)
        if scope in identity.scopes:
            identity.scopes.remove(scope)
            identity.permissions_version += 1
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
                or token.identity_version != identity.permissions_version
            ):
                return False
            if token.delegator_agent_id is not None:
                delegator = self._identities.get(token.delegator_agent_id)
                if (
                    delegator is None
                    or token.delegator_identity_version != delegator.permissions_version
                ):
                    return False
            return any(fnmatch.fnmatch(tool_name, scope) for scope in token.scopes)

        return any(fnmatch.fnmatch(tool_name, scope) for scope in identity.scopes)

    def _prune_tokens(self, now: datetime | None = None) -> None:
        """Discard expired/revoked token records before allocating more bounded state."""
        current = now or datetime.now(timezone.utc)
        for token_id, token in list(self._tokens.items()):
            if token.revoked or current >= token.expires_at:
                self._tokens.pop(token_id, None)
        self._last_token_prune_at = current

    def _prune_tokens_if_needed(self, now: datetime | None = None) -> None:
        """Avoid an O(n) token scan on every issuance while pruning at capacity or periodically."""
        current = now or datetime.now(timezone.utc)
        age = (current - self._last_token_prune_at).total_seconds()
        if len(self._tokens) >= MAX_AGENT_TOKENS or age >= 60:
            self._prune_tokens(current)

    # --- Time-scoped tokens ---

    def issue_token(self, agent_id: str, ttl_seconds: int = 300, scopes: list[str] | None = None) -> ScopedToken:
        self._prune_tokens_if_needed()
        identity = self._identities.get(agent_id)
        if identity is None:
            raise PolicyViolation("unknown_agent", agent_id)
        if not 1 <= ttl_seconds <= 3600:
            raise PolicyViolation("invalid_token_ttl", str(ttl_seconds))

        raw_scopes = identity.scopes if scopes is None else scopes
        if not isinstance(raw_scopes, (set, list, tuple)) or len(raw_scopes) > MAX_SCOPES_PER_TOKEN:
            raise PolicyViolation("invalid_token_scopes", "Token scopes exceed the supported bound")
        if any(not isinstance(scope, str) or not scope.strip() or len(scope) > 256 for scope in raw_scopes):
            raise PolicyViolation("invalid_token_scopes", "Each token scope must contain 1–256 characters")
        requested_scopes = set(raw_scopes)
        if not requested_scopes:
            raise PolicyViolation("empty_token_scopes", agent_id)
        if len(self._tokens) >= MAX_AGENT_TOKENS:
            raise PolicyViolation("token_capacity_exhausted", "Agent token capacity reached")
        not_held = requested_scopes - identity.scopes
        if not_held:
            raise PolicyViolation(f"agent_lacks_scope:{','.join(sorted(not_held))}", agent_id)

        now = datetime.now(timezone.utc)
        token = ScopedToken(
            token_id=uuid.uuid4().hex,
            agent_id=agent_id,
            scopes=requested_scopes,
            issued_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            identity_version=identity.permissions_version,
        )
        self._tokens[token.token_id] = token
        return token

    def validate_token(self, token_id: str) -> bool:
        token = self._tokens.get(token_id)
        if token is None:
            return False
        if token.revoked or datetime.now(timezone.utc) >= token.expires_at:
            return False
        identity = self._identities.get(token.agent_id)
        if identity is None or token.identity_version != identity.permissions_version:
            return False
        if token.delegator_agent_id is not None:
            delegator = self._identities.get(token.delegator_agent_id)
            if delegator is None or token.delegator_identity_version != delegator.permissions_version:
                return False
        return True

    def revoke_token(self, token_id: str) -> None:
        token = self._tokens.get(token_id)
        if token is not None:
            token.revoked = True

    def revoke_agent_tokens(self, agent_id: str) -> int:
        """Revoke every token issued to or delegated by an agent and invalidate its version."""
        identity = self._identities.get(agent_id)
        if identity is None:
            raise PolicyViolation("unknown_agent", agent_id)
        identity.permissions_version += 1
        revoked = 0
        for token in self._tokens.values():
            if token.agent_id == agent_id or token.delegator_agent_id == agent_id:
                if not token.revoked:
                    token.revoked = True
                    revoked += 1
        logger.warning(
            "Revoked all agent capabilities",
            extra={"event": "agent_tokens_revoked", "module_name": "agent_identity"},
        )
        return revoked

    # --- Delegation ---

    def delegate(self, delegator_agent_id: str, delegate_agent_id: str,
                 scopes: list[str], ttl_seconds: int = 300) -> ScopedToken:
        """
        Delegate a SUBSET of the delegator's own scopes to another agent.
        Cannot delegate scopes the delegator doesn't hold — this is the
        direct fix for OWASP's confused-deputy example: "Manager delegates
        task, full admin access persists."
        """
        self._prune_tokens_if_needed()
        if not isinstance(scopes, list) or not 1 <= len(scopes) <= MAX_SCOPES_PER_TOKEN:
            raise PolicyViolation("invalid_delegation_scopes", "Delegation must contain 1–100 scopes")
        if any(not isinstance(scope, str) or not scope.strip() or len(scope) > 256 for scope in scopes):
            raise PolicyViolation("invalid_delegation_scopes", "Each delegated scope must contain 1–256 characters")
        if len(self._tokens) >= MAX_AGENT_TOKENS:
            raise PolicyViolation("token_capacity_exhausted", "Agent token capacity reached")

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
            identity_version=delegate_identity.permissions_version,
            delegator_identity_version=delegator.permissions_version,
        )
        self._tokens[token.token_id] = token

        logger.info(
            f"Delegated {scopes} from {delegator_agent_id} to {delegate_agent_id} "
            f"(ttl={ttl_seconds}s)",
            extra={"event": "scope_delegated", "module_name": "agent_identity"},
        )
        return token
