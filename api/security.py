"""Central API authentication helpers for Auctaryn.

HTTP clients use Authorization: Bearer <key>. WebSocket clients authenticate
with their first JSON message so credentials never need to appear in URLs.
"""
import hmac
import os

from fastapi import Header, HTTPException, status


def _matches(candidate: object, configured: str | None) -> bool:
    return (
        isinstance(candidate, str)
        and bool(candidate)
        and bool(configured)
        and hmac.compare_digest(candidate, configured)
    )


def credentials_are_distinct() -> bool:
    """Prevent a service credential from accidentally becoming an admin credential."""
    service_key = os.getenv("AUCTARYN_API_KEY")
    admin_key = os.getenv("AUCTARYN_ADMIN_API_KEY")
    return not service_key or not admin_key or not hmac.compare_digest(service_key, admin_key)


def credentials_are_strong() -> bool:
    """Require distinct, non-placeholder API keys of at least 32 characters."""
    service_key = os.getenv("AUCTARYN_API_KEY")
    admin_key = os.getenv("AUCTARYN_ADMIN_API_KEY")
    if not service_key or not admin_key or hmac.compare_digest(service_key, admin_key):
        return False
    placeholders = ("replace-with", "change-me", "changeme", "password", "example")
    return all(
        len(key) >= 32
        and len(set(key)) >= 12
        and not any(marker in key.lower() for marker in placeholders)
        for key in (service_key, admin_key)
    )


def _strong_keys_required() -> bool:
    return os.getenv("AUCTARYN_REQUIRE_STRONG_API_KEYS", "true").strip().lower() not in {
        "0", "false", "no", "off",
    }


def token_role(token: str | None) -> str | None:
    """Return 'admin', 'api', or None; reject weak or identical configured keys."""
    if (
        not isinstance(token, str)
        or not token
        or not credentials_are_distinct()
        or (_strong_keys_required() and not credentials_are_strong())
    ):
        return None
    if _matches(token, os.getenv("AUCTARYN_ADMIN_API_KEY")):
        return "admin"
    if _matches(token, os.getenv("AUCTARYN_API_KEY")):
        return "api"
    return None


def configured_for(role: str) -> bool:
    """Fail closed when requested credentials are missing, weak or misconfigured."""
    if not credentials_are_distinct() or (_strong_keys_required() and not credentials_are_strong()):
        return False
    if role == "admin":
        return bool(os.getenv("AUCTARYN_ADMIN_API_KEY"))
    return bool(os.getenv("AUCTARYN_API_KEY") or os.getenv("AUCTARYN_ADMIN_API_KEY"))


def extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, separator, credential = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not credential.strip():
        return None
    return credential.strip()


def origin_allowed(origin: str | None) -> bool:
    """Reject browser WebSocket origins outside the configured CORS allowlist."""
    if not origin:
        return True  # non-browser clients must still authenticate with a key
    from core.config import get_config
    return origin in get_config().server.cors_origins

async def require_api_key(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency requiring a configured service or administrator bearer."""
    role = token_role(extract_bearer(authorization))
    if role in ("api", "admin"):
        return
    if not configured_for("api"):
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured correctly",
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Valid bearer token required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_operator_key(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency requiring the distinct administrator bearer."""
    role = token_role(extract_bearer(authorization))
    if role == "admin":
        return
    if not configured_for("admin"):
        raise HTTPException(
            status_code=503,
            detail="Administrator authentication is not configured correctly",
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Administrator bearer token required",
        headers={"WWW-Authenticate": "Bearer"},
    )
