"""Central API authentication helpers for Auctaryn.

HTTP clients use Authorization: Bearer <key>. WebSocket clients authenticate
with their first JSON message so credentials never need to appear in URLs.
"""
import hmac
import os


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


def token_role(token: str | None) -> str | None:
    """Return 'admin', 'api', or None; reject misconfigured identical keys."""
    if not isinstance(token, str) or not token or not credentials_are_distinct():
        return None
    if _matches(token, os.getenv("AUCTARYN_ADMIN_API_KEY")):
        return "admin"
    if _matches(token, os.getenv("AUCTARYN_API_KEY")):
        return "api"
    return None


def configured_for(role: str) -> bool:
    """Fail closed when requested credentials are missing or misconfigured."""
    if role == "admin":
        return bool(os.getenv("AUCTARYN_ADMIN_API_KEY")) and credentials_are_distinct()
    return bool(os.getenv("AUCTARYN_API_KEY") or os.getenv("AUCTARYN_ADMIN_API_KEY")) and credentials_are_distinct()


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
