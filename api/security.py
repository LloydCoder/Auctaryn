"""Central API authentication helpers for Auctaryn.

HTTP clients must use Authorization: Bearer <key>. WebSocket clients authenticate
with their first JSON message so credentials never need to be placed in URLs.
"""
import hmac
import os


def _matches(candidate: str, configured: str | None) -> bool:
    return bool(candidate and configured and hmac.compare_digest(candidate, configured))


def token_role(token: str | None) -> str | None:
    """Return 'admin', 'api', or None; admin credentials have the higher role."""
    if not token:
        return None
    if _matches(token, os.getenv("AUCTARYN_ADMIN_API_KEY")):
        return "admin"
    if _matches(token, os.getenv("AUCTARYN_API_KEY")):
        return "api"
    return None


def configured_for(role: str) -> bool:
    """Fail closed when the requested credential class is not configured."""
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
