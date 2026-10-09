"""Shared data structures and conservative permission heuristics."""
import difflib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class PermissionScanResult:
    risk_level: str
    flagged_permissions: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class VettingVerdict:
    skill_name: str
    approved: bool
    reasons: list[str] = field(default_factory=list)
    verdict_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


ALWAYS_CRITICAL_PERMISSIONS = {
    "exfiltrate_data", "escalate_privileges", "modify_policy", "modify_config",
    "disable_security", "disable_guard",
}
PRIVATE_DATA_PERMISSIONS = {"read_email", "read_credentials", "read_secrets", "access_filesystem"}
NETWORK_EGRESS_PERMISSIONS = {"send_email", "http_request", "webhook_call", "network_access"}


def scan_permissions(permissions: list[str]) -> PermissionScanResult:
    if not isinstance(permissions, list) or any(not isinstance(item, str) for item in permissions):
        return PermissionScanResult("critical", reason="Malformed permission list")
    flagged = sorted(set(permissions) & ALWAYS_CRITICAL_PERMISSIONS)
    if flagged:
        return PermissionScanResult("critical", flagged, "Requests always-critical permissions")
    private_data = any(item in PRIVATE_DATA_PERMISSIONS for item in permissions)
    network = any(item in NETWORK_EGRESS_PERMISSIONS for item in permissions)
    if private_data and network:
        flagged = sorted(set(permissions) & (PRIVATE_DATA_PERMISSIONS | NETWORK_EGRESS_PERMISSIONS))
        return PermissionScanResult("high", flagged, "Private-data access combined with network egress")
    if len(set(permissions)) > 3:
        return PermissionScanResult("medium", reason="Requests more than 3 distinct permissions")
    return PermissionScanResult("low")


def detect_typosquat(skill_name: str, known_skills: set[str]) -> str | None:
    if skill_name in known_skills:
        return None
    best_match = None
    best_score = 0.0
    for known in known_skills:
        score = difflib.SequenceMatcher(None, skill_name, known).ratio()
        if score > best_score:
            best_score, best_match = score, known
    return best_match if best_match and best_score >= 0.82 else None
