"""
TwinGuard — Skill/Dependency Vetting Module
Maps to OWASP ASI04:2026 — Agentic Supply Chain Compromise.

Built in direct response to confirmed real incidents: ClawHub registry
poisoned at scale (5 of top 7 downloaded skills were malware), and the
"Lethal Trifecta" pattern (private data access + untrusted content
exposure + network egress) that OWASP identifies as the root cause of
most agentic supply chain compromises.

This module never executes or sandboxes skill code — that's OpenShell's
job. This module decides whether a skill should be allowed to load at
all, before OpenShell ever sees it.
"""

import difflib
import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.logging import get_logger

logger = get_logger("skill_vetting")

REQUIRED_MANIFEST_FIELDS = {"name", "version", "content_hash", "signature", "permissions", "publisher"}

# Permissions that, individually, are always treated as critical risk —
# these map to the "ability to communicate externally" / "access to
# private data" legs of the Lethal Trifecta.
ALWAYS_CRITICAL_PERMISSIONS = {
    "exfiltrate_data", "escalate_privileges", "modify_policy", "modify_config",
    "disable_security", "disable_guard",
}

# Permission combinations that together constitute the Lethal Trifecta
# even if no single permission is critical alone.
PRIVATE_DATA_PERMS = {"read_email", "read_credentials", "read_secrets", "access_filesystem"}
NETWORK_EGRESS_PERMS = {"send_email", "http_request", "webhook_call", "network_access"}

TYPOSQUAT_SIMILARITY_THRESHOLD = 0.82


@dataclass
class PermissionScanResult:
    risk_level: str  # "low" | "medium" | "high" | "critical"
    flagged_permissions: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class VettingVerdict:
    skill_name: str
    approved: bool
    reasons: list[str] = field(default_factory=list)
    verdict_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def validate_manifest_structure(manifest: dict) -> bool:
    """All required fields must be present AND non-empty."""
    if not REQUIRED_MANIFEST_FIELDS.issubset(manifest.keys()):
        return False
    for field_name in ("name", "version", "content_hash", "publisher"):
        if not manifest.get(field_name):
            return False
    return True


def has_valid_signature(manifest: dict, trusted_publishers: set[str]) -> bool:
    """
    AST01/AST02: the skill must be signed AND the publisher must be in
    the trusted set. In production this verifies an actual ed25519
    signature against the publisher's public key; for MVP we check
    presence + a recognizable prefix + trusted publisher membership.
    """
    signature = manifest.get("signature", "")
    publisher = manifest.get("publisher", "")

    if not signature or not signature.startswith("ed25519:"):
        return False
    if publisher not in trusted_publishers:
        return False
    return True


def has_pinned_hash(manifest: dict) -> bool:
    """AST07: content_hash must be present and non-empty — no version ranges."""
    content_hash = manifest.get("content_hash", "")
    return bool(content_hash) and len(content_hash) >= 32


def verify_content_hash(content: bytes, expected_hash: str) -> bool:
    """Verify actual skill bytes match the pinned hash exactly."""
    actual = hashlib.sha256(content).hexdigest()
    return actual == expected_hash


def scan_permissions(permissions: list[str]) -> PermissionScanResult:
    """
    AST03: least-privilege scan. Flags individually-critical permissions
    and Lethal Trifecta combinations (private data + network egress).
    """
    flagged = [p for p in permissions if p in ALWAYS_CRITICAL_PERMISSIONS]
    if flagged:
        return PermissionScanResult(
            risk_level="critical",
            flagged_permissions=flagged,
            reason=f"Requests always-critical permissions: {', '.join(flagged)}",
        )

    has_private_data = any(p in PRIVATE_DATA_PERMS for p in permissions)
    has_network = any(p in NETWORK_EGRESS_PERMS for p in permissions)

    if has_private_data and has_network:
        return PermissionScanResult(
            risk_level="high",
            flagged_permissions=[p for p in permissions if p in PRIVATE_DATA_PERMS or p in NETWORK_EGRESS_PERMS],
            reason="Lethal Trifecta pattern: private data access combined with network egress",
        )

    if len(permissions) > 3:
        return PermissionScanResult(risk_level="medium", reason="Requests more than 3 permissions")

    return PermissionScanResult(risk_level="low")


def detect_typosquat(skill_name: str, known_skills: set[str]) -> str | None:
    """
    OWASP example: 'Typosquatted tool in marketplace.' Compares the
    candidate name against a known-good registry using sequence
    similarity. Returns the matched known skill name if a typosquat
    is suspected, None otherwise (including for exact matches).
    """
    if skill_name in known_skills:
        return None

    best_match = None
    best_score = 0.0
    for known in known_skills:
        score = difflib.SequenceMatcher(None, skill_name, known).ratio()
        if score > best_score:
            best_score = score
            best_match = known

    if best_match and best_score >= TYPOSQUAT_SIMILARITY_THRESHOLD:
        return best_match
    return None


class SkillVettingService:
    """
    Full vetting pipeline. Runs every check and produces a single
    approve/reject verdict with reasons — this is what gets called
    before any skill/MCP tool/plugin is allowed to load into an
    agent's available tool set.
    """

    def __init__(self, trusted_publishers: set[str] | None = None,
                 known_skills: set[str] | None = None):
        self.trusted_publishers = trusted_publishers or set()
        self.known_skills = known_skills or set()
        self.history: list[VettingVerdict] = []

    def vet(self, manifest: dict) -> VettingVerdict:
        reasons: list[str] = []
        skill_name = manifest.get("name", "unknown")

        if not validate_manifest_structure(manifest):
            reasons.append("Manifest is missing required fields")

        if not has_pinned_hash(manifest):
            reasons.append("Missing or invalid pinned content_hash")

        if not has_valid_signature(manifest, self.trusted_publishers):
            reasons.append("Missing valid signature or untrusted publisher")

        perm_scan = scan_permissions(manifest.get("permissions", []))
        if perm_scan.risk_level in ("critical", "high"):
            reasons.append(f"Permission risk {perm_scan.risk_level}: {perm_scan.reason}")

        if self.known_skills:
            typosquat_match = detect_typosquat(skill_name, self.known_skills)
            if typosquat_match:
                reasons.append(f"Possible typosquat of known skill '{typosquat_match}'")

        verdict = VettingVerdict(
            skill_name=skill_name,
            approved=len(reasons) == 0,
            reasons=reasons,
        )
        self.history.append(verdict)

        if not verdict.approved:
            logger.warning(
                f"Skill vetting REJECTED: {skill_name} — {'; '.join(reasons)}",
                extra={"event": "skill_rejected", "module_name": "skill_vetting"},
            )
        else:
            logger.info(f"Skill vetting approved: {skill_name}",
                       extra={"event": "skill_approved", "module_name": "skill_vetting"})

        return verdict
