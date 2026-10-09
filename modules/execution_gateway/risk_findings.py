"""Deterministic, provenance-aware explanations for advisory risk assessments.

This module emits findings from caller-supplied action metadata and the local
pattern classifier. It does not claim runtime observation, authorize actions,
or replace the Tinlance Agent Platform's policy engine.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any

from core.models import RiskLevel

MAX_REASON_LENGTH = 512
MAX_RULE_LENGTH = 128

CONTROL_MAP: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
    (re.compile(r"delete|drop|truncate|wipe|erase|purge|remove", re.I),
     ("OWASP-ASI02", "OWASP-ASI09")),
    (re.compile(r"sudo|root|privilege|policy|config|security|exfiltrat|secret", re.I),
     ("OWASP-ASI02", "OWASP-ASI03")),
    (re.compile(r"send|email|message|broadcast|publish", re.I),
     ("OWASP-ASI02", "OWASP-ASI09")),
    (re.compile(r"memory|context|instruction|prompt", re.I),
     ("OWASP-ASI01", "OWASP-ASI06")),
    (re.compile(r"mcp|skill|package|dependency|tool", re.I),
     ("OWASP-ASI04", "OWASP-ASI05")),
)

RECOMMENDATIONS = {
    RiskLevel.SAFE: (
        "Continue to evaluate identity, capability, tenant, and policy at the "
        "authoritative execution boundary; a low advisory score is not approval."
    ),
    RiskLevel.MODERATE: (
        "Require the authoritative policy engine to evaluate scope and resource "
        "sensitivity; obtain human review when the action is unrecognized."
    ),
    RiskLevel.DESTRUCTIVE: (
        "Require explicit, action-bound approval and verify the exact target and "
        "affected-item count immediately before execution."
    ),
    RiskLevel.CRITICAL: (
        "Deny or hold for privileged human review under Platform policy; do not "
        "execute solely because this advisory assessment was returned."
    ),
}


def _severity(level: RiskLevel) -> str:
    return {
        RiskLevel.SAFE: "info",
        RiskLevel.MODERATE: "medium",
        RiskLevel.DESTRUCTIVE: "high",
        RiskLevel.CRITICAL: "critical",
    }[level]


def _control_refs(tool_name: str, action: str, rule_id: str) -> list[str]:
    haystack = f"{tool_name} {action} {rule_id}"
    refs: list[str] = []
    for pattern, mapped in CONTROL_MAP:
        if pattern.search(haystack):
            for ref in mapped:
                if ref not in refs:
                    refs.append(ref)
    return refs or ["OWASP-ASI02"]


def build_risk_findings(
    *,
    tool_name: str,
    action: str,
    risk_level: RiskLevel,
    confidence: float,
    reason: str,
    matched_pattern: str,
    input_fingerprint: str,
) -> list[dict[str, Any]]:
    """Create one stable, bounded explanation without echoing action parameters.

    The identifier is stable for the same risk/rule/fingerprint tuple. The
    fingerprint is an unkeyed correlation hash and must not be treated as
    authorization evidence or confidentiality protection.
    """
    rule_id = (matched_pattern or "unrecognized")[:MAX_RULE_LENGTH]
    safe_reason = " ".join((reason or "No explanation supplied.").split())[:MAX_REASON_LENGTH]
    identity_material = json.dumps(
        {
            "version": "risk-finding.v1",
            "risk_level": risk_level.value,
            "rule_id": rule_id,
            "input_fingerprint": input_fingerprint,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    finding_id = sha256(identity_material).hexdigest()[:24]
    return [{
        "finding_id": finding_id,
        "finding_type": "advisory_action_risk",
        "title": f"{risk_level.value.title()} action-risk signal",
        "severity": _severity(risk_level),
        "confidence": max(0.0, min(1.0, float(confidence))),
        "rationale": safe_reason,
        "rule_id": rule_id,
        "control_refs": _control_refs(tool_name, action, rule_id),
        "recommendation": RECOMMENDATIONS[risk_level],
        "evidence_refs": ["request_fingerprint"],
        "provenance": {
            "source": "caller_supplied_action_metadata",
            "analyzer": "local_pattern_classifier",
            "runtime_observed": False,
        },
    }]
