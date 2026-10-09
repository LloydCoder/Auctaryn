"""
TwinGuard — Parliament Adapter
Maps FusionOps' FullAnalysisResult schema into TwinGuard's internal models
and decisions.

FusionOps response shape:
{
  "detection": {event_id, timestamp, source, detected, score, entropy,
                drop_ratio, z_outlier, fade_start, mitre_ttp,
                volatility_artifacts, severity},
  "triage": {event_id, triaged_at, priority, category, recommended_action,
             confidence, reasoning, mitre_ttp, escalate, auto_remediate},
  "remediation": {plan_id, event_id, ..., recommended_action, requires_human, actions}
}
"""

from core.models import ThreatFadeResult, Severity, ActionDecision

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

# Categories that always force escalation regardless of raw severity score.
# AI_AGENT_ABUSE exists in FusionOps specifically for TwinGuard's use case.
ALWAYS_ESCALATE_CATEGORIES = {"AI_AGENT_ABUSE"}

# Recommended action → TwinGuard decision mapping
ACTION_DECISION_MAP = {
    "BLOCK_IMMEDIATE": ActionDecision.VETOED,
    "ISOLATE_HOST": ActionDecision.VETOED,
    "ESCALATE_TO_ANALYST": ActionDecision.PENDING,
    "INCREASE_MONITORING": ActionDecision.APPROVED,
    "LOG_AND_WATCH": ActionDecision.APPROVED,
    "DISMISS": ActionDecision.APPROVED,
}


def map_severity(raw: str) -> Severity:
    """Map a FusionOps severity string to TwinGuard's Severity enum."""
    return SEVERITY_MAP.get((raw or "").upper(), Severity.INFO)


def to_threatfade_result(full_result: dict) -> ThreatFadeResult:
    """Convert a FusionOps FullAnalysisResult into TwinGuard's ThreatFadeResult."""
    detection = full_result.get("detection", {})

    mitre_ttp = detection.get("mitre_ttp", "")
    mitre_ttps = [mitre_ttp] if mitre_ttp else []

    return ThreatFadeResult(
        score=detection.get("score", 0.0),
        z_score=detection.get("z_outlier", 0.0),
        entropy=detection.get("entropy", 0.0),
        drop_ratio=detection.get("drop_ratio", 0.0),
        severity=map_severity(detection.get("severity", "INFO")),
        confidence=str(full_result.get("triage", {}).get("confidence", "")),
        mitre_ttps=mitre_ttps,
        fade_detected=bool(detection.get("detected", False)),
        source_file=detection.get("source", ""),
    )


def should_escalate(full_result: dict) -> bool:
    """
    Determine if this detection should force escalation in TwinGuard,
    independent of the raw severity score.
    """
    triage = full_result.get("triage", {})

    if triage.get("category") in ALWAYS_ESCALATE_CATEGORIES:
        return True

    if triage.get("escalate") is True:
        return True

    return False


def recommended_decision(full_result: dict) -> ActionDecision:
    """
    Translate FusionOps' recommended_action into a TwinGuard ActionDecision.
    AI_AGENT_ABUSE category always overrides to VETOED regardless of the
    literal recommended_action field.
    """
    triage = full_result.get("triage", {})

    if should_escalate(full_result) and triage.get("category") in ALWAYS_ESCALATE_CATEGORIES:
        return ActionDecision.VETOED

    action = triage.get("recommended_action", "LOG_AND_WATCH")
    return ACTION_DECISION_MAP.get(action, ActionDecision.PENDING)
