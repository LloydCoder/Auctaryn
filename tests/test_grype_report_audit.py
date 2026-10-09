"""Tests for Grype vulnerability report triage."""
from scripts.audit_grype_report import inspect_report


def test_unfixed_high_findings_are_reported_but_not_misclassified_as_actionable() -> None:
    report = {"matches": [{
        "vulnerability": {"id": "CVE-2026-00001", "severity": "High", "fix": {"state": "not-fixed", "versions": []}},
        "artifact": {"name": "util-linux", "version": "2.41.5"},
    }]}
    findings, actionable = inspect_report(report)
    assert len(findings) == 1
    assert findings[0]["id"] == "CVE-2026-00001"
    assert actionable == []


def test_fixable_high_findings_fail_independent_triage_gate() -> None:
    report = {"matches": [{
        "vulnerability": {"id": "CVE-2026-00002", "severity": "Critical", "fix": {"state": "fixed", "versions": ["2.42.4-1"]}},
        "artifact": {"name": "libfoo", "version": "1.0.0"},
    }]}
    findings, actionable = inspect_report(report)
    assert len(findings) == 1
    assert actionable[0]["fixed_versions"] == ["2.42.4-1"]
