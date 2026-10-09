"""Summarize CodeQL SARIF and fail on high/critical security findings."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _severity(result: dict[str, Any], rule: dict[str, Any]) -> float:
    result_props = result.get("properties") or {}
    rule_props = rule.get("properties") or {}
    raw = result_props.get("security-severity", rule_props.get("security-severity"))
    if raw is not None:
        try:
            return float(raw)
        except (TypeError, ValueError):
            pass
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    return {"error": 8.0, "warning": 5.0, "note": 2.0}.get(str(level).lower(), 0.0)


def collect_findings(paths: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in paths:
        document = json.loads(Path(path).read_text())
        for run in document.get("runs", []):
            rules = {
                rule.get("id", ""): rule
                for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules", [])
            }
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule = rules.get(rule_id, {})
                locations = result.get("locations") or []
                physical = ((locations[0].get("physicalLocation") or {}) if locations else {})
                artifact = physical.get("artifactLocation") or {}
                region = physical.get("region") or {}
                message = (result.get("message") or {}).get("text", "")
                findings.append({
                    "rule_id": rule_id,
                    "severity": _severity(result, rule),
                    "level": result.get("level", "unknown"),
                    "path": artifact.get("uri", "unknown"),
                    "line": region.get("startLine", 0),
                    "message": " ".join(str(message).split())[:400],
                })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fail-severity", choices=("high", "critical", "never"), default="high")
    parser.add_argument("sarif_paths", nargs="+")
    args = parser.parse_args()
    findings = collect_findings(args.sarif_paths)
    counts = {
        "critical": sum(item["severity"] >= 9.0 for item in findings),
        "high": sum(7.0 <= item["severity"] < 9.0 for item in findings),
        "medium": sum(4.0 <= item["severity"] < 7.0 for item in findings),
        "low_or_unrated": sum(item["severity"] < 4.0 for item in findings),
    }
    print(f"CodeQL SARIF findings: total={len(findings)}; " + "; ".join(f"{key}={value}" for key, value in counts.items()))
    for item in findings:
        if item["severity"] >= 7.0:
            print(
                f"HIGH_OR_CRITICAL rule={item['rule_id']} severity={item['severity']:.1f} "
                f"location={item['path']}:{item['line']} message={item['message']}"
            )
    if args.fail_severity == "critical" and counts["critical"]:
        return 1
    if args.fail_severity == "high" and (counts["critical"] or counts["high"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
