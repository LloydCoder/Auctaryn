"""Audit a Grype JSON report, retaining unfixable findings and blocking fixable high CVEs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def inspect_report(document: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    high_findings: list[dict[str, Any]] = []
    actionable: list[dict[str, Any]] = []
    for match in document.get("matches", []):
        vulnerability = match.get("vulnerability") or {}
        severity = str(vulnerability.get("severity", "unknown")).lower()
        if severity not in {"high", "critical"}:
            continue
        artifact = match.get("artifact") or {}
        fix = vulnerability.get("fix") or {}
        versions = fix.get("versions") or []
        state = str(fix.get("state", "unknown")).lower()
        item = {
            "id": vulnerability.get("id", "unknown"),
            "severity": severity,
            "package": artifact.get("name", "unknown"),
            "version": artifact.get("version", "unknown"),
            "fix_state": state,
            "fixed_versions": versions,
        }
        high_findings.append(item)
        if versions or state in {"fixed", "available"}:
            actionable.append(item)
    return high_findings, actionable


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    args = parser.parse_args()
    document = json.loads(Path(args.report).read_text())
    high, actionable = inspect_report(document)
    print(f"Grype full inventory: high_or_critical={len(high)}; actionable_high_or_critical={len(actionable)}")
    for item in high:
        fixed = ",".join(item["fixed_versions"]) or "none-reported"
        print(
            f"VULNERABILITY id={item['id']} severity={item['severity']} package={item['package']} "
            f"version={item['version']} fix_state={item['fix_state']} fixed_versions={fixed}"
        )
    if actionable:
        print("ERROR: full inventory contains fixable high/critical findings; inspect scanner gate and remediate.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
