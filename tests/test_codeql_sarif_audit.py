"""Unit tests for the CodeQL SARIF severity gate."""
from __future__ import annotations

import json

from scripts.audit_codeql_sarif import collect_findings


def test_collect_findings_resolves_rule_severity_and_location(tmp_path) -> None:
    report = {
        "runs": [{
            "tool": {"driver": {"rules": [{
                "id": "python/path-injection",
                "properties": {"security-severity": "8.1"},
            }, {
                "id": "js/style-note",
                "defaultConfiguration": {"level": "note"},
            }]}},
            "results": [{
                "ruleId": "python/path-injection",
                "level": "warning",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "api/routes/example.py"},
                        "region": {"startLine": 42},
                    }
                }],
                "message": {"text": "Unsafe path construction"},
            }, {
                "ruleId": "js/style-note",
                "message": {"text": "Informational note"},
            }],
        }]
    }
    path = tmp_path / "report.sarif"
    path.write_text(json.dumps(report))
    findings = collect_findings([str(path)])
    assert len(findings) == 2
    assert findings[0]["severity"] == 8.1
    assert findings[0]["path"] == "api/routes/example.py"
    assert findings[0]["line"] == 42
    assert findings[1]["severity"] == 2.0
