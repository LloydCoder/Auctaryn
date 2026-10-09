"""Tests for fail-closed production release evidence."""
import json
from pathlib import Path

from scripts.verify_release_evidence import DEFAULT_MANIFEST, validate_release_evidence

ROOT = Path(__file__).resolve().parents[1]


def _passed_evidence() -> dict:
    evidence = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    commit = "a" * 40
    evidence["tested_commit"] = commit
    for index, name in enumerate(("ci", "codeql", "supply_chain"), start=1):
        evidence["workflow_runs"][name] = {
            "run_id": index,
            "head_sha": commit,
            "conclusion": "success",
            "url": f"https://github.com/LloydCoder/Auctaryn/actions/runs/{index}",
        }
    for name, gate in evidence["pre_release_gates"].items():
        gate.update({
            "status": "passed",
            "evidence_ref": f"evidence://{name}/review",
            "reviewer": "security-owner",
            "reviewed_at": "2026-10-09T12:00:00Z",
        })
    evidence["pre_release_gates"]["independent_assessment"].update({
        "report_sha256": "b" * 64,
        "critical_open": 0,
        "high_open": 0,
    })
    return evidence


def test_pending_template_is_valid_but_cannot_be_promoted() -> None:
    evidence = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    assert validate_release_evidence(evidence) == []
    errors = validate_release_evidence(evidence, require_passed=True)
    assert any("not passed" in error for error in errors)
    assert any("tested_commit" in error for error in errors)


def test_complete_pre_release_evidence_is_accepted() -> None:
    evidence = _passed_evidence()
    assert validate_release_evidence(evidence, require_passed=True) == []


def test_open_high_finding_and_digest_mismatch_block_production_acceptance() -> None:
    evidence = _passed_evidence()
    evidence["pre_release_gates"]["independent_assessment"]["high_open"] = 1
    post = evidence["post_deployment_gates"]
    post["deployed_digest_verification"].update({
        "status": "passed",
        "evidence_ref": "evidence://deployment/digest-check",
        "reviewer": "release-operator",
        "reviewed_at": "2026-10-09T12:00:00Z",
        "expected_digest": "sha256:" + "c" * 64,
        "observed_digest": "sha256:" + "d" * 64,
    })
    post["rollback_drill"].update({
        "status": "passed",
        "evidence_ref": "evidence://deployment/rollback",
        "reviewer": "release-operator",
        "reviewed_at": "2026-10-09T12:00:00Z",
    })
    errors = validate_release_evidence(evidence, require_production=True)
    assert any("zero open critical/high" in error for error in errors)
    assert any("does not match" in error for error in errors)


def test_production_promotion_requires_post_deployment_evidence() -> None:
    evidence = _passed_evidence()
    errors = validate_release_evidence(evidence, require_production=True)
    assert any("deployed_digest_verification is not passed" in error for error in errors)
    assert any("rollback_drill is not passed" in error for error in errors)


def test_release_workflow_is_tag_gated_and_verifies_published_attestation() -> None:
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "if: startsWith(github.ref, 'refs/tags/v')" in workflow
    assert "python scripts/verify_release_evidence.py release/release-evidence.json --require-passed" in workflow
    assert "push-to-registry: true" in workflow
    assert "gh attestation verify" in workflow
    assert "release-manifest.json" in workflow
    assert "sbom-path: auctaryn-container.spdx.json" in workflow
    assert "--verify-tag" in workflow
