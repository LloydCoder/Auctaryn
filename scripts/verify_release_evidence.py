"""Fail-closed validation for Auctaryn release evidence."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "release" / "release-evidence.json"
SCHEMA_VERSION = "auctaryn-release-evidence.v1"
PRE_RELEASE_GATES = {
    "independent_assessment",
    "platform_conformance",
    "openshell_runtime_acceptance",
    "risk_register_review",
}
POST_DEPLOYMENT_GATES = {"deployed_digest_verification", "rollback_drill"}
WORKFLOW_NAMES = {"ci", "codeql", "supply_chain"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPORT_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
WORKFLOW_URL_RE = re.compile(
    r"^https://github\.com/LloydCoder/Auctaryn/actions/runs/[0-9]+$"
)


def validate_release_evidence(
    evidence: dict[str, Any],
    *,
    require_passed: bool = False,
    require_production: bool = False,
) -> list[str]:
    """Return errors for malformed evidence or unmet promotion gates."""
    if require_production:
        require_passed = True
    errors: list[str] = []
    if evidence.get("schema_version") != SCHEMA_VERSION:
        errors.append("unsupported or missing schema_version")

    tested_commit = evidence.get("tested_commit")
    if not isinstance(tested_commit, str) or (
        tested_commit != "PENDING" and not SHA_RE.fullmatch(tested_commit)
    ):
        errors.append("tested_commit must be PENDING or a 40-character lowercase commit SHA")

    runs = evidence.get("workflow_runs")
    if not isinstance(runs, dict) or set(runs) != WORKFLOW_NAMES:
        errors.append("workflow_runs must contain exactly ci, codeql and supply_chain")
        runs = {}

    for name in sorted(WORKFLOW_NAMES):
        run = runs.get(name, {})
        if not isinstance(run, dict):
            errors.append(f"workflow_runs.{name} must be an object")
            continue
        run_id = run.get("run_id")
        if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id < 0:
            errors.append(f"workflow_runs.{name}.run_id must be a non-negative integer")
        conclusion = run.get("conclusion")
        if conclusion not in {"pending", "success", "failure"}:
            errors.append(f"workflow_runs.{name}.conclusion is invalid")
        head_sha = run.get("head_sha")
        if not isinstance(head_sha, str) or (
            head_sha != "PENDING" and not SHA_RE.fullmatch(head_sha)
        ):
            errors.append(f"workflow_runs.{name}.head_sha is invalid")
        url = run.get("url")
        if not isinstance(url, str) or (url and not WORKFLOW_URL_RE.fullmatch(url)):
            errors.append(f"workflow_runs.{name}.url must be a repository Actions run URL")
        if require_passed:
            if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
                errors.append(f"workflow_runs.{name} must reference a completed run")
            if conclusion != "success":
                errors.append(f"workflow_runs.{name} is not successful")
            if head_sha != tested_commit or not isinstance(tested_commit, str) or not SHA_RE.fullmatch(tested_commit):
                errors.append(f"workflow_runs.{name}.head_sha must equal tested_commit")
            if not isinstance(url, str) or not WORKFLOW_URL_RE.fullmatch(url):
                errors.append(f"workflow_runs.{name}.url is required for release")

    pre = evidence.get("pre_release_gates")
    if not isinstance(pre, dict) or set(pre) != PRE_RELEASE_GATES:
        errors.append("pre_release_gates must contain all required pre-release gates")
        pre = {}
    for name in sorted(PRE_RELEASE_GATES):
        gate = pre.get(name, {})
        errors.extend(_validate_gate(name, gate, require_passed=require_passed))
        if isinstance(gate, dict) and name == "independent_assessment":
            report_hash = gate.get("report_sha256", "")
            critical_open = gate.get("critical_open")
            high_open = gate.get("high_open")
            if gate.get("status") == "passed":
                if not isinstance(report_hash, str) or not REPORT_HASH_RE.fullmatch(report_hash):
                    errors.append("independent_assessment.report_sha256 must be a SHA-256 hex digest")
                if critical_open != 0 or high_open != 0:
                    errors.append("independent assessment must report zero open critical/high findings")
            if require_passed and gate.get("status") != "passed":
                errors.append("independent_assessment is not passed")

    post = evidence.get("post_deployment_gates")
    if not isinstance(post, dict) or set(post) != POST_DEPLOYMENT_GATES:
        errors.append("post_deployment_gates must contain digest verification and rollback drill")
        post = {}
    for name in sorted(POST_DEPLOYMENT_GATES):
        gate = post.get(name, {})
        errors.extend(_validate_gate(name, gate, require_passed=require_production))
        if isinstance(gate, dict) and name == "deployed_digest_verification":
            expected = gate.get("expected_digest", "")
            observed = gate.get("observed_digest", "")
            if gate.get("status") == "passed" or require_production:
                if not isinstance(expected, str) or not DIGEST_RE.fullmatch(expected):
                    errors.append("deployed_digest_verification.expected_digest is invalid")
                if not isinstance(observed, str) or not DIGEST_RE.fullmatch(observed):
                    errors.append("deployed_digest_verification.observed_digest is invalid")
                if expected != observed:
                    errors.append("deployed image digest does not match the expected release digest")
        if require_production and isinstance(gate, dict) and gate.get("status") != "passed":
            errors.append(f"post-deployment gate {name} is not passed")

    return errors


def _validate_gate(name: str, gate: Any, *, require_passed: bool) -> list[str]:
    errors: list[str] = []
    if not isinstance(gate, dict):
        return [f"{name} must be an object"]
    if gate.get("status") not in {"pending", "passed"}:
        errors.append(f"{name}.status must be pending or passed")
    if gate.get("status") == "passed":
        for field in ("evidence_ref", "reviewer", "reviewed_at"):
            value = gate.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{name}.{field} is required when status is passed")
    if require_passed and gate.get("status") != "passed":
        errors.append(f"{name} is not passed")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--require-passed", action="store_true", help="require all pre-release gates and exact-head CI evidence")
    parser.add_argument("--require-production", action="store_true", help="also require deployed-digest verification and rollback-drill evidence")
    args = parser.parse_args()
    try:
        evidence = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Release evidence could not be loaded: {exc}")
        return 1
    if not isinstance(evidence, dict):
        print("Release evidence must be a JSON object")
        return 1
    errors = validate_release_evidence(
        evidence,
        require_passed=args.require_passed,
        require_production=args.require_production,
    )
    if errors:
        print("Release evidence gate failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    if args.require_production:
        print("Production acceptance evidence is complete.")
    elif args.require_passed:
        print("Pre-release evidence is complete; production deployment acceptance remains a separate gate.")
    else:
        print("Release evidence schema is valid; pending gates do not authorize publication.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
