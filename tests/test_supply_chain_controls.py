"""Regression checks for Auctaryn's secure software supply-chain contract."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_npm_lockfile_matches_manifest() -> None:
    manifest = json.loads((ROOT / "dashboard/package.json").read_text())
    lock = json.loads((ROOT / "dashboard/package-lock.json").read_text())
    assert lock["lockfileVersion"] == 3
    root_package = lock["packages"][""]
    assert root_package["name"] == manifest["name"]
    assert root_package["version"] == manifest["version"]
    assert root_package.get("dependencies", {}) == manifest.get("dependencies", {})
    assert root_package.get("devDependencies", {}) == manifest.get("devDependencies", {})


def test_python_lock_contains_hashes_and_direct_pins() -> None:
    requirements = (ROOT / "requirements.txt").read_text().splitlines()
    lock = (ROOT / "requirements.lock").read_text()
    assert "--hash=sha256:" in lock
    lock_names = {
        re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?==", line.strip()).group(1).lower().replace("_", "-")
        for line in lock.splitlines()
        if re.match(r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?==", line.strip())
    }
    direct_names = set()
    for line in requirements:
        stripped = line.strip()
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?==", stripped)
        if match:
            direct_names.add(match.group(1).lower().replace("_", "-"))
    assert direct_names <= lock_names


def test_ci_installs_hash_locked_python_and_npm_dependencies() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    supply = (ROOT / ".github/workflows/supply-chain.yml").read_text()
    assert "pip install --require-hashes -r requirements.lock" in ci
    assert "pip-audit -r requirements.lock" in ci
    assert "npm ci --no-audit --no-fund" in ci
    assert "npm ci --no-audit --no-fund" in supply
    assert "npm audit --audit-level=high" in supply


def test_all_external_github_actions_are_pinned_to_full_commit_shas() -> None:
    workflows = list((ROOT / ".github/workflows").glob("*.yml"))
    assert workflows
    failures = []
    for workflow in workflows:
        for line_number, line in enumerate(workflow.read_text().splitlines(), start=1):
            match = re.match(r"^\s*(?:-\s*)?uses:\s*([^\s]+)", line)
            if not match:
                continue
            action_ref = match.group(1)
            if action_ref.startswith("./"):
                continue
            if not re.search(r"@[0-9a-f]{40}$", action_ref):
                failures.append(f"{workflow.relative_to(ROOT)}:{line_number}: {action_ref}")
    assert not failures, "Unpinned GitHub Actions found:\n" + "\n".join(failures)


def test_supply_chain_workflow_has_required_controls() -> None:
    supply = (ROOT / ".github/workflows/supply-chain.yml").read_text()
    codeql = (ROOT / ".github/workflows/codeql.yml").read_text()
    assert "gitleaks/gitleaks-action@" in supply
    assert "anchore/sbom-action@" in supply
    assert "anchore/scan-action@" in supply
    assert "severity-cutoff: high" in supply
    assert "only-fixed: true" in supply
    inventory_step = supply.split("      - name: Record complete container vulnerability inventory", 1)[1]
    inventory_step = inventory_step.split("      - name:", 1)[0]
    assert "severity-cutoff: negligible" in inventory_step
    assert "only-fixed: false" in inventory_step
    assert "output-file: grype-full.json" in supply
    assert "audit_grype_report.py grype-full.json" in supply
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "FROM python:3.12.15-alpine3.24@sha256:7a63cb93468d7ce5f24b1332a8f7a27f444b3221b0a3d6b5573036b78d937c78" in dockerfile
    assert "apt-get install -y --no-install-recommends" not in dockerfile
    assert "curl" not in dockerfile
    assert "fail-build: true" in supply
    assert "actions/attest@" in supply
    assert "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9" in supply
    assert "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9" in codeql
    assert "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333" in supply
    assert "attestations: write" in supply
    assert "security-extended" in codeql
    assert "python,javascript-typescript" in codeql
    assert "audit_codeql_sarif.py --fail-severity high" in codeql
    assert "results/*.sarif" in codeql


def test_deployment_uses_committed_npm_lockfile() -> None:
    deploy = (ROOT / "scripts/deploy.sh").read_text()
    assert "npm ci --no-audit --no-fund" in deploy
    assert "npm install --silent" not in deploy
