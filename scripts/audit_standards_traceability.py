"""Validate the machine-readable standards-to-evidence map without network access."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config" / "standards_traceability.json"
VALID_STATUSES = {
    "mapped-local-evidence",
    "documentation-and-tests",
    "implemented-local",
    "partial",
    "external-evidence-required",
}
REQUIRED_ASI = {f"OWASP-ASI{i:02d}" for i in range(1, 11)}
REQUIRED_AI_RMF = {
    "AI-RMF-GOVERN",
    "AI-RMF-MAP",
    "AI-RMF-MEASURE",
    "AI-RMF-MANAGE",
}


def validate_manifest(root: Path = ROOT, manifest_path: Path = MANIFEST_PATH) -> list[str]:
    """Return actionable errors; an empty list means references are structurally valid."""
    errors: list[str] = []
    try:
        manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot load manifest: {exc}"]

    if manifest.get("schema_version") != "auctaryn-standards-traceability.v1":
        errors.append("unsupported or missing schema_version")
    standards = manifest.get("standards")
    controls = manifest.get("controls")
    if not isinstance(standards, list) or not isinstance(controls, list):
        return errors + ["standards and controls must be arrays"]

    standard_ids = [item.get("id") for item in standards if isinstance(item, dict)]
    if len(standard_ids) != len(set(standard_ids)):
        errors.append("duplicate standard id")
    known_standards = set(standard_ids)
    control_ids: list[str] = []
    referenced_standards: set[str] = set()

    for index, control in enumerate(controls):
        label = f"controls[{index}]"
        if not isinstance(control, dict):
            errors.append(f"{label} must be an object")
            continue
        control_id = control.get("id")
        if not isinstance(control_id, str) or not control_id:
            errors.append(f"{label} missing id")
            continue
        control_ids.append(control_id)
        if control.get("standard_id") not in known_standards:
            errors.append(f"{control_id}: unknown standard_id")
        else:
            referenced_standards.add(control["standard_id"])
        if control.get("status") not in VALID_STATUSES:
            errors.append(f"{control_id}: invalid status")
        if not isinstance(control.get("residual_risk"), str) or not control["residual_risk"].strip():
            errors.append(f"{control_id}: residual_risk must be explicit")

        implementation_paths = control.get("implementation_paths")
        if not isinstance(implementation_paths, list) or not implementation_paths:
            errors.append(f"{control_id}: implementation_paths must be non-empty")
        else:
            for relative in implementation_paths:
                if not isinstance(relative, str) or not (root / relative).is_file():
                    errors.append(f"{control_id}: missing implementation path {relative!r}")

        test_cases = control.get("test_cases")
        if not isinstance(test_cases, list) or not test_cases:
            errors.append(f"{control_id}: test_cases must be non-empty")
        else:
            for case in test_cases:
                if not isinstance(case, dict) or not isinstance(case.get("path"), str) or not isinstance(case.get("name"), str):
                    errors.append(f"{control_id}: malformed test case")
                    continue
                test_path = root / case["path"]
                if not test_path.is_file():
                    errors.append(f"{control_id}: missing test path {case['path']}")
                    continue
                source = test_path.read_text(encoding="utf-8")
                pattern = rf"^\s*(?:async\s+)?def\s+{re.escape(case['name'])}\s*\("
                if not re.search(pattern, source, flags=re.MULTILINE):
                    errors.append(f"{control_id}: test function {case['name']} not found in {case['path']}")

    if len(control_ids) != len(set(control_ids)):
        errors.append("duplicate control id")
    actual_asi = {item for item in control_ids if item.startswith("OWASP-ASI")}
    if actual_asi != REQUIRED_ASI:
        errors.append(f"OWASP ASI coverage mismatch: missing={sorted(REQUIRED_ASI - actual_asi)} extra={sorted(actual_asi - REQUIRED_ASI)}")
    if not REQUIRED_AI_RMF <= set(control_ids):
        errors.append(f"missing AI RMF functions: {sorted(REQUIRED_AI_RMF - set(control_ids))}")
    if not any(item.startswith("SSDF-") for item in control_ids):
        errors.append("missing NIST SSDF controls")
    if referenced_standards != known_standards:
        errors.append(f"unreferenced standards: {sorted(known_standards - referenced_standards)}")
    return errors


def main() -> int:
    errors = validate_manifest()
    if errors:
        print("Standards traceability validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Standards traceability valid: OWASP ASI01–ASI10, NIST SSDF and AI RMF mappings resolve to repository evidence.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
