"""Tests for machine-readable security standards traceability."""
import json
from pathlib import Path

from scripts.audit_standards_traceability import MANIFEST_PATH, ROOT, validate_manifest


def test_standards_traceability_maps_every_owasp_asi_category() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert validate_manifest(ROOT, MANIFEST_PATH) == []
    asi = {control["id"] for control in manifest["controls"] if control["id"].startswith("OWASP-ASI")}
    assert asi == {f"OWASP-ASI{i:02d}" for i in range(1, 11)}


def test_traceability_validator_fails_closed_for_missing_paths_and_unknown_status(tmp_path: Path) -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest["controls"][0]["status"] = "certified"
    manifest["controls"][0]["implementation_paths"] = ["does/not/exist.py"]
    bad_manifest = tmp_path / "bad-traceability.json"
    bad_manifest.write_text(json.dumps(manifest), encoding="utf-8")

    errors = validate_manifest(ROOT, bad_manifest)
    assert any("invalid status" in error for error in errors)
    assert any("does/not/exist.py" in error for error in errors)
