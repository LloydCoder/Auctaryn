"""Static security validation for the checked-in OpenShell baseline."""

from pathlib import Path

import pytest

from modules.execution_gateway.policy_validation import (
    PolicyValidationError,
    load_and_validate_baseline,
    validate_baseline_policy,
)


POLICY_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "openshell"
    / "auctaryn-policy.yaml"
)


def test_checked_in_baseline_is_restrictive_and_hashable():
    policy, digest = load_and_validate_baseline(POLICY_PATH)
    assert validate_baseline_policy(policy) == []
    assert len(digest) == 64
    assert policy["landlock"]["compatibility"] == "hard_requirement"
    assert policy["network_policies"] == {}


def test_baseline_rejects_best_effort_landlock():
    policy, _ = load_and_validate_baseline(POLICY_PATH)
    policy["landlock"]["compatibility"] = "best_effort"
    assert any("hard_requirement" in error for error in validate_baseline_policy(policy))


def test_baseline_rejects_broad_readable_paths():
    policy, _ = load_and_validate_baseline(POLICY_PATH)
    policy["filesystem_policy"]["read_only"].append("/")
    assert any("unapproved readable path" in error for error in validate_baseline_policy(policy))


def test_baseline_rejects_unapproved_writable_paths():
    policy, _ = load_and_validate_baseline(POLICY_PATH)
    policy["filesystem_policy"]["read_write"].append("/")
    assert any("unapproved writable path" in error for error in validate_baseline_policy(policy))


def test_baseline_rejects_network_allow_rules_by_default():
    policy, _ = load_and_validate_baseline(POLICY_PATH)
    policy["network_policies"] = {
        "unreviewed": {"endpoints": [{"host": "*", "port": 443}]}
    }
    assert any("network_policies must be empty" in error for error in validate_baseline_policy(policy))


def test_baseline_rejects_unreviewed_policy_sections():
    policy, _ = load_and_validate_baseline(POLICY_PATH)
    policy["custom_network_override"] = {"allow_all": True}
    assert any("unreviewed top-level section" in error for error in validate_baseline_policy(policy))


def test_baseline_rejects_non_mapping_document():
    assert validate_baseline_policy(["not", "a", "mapping"]) == ["policy root must be a mapping"]


def test_malformed_yaml_fails_closed(tmp_path):
    policy_path = tmp_path / "invalid.yaml"
    policy_path.write_text("filesystem_policy: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyValidationError, match="not valid YAML"):
        load_and_validate_baseline(policy_path)



def test_duplicate_yaml_keys_fail_closed(tmp_path):
    policy_path = tmp_path / "duplicate.yaml"
    policy_path.write_text("version: 1\nversion: 2\n", encoding="utf-8")
    with pytest.raises(PolicyValidationError, match="duplicate keys"):
        load_and_validate_baseline(policy_path)
