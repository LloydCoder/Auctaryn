"""Static validation for Auctaryn's restrictive OpenShell baseline policy."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

_ALLOWED_WRITE_PATHS = {"/sandbox", "/tmp", "/dev/null"}
_ALLOWED_READ_ONLY_PATHS = {
    "/bin", "/usr", "/lib", "/proc", "/dev/urandom", "/etc", "/var/log"
}
_REQUIRED_READ_ONLY_PATHS = {"/bin", "/usr", "/lib", "/etc"}


class PolicyValidationError(ValueError):
    """Raised when the checked-in runtime baseline violates required controls."""


class _UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ValueError("duplicate YAML mapping key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def validate_baseline_policy(policy: Any) -> list[str]:
    """Return policy violations for the deliberately restrictive default baseline."""
    errors: list[str] = []
    if not isinstance(policy, dict):
        return ["policy root must be a mapping"]
    if policy.get("version") != 1:
        errors.append("policy version must be 1")
    if set(policy) - {"version", "filesystem_policy", "landlock", "network_policies"}:
        errors.append("policy contains an unreviewed top-level section")

    filesystem = policy.get("filesystem_policy")
    if not isinstance(filesystem, dict):
        errors.append("filesystem_policy must be a mapping")
    else:
        if set(filesystem) - {"include_workdir", "read_only", "read_write"}:
            errors.append("filesystem_policy contains an unreviewed setting")
        read_only = filesystem.get("read_only")
        read_write = filesystem.get("read_write")
        if not isinstance(read_only, list) or any(not isinstance(path, str) for path in read_only):
            errors.append("filesystem_policy.read_only must be a list of paths")
        else:
            read_only_paths = set(read_only)
            if not _REQUIRED_READ_ONLY_PATHS.issubset(read_only_paths):
                errors.append("filesystem_policy.read_only is missing required system paths")
            if not read_only_paths.issubset(_ALLOWED_READ_ONLY_PATHS):
                errors.append("filesystem_policy.read_only contains an unapproved readable path")

        if not isinstance(read_write, list) or any(not isinstance(path, str) for path in read_write):
            errors.append("filesystem_policy.read_write must be a list of paths")
        else:
            write_paths = set(read_write)
            if not write_paths.issubset(_ALLOWED_WRITE_PATHS):
                errors.append("filesystem_policy.read_write contains an unapproved writable path")
            if not write_paths:
                errors.append("filesystem_policy.read_write must retain the approved workspace/temp paths")

        if filesystem.get("include_workdir") is not True:
            errors.append("filesystem_policy.include_workdir must be true")

    landlock = policy.get("landlock")
    if not isinstance(landlock, dict) or landlock.get("compatibility") != "hard_requirement":
        errors.append("landlock.compatibility must be hard_requirement")
    elif set(landlock) - {"compatibility"}:
        errors.append("landlock contains an unreviewed setting")

    network = policy.get("network_policies")
    if network != {}:
        errors.append("baseline network_policies must be empty; network access requires separate review")

    return errors


def load_and_validate_baseline(path: str | Path) -> tuple[dict[str, Any], str]:
    """Load a YAML baseline safely, validate it, and return its source SHA-256."""
    source = Path(path).read_bytes()
    try:
        policy = yaml.load(source, Loader=_UniqueKeyLoader)
    except (yaml.YAMLError, ValueError) as exc:
        raise PolicyValidationError("OpenShell baseline policy is invalid or contains duplicate keys") from exc

    errors = validate_baseline_policy(policy)
    if errors:
        raise PolicyValidationError("; ".join(errors))
    return policy, hashlib.sha256(source).hexdigest()


def default_baseline_path() -> Path:
    """Resolve the repository-owned baseline relative to this module, not CWD."""
    return Path(__file__).resolve().parents[2] / "deploy" / "openshell" / "auctaryn-policy.yaml"
