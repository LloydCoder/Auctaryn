#!/usr/bin/env python3
"""Verify the effective OpenShell policy hash against a reviewed deployment pin."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import subprocess
from collections.abc import Callable
from typing import Any


def verify_effective_policy(
    sandbox_name: str,
    expected_sha256: str,
    *,
    runner: Callable[..., Any] = subprocess.run,
) -> str:
    if not sandbox_name or not sandbox_name.strip() or len(sandbox_name) > 128:
        raise ValueError("A bounded OpenShell sandbox name is required.")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256 or ""):
        raise ValueError("A reviewed 64-character SHA-256 policy pin is required.")

    try:
        result = runner(
            ["openshell", "sandbox", "get", sandbox_name, "--policy-only"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Could not retrieve the effective OpenShell policy.") from exc

    if result.returncode != 0 or not isinstance(result.stdout, str) or not result.stdout.strip():
        raise RuntimeError("OpenShell did not return an effective policy document.")

    actual = hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual, expected_sha256.lower()):
        raise RuntimeError("Effective OpenShell policy hash does not match the reviewed pin.")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sandbox", default=os.getenv("OPENSHELL_SANDBOX_NAME", ""))
    parser.add_argument(
        "--expected-sha256",
        default=os.getenv("AUCTARYN_EXPECTED_EFFECTIVE_POLICY_SHA256", ""),
        help="SHA-256 of the independently reviewed effective policy YAML",
    )
    args = parser.parse_args()
    try:
        digest = verify_effective_policy(args.sandbox, args.expected_sha256)
    except (ValueError, RuntimeError) as exc:
        parser.exit(2, f"policy verification failed: {exc}\n")
    print(f"Effective OpenShell policy verified: sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
