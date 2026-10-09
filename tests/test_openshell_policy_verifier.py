"""Tests for the live effective-policy pin verifier."""

import hashlib
from types import SimpleNamespace

import pytest

from scripts.verify_openshell_policy import verify_effective_policy


def test_effective_policy_verifier_accepts_exact_reviewed_hash():
    policy = "version: 1\nnetwork_policies: {}\n"
    expected = hashlib.sha256(policy.encode("utf-8")).hexdigest()
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=policy)

    assert verify_effective_policy("prod-sandbox", expected, runner=runner) == expected
    assert calls[0][0] == ["openshell", "sandbox", "get", "prod-sandbox", "--policy-only"]
    assert calls[0][1]["timeout"] == 10
    assert calls[0][1]["shell"] is False


def test_effective_policy_verifier_rejects_policy_drift():
    with pytest.raises(RuntimeError, match="does not match"):
        verify_effective_policy(
            "prod-sandbox",
            "a" * 64,
            runner=lambda *_args, **_kwargs: SimpleNamespace(
                returncode=0, stdout="different effective policy"
            ),
        )


def test_effective_policy_verifier_rejects_cli_failure():
    with pytest.raises(RuntimeError, match="did not return"):
        verify_effective_policy(
            "prod-sandbox",
            "a" * 64,
            runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=""),
        )


def test_effective_policy_verifier_requires_reviewed_hash_before_cli_call():
    called = False

    def runner(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("CLI must not run without a valid pin")

    with pytest.raises(ValueError, match="reviewed 64-character"):
        verify_effective_policy("prod-sandbox", "", runner=runner)
    assert called is False



def test_effective_policy_verifier_rejects_cli_option_as_sandbox_name():
    called = False

    def runner(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("CLI must not run for an invalid sandbox name")

    with pytest.raises(ValueError, match="unsupported characters"):
        verify_effective_policy("--help", "a" * 64, runner=runner)
    assert called is False
