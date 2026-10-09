"""Ensure the secret scanner covers the full PR/push change range."""
from pathlib import Path


def test_gitleaks_is_checksum_pinned_and_scans_explicit_commit_ranges():
    workflow = Path(".github/workflows/supply-chain.yml").read_text(encoding="utf-8")
    assert "gitleaks/gitleaks-action@" not in workflow
    assert "gitleaks_8.30.1_linux_x64.tar.gz" in workflow
    assert "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" in workflow
    assert 'range="${PR_BASE_SHA}..${PR_HEAD_SHA}"' in workflow
    assert 'range="${PUSH_BEFORE}..${PUSH_AFTER}"' in workflow
    assert 'range="$GITHUB_SHA"' in workflow
    assert '--log-opts="$range"' in workflow
    assert "Scan full history reachable from this ref" in workflow
    assert '--log-opts="$GITHUB_SHA"' in workflow
    assert "history-results.sarif" in workflow
    assert "Upload Gitleaks SARIF" in workflow
