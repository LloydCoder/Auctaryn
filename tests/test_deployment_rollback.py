"""Phase 21 rollback guard and script regression tests."""
import os
from pathlib import Path
import subprocess


def _fake_commands(tmp_path: Path) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker.log"
    docker = bin_dir / "docker"
    docker.write_text(
        """#!/usr/bin/env bash
set -e
printf '%s\\n' "$*" >> "$DOCKER_TEST_LOG"
if [[ "$1 $2 $3" == "compose ps -q" ]]; then echo "container-current"; fi
if [[ "$1 $2" == "inspect --format" ]]; then echo "$CURRENT_IMAGE_ID"; fi
exit 0
""",
        encoding="utf-8",
    )
    curl = bin_dir / "curl"
    curl.write_text(
        """#!/usr/bin/env bash
if [[ "$*" == *"/health/ready"* ]]; then
  echo '{"ready":true}'
fi
exit 0
""",
        encoding="utf-8",
    )
    docker.chmod(0o700)
    curl.chmod(0o700)
    return bin_dir, log


def test_rollback_restores_recorded_immutable_image(tmp_path):
    repo = tmp_path / "repo"
    state = repo / ".deploy-state"
    state.mkdir(parents=True)
    (repo / ".env").write_text("AUCTARYN_API_KEY=test\\n", encoding="utf-8")
    previous = "sha256:" + "b" * 64
    (state / "previous-image-id").write_text(previous + "\\n", encoding="utf-8")
    bin_dir, log = _fake_commands(tmp_path)
    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "DOCKER_TEST_LOG": str(log),
        "CURRENT_IMAGE_ID": "sha256:" + "a" * 64,
        "AUCTARYN_REPO_DIR": str(repo),
        "AUCTARYN_DEPLOY_STATE_DIR": str(state),
    }

    result = subprocess.run(["bash", "scripts/rollback.sh"], env=env, capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr + result.stdout
    commands = log.read_text(encoding="utf-8")
    assert f"image tag {previous} auctaryn:latest" in commands
    assert "compose up -d --no-build api" in commands


def test_rollback_fails_closed_without_valid_previous_image(tmp_path):
    repo = tmp_path / "repo"
    state = repo / ".deploy-state"
    state.mkdir(parents=True)
    (repo / ".env").write_text("", encoding="utf-8")
    (state / "previous-image-id").write_text("not-an-image-id", encoding="utf-8")
    bin_dir, log = _fake_commands(tmp_path)
    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "DOCKER_TEST_LOG": str(log),
        "CURRENT_IMAGE_ID": "sha256:" + "a" * 64,
        "AUCTARYN_REPO_DIR": str(repo),
        "AUCTARYN_DEPLOY_STATE_DIR": str(state),
    }

    result = subprocess.run(["bash", "scripts/rollback.sh"], env=env, capture_output=True, text=True, check=False)

    assert result.returncode != 0
    assert "compose up -d --no-build api" not in log.read_text(encoding="utf-8")


def test_deployment_scripts_pass_bash_syntax_check():
    for path in ("scripts/deploy.sh", "scripts/rollback.sh"):
        result = subprocess.run(["bash", "-n", path], capture_output=True, text=True, check=False)
        assert result.returncode == 0, f"{path}: {result.stderr}"
