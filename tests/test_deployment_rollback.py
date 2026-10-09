"""Phase 24 digest-pinned deployment and rollback regression tests."""
import json
import os
from pathlib import Path
import subprocess


def _fake_commands(tmp_path: Path, image_id: str) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "commands.log"

    docker = bin_dir / "docker"
    docker.write_text(
        """#!/usr/bin/env bash
set -e
printf 'docker %s\\n' "$*" >> "$DOCKER_TEST_LOG"
if [[ "$1 $2 $3" == "compose ps -q" ]]; then echo "container-current"; fi
if [[ "$1 $2" == "image inspect" ]]; then echo "$PULLED_IMAGE_ID"; fi
if [[ "$1 $2" == "inspect --format" ]]; then echo "$CURRENT_IMAGE_ID"; fi
exit 0
""",
        encoding="utf-8",
    )
    gh = bin_dir / "gh"
    gh.write_text(
        """#!/usr/bin/env bash
set -e
printf 'gh %s\\n' "$*" >> "$DOCKER_TEST_LOG"
if [[ "$1 $2" == "auth status" ]]; then exit 0; fi
if [[ "$1 $2" == "release download" ]]; then
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir) shift; outdir="$1" ;;
    esac
    shift
  done
  mkdir -p "$outdir"
  printf '%s\\n' '{"schema_version":"auctaryn-release-manifest.v1"}' > "$outdir/release-manifest.json"
  exit 0
fi
if [[ "$1 $2" == "attestation verify" ]]; then exit 0; fi
exit 0
""",
        encoding="utf-8",
    )
    jq = bin_dir / "jq"
    jq.write_text(
        """#!/usr/bin/env bash
# The release-manifest schema is validated in the real CI contract tests;
# this process test only exercises rollback orchestration and external call order.
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
    for path in (docker, gh, jq, curl):
        path.chmod(0o700)
    return bin_dir, log


def _release_ref(digest_char: str) -> str:
    return "ghcr.io/lloydcoder/auctaryn@sha256:" + digest_char * 64


def test_rollback_restores_attested_immutable_release(tmp_path):
    repo = tmp_path / "repo"
    state = repo / ".deploy-state"
    state.mkdir(parents=True)
    current_ref = _release_ref("a")
    previous_ref = _release_ref("b")
    (repo / ".env").write_text(
        f"AUCTARYN_API_KEY={'x' * 32}\n"
        f"AUCTARYN_IMAGE={current_ref}\n"
        "AUCTARYN_RELEASE_TAG=v1.0.0\n",
        encoding="utf-8",
    )
    (state / "previous-image-ref").write_text(previous_ref + "\n", encoding="utf-8")
    (state / "previous-image-id").write_text("sha256:" + "b" * 64 + "\n", encoding="utf-8")
    (state / "previous-release-tag").write_text("v0.9.0\n", encoding="utf-8")
    bin_dir, log = _fake_commands(tmp_path, "sha256:" + "b" * 64)
    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "DOCKER_TEST_LOG": str(log),
        "CURRENT_IMAGE_ID": "sha256:" + "b" * 64,
        "PULLED_IMAGE_ID": "sha256:" + "b" * 64,
        "AUCTARYN_REPO_DIR": str(repo),
        "AUCTARYN_DEPLOY_STATE_DIR": str(state),
    }

    result = subprocess.run(["bash", "scripts/rollback.sh"], env=env, capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr + result.stdout
    commands = log.read_text(encoding="utf-8")
    assert f"docker pull {previous_ref}" in commands
    assert "gh attestation verify" in commands
    assert "docker compose up -d --no-build api" in commands
    assert "docker image tag" not in commands
    assert f"AUCTARYN_IMAGE={previous_ref}" in (repo / ".env").read_text(encoding="utf-8")
    assert "AUCTARYN_RELEASE_TAG=v0.9.0" in (repo / ".env").read_text(encoding="utf-8")
    assert not (state / "previous-image-ref").exists()


def test_rollback_fails_closed_without_valid_previous_release(tmp_path):
    repo = tmp_path / "repo"
    state = repo / ".deploy-state"
    state.mkdir(parents=True)
    (repo / ".env").write_text("", encoding="utf-8")
    (state / "previous-image-id").write_text("not-an-image-id", encoding="utf-8")
    bin_dir, log = _fake_commands(tmp_path, "sha256:" + "a" * 64)
    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "DOCKER_TEST_LOG": str(log),
        "CURRENT_IMAGE_ID": "sha256:" + "a" * 64,
        "PULLED_IMAGE_ID": "sha256:" + "a" * 64,
        "AUCTARYN_REPO_DIR": str(repo),
        "AUCTARYN_DEPLOY_STATE_DIR": str(state),
    }

    result = subprocess.run(["bash", "scripts/rollback.sh"], env=env, capture_output=True, text=True, check=False)

    assert result.returncode != 0
    commands = log.read_text(encoding="utf-8") if log.exists() else ""
    assert "docker compose up -d --no-build api" not in commands


def test_deployment_script_requires_attested_digest_and_runtime_evidence():
    script = Path("scripts/deploy.sh").read_text(encoding="utf-8")
    assert "gh attestation verify" in script
    assert "AUCTARYN_IMAGE must be the exact lowercase GHCR image digest" in script
    assert "docker pull \"$IMAGE_REF\"" in script
    assert "docker compose up -d --no-build api" in script
    assert "docker compose build api" not in script
    assert "OPENSHELL_SYSTEM_GATEWAY_DIR" in script
    assert "verify_openshell_gateway_metadata.py" in script
    assert "AUCTARYN_EVIDENCE_HMAC_KEY_FILE" in script
    assert "AUCTARYN_RUNTIME_ADAPTER" in script
    assert "AUCTARYN_DOMAIN" in script


def test_deployment_scripts_pass_bash_syntax_check():
    for path in ("scripts/deploy.sh", "scripts/rollback.sh"):
        result = subprocess.run(["bash", "-n", path], capture_output=True, text=True, check=False)
        assert result.returncode == 0, f"{path}: {result.stderr}"
