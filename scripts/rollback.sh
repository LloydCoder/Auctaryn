#!/usr/bin/env bash
# Restore the immutable image captured by the last deployment.
set -euo pipefail

REPO_DIR="${AUCTARYN_REPO_DIR:-/opt/auctaryn}"
DEPLOY_STATE_DIR="${AUCTARYN_DEPLOY_STATE_DIR:-${REPO_DIR}/.deploy-state}"
cd "$REPO_DIR"

if [[ ! -f .env ]]; then
  echo "Missing $REPO_DIR/.env; refusing rollback without the deployment configuration."
  exit 1
fi
STATE_FILE="$DEPLOY_STATE_DIR/previous-image-id"
if [[ ! -f "$STATE_FILE" ]]; then
  echo "No previous immutable image recorded. Auctaryn has no verified rollback target."
  exit 1
fi
PREVIOUS_IMAGE_ID=$(cat "$STATE_FILE")
if [[ ! "$PREVIOUS_IMAGE_ID" =~ ^sha256:[a-f0-9]{64}$ ]]; then
  echo "Rollback state is malformed; refusing to tag an untrusted image reference."
  exit 1
fi
if ! docker image inspect "$PREVIOUS_IMAGE_ID" >/dev/null 2>&1; then
  echo "Previous image $PREVIOUS_IMAGE_ID is unavailable locally; restore it from the approved registry first."
  exit 1
fi

IMAGE_REF="${AUCTARYN_IMAGE:-$(grep -E '^AUCTARYN_IMAGE=' .env | head -n1 | cut -d= -f2- || true)}"
IMAGE_REF="${IMAGE_REF:-auctaryn:latest}"
if [[ ! "$IMAGE_REF" =~ ^[a-zA-Z0-9._/:@-]+$ ]]; then
  echo "AUCTARYN_IMAGE contains invalid characters; refusing rollback."
  exit 1
fi

CURRENT_CONTAINER=$(docker compose ps -q api 2>/dev/null || true)
if [[ -n "$CURRENT_CONTAINER" ]]; then
  CURRENT_IMAGE_ID=$(docker inspect --format '{{.Image}}' "$CURRENT_CONTAINER")
  if [[ "$CURRENT_IMAGE_ID" == "$PREVIOUS_IMAGE_ID" ]]; then
    echo "The recorded previous image is already running: $PREVIOUS_IMAGE_ID"
    exit 0
  fi
fi

echo "Restoring immutable image $PREVIOUS_IMAGE_ID to $IMAGE_REF"
docker image tag "$PREVIOUS_IMAGE_ID" "$IMAGE_REF"
docker compose up -d --no-build api

echo "Waiting for rollback liveness..."
healthy=false
for _ in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8400/health >/dev/null 2>&1; then
    healthy=true
    break
  fi
  sleep 2
done
if [[ "$healthy" != true ]]; then
  docker compose logs --tail=100 api
  echo "Rollback image is not live. Keep public exposure disabled and investigate."
  exit 1
fi

if [[ "${AUCTARYN_REQUIRE_READY:-true}" != "false" ]]; then
  READINESS=$(curl -fsS http://127.0.0.1:8400/health/ready || true)
  if ! grep -Eq '"ready"[[:space:]]*:[[:space:]]*true' <<< "$READINESS"; then
    echo "Rollback image is live but not ready. Keep public exposure disabled. Readiness: $READINESS"
    exit 1
  fi
fi

echo "Rollback completed. Persistent data volumes were not rolled back; verify evidence integrity and incident controls before restoring traffic."
