#!/usr/bin/env bash
# Restore the last recorded, attested, digest-pinned Auctaryn release.
set -euo pipefail

REPO_DIR="${AUCTARYN_REPO_DIR:-/opt/auctaryn}"
DEPLOY_STATE_DIR="${AUCTARYN_DEPLOY_STATE_DIR:-${REPO_DIR}/.deploy-state}"
cd "$REPO_DIR"

[[ -f .env ]] || { echo "Missing .env; refusing rollback without deployment configuration." >&2; exit 1; }
chmod 600 .env

env_value() {
  local key="$1"
  grep -E "^\${key}=" .env | tail -n1 | cut -d= -f2- || true
}

PREVIOUS_IMAGE_REF="$(cat "$DEPLOY_STATE_DIR/previous-image-ref" 2>/dev/null || true)"
PREVIOUS_IMAGE_ID="$(cat "$DEPLOY_STATE_DIR/previous-image-id" 2>/dev/null || true)"
PREVIOUS_RELEASE_TAG="$(cat "$DEPLOY_STATE_DIR/previous-release-tag" 2>/dev/null || true)"
[[ "$PREVIOUS_IMAGE_REF" =~ ^ghcr\.io/lloydcoder/auctaryn@sha256:[a-f0-9]{64}$ ]] || { echo "No valid immutable previous image reference; refusing rollback." >&2; exit 1; }
[[ "$PREVIOUS_IMAGE_ID" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "Recorded previous image ID is malformed." >&2; exit 1; }
[[ "$PREVIOUS_RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || { echo "Recorded previous release tag is malformed." >&2; exit 1; }

for cmd in gh docker jq curl; do command -v "$cmd" >/dev/null 2>&1 || { echo "Required command is missing: $cmd" >&2; exit 1; }; done
gh auth status >/dev/null 2>&1 || { echo "Authenticate GitHub CLI to verify the previous release." >&2; exit 1; }

RELEASE_ASSET_DIR="$DEPLOY_STATE_DIR/rollback-assets/$PREVIOUS_RELEASE_TAG"
mkdir -p "$RELEASE_ASSET_DIR"
gh release download "$PREVIOUS_RELEASE_TAG" --repo LloydCoder/Auctaryn --pattern release-manifest.json --dir "$RELEASE_ASSET_DIR" --clobber
RELEASE_MANIFEST="$RELEASE_ASSET_DIR/release-manifest.json"
gh attestation verify "$RELEASE_MANIFEST" -R LloydCoder/Auctaryn
gh attestation verify "oci://$PREVIOUS_IMAGE_REF" -R LloydCoder/Auctaryn
gh attestation verify "oci://$PREVIOUS_IMAGE_REF" -R LloydCoder/Auctaryn --predicate-type https://spdx.dev/Document/v2.3
jq -e --arg tag "$PREVIOUS_RELEASE_TAG" --arg image_ref "$PREVIOUS_IMAGE_REF" '
  .schema_version == "auctaryn-release-manifest.v1" and
  .release_tag == $tag and
  (.image + "@" + .image_digest) == $image_ref and
  (.image_digest | test("^sha256:[a-f0-9]{64}$"))
' "$RELEASE_MANIFEST" >/dev/null || { echo "Previous release manifest does not match the recorded image." >&2; exit 1; }

docker pull "$PREVIOUS_IMAGE_REF"
RESTORED_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$PREVIOUS_IMAGE_REF")"
[[ "$RESTORED_IMAGE_ID" == "$PREVIOUS_IMAGE_ID" ]] || { echo "Pulled previous digest does not match the recorded image ID." >&2; exit 1; }

update_env_value() {
  local key="$1" value="$2"
  if grep -q "^$key=" .env; then
    sed -i "s|^$key=.*|$key=$value|" .env
  else
    printf '%s=%s\n' "$key" "$value" >> .env
  fi
}
update_env_value AUCTARYN_IMAGE "$PREVIOUS_IMAGE_REF"
update_env_value AUCTARYN_RELEASE_TAG "$PREVIOUS_RELEASE_TAG"
chmod 600 .env

export COMPOSE_FILE="$REPO_DIR/docker-compose.yml:$REPO_DIR/docker-compose.production.yml"
echo "Restoring attested release $PREVIOUS_RELEASE_TAG ($PREVIOUS_IMAGE_REF)"
docker compose up -d --no-build api

healthy=false
for _ in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8400/health >/dev/null 2>&1; then healthy=true; break; fi
  sleep 2
done
if [[ "$healthy" != true ]]; then
  docker compose logs --tail=100 api
  echo "Rollback liveness failed; keep public traffic disabled." >&2
  exit 1
fi
READINESS="$(curl -fsS http://127.0.0.1:8400/health/ready || true)"
if ! grep -Eq '"ready"[[:space:]]*:[[:space:]]*true' <<< "$READINESS"; then
  echo "Rollback liveness passed but readiness failed: $READINESS" >&2
  exit 1
fi

CURRENT_CONTAINER="$(docker compose ps -q api)"
CURRENT_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$CURRENT_CONTAINER")"
printf '%s\n' "$PREVIOUS_IMAGE_REF" > "$DEPLOY_STATE_DIR/current-image-ref.tmp"
printf '%s\n' "$CURRENT_IMAGE_ID" > "$DEPLOY_STATE_DIR/current-image-id.tmp"
printf '%s\n' "$PREVIOUS_RELEASE_TAG" > "$DEPLOY_STATE_DIR/current-release-tag.tmp"
chmod 600 "$DEPLOY_STATE_DIR"/current-image-*.tmp "$DEPLOY_STATE_DIR/current-release-tag.tmp"
mv -f "$DEPLOY_STATE_DIR/current-image-ref.tmp" "$DEPLOY_STATE_DIR/current-image-ref"
mv -f "$DEPLOY_STATE_DIR/current-image-id.tmp" "$DEPLOY_STATE_DIR/current-image-id"
mv -f "$DEPLOY_STATE_DIR/current-release-tag.tmp" "$DEPLOY_STATE_DIR/current-release-tag"
rm -f "$DEPLOY_STATE_DIR/previous-image-ref" "$DEPLOY_STATE_DIR/previous-image-id" "$DEPLOY_STATE_DIR/previous-release-tag"

echo "Rollback completed and readiness is green on $PREVIOUS_RELEASE_TAG."
