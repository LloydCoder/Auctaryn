#!/usr/bin/env bash
# Deploy only a tag-gated, attested Auctaryn release pinned by immutable OCI digest.
set -Eeuo pipefail

REPO_DIR="${AUCTARYN_REPO_DIR:-/opt/auctaryn}"
DEPLOY_STATE_DIR="${AUCTARYN_DEPLOY_STATE_DIR:-${REPO_DIR}/.deploy-state}"
DOMAIN_INPUT="${AUCTARYN_DOMAIN:-}"
EMAIL_INPUT="${AUCTARYN_TLS_EMAIL:-}"

if [[ -d "$REPO_DIR/.git" ]]; then
    git -C "$REPO_DIR" fetch origin main --tags
    git -C "$REPO_DIR" checkout --force main
    git -C "$REPO_DIR" reset --hard origin/main
else
    sudo mkdir -p "$REPO_DIR"
    sudo chown "$USER:$USER" "$REPO_DIR"
    git clone https://github.com/LloydCoder/Auctaryn.git "$REPO_DIR"
    git -C "$REPO_DIR" fetch origin main --tags
fi
REPO_DIR="$(cd "$REPO_DIR" && pwd)"
cd "$REPO_DIR"

if [[ ! -f .env ]]; then
    cp .env.example .env
    chmod 600 .env
    echo "Created .env from the template. Configure production release, secrets, and runtime metadata, then rerun."
    exit 1
fi
chmod 600 .env

env_value() {
    local key="$1"
    grep -E "^${key}=" .env | tail -n1 | cut -d= -f2- || true
}

DOMAIN="${DOMAIN_INPUT:-$(env_value AUCTARYN_DOMAIN)}"
EMAIL="${EMAIL_INPUT:-$(env_value AUCTARYN_TLS_EMAIL)}"
EMAIL="${EMAIL:-hello@tinlance.com}"
RELEASE_TAG="$(env_value AUCTARYN_RELEASE_TAG)"
IMAGE_REF="$(env_value AUCTARYN_IMAGE)"
API_KEY="$(env_value AUCTARYN_API_KEY)"
ADMIN_KEY="$(env_value AUCTARYN_ADMIN_API_KEY)"
THREATFADE_URL="$(env_value THREATFADE_SERVICE_URL)"
THREATFADE_TOKEN="$(env_value THREATFADE_SERVICE_TOKEN)"
RUNTIME_ADAPTER="$(env_value AUCTARYN_RUNTIME_ADAPTER)"
SANDBOX_NAME="$(env_value OPENSHELL_SANDBOX_NAME)"
WORKSPACE="$(env_value OPENSHELL_WORKSPACE)"
OIDC_ISSUER="$(env_value OPENSHELL_OIDC_ISSUER)"
OIDC_CLIENT_ID="$(env_value OPENSHELL_OIDC_CLIENT_ID)"
OIDC_CLIENT_SECRET="$(env_value OPENSHELL_OIDC_CLIENT_SECRET)"
OIDC_AUDIENCE="$(env_value OPENSHELL_OIDC_AUDIENCE)"
ALLOW_USER_CREDENTIALS="$(env_value OPENSHELL_ALLOW_USER_CREDENTIALS)"
EVIDENCE_KEY_FILE="$(env_value AUCTARYN_EVIDENCE_HMAC_KEY_FILE)"
OPEN_SHELL_DIR="$(env_value OPENSHELL_SYSTEM_GATEWAY_DIR)"

die() { echo "Deployment refused: $*" >&2; exit 1; }

[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]] || die "AUCTARYN_DOMAIN must be a valid DNS hostname."
[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die "AUCTARYN_RELEASE_TAG must be a version tag such as v1.2.3."
[[ "$IMAGE_REF" =~ ^ghcr\.io/lloydcoder/auctaryn@sha256:[a-f0-9]{64}$ ]] || die "AUCTARYN_IMAGE must be the exact lowercase GHCR image digest from the release manifest."
if [[ "${#API_KEY}" -lt 32 || "${#ADMIN_KEY}" -lt 32 || "$API_KEY" == "$ADMIN_KEY" || "$API_KEY" == *replace-with* || "$ADMIN_KEY" == *replace-with* ]]; then
    die "AUCTARYN_API_KEY and AUCTARYN_ADMIN_API_KEY must be distinct 32+ character secrets."
fi
[[ "$THREATFADE_URL" == https://* && "$THREATFADE_URL" != *replace-with* ]] || die "THREATFADE_SERVICE_URL must be a real HTTPS endpoint."
[[ -n "$THREATFADE_TOKEN" && "$THREATFADE_TOKEN" != *replace-with* ]] || die "THREATFADE_SERVICE_TOKEN is required for external ThreatFade."
[[ "$RUNTIME_ADAPTER" == "openshell" ]] || die "Production requires AUCTARYN_RUNTIME_ADAPTER=openshell."
[[ "$SANDBOX_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die "OPENSHELL_SANDBOX_NAME is missing or invalid."
[[ -n "$WORKSPACE" ]] || die "OPENSHELL_WORKSPACE must be non-empty."
[[ "$OIDC_ISSUER" == https://* ]] || die "OPENSHELL_OIDC_ISSUER must be an HTTPS issuer URL."
[[ -n "$OIDC_CLIENT_ID" && -n "$OIDC_CLIENT_SECRET" && -n "$OIDC_AUDIENCE" ]] || die "OpenShell OIDC client ID, client secret and audience are required."
[[ "$ALLOW_USER_CREDENTIALS" != "true" ]] || die "User credentials are prohibited in production; use OpenShell OIDC service credentials."
[[ "$EVIDENCE_KEY_FILE" == /* && -f "$EVIDENCE_KEY_FILE" ]] || die "AUCTARYN_EVIDENCE_HMAC_KEY_FILE must point to an existing absolute host file."
EVIDENCE_KEY_BYTES="$(tr -d '\r\n' < "$EVIDENCE_KEY_FILE" | wc -c)"
[[ "$EVIDENCE_KEY_BYTES" -ge 32 ]] || die "Evidence HMAC key file must contain at least 32 bytes."
[[ "$OPEN_SHELL_DIR" == /* && -f "$OPEN_SHELL_DIR/active_gateway" ]] || die "OPENSHELL_SYSTEM_GATEWAY_DIR must contain active_gateway metadata."
ACTIVE_GATEWAY="$(tr -d '\r\n' < "$OPEN_SHELL_DIR/active_gateway")"
[[ "$ACTIVE_GATEWAY" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die "OpenShell active_gateway name is invalid."
GATEWAY_METADATA="$OPEN_SHELL_DIR/gateways/$ACTIVE_GATEWAY/metadata.json"
[[ -f "$GATEWAY_METADATA" ]] || die "OpenShell active gateway metadata is missing."
jq -e 'type == "object"' "$GATEWAY_METADATA" >/dev/null || die "OpenShell gateway metadata is invalid JSON."
grep -Eq '"endpoint"[[:space:]]*:[[:space:]]*"https://' "$GATEWAY_METADATA" || die "OpenShell system metadata must define a remote HTTPS endpoint."
grep -Eq '"endpoint"[[:space:]]*:[[:space:]]*"http://(localhost|127\.0\.0\.1|0\.0\.0\.0)' "$GATEWAY_METADATA" && die "A container cannot use a host-loopback OpenShell endpoint."

for cmd in gh docker npm nginx certbot jq; do command -v "$cmd" >/dev/null 2>&1 || die "Required command is missing: $cmd"; done
gh auth status >/dev/null 2>&1 || die "Authenticate GitHub CLI with permission to verify attestations and download releases."

echo "Verifying Auctaryn release $RELEASE_TAG for $DOMAIN"
mkdir -p "$DEPLOY_STATE_DIR"
chmod 700 "$DEPLOY_STATE_DIR"
RELEASE_ASSET_DIR="$DEPLOY_STATE_DIR/release-assets/$RELEASE_TAG"
mkdir -p "$RELEASE_ASSET_DIR"
gh release download "$RELEASE_TAG" --repo LloydCoder/Auctaryn --pattern release-manifest.json --dir "$RELEASE_ASSET_DIR" --clobber
RELEASE_MANIFEST="$RELEASE_ASSET_DIR/release-manifest.json"
gh attestation verify "$RELEASE_MANIFEST" -R LloydCoder/Auctaryn
gh attestation verify "oci://$IMAGE_REF" -R LloydCoder/Auctaryn
gh attestation verify "oci://$IMAGE_REF" -R LloydCoder/Auctaryn --predicate-type https://spdx.dev/Document/v2.3
jq -e --arg tag "$RELEASE_TAG" --arg image_ref "$IMAGE_REF" '
  .schema_version == "auctaryn-release-manifest.v1" and
  .release_tag == $tag and
  (.image + "@" + .image_digest) == $image_ref and
  (.image_digest | test("^sha256:[a-f0-9]{64}$")) and
  (.tested_commit | test("^[a-f0-9]{40}$")) and
  (.source_commit | test("^[a-f0-9]{40}$"))
' "$RELEASE_MANIFEST" >/dev/null || die "Release manifest does not bind the selected tag to the exact image digest."
git fetch origin --tags
git checkout --detach "$RELEASE_TAG"
SOURCE_COMMIT="$(git rev-parse HEAD)"
MANIFEST_SOURCE_COMMIT="$(jq -r '.source_commit' "$RELEASE_MANIFEST")"
TESTED_COMMIT="$(jq -r '.tested_commit' "$RELEASE_MANIFEST")"
[[ "$SOURCE_COMMIT" == "$MANIFEST_SOURCE_COMMIT" ]] || die "Checked-out tag does not match the attested release manifest."
git merge-base --is-ancestor "$TESTED_COMMIT" "$SOURCE_COMMIT" || die "Release tag is not descended from the tested commit."
docker pull "$IMAGE_REF"
PULLED_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$IMAGE_REF")"
[[ "$PULLED_IMAGE_ID" =~ ^sha256:[a-f0-9]{64}$ ]] || die "Pulled image has no immutable local image ID."

export AUCTARYN_DOMAIN="$DOMAIN"
export AUCTARYN_CORS_ORIGINS="https://$DOMAIN"
export COMPOSE_FILE="$REPO_DIR/docker-compose.yml:$REPO_DIR/docker-compose.production.yml"

# Build only the static dashboard from the exact release tag. The API is the
# already-verified OCI digest; production never builds API code from a moving branch.
echo "Building dashboard assets from $RELEASE_TAG..."
(cd dashboard && VITE_API_URL="https://$DOMAIN" VITE_WS_URL="wss://$DOMAIN" npm ci --no-audit --no-fund && VITE_API_URL="https://$DOMAIN" VITE_WS_URL="wss://$DOMAIN" npm run build -- --base=/dashboard/)

# Capture the current immutable deployment as a rollback target before switching.
ROLLBACK_AVAILABLE=false
RUNNING_CONTAINER="$(docker compose ps -q api 2>/dev/null || true)"
if [[ -n "$RUNNING_CONTAINER" ]]; then
    PREVIOUS_IMAGE_REF="$(docker inspect --format '{{.Config.Image}}' "$RUNNING_CONTAINER")"
    PREVIOUS_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$RUNNING_CONTAINER")"
    PREVIOUS_RELEASE_TAG="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$RUNNING_CONTAINER" | sed -n 's/^AUCTARYN_RELEASE_TAG=//p' | tail -n1)"
    [[ "$PREVIOUS_IMAGE_REF" =~ ^ghcr\.io/lloydcoder/auctaryn@sha256:[a-f0-9]{64}$ ]] || die "Existing service is not running a digest-pinned Auctaryn release; migrate it manually before updating."
    [[ "$PREVIOUS_RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die "Existing service has no valid AUCTARYN_RELEASE_TAG; rollback cannot be proven."
    printf '%s\n' "$PREVIOUS_IMAGE_REF" > "$DEPLOY_STATE_DIR/previous-image-ref.tmp"
    printf '%s\n' "$PREVIOUS_IMAGE_ID" > "$DEPLOY_STATE_DIR/previous-image-id.tmp"
    printf '%s\n' "$PREVIOUS_RELEASE_TAG" > "$DEPLOY_STATE_DIR/previous-release-tag.tmp"
    chmod 600 "$DEPLOY_STATE_DIR"/previous-image-*.tmp "$DEPLOY_STATE_DIR/previous-release-tag.tmp"
    mv -f "$DEPLOY_STATE_DIR/previous-image-ref.tmp" "$DEPLOY_STATE_DIR/previous-image-ref"
    mv -f "$DEPLOY_STATE_DIR/previous-image-id.tmp" "$DEPLOY_STATE_DIR/previous-image-id"
    mv -f "$DEPLOY_STATE_DIR/previous-release-tag.tmp" "$DEPLOY_STATE_DIR/previous-release-tag"
    ROLLBACK_AVAILABLE=true
fi

DEPLOY_SWITCHED=false
on_exit() {
    local status=$?
    trap - EXIT
    if [[ "$status" -ne 0 && "$DEPLOY_SWITCHED" == true && "$ROLLBACK_AVAILABLE" == true ]]; then
        echo "Deployment failed after switching the API; attempting verified rollback." >&2
        bash "$REPO_DIR/scripts/rollback.sh" || echo "Automatic rollback failed; keep public traffic disabled and follow the runbook." >&2
    fi
    exit "$status"
}
trap on_exit EXIT

# The production compose override mounts the OpenShell system gateway metadata and
# evidence HMAC key, and pins the API image to the verified digest.
DEPLOY_SWITCHED=true
docker compose up -d --no-build api

echo "Waiting for API liveness..."
healthy=false
for _ in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8400/health >/dev/null 2>&1; then healthy=true; break; fi
    sleep 2
done
[[ "$healthy" == true ]] || { docker compose logs --tail=100 api; die "API liveness check failed."; }

READINESS="$(curl -fsS http://127.0.0.1:8400/health/ready || true)"
grep -Eq '"ready"[[:space:]]*:[[:space:]]*true' <<< "$READINESS" || {
    echo "Auctaryn is alive but not ready for public exposure. Current readiness: $READINESS" >&2
    die "Resolve security/runtime readiness checks before enabling Nginx/TLS."
}

# Configure a domain-validated reverse proxy only after runtime readiness passes.
NGINX_CONF="/etc/nginx/sites-available/auctaryn"
if [[ ! -f "$NGINX_CONF" ]]; then
    sudo tee "$NGINX_CONF" >/dev/null <<NGINXEOF
server {
    listen 80;
    server_name $DOMAIN;
    root $REPO_DIR/site;
    index index.html;

    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-Frame-Options "DENY" always;

    location / {
        try_files \$uri \$uri.html \$uri/ =404;
    }

    location /dashboard/ {
        alias $REPO_DIR/dashboard/dist/;
        try_files \$uri \$uri/ /dashboard/index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8400/api/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8400/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600s;
    }

    location /docs {
        proxy_pass http://127.0.0.1:8400/docs;
        proxy_set_header Host \$host;
    }
    location /openapi.json {
        proxy_pass http://127.0.0.1:8400/openapi.json;
        proxy_set_header Host \$host;
    }
    location /health {
        proxy_pass http://127.0.0.1:8400/health;
    }
}
NGINXEOF
    sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/auctaryn
    sudo nginx -t
    sudo systemctl reload nginx
else
    grep -Fq "server_name $DOMAIN;" "$NGINX_CONF" || die "Existing Nginx site uses a different domain; update it explicitly before deployment."
fi

if ! sudo certbot certificates 2>/dev/null | grep -q "$DOMAIN"; then
    sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL"
fi

CURRENT_CONTAINER="$(docker compose ps -q api)"
CURRENT_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$CURRENT_CONTAINER")"
printf '%s\n' "$IMAGE_REF" > "$DEPLOY_STATE_DIR/current-image-ref.tmp"
printf '%s\n' "$CURRENT_IMAGE_ID" > "$DEPLOY_STATE_DIR/current-image-id.tmp"
printf '%s\n' "$RELEASE_TAG" > "$DEPLOY_STATE_DIR/current-release-tag.tmp"
chmod 600 "$DEPLOY_STATE_DIR"/current-image-*.tmp "$DEPLOY_STATE_DIR/current-release-tag.tmp"
mv -f "$DEPLOY_STATE_DIR/current-image-ref.tmp" "$DEPLOY_STATE_DIR/current-image-ref"
mv -f "$DEPLOY_STATE_DIR/current-image-id.tmp" "$DEPLOY_STATE_DIR/current-image-id"
mv -f "$DEPLOY_STATE_DIR/current-release-tag.tmp" "$DEPLOY_STATE_DIR/current-release-tag"

echo "Verified Auctaryn release $RELEASE_TAG is deployed and ready."
echo "Dashboard: https://$DOMAIN/dashboard/"
echo "API docs:  https://$DOMAIN/docs"
echo "Liveness:  https://$DOMAIN/health"
echo "Production deployment acceptance and rollback evidence must still be recorded in release/release-evidence.json."
