#!/usr/bin/env bash
# Auctaryn deployment helper. Verify DNS and secrets before running.
set -euo pipefail

REPO_DIR="${AUCTARYN_REPO_DIR:-/opt/auctaryn}"
DEPLOY_STATE_DIR="${AUCTARYN_DEPLOY_STATE_DIR:-${REPO_DIR}/.deploy-state}"
DOMAIN="${AUCTARYN_DOMAIN:?Set AUCTARYN_DOMAIN to a verified DNS name}"
EMAIL="${AUCTARYN_TLS_EMAIL:-hello@tinlance.com}"

echo "Deploying Auctaryn for ${DOMAIN}"

# 1. Pull the canonical repository.
if [ -d "$REPO_DIR/.git" ]; then
    git -C "$REPO_DIR" pull --ff-only origin main
else
    sudo mkdir -p "$REPO_DIR"
    sudo chown "$USER:$USER" "$REPO_DIR"
    git clone https://github.com/LloydCoder/Auctaryn.git "$REPO_DIR"
fi
cd "$REPO_DIR"

# 2. Require independently generated service/admin credentials.
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env.example copy. Edit $REPO_DIR/.env with two independent secrets, then rerun."
    exit 1
fi
API_KEY=$(grep -E '^AUCTARYN_API_KEY=' .env | head -n1 | cut -d= -f2- || true)
ADMIN_KEY=$(grep -E '^AUCTARYN_ADMIN_API_KEY=' .env | head -n1 | cut -d= -f2- || true)
if [ "${#API_KEY}" -lt 32 ] || [ "${#ADMIN_KEY}" -lt 32 ] || [ "$API_KEY" = "$ADMIN_KEY" ] || [[ "$API_KEY" == *replace-with* ]] || [[ "$ADMIN_KEY" == *replace-with* ]]; then
    echo "AUCTARYN_API_KEY and AUCTARYN_ADMIN_API_KEY must be different high-entropy values (32+ characters)."
    exit 1
fi

# Compose inherits the verified public origin; the API itself binds only to localhost.
export AUCTARYN_CORS_ORIGINS="https://${DOMAIN}"
export AUCTARYN_DOMAIN="${DOMAIN}"

# 3. Build the dashboard with same-origin HTTPS/WSS URLs; never bake API secrets into Vite.
echo "Building dashboard assets..."
(cd dashboard && VITE_API_URL="https://${DOMAIN}" VITE_WS_URL="wss://${DOMAIN}" npm install --silent && VITE_API_URL="https://${DOMAIN}" VITE_WS_URL="wss://${DOMAIN}" npm run build -- --base=/dashboard/)

# 4. Capture the currently running immutable image ID before rebuilding so rollback
# remains possible even after the mutable auctaryn:latest tag moves.
mkdir -p "$DEPLOY_STATE_DIR"
chmod 700 "$DEPLOY_STATE_DIR"
RUNNING_CONTAINER=$(docker compose ps -q api 2>/dev/null || true)
if [ -n "$RUNNING_CONTAINER" ]; then
    PREVIOUS_IMAGE_ID=$(docker inspect --format '{{.Image}}' "$RUNNING_CONTAINER")
    if [[ ! "$PREVIOUS_IMAGE_ID" =~ ^sha256:[a-f0-9]{64}$ ]]; then
        echo "Refusing deployment: could not identify the running image immutably."
        exit 1
    fi
    STATE_TMP="$DEPLOY_STATE_DIR/previous-image-id.tmp"
    printf '%s\\n' "$PREVIOUS_IMAGE_ID" > "$STATE_TMP"
    chmod 600 "$STATE_TMP"
    mv -f "$STATE_TMP" "$DEPLOY_STATE_DIR/previous-image-id"
fi

# Build and start the API with the configured external ThreatFade client.
echo "Building containers..."
THREATFADE_URL=$(grep -E '^THREATFADE_SERVICE_URL=' .env | head -n1 | cut -d= -f2- || true)
if [[ "$THREATFADE_URL" != https://* ]] || [[ "$THREATFADE_URL" == *replace-with* ]]; then
    echo "Set THREATFADE_SERVICE_URL to your real HTTPS endpoint in .env before deployment."
    exit 1
fi
docker compose build api
echo "Starting services..."
docker compose up -d api

echo "Waiting for API liveness..."
healthy=false
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8400/health >/dev/null 2>&1; then
        healthy=true
        break
    fi
    sleep 2
done
if [ "$healthy" != true ]; then
    docker compose logs --tail=100 api
    echo "API liveness check failed."
    exit 1
fi

# Liveness is not readiness. Do not expose the service while runtime enforcement
# and the OpenShell connectivity probe are still unverified.
READINESS=$(curl -fsS http://127.0.0.1:8400/health/ready || true)
if ! grep -Eq '"ready"[[:space:]]*:[[:space:]]*true' <<< "$READINESS"; then
    echo "Auctaryn is alive but not ready for public exposure. Current readiness: $READINESS"
    echo "Resolve the listed security/runtime checks before enabling Nginx/TLS."
    exit 1
fi

# 5. Configure the reverse proxy. Certbot adds HTTPS after the HTTP vhost exists.
NGINX_CONF="/etc/nginx/sites-available/auctaryn"
if [ ! -f "$NGINX_CONF" ]; then
    echo "Configuring Nginx for ${DOMAIN}..."
    sudo tee "$NGINX_CONF" >/dev/null <<NGINXEOF
server {
    listen 80;
    server_name ${DOMAIN};
    root ${REPO_DIR}/site;
    index index.html;

    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header X-Frame-Options "DENY" always;

    location / {
        try_files \$uri \$uri.html \$uri/ =404;
    }

    location /dashboard/ {
        alias ${REPO_DIR}/dashboard/dist/;
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
fi

# 6. Provision TLS only after DNS points at this host.
if ! sudo certbot certificates 2>/dev/null | grep -q "$DOMAIN"; then
    sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL"
fi

echo "Deployment services are live. Verify TLS, dashboard sign-in, API credentials, and runtime integration."
echo "Dashboard: https://${DOMAIN}/dashboard/"
echo "API docs:  https://${DOMAIN}/docs"
echo "Liveness:  https://${DOMAIN}/health"
