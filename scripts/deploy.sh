#!/bin/bash
# TwinGuard — Production Deployment Script
# Run on Contabo VPS (Ubuntu 22.04+). Idempotent — safe to re-run.

set -euo pipefail

REPO_DIR="/opt/twinguard"
SERVICE_USER="twinguard"
DOMAIN="${TWINGUARD_DOMAIN:-twinguard.tinlance.com}"

echo "============================================"
echo "  TwinGuard Production Deployment"
echo "============================================"

# 1. Kernel check (OpenShell requires >= 5.13)
KERNEL=$(uname -r | cut -d. -f1-2)
echo "Kernel: $KERNEL"

# 2. Pull latest code
if [ -d "$REPO_DIR/.git" ]; then
    echo "→ Updating existing deployment..."
    cd "$REPO_DIR" && git pull origin main
else
    echo "→ Fresh clone..."
    sudo mkdir -p "$REPO_DIR"
    sudo chown "$USER:$USER" "$REPO_DIR"
    git clone https://github.com/Tinlance/twinguard.git "$REPO_DIR"
    cd "$REPO_DIR"
fi

# 3. Environment file check
if [ ! -f .env ]; then
    echo "⚠ No .env found. Copying template — YOU MUST EDIT THIS."
    cp .env.example .env
    echo "   Run: nano $REPO_DIR/.env"
    echo "   Then re-run this script."
    exit 1
fi

# 4. Build the dashboard as static assets — Nginx serves dashboard/dist
# directly (see step 6), it no longer proxies to a running Vite dev
# server in production.
echo "→ Building dashboard..."
(cd dashboard && npm install --silent && npm run build)

# 5. Build and start the API + ThreatFade Oracle via Docker Compose
echo "→ Building containers..."
docker compose build api threatfade

echo "→ Starting services..."
docker compose up -d api threatfade

# 6. Wait for health check
echo "→ Waiting for API to be healthy..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:8400/health > /dev/null 2>&1; then
        echo "✓ API is healthy"
        break
    fi
    sleep 2
done

# 6. Nginx reverse proxy (if not already configured)
NGINX_CONF="/etc/nginx/sites-available/twinguard"
if [ ! -f "$NGINX_CONF" ]; then
    echo "→ Configuring Nginx for $DOMAIN..."
    sudo tee "$NGINX_CONF" > /dev/null << NGINXEOF
server {
    listen 80;
    server_name $DOMAIN;

    # Marketing site (static files) — served as the root
    root $REPO_DIR/site;
    index index.html;

    location / {
        try_files \$uri \$uri.html \$uri/ =404;
    }

    # React dashboard app (the operational console, distinct from the
    # marketing site at /). Built dashboard assets are served from here.
    location /dashboard {
        alias $REPO_DIR/dashboard/dist;
        try_files \$uri \$uri/ /dashboard/index.html;
    }

    # API
    location /api/ {
        proxy_pass http://localhost:8400/api/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    # WebSocket — actions/alerts live streams
    location /ws/ {
        proxy_pass http://localhost:8400/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    # FastAPI interactive docs (Swagger UI)
    location /docs {
        proxy_pass http://localhost:8400/docs;
    }

    location /openapi.json {
        proxy_pass http://localhost:8400/openapi.json;
    }

    # API health check (used by deploy script + monitoring)
    location /health {
        proxy_pass http://localhost:8400/health;
    }
}
NGINXEOF
    sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/
    sudo nginx -t && sudo systemctl reload nginx
    echo "✓ Nginx configured"
else
    echo "✓ Nginx already configured"
fi

# 7. SSL via Certbot (only if not already issued)
if ! sudo certbot certificates 2>/dev/null | grep -q "$DOMAIN"; then
    echo "→ Requesting SSL certificate for $DOMAIN..."
    sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m hello@tinlance.com || \
        echo "⚠ Certbot failed — DNS may not be pointed yet. Run manually later: sudo certbot --nginx -d $DOMAIN"
else
    echo "✓ SSL already issued for $DOMAIN"
fi

echo ""
echo "============================================"
echo "  Deployment Complete"
echo "============================================"
echo "  Dashboard: https://$DOMAIN"
echo "  API docs:  https://$DOMAIN/docs"
echo "  Health:    https://$DOMAIN/api/v1/../health"
echo ""
echo "  Verify: curl -s http://localhost:8400/health | jq"
echo "============================================"
