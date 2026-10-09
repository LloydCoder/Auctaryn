#!/bin/bash
# TwinGuard — One-Command Setup
# Run on a fresh Ubuntu 22.04+ VPS (Contabo)

set -euo pipefail

echo "============================================"
echo "  TwinGuard Setup — Tinlance Limited"
echo "============================================"
echo ""

# Check Linux kernel version (need >= 5.13 for Landlock)
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 13 ]); then
    echo "ERROR: Kernel $KERNEL_VERSION detected. OpenShell requires >= 5.13"
    echo "Upgrade your kernel or use Ubuntu 22.04+"
    exit 1
fi
echo "✓ Kernel $KERNEL_VERSION OK"

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER"
    echo "✓ Docker installed"
else
    echo "✓ Docker already installed"
fi

# Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "Installing Docker Compose..."
    sudo apt-get install -y docker-compose-plugin
    echo "✓ Docker Compose installed"
else
    echo "✓ Docker Compose already installed"
fi

# Install Python 3.11+ if not present
if ! command -v python3.11 &> /dev/null && ! python3 --version | grep -qE "3\.(1[1-9]|[2-9][0-9])"; then
    echo "Installing Python 3.11..."
    sudo apt-get update
    sudo apt-get install -y python3.11 python3.11-venv python3-pip
    echo "✓ Python 3.11 installed"
else
    echo "✓ Python 3.11+ already installed"
fi

# Install Node.js 18+ if not present
if ! command -v node &> /dev/null; then
    echo "Installing Node.js 18..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
    echo "✓ Node.js installed"
else
    echo "✓ Node.js already installed"
fi

# Create .env from template if not exists
if [ ! -f .env ]; then
    cp .env.example .env
    echo ""
    echo "⚠ Created .env from template — edit it with your API keys:"
    echo "  nano .env"
    echo ""
fi

# Create data directories
mkdir -p data/pcaps data/reports logs

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt -q

# Install dashboard dependencies
echo "Installing dashboard dependencies..."
cd dashboard && npm install -q && cd ..

echo ""
echo "============================================"
echo "  Setup Complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your ANTHROPIC_API_KEY"
echo "  2. Run: docker-compose up -d"
echo "  3. Open: http://your-server:3000"
echo ""
echo "Or run locally:"
echo "  API:       uvicorn api.main:app --port 8400 --reload"
echo "  Dashboard: cd dashboard && npm run dev"
echo ""
