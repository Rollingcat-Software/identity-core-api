#!/usr/bin/env bash
# ============================================================================
# FIVUCSAS Identity Core API - Hetzner VPS Deployment Script
# ============================================================================
# Prerequisites:
#   - SSH key at ~/.ssh/hetzner_ed25519
#   - .env.hetzner file with production values
#
# Usage:
#   chmod +x scripts/deploy-hetzner.sh
#   ./scripts/deploy-hetzner.sh
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HETZNER_HOST="root@116.203.222.213"
SSH_KEY="$HOME/.ssh/hetzner_ed25519"
REMOTE_DIR="/opt/identity-core-api"
ENV_FILE=".env.hetzner"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
info "Running pre-flight checks..."

if [ ! -f "$HOME/.ssh/hetzner_ed25519" ]; then
    error "SSH key not found at ~/.ssh/hetzner_ed25519"
    exit 1
fi

if [ ! -f "$PROJECT_DIR/$ENV_FILE" ]; then
    error "$ENV_FILE not found. Copy .env.hetzner and fill in production values."
    exit 1
fi

# Check for placeholder values in .env.hetzner
if grep -q "CHANGE_ME" "$PROJECT_DIR/$ENV_FILE"; then
    error "Found CHANGE_ME placeholders in $ENV_FILE. Update all values before deploying."
    exit 1
fi

info "Using Hetzner VPS: 116.203.222.213 (Nuremberg, Germany)"

# Test SSH connectivity
info "Testing SSH connectivity..."
ssh -i "$SSH_KEY" -o ConnectTimeout=10 "$HETZNER_HOST" "echo 'SSH connection OK'"

# ---------------------------------------------------------------------------
# Step 1: Build JAR
# ---------------------------------------------------------------------------
info "Building Maven artifact..."
cd "$PROJECT_DIR"
mvn clean package -DskipTests -q
JAR_FILE=$(ls target/*.jar | head -1)
info "Built: $JAR_FILE"

# ---------------------------------------------------------------------------
# Step 2: Transfer project files to VPS
# ---------------------------------------------------------------------------
info "Creating project directory on VPS..."
ssh -i "$SSH_KEY" "$HETZNER_HOST" "mkdir -p $REMOTE_DIR"

info "Transferring project files..."

# Create a temporary directory with only needed files
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Copy essential files
cp "$PROJECT_DIR/docker-compose.yml" "$TEMP_DIR/"
cp "$PROJECT_DIR/Dockerfile" "$TEMP_DIR/"
cp "$PROJECT_DIR/$ENV_FILE" "$TEMP_DIR/.env"
cp "$JAR_FILE" "$TEMP_DIR/app.jar"

# SCP files to VPS
scp -i "$SSH_KEY" -r "$TEMP_DIR"/* "$HETZNER_HOST:$REMOTE_DIR/"

info "Files transferred successfully."

# ---------------------------------------------------------------------------
# Step 3: Start services
# ---------------------------------------------------------------------------
info "Starting Docker Compose services on VPS..."
ssh -i "$SSH_KEY" "$HETZNER_HOST" "bash -s" <<'DEPLOY_SCRIPT'
set -euo pipefail

cd /opt/identity-core-api

echo "Building and starting services..."
docker compose up -d --build

echo ""
echo "Waiting for services to start..."
sleep 15

echo ""
echo "Service status:"
docker compose ps

echo ""
echo "Checking API health..."
for i in {1..12}; do
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/actuator/health | grep -q "200"; then
        echo "API is healthy!"
        curl -s http://localhost:8080/actuator/health | head -c 200
        echo ""
        break
    fi
    echo "Attempt $i/12: API not ready yet, waiting 10s..."
    sleep 10
done
DEPLOY_SCRIPT

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================================================"
info "Deployment complete!"
echo "============================================================================"
echo ""
echo "  VPS:            Hetzner CX33, Nuremberg, Germany"
echo "  External IP:    116.203.222.213"
echo ""
echo "  API Base URL:    http://116.203.222.213:8080"
echo "  Health Check:    http://116.203.222.213:8080/actuator/health"
echo "  Swagger UI:      http://116.203.222.213:8080/swagger-ui.html"
echo ""
echo "  SSH into VPS:    ssh -i ~/.ssh/hetzner_ed25519 root@116.203.222.213"
echo "  View logs:       ssh -i ~/.ssh/hetzner_ed25519 root@116.203.222.213 'cd /opt/identity-core-api && docker compose logs -f'"
echo "  Stop services:   ssh -i ~/.ssh/hetzner_ed25519 root@116.203.222.213 'cd /opt/identity-core-api && docker compose down'"
echo ""
warn "Remember to update CORS_ALLOWED_ORIGINS in .env.hetzner if needed"
echo "============================================================================"
