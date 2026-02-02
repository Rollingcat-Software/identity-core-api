#!/usr/bin/env bash
# ============================================================================
# FIVUCSAS Identity Core API - GCP Deployment Script
# ============================================================================
# Prerequisites:
#   - gcloud CLI installed and authenticated (gcloud auth login)
#   - A GCP project selected (gcloud config set project <PROJECT_ID>)
#   - Billing enabled on the project
#
# Usage:
#   chmod +x scripts/deploy-gcp.sh
#   ./scripts/deploy-gcp.sh
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
VM_NAME="fivucsas-identity-core"
ZONE="europe-central2-a"
MACHINE_TYPE="e2-medium"
IMAGE_FAMILY="ubuntu-2204-lts"
IMAGE_PROJECT="ubuntu-os-cloud"
DISK_SIZE="30GB"
FIREWALL_RULE="allow-identity-core-api"
ENV_FILE=".env.gcp"
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

if ! command -v gcloud &> /dev/null; then
    error "gcloud CLI not found. Install from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

ACTIVE_PROJECT=$(gcloud config get-value project 2>/dev/null)
if [ -z "$ACTIVE_PROJECT" ] || [ "$ACTIVE_PROJECT" = "(unset)" ]; then
    error "No GCP project selected. Run: gcloud config set project <PROJECT_ID>"
    exit 1
fi
info "Using GCP project: $ACTIVE_PROJECT"

if [ ! -f "$PROJECT_DIR/$ENV_FILE" ]; then
    error "$ENV_FILE not found. Copy .env.gcp and fill in production values."
    exit 1
fi

# Check for placeholder values in .env.gcp
if grep -q "CHANGE_ME" "$PROJECT_DIR/$ENV_FILE"; then
    error "Found CHANGE_ME placeholders in $ENV_FILE. Update all values before deploying."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Create VM
# ---------------------------------------------------------------------------
info "Checking if VM '$VM_NAME' already exists..."
if gcloud compute instances describe "$VM_NAME" --zone="$ZONE" &> /dev/null; then
    warn "VM '$VM_NAME' already exists. Skipping creation."
else
    info "Creating VM: $VM_NAME ($MACHINE_TYPE) in $ZONE..."
    gcloud compute instances create "$VM_NAME" \
        --zone="$ZONE" \
        --machine-type="$MACHINE_TYPE" \
        --image-family="$IMAGE_FAMILY" \
        --image-project="$IMAGE_PROJECT" \
        --boot-disk-size="$DISK_SIZE" \
        --boot-disk-type="pd-balanced" \
        --tags="http-server,identity-core-api" \
        --metadata=startup-script='#!/bin/bash
            echo "VM startup complete" > /tmp/startup-done'
    info "VM created successfully."
fi

# Wait for VM to be ready
info "Waiting for VM to be reachable..."
sleep 15

# Test SSH connectivity (no passthrough flags - compatible with Windows plink)
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="echo 'SSH connection OK'"

# ---------------------------------------------------------------------------
# Step 2: Install Docker and Docker Compose on VM
# ---------------------------------------------------------------------------
info "Installing Docker and Docker Compose on VM..."
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="bash -s" <<'INSTALL_SCRIPT'
set -euo pipefail

if command -v docker &> /dev/null; then
    echo "Docker already installed: $(docker --version)"
else
    echo "Installing Docker..."
    sudo apt-get update -y
    sudo apt-get install -y ca-certificates curl gnupg

    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    sudo usermod -aG docker "$USER"
    echo "Docker installed: $(docker --version)"
fi

echo "Docker Compose version: $(docker compose version)"
INSTALL_SCRIPT

# ---------------------------------------------------------------------------
# Step 3: Transfer project files to VM
# ---------------------------------------------------------------------------
info "Creating project directory on VM..."
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="mkdir -p ~/identity-core-api"

info "Transferring project files..."

# Create a temporary directory with only needed files
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Copy essential files
cp "$PROJECT_DIR/docker-compose.yml" "$TEMP_DIR/"
cp "$PROJECT_DIR/Dockerfile" "$TEMP_DIR/"
cp "$PROJECT_DIR/pom.xml" "$TEMP_DIR/"
cp "$PROJECT_DIR/$ENV_FILE" "$TEMP_DIR/.env"
cp -r "$PROJECT_DIR/src" "$TEMP_DIR/"

# SCP files to VM
gcloud compute scp --recurse "$TEMP_DIR"/* "$VM_NAME:~/identity-core-api/" --zone="$ZONE"

info "Files transferred successfully."

# ---------------------------------------------------------------------------
# Step 4: Start services
# ---------------------------------------------------------------------------
info "Starting Docker Compose services on VM..."
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="bash -s" <<'DEPLOY_SCRIPT'
set -euo pipefail

cd ~/identity-core-api

# Use sg to pick up docker group without re-login
echo "Building and starting services..."
sg docker -c "docker compose up -d --build"

echo ""
echo "Waiting for services to start..."
sleep 15

echo ""
echo "Service status:"
sg docker -c "docker compose ps"

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
# Step 5: Configure firewall
# ---------------------------------------------------------------------------
info "Configuring firewall rule for port 8080..."
if gcloud compute firewall-rules describe "$FIREWALL_RULE" &> /dev/null; then
    warn "Firewall rule '$FIREWALL_RULE' already exists. Skipping."
else
    gcloud compute firewall-rules create "$FIREWALL_RULE" \
        --allow=tcp:8080 \
        --target-tags=identity-core-api \
        --description="Allow HTTP traffic to Identity Core API" \
        --direction=INGRESS
    info "Firewall rule created."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
EXTERNAL_IP=$(gcloud compute instances describe "$VM_NAME" --zone="$ZONE" \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo ""
echo "============================================================================"
info "Deployment complete!"
echo "============================================================================"
echo ""
echo "  VM Name:      $VM_NAME"
echo "  Zone:         $ZONE"
echo "  External IP:  $EXTERNAL_IP"
echo ""
echo "  API Base URL:    http://$EXTERNAL_IP:8080"
echo "  Health Check:    http://$EXTERNAL_IP:8080/actuator/health"
echo "  Swagger UI:      http://$EXTERNAL_IP:8080/swagger-ui.html"
echo ""
echo "  SSH into VM:     gcloud compute ssh $VM_NAME --zone=$ZONE"
echo "  View logs:       gcloud compute ssh $VM_NAME --zone=$ZONE --command='cd ~/identity-core-api && docker compose logs -f'"
echo "  Stop services:   gcloud compute ssh $VM_NAME --zone=$ZONE --command='cd ~/identity-core-api && docker compose down'"
echo ""
warn "Remember to update CORS_ALLOWED_ORIGINS in .env.gcp with: http://$EXTERNAL_IP:8080"
echo "============================================================================"
