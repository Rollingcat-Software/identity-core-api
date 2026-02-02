#!/usr/bin/env bash
# ============================================================================
# GCP Compute Engine Setup Script for Identity Core API
# Target: Ubuntu 22.04 LTS on e2-standard-2 (2 vCPU, 8 GB RAM)
#
# Usage:
#   1. Create a GCP Compute Engine instance (Ubuntu 22.04 LTS)
#   2. SSH into the instance
#   3. Upload this script and run: chmod +x gcp-setup.sh && sudo ./gcp-setup.sh
#   4. Configure .env file with production values
#   5. Run: docker compose up -d
# ============================================================================

set -euo pipefail

echo "============================================"
echo " Identity Core API - GCP Setup"
echo "============================================"

# Update system
echo "[1/6] Updating system packages..."
apt-get update -y && apt-get upgrade -y

# Install Docker
echo "[2/6] Installing Docker Engine..."
apt-get install -y ca-certificates curl gnupg lsb-release

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable Docker service
systemctl enable docker
systemctl start docker

# Add current user to docker group
echo "[3/6] Configuring Docker permissions..."
if [ -n "${SUDO_USER:-}" ]; then
    usermod -aG docker "$SUDO_USER"
    echo "Added $SUDO_USER to docker group"
fi

# Configure firewall
echo "[4/6] Configuring UFW firewall..."
apt-get install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 8080/tcp  # API port
ufw --force enable

# Create application directory
echo "[5/6] Setting up application directory..."
APP_DIR="/opt/identity-core-api"
mkdir -p "$APP_DIR"
cd "$APP_DIR"

# Create .env template if it doesn't exist
if [ ! -f "$APP_DIR/.env" ]; then
    cat > "$APP_DIR/.env" << 'ENVEOF'
# ============================================================================
# Identity Core API - Production Environment Configuration
# ============================================================================

# Database (PostgreSQL)
DB_NAME=identity_core_db
DB_USERNAME=identity_admin
DB_PASSWORD=CHANGE_ME_TO_STRONG_PASSWORD

# Redis
REDIS_PASSWORD=CHANGE_ME_TO_STRONG_PASSWORD

# JWT Secret (generate with: openssl rand -base64 64)
JWT_SECRET=CHANGE_ME_GENERATE_WITH_OPENSSL
JWT_EXPIRATION=86400000
JWT_REFRESH_EXPIRATION=604800000

# CORS (comma-separated origins)
CORS_ALLOWED_ORIGINS=https://your-domain.com

# API Port
API_PORT=8080
ENVEOF
    echo "Created .env template at $APP_DIR/.env"
    echo "IMPORTANT: Edit .env with production values before starting!"
fi

# Setup log rotation for Docker
echo "[6/6] Configuring Docker log rotation..."
cat > /etc/docker/daemon.json << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "5"
  }
}
EOF
systemctl restart docker

echo ""
echo "============================================"
echo " Setup Complete!"
echo "============================================"
echo ""
echo " Next steps:"
echo "   1. cd $APP_DIR"
echo "   2. Edit .env with production values"
echo "   3. Copy docker-compose.yml and Dockerfile here"
echo "   4. docker compose up -d"
echo "   5. docker compose logs -f identity-api"
echo ""
echo " Health check: curl http://localhost:8080/actuator/health"
echo ""
