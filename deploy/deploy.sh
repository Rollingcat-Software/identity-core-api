#!/usr/bin/env bash
# ============================================================================
# Identity Core API - Zero-Downtime Deployment Script
# Run this on the GCP Compute Engine instance to deploy updates.
#
# Usage:
#   ./deploy.sh                    # Build and deploy
#   ./deploy.sh --pull-only        # Pull latest image only (if using registry)
#   ./deploy.sh --restart          # Restart without rebuilding
# ============================================================================

set -euo pipefail

APP_DIR="/opt/identity-core-api"
COMPOSE_FILE="$APP_DIR/docker-compose.yml"
LOG_FILE="$APP_DIR/deploy-$(date +%Y%m%d-%H%M%S).log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

cd "$APP_DIR"

log "Starting deployment..."

# Pre-flight checks
if [ ! -f "$COMPOSE_FILE" ]; then
    log "ERROR: docker-compose.yml not found at $COMPOSE_FILE"
    exit 1
fi

if [ ! -f "$APP_DIR/.env" ]; then
    log "ERROR: .env file not found at $APP_DIR/.env"
    exit 1
fi

case "${1:-build}" in
    --restart)
        log "Restarting identity-api..."
        docker compose restart identity-api
        ;;
    --pull-only)
        log "Pulling latest images..."
        docker compose pull
        docker compose up -d --no-build
        ;;
    *)
        # Full build and deploy
        log "Building and deploying..."

        # Build new image
        log "Building Docker image..."
        docker compose build --no-cache identity-api 2>&1 | tee -a "$LOG_FILE"

        # Restart only the API (keeps DB and Redis running)
        log "Restarting API service..."
        docker compose up -d --no-deps identity-api 2>&1 | tee -a "$LOG_FILE"
        ;;
esac

# Wait for health check
log "Waiting for health check..."
RETRIES=30
DELAY=5
for i in $(seq 1 $RETRIES); do
    if curl -sf http://localhost:8080/actuator/health > /dev/null 2>&1; then
        log "Health check PASSED (attempt $i/$RETRIES)"
        break
    fi
    if [ "$i" -eq "$RETRIES" ]; then
        log "ERROR: Health check FAILED after $RETRIES attempts"
        log "Rolling back..."
        docker compose logs --tail=50 identity-api | tee -a "$LOG_FILE"
        exit 1
    fi
    sleep $DELAY
done

# Cleanup old images
log "Cleaning up dangling images..."
docker image prune -f 2>&1 | tee -a "$LOG_FILE"

log "Deployment complete!"
docker compose ps | tee -a "$LOG_FILE"
