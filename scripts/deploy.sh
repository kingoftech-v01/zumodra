#!/bin/bash
# Production deployment with automated verification
# This script deploys the latest code and ensures all migrations are applied

set -e

echo "=== Zumodra Production Deployment ==="
echo "Started: $(date)"
echo ""

# Configuration
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
BRANCH="${BRANCH:-main}"

# Step 1: Pull latest code
echo "[1/6] Pulling latest code from $BRANCH..."
git fetch origin
git checkout "$BRANCH"
git pull origin "$BRANCH"
echo ""

# Step 2: Rebuild Docker images
echo "[2/6] Rebuilding Docker images..."
docker-compose -f "$COMPOSE_FILE" build --no-cache
echo ""

# Step 3: Stop services
echo "[3/6] Stopping services..."
docker-compose -f "$COMPOSE_FILE" down
echo ""

# Step 4: Start services (migrations run in entrypoint.sh)
echo "[4/6] Starting services..."
docker-compose -f "$COMPOSE_FILE" up -d
echo ""

# Step 5: Wait for services to be healthy
echo "[5/6] Waiting for services to be healthy..."
echo "This may take a few minutes while migrations run..."
sleep 30  # Initial wait for services to start

# Check web service health
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if docker-compose -f "$COMPOSE_FILE" ps | grep -q "web.*healthy"; then
        echo "✓ Web service is healthy!"
        break
    fi
    echo "Waiting for web service to be healthy... (attempt $((RETRY_COUNT + 1))/$MAX_RETRIES)"
    sleep 10
    RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "⚠ WARNING: Web service did not become healthy in time"
    echo "Check logs with: docker-compose -f $COMPOSE_FILE logs web"
    echo "Continuing with verification anyway..."
fi
echo ""

# Step 6: Run automated verification
echo "[6/6] Running automated verification..."
if [ -f "./scripts/fix_production_migrations.sh" ]; then
    ./scripts/fix_production_migrations.sh
else
    echo "⚠ WARNING: fix_production_migrations.sh not found, skipping verification"
    # Run basic health check instead
    docker exec zumodra_web python manage.py health_check --full || true
fi
echo ""

echo "=== Deployment Complete ==="
echo "Finished: $(date)"
echo ""
echo "Next steps:"
echo "1. Check application logs: docker-compose -f $COMPOSE_FILE logs -f web"
echo "2. Monitor health: docker exec zumodra_web python manage.py health_check --full"
echo "3. Verify application is accessible in browser"
echo ""
