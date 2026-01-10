#!/bin/bash
# Production Clean Rebuild Script for Zumodra
# This script performs a complete clean rebuild of the application

set -e  # Exit on error

echo "========================================"
echo "Zumodra Production Clean Rebuild"
echo "========================================"
echo ""

# Step 1: Pull latest code
echo "[1/6] Pulling latest code from GitHub..."
git pull origin main
echo "✓ Code updated"
echo ""

# Step 2: Show current status
echo "[2/6] Current Docker status:"
docker ps -a
echo ""

# Step 3: Stop and remove EVERYTHING (critical step)
echo "[3/6] Stopping and removing all containers, volumes, and networks..."
docker compose down -v --remove-orphans
echo "✓ All containers and volumes removed"
echo ""

# Step 4: Remove all images for clean build
echo "[4/6] Removing all Docker images..."
docker image prune -a -f
echo "✓ Images cleaned"
echo ""

# Step 5: Verify clean state
echo "[5/6] Verifying clean state..."
echo "Containers:"
docker ps -a
echo ""
echo "Volumes:"
docker volume ls | grep zumodra || echo "  (none - this is correct!)"
echo ""
echo "Images:"
docker images | grep zumodra || echo "  (none - this is correct!)"
echo ""

# Step 6: Rebuild and start
echo "[6/6] Building and starting services..."
echo "This will take a few minutes..."
docker compose build --no-cache
docker compose up -d
echo ""

echo "========================================"
echo "✓ Clean rebuild complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Watch logs: docker compose logs -f web"
echo "2. Wait for: 'Starting gunicorn' message"
echo "3. Test: curl http://localhost:8000/health/"
echo ""
echo "The database will be completely new with:"
echo "  - Fresh schema (UUID primary keys)"
echo "  - TenantAwareModel for all HR models"
echo "  - Demo tenant with sample data"
echo ""
