#!/bin/bash
# Complete deployment script for all URL and migration fixes
# Run this on your server after pulling latest code

set -e  # Exit on error

echo "===== Zumodra FreelanHub Deployment ====="
echo ""

# Step 1: Pull latest code
echo "[1/6] Pulling latest code from Git..."
git pull origin main

# Step 2: Rebuild containers with latest code
echo ""
echo "[2/6] Rebuilding Docker containers..."
docker compose down
docker compose build --no-cache web channels

# Step 3: Start services
echo ""
echo "[3/6] Starting services..."
docker compose up -d

# Wait for database to be ready
echo "Waiting for database to be ready..."
sleep 10

# Step 4: Run migrations on shared schema
echo ""
echo "[4/6] Running migrations on shared schema..."
docker compose exec -T web python manage.py migrate_schemas --shared

# Step 5: Run migrations on all tenant schemas
echo ""
echo "[5/6] Running migrations on tenant schemas..."
docker compose exec -T web python manage.py migrate_schemas --tenant

# Step 6: Restart services to load new URL patterns
echo ""
echo "[6/6] Restarting services..."
docker compose restart web channels

echo ""
echo "===== Deployment Complete ====="
echo ""
echo "Fixed issues:"
echo "  ✅ URL namespace errors (careers, header, sidebar, HR)"
echo "  ✅ Custom template filter (sync settings)"
echo "  ✅ Database tables (TrustScore, UserStatus, OutboundWebhook)"
echo ""
echo "Services running:"
docker compose ps
echo ""
echo "Test the following URLs:"
echo "  - Dashboard: /app/dashboard/"
echo "  - Careers: /en/careers/"
echo "  - Messages: /app/messages/"
echo "  - Sync Settings: /user/sync-settings/"
