#!/bin/bash
# =============================================================================
# Server Deployment Script - Migration Fix
# =============================================================================
# Run this on your production server after pulling the latest code
# =============================================================================

set -e

echo "=========================================="
echo "Zumodra - Deploy Migration Fixes"
echo "=========================================="

# Confirm we're on the server
echo ""
read -p "Are you running this on the PRODUCTION server? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborting. Run this script on the production server after pulling latest code."
    exit 1
fi

# Step 1: Pull latest code
echo ""
echo "[1/5] Pulling latest code from main branch..."
git fetch origin
git checkout main
git pull origin main

# Step 2: Stop services
echo ""
echo "[2/5] Stopping services..."
docker compose down

# Step 3: Rebuild images (CRITICAL - loads new settings_tenants.py)
echo ""
echo "[3/5] Rebuilding Docker images with new configuration..."
echo "  This step is CRITICAL - it loads the updated settings_tenants.py"
echo "  with integrations, core, security, ai_matching in SHARED_APPS"
docker compose build --no-cache web channels celery

# Step 4: Start services (migrations run automatically via entrypoint)
echo ""
echo "[4/5] Starting services..."
echo "  The entrypoint will automatically run:"
echo "  - migrate_schemas --shared (creates integrations tables in public schema)"
echo "  - migrate_schemas --tenant (migrates tenant schemas)"
docker compose up -d

# Step 5: Monitor logs for errors
echo ""
echo "[5/5] Monitoring startup logs..."
echo "  Watching for migration completion..."
echo "  Press Ctrl+C when you see 'Starting application'"
echo ""
sleep 5
docker compose logs -f web 2>&1 | grep --line-buffered -E "(INFO|ERROR|Starting migration|integrations|Migrating shared schema)"

echo ""
echo "=========================================="
echo "Deployment complete!"
echo "=========================================="
echo ""
echo "To verify the fix worked:"
echo "  docker compose exec web python manage.py dbshell"
echo "  Then run: \\dt integrations_*"
echo "  You should see integrations_outboundwebhook table"
echo ""
echo "Check application logs:"
echo "  docker compose logs web | grep -i 'integrations_outboundwebhook'"
echo ""
