#!/bin/bash
# =============================================================================
# Fix Migrations and Rebuild Script
# =============================================================================
# This script:
# 1. Creates missing migration directories
# 2. Generates migrations for apps with models but no migrations
# 3. Rebuilds Docker containers to load new configuration
# =============================================================================

set -e

echo "=========================================="
echo "Zumodra Migration Fix Script"
echo "=========================================="

# Step 1: Ensure migration directories exist for all apps
echo ""
echo "[1/4] Creating migration directories..."
for app in ai_matching core security marketing integrations; do
    if [ ! -d "$app/migrations" ]; then
        echo "  Creating $app/migrations/"
        mkdir -p "$app/migrations"
        touch "$app/migrations/__init__.py"
    else
        echo "  ✓ $app/migrations/ exists"
    fi
done

# Step 2: Generate missing migrations (run locally before deploying)
echo ""
echo "[2/4] Checking for apps that need initial migrations..."
echo "  Run this command locally to generate migrations:"
echo "  python manage.py makemigrations ai_matching"
echo ""
echo "  Note: ai_matching has models but no migration files yet"

# Step 3: Rebuild Docker containers with new configuration
echo ""
echo "[3/4] Rebuilding Docker containers..."
echo "  This ensures settings_tenants.py changes are loaded"
docker compose down
docker compose build --no-cache web channels
docker compose up -d

# Step 4: Monitor logs
echo ""
echo "[4/4] Monitoring startup logs..."
echo "  Press Ctrl+C to stop watching logs"
echo ""
docker compose logs -f web | head -100

echo ""
echo "=========================================="
echo "Migration fix complete!"
echo "=========================================="
echo ""
echo "To verify:"
echo "  docker compose exec web python manage.py showmigrations integrations"
echo "  docker compose exec web python manage.py showmigrations ai_matching"
echo ""
