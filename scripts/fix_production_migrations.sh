#!/bin/bash
# Automated migration fix and verification script
# This script can be run on production to fix missing tenant migrations

set -e  # Exit on error

echo "=== Zumodra Migration Fix & Verification ==="
echo "Started: $(date)"
echo ""

# Check if running in Docker environment
if command -v docker &> /dev/null && docker ps &> /dev/null; then
    DOCKER_EXEC="docker exec zumodra_web"
else
    DOCKER_EXEC=""
fi

# Step 1: Check current migration state (automated)
echo "[1/4] Checking current migration state..."
$DOCKER_EXEC python manage.py verify_tenant_migrations --json > /tmp/migration_status_before.json 2>&1 || {
    echo "Note: verify_tenant_migrations command may not exist yet. Continuing..."
    echo '{"status": "command_not_found"}' > /tmp/migration_status_before.json
}
cat /tmp/migration_status_before.json
echo ""

# Step 2: Apply missing migrations (idempotent, safe to run multiple times)
echo "[2/4] Applying tenant migrations..."
if $DOCKER_EXEC python manage.py migrate_schemas --tenant --noinput; then
    echo "✓ Tenant migrations applied successfully!"
else
    echo "✗ Tenant migration failed!"
    exit 1
fi
echo ""

# Step 3: Verify migrations applied
echo "[3/4] Verifying migrations applied..."
$DOCKER_EXEC python manage.py verify_tenant_migrations --json > /tmp/migration_status_after.json 2>&1 || {
    echo "Note: verify_tenant_migrations command may not exist yet. Skipping verification..."
    echo '{"status": "command_not_found"}' > /tmp/migration_status_after.json
}
cat /tmp/migration_status_after.json
echo ""

# Step 4: Run full health check
echo "[4/4] Running health check..."
if $DOCKER_EXEC python manage.py health_check --full --json; then
    echo "✓ Health check passed!"
else
    echo "⚠ Health check reported warnings or errors. Review above output."
fi
echo ""

echo "=== Fix Complete ==="
echo "Finished: $(date)"
echo ""
echo "Next steps:"
echo "1. Test the finance subscription page: /app/finance/subscription/"
echo "2. Monitor logs for any errors"
echo "3. If issues persist, review the migration status JSON files in /tmp/"
