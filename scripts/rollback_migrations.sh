#!/bin/bash
# Rollback migrations to a previous state
# WARNING: This is a destructive operation. Use with caution.

set -e

echo "=== Zumodra Migration Rollback ==="
echo "⚠ WARNING: This will rollback database migrations"
echo ""

# Check if backup file is provided
if [ -z "$1" ]; then
    echo "ERROR: No backup file specified"
    echo ""
    echo "Usage: $0 <backup_file> [options]"
    echo ""
    echo "Options:"
    echo "  --app=<app_name>          Rollback specific app only"
    echo "  --migration=<migration>   Rollback to specific migration"
    echo "  --tenant=<schema_name>    Rollback specific tenant only"
    echo "  --force                   Skip confirmation prompts"
    echo ""
    echo "Examples:"
    echo "  $0 /backups/zumodra_backup_20260115.dump"
    echo "  $0 /backups/latest.dump --app=finance --force"
    echo "  $0 /backups/latest.dump --tenant=tenant_demo"
    echo ""
    exit 1
fi

BACKUP_FILE="$1"
shift  # Remove first argument

# Parse additional options
FORCE=false
APP=""
MIGRATION=""
TENANT=""

for arg in "$@"; do
    case $arg in
        --force)
            FORCE=true
            ;;
        --app=*)
            APP="${arg#*=}"
            ;;
        --migration=*)
            MIGRATION="${arg#*=}"
            ;;
        --tenant=*)
            TENANT="${arg#*=}"
            ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

# Verify backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Check if file is gzipped
if [[ "$BACKUP_FILE" == *.gz ]]; then
    echo "Note: Backup file is compressed"
    NEEDS_DECOMPRESS=true
else
    NEEDS_DECOMPRESS=false
fi

echo "Rollback Details:"
echo "  Backup file: $BACKUP_FILE"
echo "  Backup size: $(du -h "$BACKUP_FILE" | cut -f1)"
if [ -n "$APP" ]; then
    echo "  App: $APP"
fi
if [ -n "$MIGRATION" ]; then
    echo "  Migration: $MIGRATION"
fi
if [ -n "$TENANT" ]; then
    echo "  Tenant: $TENANT"
fi
echo ""

# Confirmation unless forced
if [ "$FORCE" != true ]; then
    echo "⚠ THIS OPERATION WILL:"
    echo "  1. Stop all services"
    echo "  2. Restore database from backup"
    echo "  3. Restart services"
    echo ""
    echo "This may result in data loss!"
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " CONFIRM

    if [ "$CONFIRM" != "yes" ]; then
        echo "Rollback cancelled."
        exit 0
    fi
fi

# Configuration
DB_CONTAINER="${DB_CONTAINER:-zumodra_postgres}"
DB_USER="${DB_USER:-zumodra_user}"
DB_NAME="${DB_NAME:-zumodra_db}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"

echo ""
echo "Starting rollback process..."
echo ""

# Step 1: Create safety backup of current state
echo "[1/6] Creating safety backup of current state..."
SAFETY_BACKUP="/tmp/zumodra_pre_rollback_$(date +%Y%m%d_%H%M%S).dump"
if docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" -Fc > "$SAFETY_BACKUP" 2>&1; then
    echo "✓ Safety backup created: $SAFETY_BACKUP"
    echo "  (You can use this to recover if rollback fails)"
else
    echo "⚠ WARNING: Could not create safety backup"
    if [ "$FORCE" != true ]; then
        read -p "Continue anyway? (yes/no): " CONTINUE
        if [ "$CONTINUE" != "yes" ]; then
            echo "Rollback cancelled."
            exit 1
        fi
    fi
fi
echo ""

# Step 2: Stop services
echo "[2/6] Stopping services..."
docker-compose -f "$COMPOSE_FILE" stop web channels celery celery-beat
echo "✓ Services stopped"
echo ""

# Step 3: Decompress if needed
RESTORE_FILE="$BACKUP_FILE"
if [ "$NEEDS_DECOMPRESS" = true ]; then
    echo "[3/6] Decompressing backup..."
    TEMP_FILE="/tmp/zumodra_restore_temp.dump"
    gunzip -c "$BACKUP_FILE" > "$TEMP_FILE"
    RESTORE_FILE="$TEMP_FILE"
    echo "✓ Backup decompressed"
else
    echo "[3/6] Backup already decompressed"
fi
echo ""

# Step 4: Restore database
echo "[4/6] Restoring database from backup..."
echo "  This may take several minutes..."

# Drop and recreate database
docker exec "$DB_CONTAINER" psql -U "$DB_USER" -c "DROP DATABASE IF EXISTS ${DB_NAME}_temp;" postgres
docker exec "$DB_CONTAINER" psql -U "$DB_USER" -c "CREATE DATABASE ${DB_NAME}_temp WITH TEMPLATE template0;" postgres

# Restore to temp database
if cat "$RESTORE_FILE" | docker exec -i "$DB_CONTAINER" pg_restore -U "$DB_USER" -d "${DB_NAME}_temp" --no-owner --no-acl 2>&1 | grep -v "WARNING"; then
    # Swap databases
    docker exec "$DB_CONTAINER" psql -U "$DB_USER" -c "
        SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$DB_NAME';
    " postgres
    docker exec "$DB_CONTAINER" psql -U "$DB_USER" -c "ALTER DATABASE $DB_NAME RENAME TO ${DB_NAME}_old;" postgres
    docker exec "$DB_CONTAINER" psql -U "$DB_USER" -c "ALTER DATABASE ${DB_NAME}_temp RENAME TO $DB_NAME;" postgres

    echo "✓ Database restored successfully"
else
    echo "✗ Database restore failed!"
    echo "  Attempting to recover..."

    # Try to recover
    docker exec "$DB_CONTAINER" psql -U "$DB_USER" -c "DROP DATABASE IF EXISTS ${DB_NAME}_temp;" postgres

    echo "Rollback failed. Services are still stopped."
    echo "To recover:"
    echo "  1. Check logs for errors"
    echo "  2. Try restoring from safety backup: $SAFETY_BACKUP"
    echo "  3. Or restart services with current state: docker-compose -f $COMPOSE_FILE start"
    exit 1
fi
echo ""

# Clean up temp file if created
if [ "$NEEDS_DECOMPRESS" = true ] && [ -f "$TEMP_FILE" ]; then
    rm -f "$TEMP_FILE"
fi

# Step 5: Restart services
echo "[5/6] Restarting services..."
docker-compose -f "$COMPOSE_FILE" start web channels celery celery-beat

# Wait for services to be ready
echo "  Waiting for services to be ready..."
sleep 10
echo "✓ Services restarted"
echo ""

# Step 6: Verify rollback
echo "[6/6] Verifying rollback..."

# Check database connectivity
if docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null 2>&1; then
    echo "✓ Database accessible"
else
    echo "✗ Database not accessible!"
    exit 1
fi

# Run migrations verification
if command -v python &> /dev/null || docker exec zumodra_web python --version > /dev/null 2>&1; then
    echo "Running migration verification..."
    if docker exec zumodra_web python manage.py verify_tenant_migrations --json > /tmp/rollback_verify.json 2>&1; then
        TENANTS_WITH_ISSUES=$(python3 -c "import json; print(json.load(open('/tmp/rollback_verify.json')).get('tenants_with_issues', 0))" 2>/dev/null || echo "unknown")
        echo "  Tenants with migration issues: $TENANTS_WITH_ISSUES"
    fi
fi

# Clean up old database
echo ""
read -p "Remove old database backup (${DB_NAME}_old)? (yes/no): " CLEANUP
if [ "$CLEANUP" = "yes" ]; then
    docker exec "$DB_CONTAINER" psql -U "$DB_USER" -c "DROP DATABASE IF EXISTS ${DB_NAME}_old;" postgres
    echo "✓ Old database removed"
fi

echo ""
echo "=== Rollback Complete ==="
echo "Restored from: $BACKUP_FILE"
echo "Safety backup: $SAFETY_BACKUP"
echo ""
echo "Next steps:"
echo "  1. Verify application is working"
echo "  2. Check logs for any errors"
echo "  3. Run health check: python manage.py health_check --full"
echo "  4. Monitor for issues"
echo ""
echo "To remove safety backup later:"
echo "  rm $SAFETY_BACKUP"
echo ""

exit 0
