#!/bin/bash
# =============================================================================
# Zumodra Docker Entrypoint Script
# =============================================================================
# Robust entrypoint that waits for services and runs migrations before starting
# Usage: entrypoint.sh [command] [args...]
# =============================================================================

set -e

# -----------------------------------------------------------------------------
# Configuration - Read from environment with sensible defaults
# -----------------------------------------------------------------------------
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-zumodra}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-}"

# Redis configuration
REDIS_URL="${REDIS_URL:-redis://localhost:6379/0}"

# RabbitMQ configuration
RABBITMQ_HOST="${RABBITMQ_HOST:-rabbitmq}"
RABBITMQ_PORT="${RABBITMQ_PORT:-5672}"

# Retry configuration
MAX_DB_RETRIES="${MAX_DB_RETRIES:-60}"
DB_RETRY_INTERVAL="${DB_RETRY_INTERVAL:-2}"
MAX_REDIS_RETRIES="${MAX_REDIS_RETRIES:-30}"
REDIS_RETRY_INTERVAL="${REDIS_RETRY_INTERVAL:-2}"
MAX_RABBITMQ_RETRIES="${MAX_RABBITMQ_RETRIES:-30}"
RABBITMQ_RETRY_INTERVAL="${RABBITMQ_RETRY_INTERVAL:-2}"

# Service configuration
SERVICE_TYPE="${SERVICE_TYPE:-web}"
SKIP_MIGRATIONS="${SKIP_MIGRATIONS:-false}"
SKIP_COLLECTSTATIC="${SKIP_COLLECTSTATIC:-false}"
CREATE_DEMO_TENANT="${CREATE_DEMO_TENANT:-false}"
SETUP_DEMO_DATA="${SETUP_DEMO_DATA:-false}"
RUN_GEOCODING="${RUN_GEOCODING:-false}"
RUN_TESTS="${RUN_TESTS:-false}"
TESTS_FAIL_FAST="${TESTS_FAIL_FAST:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Logging Functions
# -----------------------------------------------------------------------------
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_debug() {
    echo -e "${CYAN}[DEBUG]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# -----------------------------------------------------------------------------
# Print Configuration (for diagnosis)
# -----------------------------------------------------------------------------
print_config() {
    log_info "=========================================="
    log_info "Zumodra Entrypoint - Configuration"
    log_info "=========================================="
    log_info "Service Type: ${SERVICE_TYPE}"
    log_info ""
    log_info "Database Configuration (from env):"
    log_info "  DB_HOST     = ${DB_HOST}"
    log_info "  DB_PORT     = ${DB_PORT}"
    log_info "  DB_NAME     = ${DB_NAME}"
    log_info "  DB_USER     = ${DB_USER}"
    log_info "  DB_PASSWORD = ${DB_PASSWORD:+[SET]}${DB_PASSWORD:-[NOT SET]}"
    log_info ""
    log_info "Redis Configuration:"
    log_info "  REDIS_URL   = ${REDIS_URL}"
    log_info ""
    if [[ "$SERVICE_TYPE" == "celery"* ]]; then
        log_info "RabbitMQ Configuration:"
        log_info "  RABBITMQ_HOST = ${RABBITMQ_HOST}"
        log_info "  RABBITMQ_PORT = ${RABBITMQ_PORT}"
        log_info ""
    fi
    log_info "=========================================="
}

# -----------------------------------------------------------------------------
# Check Database Connection (with verbose error reporting)
# -----------------------------------------------------------------------------
check_db() {
    python3 << 'PYEOF'
import os
import sys

# Read from environment (same vars the entrypoint uses)
host = os.environ.get("DB_HOST", "localhost")
port = os.environ.get("DB_PORT", "5432")
name = os.environ.get("DB_NAME", "zumodra")
user = os.environ.get("DB_USER", "postgres")
password = os.environ.get("DB_PASSWORD", "")

try:
    port = int(port)
except ValueError:
    print(f"[DB-CHECK] Invalid port value: {port}")
    sys.exit(1)

# Try psycopg (v3) first, fall back to psycopg2
driver = None
try:
    import psycopg
    driver = "psycopg3"
except ImportError:
    try:
        import psycopg2 as psycopg
        driver = "psycopg2"
    except ImportError:
        print("[DB-CHECK] Neither psycopg nor psycopg2 is installed!")
        sys.exit(1)

try:
    if driver == "psycopg3":
        conn = psycopg.connect(
            host=host,
            port=port,
            dbname=name,
            user=user,
            password=password,
            connect_timeout=5,
        )
    else:
        conn = psycopg.connect(
            host=host,
            port=port,
            dbname=name,
            user=user,
            password=password,
            connect_timeout=5,
        )
    with conn.cursor() as cur:
        cur.execute("SELECT 1;")
    conn.close()
    sys.exit(0)
except Exception as e:
    print(f"[DB-CHECK] Failed to connect to {host}:{port}/{name} as {user}: {e}")
    sys.exit(1)
PYEOF
}

# -----------------------------------------------------------------------------
# Wait for PostgreSQL
# -----------------------------------------------------------------------------
wait_for_postgres() {
    log_info "Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT}/${DB_NAME}..."

    local retries=0
    while [ $retries -lt $MAX_DB_RETRIES ]; do
        retries=$((retries + 1))

        # Run the check and capture output
        if output=$(check_db 2>&1); then
            log_info "PostgreSQL is ready at ${DB_HOST}:${DB_PORT}/${DB_NAME}"
            return 0
        else
            # Show the actual error on every 5th attempt or the first attempt
            if [ $retries -eq 1 ] || [ $((retries % 5)) -eq 0 ]; then
                log_warn "PostgreSQL not ready (attempt ${retries}/${MAX_DB_RETRIES})"
                if [ -n "$output" ]; then
                    log_debug "$output"
                fi
            else
                log_warn "PostgreSQL not ready (attempt ${retries}/${MAX_DB_RETRIES})..."
            fi
        fi

        sleep $DB_RETRY_INTERVAL
    done

    log_error "Failed to connect to PostgreSQL at ${DB_HOST}:${DB_PORT}/${DB_NAME} after ${MAX_DB_RETRIES} attempts"
    log_error "Please verify:"
    log_error "  1. Database host '${DB_HOST}' is reachable from this container"
    log_error "  2. PostgreSQL is running on port ${DB_PORT}"
    log_error "  3. Database '${DB_NAME}' exists"
    log_error "  4. User '${DB_USER}' has access with the provided password"
    return 1
}

# -----------------------------------------------------------------------------
# Check Redis Connection (with verbose error reporting)
# -----------------------------------------------------------------------------
check_redis() {
    python3 << 'PYEOF'
import os
import sys

redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

try:
    import redis
except ImportError:
    print("[REDIS-CHECK] redis-py is not installed!")
    sys.exit(1)

try:
    r = redis.from_url(redis_url, socket_connect_timeout=5)
    r.ping()
    sys.exit(0)
except Exception as e:
    print(f"[REDIS-CHECK] Failed to connect to {redis_url}: {e}")
    sys.exit(1)
PYEOF
}

# -----------------------------------------------------------------------------
# Wait for Redis
# -----------------------------------------------------------------------------
wait_for_redis() {
    log_info "Waiting for Redis at ${REDIS_URL}..."

    local retries=0
    while [ $retries -lt $MAX_REDIS_RETRIES ]; do
        retries=$((retries + 1))

        if output=$(check_redis 2>&1); then
            log_info "Redis is ready!"
            return 0
        else
            if [ $retries -eq 1 ] || [ $((retries % 5)) -eq 0 ]; then
                log_warn "Redis not ready (attempt ${retries}/${MAX_REDIS_RETRIES})"
                if [ -n "$output" ]; then
                    log_debug "$output"
                fi
            else
                log_warn "Redis not ready (attempt ${retries}/${MAX_REDIS_RETRIES})..."
            fi
        fi

        sleep $REDIS_RETRY_INTERVAL
    done

    log_error "Failed to connect to Redis at ${REDIS_URL} after ${MAX_REDIS_RETRIES} attempts"
    return 1
}

# -----------------------------------------------------------------------------
# Check RabbitMQ Connection (with verbose error reporting)
# -----------------------------------------------------------------------------
check_rabbitmq() {
    python3 << 'PYEOF'
import os
import sys
import socket

host = os.environ.get("RABBITMQ_HOST", "rabbitmq")
port_str = os.environ.get("RABBITMQ_PORT", "5672")

try:
    port = int(port_str)
except ValueError:
    print(f"[RABBITMQ-CHECK] Invalid port value: {port_str}")
    sys.exit(1)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex((host, port))
    sock.close()
    if result == 0:
        sys.exit(0)
    else:
        print(f"[RABBITMQ-CHECK] Connection refused to {host}:{port} (error code: {result})")
        sys.exit(1)
except Exception as e:
    print(f"[RABBITMQ-CHECK] Failed to connect to {host}:{port}: {e}")
    sys.exit(1)
PYEOF
}

# -----------------------------------------------------------------------------
# Wait for RabbitMQ (only for Celery services)
# -----------------------------------------------------------------------------
wait_for_rabbitmq() {
    log_info "Waiting for RabbitMQ at ${RABBITMQ_HOST}:${RABBITMQ_PORT}..."

    local retries=0
    while [ $retries -lt $MAX_RABBITMQ_RETRIES ]; do
        retries=$((retries + 1))

        if output=$(check_rabbitmq 2>&1); then
            log_info "RabbitMQ is ready!"
            return 0
        else
            if [ $retries -eq 1 ] || [ $((retries % 5)) -eq 0 ]; then
                log_warn "RabbitMQ not ready (attempt ${retries}/${MAX_RABBITMQ_RETRIES})"
                if [ -n "$output" ]; then
                    log_debug "$output"
                fi
            else
                log_warn "RabbitMQ not ready (attempt ${retries}/${MAX_RABBITMQ_RETRIES})..."
            fi
        fi

        sleep $RABBITMQ_RETRY_INTERVAL
    done

    log_error "Failed to connect to RabbitMQ at ${RABBITMQ_HOST}:${RABBITMQ_PORT} after ${MAX_RABBITMQ_RETRIES} attempts"
    return 1
}

# -----------------------------------------------------------------------------
# Fix Migration Directory Permissions (Docker compatibility)
# -----------------------------------------------------------------------------
fix_migration_permissions() {
    log_info "Ensuring migration directories have correct permissions..."

    # List of core apps that need migration directories
    local apps=("tenants" "accounts" "custom_account_u" "ats" "hr_core" "services" "finance" "notifications" "messages_sys" "integrations" "core" "security" "ai_matching" "marketing")

    for app in "${apps[@]}"; do
        local migration_dir="${app}/migrations"

        # Create migrations directory if it doesn't exist
        if [ ! -d "$migration_dir" ]; then
            log_info "Creating migrations directory for ${app}..."
            mkdir -p "$migration_dir"
            touch "${migration_dir}/__init__.py"
        fi

        # Ensure directory is writable (fixes Docker permission issues)
        if [ -d "$migration_dir" ]; then
            chmod -R 755 "$migration_dir" 2>/dev/null || log_warn "Could not fix permissions for ${migration_dir}"

            # If initial migration exists but has permission issues, try to fix
            if [ -f "${migration_dir}/0001_initial.py" ]; then
                chmod 644 "${migration_dir}/0001_initial.py" 2>/dev/null || true
            fi
        fi
    done

    log_info "Migration directory permissions verified"
}

# -----------------------------------------------------------------------------
# Enable PostGIS Extension (required for geographic fields)
# -----------------------------------------------------------------------------
enable_postgis() {
    log_info "Enabling PostGIS extension in database..."

    python3 << 'PYEOF'
import os
import sys

# Read database config from environment
host = os.environ.get("DB_HOST", "localhost")
port = os.environ.get("DB_PORT", "5432")
dbname = os.environ.get("DB_NAME", "zumodra")
user = os.environ.get("DB_USER", "postgres")
password = os.environ.get("DB_PASSWORD", "")

try:
    port = int(port)
except ValueError:
    print(f"[POSTGIS] Invalid port value: {port}")
    sys.exit(1)

# Try psycopg (v3) first, fall back to psycopg2
driver = None
try:
    import psycopg
    driver = "psycopg3"
except ImportError:
    try:
        import psycopg2 as psycopg
        driver = "psycopg2"
    except ImportError:
        print("[POSTGIS] Neither psycopg nor psycopg2 is installed!")
        sys.exit(1)

try:
    if driver == "psycopg3":
        conn = psycopg.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password,
            connect_timeout=5,
        )
    else:
        conn = psycopg.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password,
            connect_timeout=5,
        )

    # Enable PostGIS extension
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS postgis;")
        print("[POSTGIS] PostGIS extension enabled successfully!")

        # Verify PostGIS is working
        cur.execute("SELECT PostGIS_version();")
        version = cur.fetchone()[0]
        print(f"[POSTGIS] PostGIS version: {version}")

    conn.close()
    sys.exit(0)
except Exception as e:
    print(f"[POSTGIS] Failed to enable PostGIS: {e}")
    sys.exit(1)
PYEOF

    if [ $? -eq 0 ]; then
        log_info "PostGIS extension enabled successfully!"
    else
        log_error "Failed to enable PostGIS extension!"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Run Django Migrations (django-tenants compatible)
# -----------------------------------------------------------------------------
run_migrations() {
    if [ "$SKIP_MIGRATIONS" = "true" ]; then
        log_info "Skipping migrations (SKIP_MIGRATIONS=true)"
        return 0
    fi

    log_info "Running Django migrations (django-tenants)..."

    # Fix migration directory permissions (Docker compatibility)
    fix_migration_permissions

    # Enable PostGIS extension before migrations
    enable_postgis || return 1

    # Step 1: Run migrations for SHARED_APPS on the public schema
    log_info "Step 1/4: Migrating shared schema (public)..."
    if python manage.py migrate_schemas --shared --noinput; then
        log_info "Shared schema migrations completed successfully!"
    else
        log_error "Shared schema migration failed!"
        return 1
    fi

    # Step 2: Migrate existing tenant schemas (BLOCKING - MUST SUCCEED)
    log_info "Step 2/4: Migrating existing tenant schemas..."
    if python manage.py migrate_schemas --tenant --noinput; then
        log_info "✓ Existing tenant schema migrations completed successfully!"
    else
        log_error "✗ FATAL: Tenant schema migration FAILED!"
        log_error "Container cannot start with missing migrations."
        log_error "All tenant schemas must have complete migrations applied."
        return 1
    fi

    # Step 2.5: Verify tenant migrations were applied successfully (BLOCKING - MUST PASS)
    log_info "Step 2.5/5: Verifying tenant migrations..."
    if python manage.py verify_tenant_migrations --fix 2>&1 | tee -a /tmp/migration_verification.log; then
        log_info "✓ All tenant migrations verified and applied!"
    else
        log_error "✗ FATAL: Tenant migration verification FAILED!"
        log_error "Some tenant schemas have incomplete migrations."
        log_error "=========================================="
        log_error "Migration Verification Report:"
        log_error "=========================================="
        cat /tmp/migration_verification.log | while IFS= read -r line; do
            log_error "  $line"
        done
        log_error "=========================================="
        return 1
    fi

    # Step 3: Create demo tenants if configured
    if [ "$CREATE_DEMO_TENANT" = "true" ]; then
        log_info "Step 3/5: Creating demo tenants..."
        if python manage.py bootstrap_demo_tenants; then
            log_info "✓ Demo tenants created successfully!"
        else
            log_warn "Demo tenant creation had issues (may already exist)"
        fi

        # Step 4: Run tenant migrations again for newly created demo tenants
        log_info "Step 4/5: Migrating newly created demo tenant schemas..."
        if python manage.py migrate_schemas --tenant --noinput; then
            log_info "✓ Demo tenant schema migrations completed successfully!"
        else
            log_error "Demo tenant schema migration failed!"
            return 1
        fi

        # Step 4.5: CRITICAL - Verify demo tenant migrations (BLOCKING)
        log_info "Step 4.5/6: Verifying demo tenant migrations (BLOCKING CHECK)..."

        DEMO_CHECK_OUTPUT=$(python manage.py verify_tenant_migrations --tenant=demo --fix 2>&1)
        DEMO_CHECK_STATUS=$?

        echo "$DEMO_CHECK_OUTPUT"

        if [ $DEMO_CHECK_STATUS -ne 0 ]; then
            log_error "╔════════════════════════════════════════════════════════════════╗"
            log_error "║  FATAL: Demo tenant migration verification FAILED             ║"
            log_error "║                                                                ║"
            log_error "║  The finance app and other tenant migrations were not applied ║"
            log_error "║  Container startup is BLOCKED to prevent data corruption      ║"
            log_error "║                                                                ║"
            log_error "║  ACTION REQUIRED:                                              ║"
            log_error "║  1. Check migration files exist in finance/migrations/        ║"
            log_error "║  2. Verify TENANT_APPS includes 'finance' in settings.py      ║"
            log_error "║  3. Check logs above for specific migration errors            ║"
            log_error "║  4. Manually run: python manage.py migrate_schemas --tenant   ║"
            log_error "╚════════════════════════════════════════════════════════════════╝"
            exit 1  # BLOCKING: Halt container startup
        fi

        log_info "✓ Demo tenant migrations verified and applied successfully!"

        # Step 4.6: CRITICAL - Verify ALL tenant migrations (BLOCKING)
        log_info "Step 4.6/6: Verifying all tenant migrations (BLOCKING CHECK)..."

        ALL_CHECK_OUTPUT=$(python manage.py verify_tenant_migrations --fix 2>&1)
        ALL_CHECK_STATUS=$?

        echo "$ALL_CHECK_OUTPUT"

        if [ $ALL_CHECK_STATUS -ne 0 ]; then
            log_error "╔════════════════════════════════════════════════════════════════╗"
            log_error "║  FATAL: Tenant migration verification FAILED                  ║"
            log_error "║                                                                ║"
            log_error "║  One or more tenants have pending migrations                  ║"
            log_error "║  Container startup is BLOCKED to prevent data corruption      ║"
            log_error "║                                                                ║"
            log_error "║  ACTION REQUIRED:                                              ║"
            log_error "║  1. Check logs above for affected tenants                     ║"
            log_error "║  2. Run: python manage.py verify_tenant_migrations --json     ║"
            log_error "║  3. Then: python manage.py migrate_schemas --tenant --noinput ║"
            log_error "╚════════════════════════════════════════════════════════════════╝"
            exit 1  # BLOCKING: Halt container startup
        fi

        log_info "✓ All tenant migrations verified and applied successfully!"

        # Step 5: Backfill TenantProfiles for existing users
        log_info "Step 5/6: Backfilling TenantProfiles for existing users..."
        if python manage.py create_tenant_profiles; then
            log_info "✓ TenantProfiles backfilled successfully!"
        else
            log_warn "TenantProfile backfill had issues (may be no users yet)"
        fi
    else
        log_info "Step 3/6: Skipping demo tenant creation (CREATE_DEMO_TENANT not set)"
        log_info "Step 4/6: No new tenants to migrate"
        log_info "Step 4.5/6: Skipping demo tenant verification (no demo tenants)"
        log_info "Step 4.6/6: Skipping all tenant verification (no demo tenants created)"
        log_info "Step 5/6: Skipping TenantProfile backfill (no demo tenants)"
    fi
}

# -----------------------------------------------------------------------------
# Run collectstatic
# -----------------------------------------------------------------------------
run_collectstatic() {
    if [ "$SKIP_COLLECTSTATIC" = "true" ]; then
        log_info "Skipping collectstatic (SKIP_COLLECTSTATIC=true)"
        return 0
    fi

    # Only run collectstatic for web service
    if [ "$SERVICE_TYPE" != "web" ]; then
        log_info "Skipping collectstatic for non-web service"
        return 0
    fi

    log_info "Collecting static files..."

    # Check if static directory is writable
    if [ -w "/app/static" ] || [ -w "/app" ]; then
        if python manage.py collectstatic --noinput --clear 2>/dev/null; then
            log_info "Static files collected successfully!"
        else
            log_warn "collectstatic failed, but continuing (static files may already exist)"
        fi
    else
        log_warn "Static directory not writable, skipping collectstatic"
    fi
}

# -----------------------------------------------------------------------------
# Create cache tables (if using database cache)
# -----------------------------------------------------------------------------
create_cache_table() {
    log_info "Creating cache table if needed..."
    python manage.py createcachetable 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# Health check endpoint verification
# -----------------------------------------------------------------------------
verify_django_setup() {
    log_info "Verifying Django configuration..."

    # Capture both stdout and stderr from deployment checks
    check_output=$(python manage.py check --deploy 2>&1)
    check_exit_code=$?

    if [ $check_exit_code -eq 0 ]; then
        log_info "Django configuration verified!"
    else
        log_warn "Django deployment checks returned warnings/errors (non-fatal):"
        log_warn "================================================================"
        # Display the actual output line by line with proper formatting
        echo "$check_output" | while IFS= read -r line; do
            log_warn "  $line"
        done
        log_warn "================================================================"
    fi
}

# -----------------------------------------------------------------------------
# Bootstrap Demo Tenants (optional) - Creates COMPANY and FREELANCER types
# -----------------------------------------------------------------------------
bootstrap_demo_tenant() {
    if [ "$CREATE_DEMO_TENANT" != "true" ] && [ "$CREATE_DEMO_TENANT" != "1" ]; then
        log_info "Skipping demo tenants (CREATE_DEMO_TENANT not set)"
        return 0
    fi

    log_info "Bootstrapping demo tenants (COMPANY and FREELANCER types)..."

    if python manage.py bootstrap_demo_tenants 2>&1; then
        log_info "Demo tenants bootstrapped successfully!"
    else
        log_warn "Demo tenants bootstrap had issues (non-fatal, continuing...)"
    fi
}

# -----------------------------------------------------------------------------
# Setup Demo Data (optional) - Creates sample jobs, candidates, etc.
# -----------------------------------------------------------------------------
setup_demo_data() {
    if [ "$SETUP_DEMO_DATA" != "true" ] && [ "$SETUP_DEMO_DATA" != "1" ]; then
        log_info "Skipping demo data setup (SETUP_DEMO_DATA not set)"
        return 0
    fi

    log_info "Setting up demo data (jobs, candidates, etc.)..."

    if python manage.py setup_demo_data --num-jobs 15 --num-candidates 50 2>&1; then
        log_info "Demo data setup completed successfully!"
    else
        log_warn "Demo data setup had issues (non-fatal, continuing...)"
    fi
}

# -----------------------------------------------------------------------------
# Run Geocoding (optional) - Geocodes tenant, job, and service locations
# -----------------------------------------------------------------------------
run_geocoding() {
    if [ "$RUN_GEOCODING" != "true" ] && [ "$RUN_GEOCODING" != "1" ]; then
        log_info "Skipping geocoding (RUN_GEOCODING not set)"
        return 0
    fi

    log_info "=========================================="
    log_info "Running Geocoding for Locations"
    log_info "=========================================="

    log_info "Geocoding tenant addresses, job locations, and service providers..."

    if python manage.py geocode_locations --all 2>&1; then
        log_info "=========================================="
        log_info "Geocoding completed successfully!"
        log_info "=========================================="
        return 0
    else
        log_warn "=========================================="
        log_warn "Geocoding had some issues (non-fatal)"
        log_warn "=========================================="
        # Don't fail - geocoding failures are non-fatal
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Run Tests (optional)
# -----------------------------------------------------------------------------
run_tests() {
    if [ "$RUN_TESTS" != "true" ] && [ "$RUN_TESTS" != "1" ]; then
        log_info "Skipping tests (RUN_TESTS not set)"
        return 0
    fi

    log_info "=========================================="
    log_info "Running Test Suite"
    log_info "=========================================="

    local pytest_args="-v --tb=short"

    # Add fail-fast if enabled
    if [ "$TESTS_FAIL_FAST" = "true" ] || [ "$TESTS_FAIL_FAST" = "1" ]; then
        pytest_args="$pytest_args -x"
    fi

    # Add coverage if requested
    if [ "$TEST_COVERAGE" = "true" ] || [ "$TEST_COVERAGE" = "1" ]; then
        pytest_args="$pytest_args --cov --cov-report=term-missing"
    fi

    log_info "Running: pytest $pytest_args"

    if pytest $pytest_args; then
        log_info "=========================================="
        log_info "All tests passed successfully!"
        log_info "=========================================="
        return 0
    else
        log_error "=========================================="
        log_error "Some tests failed!"
        log_error "=========================================="
        # Don't exit - just warn, so the app still starts
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Migration Lock (for production with multiple replicas)
# Uses Redis to ensure only one instance runs migrations at a time
# -----------------------------------------------------------------------------
acquire_migration_lock() {
    python3 << 'PYEOF'
import os
import sys

redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
lock_key = "zumodra:migration:lock"
lock_timeout = 600  # 10 minutes

try:
    import redis
    r = redis.from_url(redis_url, socket_connect_timeout=5)
    acquired = r.set(lock_key, "locked", nx=True, ex=lock_timeout)
    if acquired:
        print("ACQUIRED")
    else:
        print("WAITING")
except Exception as e:
    # If Redis fails, proceed without lock (fail open for dev environments)
    print(f"ERROR: {e}")
    sys.exit(0)
PYEOF
}

release_migration_lock() {
    python3 << 'PYEOF'
import os

redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
lock_key = "zumodra:migration:lock"

try:
    import redis
    r = redis.from_url(redis_url, socket_connect_timeout=5)
    r.delete(lock_key)
except:
    pass  # Best effort - ignore errors
PYEOF
}

# -----------------------------------------------------------------------------
# Main Entrypoint Logic
# -----------------------------------------------------------------------------
main() {
    # Print configuration for diagnosis
    print_config

    # Wait for required services
    wait_for_postgres || exit 1
    wait_for_redis || exit 1

    # Celery services need RabbitMQ
    if [[ "$SERVICE_TYPE" == "celery"* ]]; then
        wait_for_rabbitmq || exit 1
    fi

    # Only run migrations and collectstatic for the web service
    # Uses Redis-based locking to prevent race conditions with multiple replicas
    if [ "$SERVICE_TYPE" = "web" ]; then
        local lock_status
        lock_status=$(acquire_migration_lock)

        if [ "$lock_status" = "ACQUIRED" ]; then
            log_info "Migration lock acquired, running database setup..."
            run_migrations || { release_migration_lock; exit 1; }
            create_cache_table
            run_collectstatic
            bootstrap_demo_tenant
            setup_demo_data
            run_geocoding || log_warn "Geocoding had issues, but continuing..."
            verify_django_setup
            run_tests || log_warn "Tests had failures, but continuing..."
            release_migration_lock
            log_info "Migration lock released"
        elif [ "$lock_status" = "WAITING" ]; then
            log_info "Another instance is running migrations, waiting for completion..."

            # Wait up to 10 minutes (600 seconds) for migrations to complete
            local max_wait=600
            local wait_interval=10
            local waited=0

            while [ $waited -lt $max_wait ]; do
                sleep $wait_interval
                waited=$((waited + wait_interval))

                # Check if lock is released (migrations completed)
                local new_lock_status
                new_lock_status=$(acquire_migration_lock)
                if [ "$new_lock_status" = "ACQUIRED" ]; then
                    log_info "✓ Migration lock released, migrations completed by another instance"
                    release_migration_lock
                    break
                fi

                log_info "Still waiting for migrations... (${waited}s / ${max_wait}s)"
            done

            if [ $waited -ge $max_wait ]; then
                log_error "Timeout waiting for migrations after ${max_wait}s"
                exit 1
            fi

            # Verify migrations completed successfully
            log_info "Verifying migrations completed successfully..."
            if ! python manage.py migrate_schemas --check; then
                log_error "Migrations verification failed - running migrations on this instance"
                # Fallback: try to run migrations on this instance
                run_migrations || exit 1
                create_cache_table
                run_collectstatic
                bootstrap_demo_tenant
                setup_demo_data
                run_geocoding || log_warn "Geocoding had issues, but continuing..."
                verify_django_setup
            else
                log_info "✓ Migrations verified successfully"
            fi
        else
            # Lock acquisition failed (Redis error) - proceed anyway for dev
            log_warn "Could not acquire migration lock (Redis error), proceeding without lock..."
            run_migrations || exit 1
            create_cache_table
            run_collectstatic
            bootstrap_demo_tenant
            setup_demo_data
            run_geocoding || log_warn "Geocoding had issues, but continuing..."
            verify_django_setup
            run_tests || log_warn "Tests had failures, but continuing..."
        fi
    fi
    # Note: celery services do NOT run migrations - web container handles all migrations
    # django_celery_beat tables are in SHARED_APPS and migrated with --shared flag

    log_info "=========================================="
    log_info "Starting application: $@"
    log_info "=========================================="

    # Execute the main command
    exec "$@"
}

# Run main with all arguments
main "$@"
