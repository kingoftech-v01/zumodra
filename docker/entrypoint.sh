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
# Database configuration - supports both DB_PORT and DB_DEFAULT_PORT
# Priority: DB_PORT > DB_DEFAULT_PORT > default 5432
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-${DB_DEFAULT_PORT:-5432}}"
DB_NAME="${DB_NAME:-${DB_DEFAULT_NAME:-zumodra}}"
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
# Support both DB_PORT and DB_DEFAULT_PORT
port = os.environ.get("DB_PORT", os.environ.get("DB_DEFAULT_PORT", "5432"))
name = os.environ.get("DB_NAME", os.environ.get("DB_DEFAULT_NAME", "zumodra"))
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
# Run Django Migrations
# -----------------------------------------------------------------------------
run_migrations() {
    if [ "$SKIP_MIGRATIONS" = "true" ]; then
        log_info "Skipping migrations (SKIP_MIGRATIONS=true)"
        return 0
    fi

    log_info "Running Django migrations..."

    # Run migrations for all apps
    if python manage.py migrate --noinput; then
        log_info "Migrations completed successfully!"
    else
        log_error "Migration failed!"
        return 1
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

    if python manage.py check --deploy 2>/dev/null; then
        log_info "Django configuration verified!"
    else
        log_warn "Django deployment checks returned warnings (non-fatal)"
    fi
}

# -----------------------------------------------------------------------------
# Bootstrap Demo Tenant (optional)
# -----------------------------------------------------------------------------
bootstrap_demo_tenant() {
    if [ "$CREATE_DEMO_TENANT" != "true" ] && [ "$CREATE_DEMO_TENANT" != "1" ]; then
        log_info "Skipping demo tenant (CREATE_DEMO_TENANT not set)"
        return 0
    fi

    log_info "Bootstrapping demo tenant..."

    if python manage.py bootstrap_demo_tenant 2>&1; then
        log_info "Demo tenant bootstrapped successfully!"
    else
        log_warn "Demo tenant bootstrap had issues (non-fatal, continuing...)"
    fi
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

    # Only run migrations and collectstatic for the primary web instance
    # or when explicitly enabled
    if [ "$SERVICE_TYPE" = "web" ]; then
        run_migrations || exit 1
        create_cache_table
        run_collectstatic
        bootstrap_demo_tenant
        verify_django_setup
    elif [ "$SERVICE_TYPE" = "celery-beat" ]; then
        # Celery beat needs migrations for django_celery_beat tables
        run_migrations || exit 1
    fi

    log_info "=========================================="
    log_info "Starting application: $@"
    log_info "=========================================="

    # Execute the main command
    exec "$@"
}

# Run main with all arguments
main "$@"
