#!/bin/bash
# =============================================================================
# Zumodra Docker Entrypoint Script
# =============================================================================
# Robust entrypoint that waits for services and runs migrations before starting
# Usage: entrypoint.sh [command] [args...]
# =============================================================================

set -e

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
DB_HOST="${DB_HOST:-postgres-primary}"
DB_DEFAULT_PORT="${DB_DEFAULT_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_DEFAULT_NAME="${DB_DEFAULT_NAME:-zumodra}"
MAX_DB_RETRIES="${MAX_DB_RETRIES:-60}"
DB_RETRY_INTERVAL="${DB_RETRY_INTERVAL:-2}"

REDIS_URL="${REDIS_URL:-redis://redis-master:6379/0}"
MAX_REDIS_RETRIES="${MAX_REDIS_RETRIES:-30}"
REDIS_RETRY_INTERVAL="${REDIS_RETRY_INTERVAL:-2}"

RABBITMQ_HOST="${RABBITMQ_HOST:-rabbitmq}"
RABBITMQ_PORT="${RABBITMQ_PORT:-5672}"
MAX_RABBITMQ_RETRIES="${MAX_RABBITMQ_RETRIES:-30}"
RABBITMQ_RETRY_INTERVAL="${RABBITMQ_RETRY_INTERVAL:-2}"

SERVICE_TYPE="${SERVICE_TYPE:-web}"
SKIP_MIGRATIONS="${SKIP_MIGRATIONS:-false}"
SKIP_COLLECTSTATIC="${SKIP_COLLECTSTATIC:-false}"
CREATE_DEMO_TENANT="${CREATE_DEMO_TENANT:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# -----------------------------------------------------------------------------
# Wait for PostgreSQL
# -----------------------------------------------------------------------------
wait_for_postgres() {
    log_info "Waiting for PostgreSQL at ${DB_HOST}:${DB_DEFAULT_PORT}..."

    local retries=0
    while [ $retries -lt $MAX_DB_RETRIES ]; do
        # Try to connect using pg_isready if available, otherwise use Python
        if command -v pg_isready &> /dev/null; then
            if pg_isready -h "$DB_HOST" -p "$DB_DEFAULT_PORT" -U "$DB_USER" -d "$DB_DEFAULT_NAME" -q; then
                log_info "PostgreSQL is ready!"
                return 0
            fi
        else
            # Use Python to check database connection
            if python -c "
import sys
import psycopg2
try:
    conn = psycopg2.connect(
        host='$DB_HOST',
        port='$DB_DEFAULT_PORT',
        user='$DB_USER',
        dbname='$DB_DEFAULT_NAME',
        connect_timeout=5
    )
    conn.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
                log_info "PostgreSQL is ready!"
                return 0
            fi
        fi

        retries=$((retries + 1))
        log_warn "PostgreSQL not ready yet (attempt $retries/$MAX_DB_RETRIES)..."
        sleep $DB_RETRY_INTERVAL
    done

    log_error "Failed to connect to PostgreSQL after $MAX_DB_RETRIES attempts"
    return 1
}

# -----------------------------------------------------------------------------
# Wait for Redis
# -----------------------------------------------------------------------------
wait_for_redis() {
    log_info "Waiting for Redis..."

    # Extract host and port from REDIS_URL
    local redis_host=$(echo "$REDIS_URL" | sed -E 's|redis://([^:]+):([0-9]+)/.*|\1|')
    local redis_port=$(echo "$REDIS_URL" | sed -E 's|redis://([^:]+):([0-9]+)/.*|\2|')

    local retries=0
    while [ $retries -lt $MAX_REDIS_RETRIES ]; do
        if python -c "
import sys
import redis
try:
    r = redis.from_url('$REDIS_URL', socket_connect_timeout=5)
    r.ping()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
            log_info "Redis is ready!"
            return 0
        fi

        retries=$((retries + 1))
        log_warn "Redis not ready yet (attempt $retries/$MAX_REDIS_RETRIES)..."
        sleep $REDIS_RETRY_INTERVAL
    done

    log_error "Failed to connect to Redis after $MAX_REDIS_RETRIES attempts"
    return 1
}

# -----------------------------------------------------------------------------
# Wait for RabbitMQ (only for Celery services)
# -----------------------------------------------------------------------------
wait_for_rabbitmq() {
    log_info "Waiting for RabbitMQ at ${RABBITMQ_HOST}:${RABBITMQ_PORT}..."

    local retries=0
    while [ $retries -lt $MAX_RABBITMQ_RETRIES ]; do
        # Simple TCP check using Python
        if python -c "
import sys
import socket
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex(('$RABBITMQ_HOST', $RABBITMQ_PORT))
    sock.close()
    sys.exit(0 if result == 0 else 1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
            log_info "RabbitMQ is ready!"
            return 0
        fi

        retries=$((retries + 1))
        log_warn "RabbitMQ not ready yet (attempt $retries/$MAX_RABBITMQ_RETRIES)..."
        sleep $RABBITMQ_RETRY_INTERVAL
    done

    log_error "Failed to connect to RabbitMQ after $MAX_RABBITMQ_RETRIES attempts"
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
    if [ -w "/app/static" ]; then
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
    log_info "=========================================="
    log_info "Zumodra Entrypoint - Service: $SERVICE_TYPE"
    log_info "=========================================="

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
