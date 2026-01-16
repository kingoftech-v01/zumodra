#!/bin/bash
# ============================================================================
# Fix Demo Tenant Missing Migrations
# ============================================================================
# This script fixes the missing finance_invoice table issue on production
# by applying all pending migrations to the demo tenant.
#
# Usage:
#   bash scripts/fix_demo_tenant_migrations.sh
#
# Or inside Docker container:
#   docker exec -it zumodra-web-1 bash scripts/fix_demo_tenant_migrations.sh
# ============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# ============================================================================
# Main Script
# ============================================================================

log_header "Demo Tenant Migration Fix"

# Step 1: Check if demo tenant exists
log_info "Step 1/5: Checking if demo tenant exists..."

TENANT_CHECK=$(python manage.py shell -c "
from tenants.models import Tenant
try:
    tenant = Tenant.objects.get(schema_name='demo')
    print(f'EXISTS|{tenant.name}|{tenant.schema_name}')
except Tenant.DoesNotExist:
    print('NOT_FOUND')
" 2>&1)

if echo "$TENANT_CHECK" | grep -q "NOT_FOUND"; then
    log_error "Demo tenant not found!"
    log_info "Please create demo tenant first using: python manage.py bootstrap_demo_tenant"
    exit 1
fi

TENANT_INFO=$(echo "$TENANT_CHECK" | grep "EXISTS" | cut -d'|' -f2-)
log_success "Demo tenant found: $TENANT_INFO"

# Step 2: Check current migration status
log_info "Step 2/5: Checking current migration status..."

echo ""
python manage.py verify_tenant_migrations --tenant=demo
MIGRATION_STATUS=$?

if [ $MIGRATION_STATUS -eq 0 ]; then
    log_success "All migrations already applied!"
    log_info "Nothing to fix. Demo tenant is up to date."
else
    log_warning "Pending migrations detected!"
fi

echo ""

# Step 3: Apply missing migrations with --fix flag
log_info "Step 3/5: Applying missing migrations to demo tenant..."

if python manage.py verify_tenant_migrations --tenant=demo --fix; then
    log_success "Migrations applied successfully!"
else
    log_error "Migration application failed!"
    log_error "Check the error messages above for details."
    exit 1
fi

echo ""

# Step 4: Verify all migrations applied
log_info "Step 4/5: Verifying all migrations are now applied..."

if python manage.py verify_tenant_migrations --tenant=demo; then
    log_success "All migrations verified!"
else
    log_error "Verification failed! Some migrations may still be pending."
    exit 1
fi

echo ""

# Step 5: Test finance tables exist
log_info "Step 5/5: Testing finance tables are accessible..."

FINANCE_CHECK=$(python manage.py shell -c "
from django_tenants.utils import schema_context, get_tenant_model
Tenant = get_tenant_model()
tenant = Tenant.objects.get(schema_name='demo')
with schema_context(tenant.schema_name):
    from finance.models import Invoice
    count = Invoice.objects.count()
    print(f'SUCCESS|{count}')
" 2>&1)

if echo "$FINANCE_CHECK" | grep -q "SUCCESS"; then
    INVOICE_COUNT=$(echo "$FINANCE_CHECK" | grep "SUCCESS" | cut -d'|' -f2)
    log_success "Finance tables accessible! Invoice count: $INVOICE_COUNT"
else
    log_error "Finance tables still not accessible!"
    echo "$FINANCE_CHECK"
    exit 1
fi

echo ""
log_header "✓ Migration Fix Complete!"
echo ""
log_success "Demo tenant migrations have been successfully applied."
log_info "You can now access the invoice page without errors."
echo ""
log_info "Test the invoice page:"
log_info "  curl -I https://demo.zumodra.rhematek-solutions.com/fr/app/finance/invoices/"
echo ""
