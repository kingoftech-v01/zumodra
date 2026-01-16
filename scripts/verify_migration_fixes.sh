#!/bin/bash
# ============================================================================
# Verify Migration Fixes
# ============================================================================
# This script verifies that all migration fixes are working correctly:
# 1. Tests bootstrap_demo_tenant.py includes migrations
# 2. Tests bootstrap_demo_tenants.py includes migrations
# 3. Tests TenantService.create_tenant() includes migrations
# 4. Verifies Docker entrypoint has blocking checks
# 5. Tests all existing tenants have complete migrations
#
# Usage:
#   bash scripts/verify_migration_fixes.sh
#
# Or inside Docker container:
#   docker exec -it zumodra-web-1 bash scripts/verify_migration_fixes.sh
# ============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

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
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

test_start() {
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo ""
    log_info "Test $TESTS_TOTAL: $1"
}

test_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log_success "$1"
}

test_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    log_error "$1"
}

# ============================================================================
# Code Verification Tests
# ============================================================================

log_header "Code Verification Tests"

# Test 1: Check bootstrap_demo_tenant.py has migrate_schemas call
test_start "Verify bootstrap_demo_tenant.py includes migrate_schemas"
if grep -q "migrate_schemas" tenants/management/commands/bootstrap_demo_tenant.py && \
   grep -q "schema_context(tenant.schema_name)" tenants/management/commands/bootstrap_demo_tenant.py && \
   grep -q "tenant.delete()" tenants/management/commands/bootstrap_demo_tenant.py; then
    test_pass "bootstrap_demo_tenant.py has explicit migration call with rollback"
else
    test_fail "bootstrap_demo_tenant.py missing migration code!"
fi

# Test 2: Check bootstrap_demo_tenants.py has migrate_schemas call
test_start "Verify bootstrap_demo_tenants.py includes migrate_schemas"
if grep -q "migrate_schemas" tenants/management/commands/bootstrap_demo_tenants.py && \
   grep -q "schema_context(tenant.schema_name)" tenants/management/commands/bootstrap_demo_tenants.py && \
   grep -q "tenant.delete()" tenants/management/commands/bootstrap_demo_tenants.py; then
    test_pass "bootstrap_demo_tenants.py has explicit migration call with rollback"
else
    test_fail "bootstrap_demo_tenants.py missing migration code!"
fi

# Test 3: Check TenantService.create_tenant has migrate_schemas call
test_start "Verify TenantService.create_tenant includes migrate_schemas"
if grep -q "migrate_schemas" tenants/services.py && \
   grep -A 20 "def create_tenant" tenants/services.py | grep -q "schema_context"; then
    test_pass "TenantService.create_tenant has explicit migration call"
else
    test_fail "TenantService.create_tenant missing migration code!"
fi

# Test 4: Check Docker entrypoint has blocking verification
test_start "Verify Docker entrypoint has blocking migration checks"
if grep -q "Step 4.5" docker/entrypoint.sh && \
   grep -q "Step 4.6" docker/entrypoint.sh && \
   grep -q "verify_tenant_migrations --tenant=demo --fix" docker/entrypoint.sh && \
   grep -q "exit 1.*BLOCKING" docker/entrypoint.sh; then
    test_pass "Docker entrypoint has blocking verification steps"
else
    test_fail "Docker entrypoint missing blocking verification!"
fi

# Test 5: Verify error handling includes tenant cleanup
test_start "Verify error handling includes automatic tenant cleanup"
CLEANUP_COUNT=$(grep -c "tenant.delete()" tenants/management/commands/bootstrap_demo_tenant.py tenants/management/commands/bootstrap_demo_tenants.py tenants/services.py 2>/dev/null || echo "0")
if [ "$CLEANUP_COUNT" -ge 3 ]; then
    test_pass "All tenant creation methods have cleanup on failure ($CLEANUP_COUNT found)"
else
    test_fail "Some methods missing tenant cleanup! Only $CLEANUP_COUNT found, expected 3"
fi

# ============================================================================
# Database Verification Tests
# ============================================================================

log_header "Database Verification Tests"

# Test 6: Check all tenants have complete migrations
test_start "Verify all existing tenants have complete migrations"
VERIFICATION_OUTPUT=$(python manage.py verify_tenant_migrations --json 2>&1 || echo "FAILED")
if echo "$VERIFICATION_OUTPUT" | grep -q "FAILED"; then
    test_fail "Some tenants have pending migrations!"
    echo "$VERIFICATION_OUTPUT"
else
    test_pass "All tenants have complete migrations"
fi

# Test 7: Check demo tenant specifically
test_start "Verify demo tenant migrations specifically"
if python manage.py verify_tenant_migrations --tenant=demo 2>&1 | grep -q "No pending migrations" || \
   python manage.py verify_tenant_migrations --tenant=demo 2>&1 | grep -q "All migrations applied"; then
    test_pass "Demo tenant migrations are complete"
else
    test_fail "Demo tenant has pending migrations!"
fi

# Test 8: Test finance tables exist in demo tenant
test_start "Verify finance tables exist in demo tenant"
FINANCE_TEST=$(python manage.py shell -c "
from django_tenants.utils import schema_context, get_tenant_model
Tenant = get_tenant_model()
try:
    tenant = Tenant.objects.get(schema_name='demo')
    with schema_context(tenant.schema_name):
        from finance.models import Invoice, PaymentTransaction, SubscriptionPlan
        invoice_count = Invoice.objects.count()
        payment_count = PaymentTransaction.objects.count()
        plan_count = SubscriptionPlan.objects.count()
        print('SUCCESS')
except Exception as e:
    print(f'FAILED: {e}')
" 2>&1)

if echo "$FINANCE_TEST" | grep -q "SUCCESS"; then
    test_pass "Finance tables are accessible in demo tenant"
else
    test_fail "Finance tables not accessible!"
    echo "$FINANCE_TEST"
fi

# ============================================================================
# Configuration Verification Tests
# ============================================================================

log_header "Configuration Verification Tests"

# Test 9: Verify finance app is in TENANT_APPS
test_start "Verify finance app is in TENANT_APPS"
if grep -q "'finance'" zumodra/settings.py && \
   grep -B 5 -A 30 "TENANT_APPS" zumodra/settings.py | grep -q "'finance'"; then
    test_pass "finance app is in TENANT_APPS"
else
    test_fail "finance app not found in TENANT_APPS!"
fi

# Test 10: Verify verify_tenant_migrations command exists
test_start "Verify verify_tenant_migrations command exists"
if [ -f "core/management/commands/verify_tenant_migrations.py" ]; then
    test_pass "verify_tenant_migrations command exists"
else
    test_fail "verify_tenant_migrations command not found!"
fi

# ============================================================================
# Test Results Summary
# ============================================================================

echo ""
log_header "Test Results Summary"
echo ""
echo -e "  Total Tests:  ${CYAN}$TESTS_TOTAL${NC}"
echo -e "  ${GREEN}Passed:       $TESTS_PASSED${NC}"
echo -e "  ${RED}Failed:       $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    log_header "✓ ALL TESTS PASSED!"
    echo ""
    log_success "All migration fixes are properly implemented!"
    log_info "The system is protected against missing migration issues."
    echo ""
    exit 0
else
    log_header "✗ SOME TESTS FAILED"
    echo ""
    log_error "$TESTS_FAILED test(s) failed!"
    log_warning "Please review the failures above and fix the issues."
    echo ""
    exit 1
fi
