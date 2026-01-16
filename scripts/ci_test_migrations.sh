#!/bin/bash
# CI/CD integration test for migration handling
# This script runs in CI/CD pipelines to ensure migration safety

set -e

echo "=== Zumodra CI/CD Migration Tests ==="
echo "Started: $(date)"
echo ""

# Exit codes
EXIT_SUCCESS=0
EXIT_FAILURE=1

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
pass_test() {
    echo "✓ PASS: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail_test() {
    echo "✗ FAIL: $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# Test 1: Verify command exists and has help
echo "[Test 1/10] Verify tenant migrations command exists..."
if python manage.py verify_tenant_migrations --help > /dev/null 2>&1; then
    pass_test "verify_tenant_migrations command exists"
else
    fail_test "verify_tenant_migrations command not found"
fi
echo ""

# Test 2: Verify command accepts required flags
echo "[Test 2/10] Verify command accepts all required flags..."
FLAGS_OK=true
for flag in "--json" "--fix" "--tenant" "--app" "--quiet"; do
    if python manage.py verify_tenant_migrations --help | grep -q "$flag"; then
        echo "  ✓ Flag $flag supported"
    else
        echo "  ✗ Flag $flag NOT supported"
        FLAGS_OK=false
    fi
done

if [ "$FLAGS_OK" = true ]; then
    pass_test "All required flags supported"
else
    fail_test "Some flags missing"
fi
echo ""

# Test 3: Health check includes tenant migration check
echo "[Test 3/10] Verify health check includes tenant migration check..."
if python manage.py health_check --full --json 2>/dev/null | grep -q "tenant_migrations"; then
    pass_test "Health check includes tenant_migrations"
else
    fail_test "Health check missing tenant_migrations check"
fi
echo ""

# Test 4: JSON output is valid
echo "[Test 4/10] Verify JSON output is valid..."
if python manage.py verify_tenant_migrations --json 2>/dev/null | python -m json.tool > /dev/null 2>&1; then
    pass_test "JSON output is valid"
else
    fail_test "JSON output is invalid"
fi
echo ""

# Test 5: Command exits with appropriate codes
echo "[Test 5/10] Verify command exit codes..."
python manage.py verify_tenant_migrations --json > /dev/null 2>&1
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 1 ]; then
    pass_test "Command returns appropriate exit code ($EXIT_CODE)"
else
    fail_test "Command returned unexpected exit code ($EXIT_CODE)"
fi
echo ""

# Test 6: Finance models have defensive error handling
echo "[Test 6/10] Check finance views have error handling..."
if grep -q "OperationalError\|ProgrammingError" finance/template_views.py; then
    pass_test "Finance views have database error handling"
else
    fail_test "Finance views missing error handling"
fi
echo ""

# Test 7: All finance view methods handle errors
echo "[Test 7/10] Verify comprehensive error handling..."
ERROR_HANDLING_OK=true
for method in "FinanceDashboardView" "SubscriptionTemplateView" "SubscriptionStatusPartialView" "SubscriptionPlansPartialView"; do
    if grep -A 50 "class $method" finance/template_views.py | grep -q "except.*Error"; then
        echo "  ✓ $method has error handling"
    else
        echo "  ✗ $method missing error handling"
        ERROR_HANDLING_OK=false
    fi
done

if [ "$ERROR_HANDLING_OK" = true ]; then
    pass_test "All finance views have error handling"
else
    fail_test "Some finance views missing error handling"
fi
echo ""

# Test 8: Migration error context variable is set
echo "[Test 8/10] Verify migration_error context variable..."
if grep -q "migration_error" finance/template_views.py; then
    pass_test "migration_error context variable present"
else
    fail_test "migration_error context variable missing"
fi
echo ""

# Test 9: Subscription template has error UI
echo "[Test 9/10] Verify subscription template has error UI..."
if [ -f "finance/templates/finance/subscription/index.html" ]; then
    if grep -q "migration_error" finance/templates/finance/subscription/index.html; then
        pass_test "Subscription template has migration error UI"
    else
        fail_test "Subscription template missing error UI"
    fi
else
    fail_test "Subscription template not found"
fi
echo ""

# Test 10: Run pytest tests
echo "[Test 10/10] Run pytest migration tests..."
if command -v pytest > /dev/null 2>&1; then
    if pytest tests/test_tenant_migrations.py -v --tb=short -m "not integration and not performance" 2>&1 | tee /tmp/pytest_output.txt; then
        pass_test "Pytest migration tests passed"
    else
        fail_test "Pytest migration tests failed"
        echo "See /tmp/pytest_output.txt for details"
    fi
else
    echo "⚠ pytest not installed, skipping unit tests"
fi
echo ""

# Summary
echo "=== Test Summary ==="
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"
echo "Total Tests:  $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo "✓ All CI migration tests PASSED"
    echo "Finished: $(date)"
    exit $EXIT_SUCCESS
else
    echo "✗ Some CI migration tests FAILED"
    echo "Finished: $(date)"
    exit $EXIT_FAILURE
fi
