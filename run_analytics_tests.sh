#!/bin/bash
################################################################################
# Analytics and Reporting System Test Runner
################################################################################
# This script runs comprehensive tests for the analytics system
# Usage: bash run_analytics_tests.sh
################################################################################

set -e

echo "================================================================================"
echo "ZUMODRA ANALYTICS AND REPORTING SYSTEM TEST SUITE"
echo "================================================================================"
echo ""

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Function to print section headers
print_header() {
    echo ""
    echo "================================================================================"
    echo "$1"
    echo "================================================================================"
}

# Function to print test status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASSED${NC}: $2"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}✗ FAILED${NC}: $2"
        ((FAILED_TESTS++))
    fi
    ((TOTAL_TESTS++))
}

# Step 1: Environment Check
print_header "Step 1: Environment Check"

echo "Checking Python installation..."
if command -v python &> /dev/null; then
    PYTHON_VERSION=$(python --version)
    echo -e "${GREEN}✓${NC} Python installed: $PYTHON_VERSION"
else
    echo -e "${RED}✗${NC} Python not found"
    exit 1
fi

echo "Checking Django installation..."
if python -c "import django; print(django.VERSION)" 2>/dev/null; then
    DJANGO_VERSION=$(python -c "import django; print(django.VERSION)")
    echo -e "${GREEN}✓${NC} Django installed: $DJANGO_VERSION"
else
    echo -e "${RED}✗${NC} Django not installed"
    exit 1
fi

echo "Checking pytest installation..."
if command -v pytest &> /dev/null; then
    PYTEST_VERSION=$(pytest --version)
    echo -e "${GREEN}✓${NC} Pytest installed: $PYTEST_VERSION"
else
    echo -e "${RED}✗${NC} Pytest not found"
    exit 1
fi

# Step 2: Module Import Test
print_header "Step 2: Module Import Tests"

echo "Testing analytics module imports..."
python -c "from analytics.services import DateRangeFilter, RecruitmentAnalyticsService" && \
    print_status 0 "Analytics services import" || print_status 1 "Analytics services import"

python -c "from analytics.views import RecruitmentDashboardView, ExportReportView" && \
    print_status 0 "Analytics views import" || print_status 1 "Analytics views import"

python -c "from analytics.models import RecruitmentMetric, DiversityMetric" && \
    print_status 0 "Analytics models import" || print_status 1 "Analytics models import"

python -c "from analytics.serializers import RecruitmentDashboardSerializer" && \
    print_status 0 "Analytics serializers import" || print_status 1 "Analytics serializers import"

# Step 3: URL Configuration Test
print_header "Step 3: URL Configuration Tests"

echo "Testing analytics URL configuration..."
python -c "from django.urls import reverse; reverse('analytics:api_recruitment_dashboard')" && \
    print_status 0 "Analytics URL routing" || print_status 1 "Analytics URL routing"

# Step 4: Run Unit Tests
print_header "Step 4: Unit Tests (DateRangeFilter)"

echo "Running DateRangeFilter tests..."
pytest tests/test_analytics_api.py::TestDateRangeFilter -v --tb=short 2>&1 | tee /tmp/analytics_tests.log
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    print_status 0 "DateRangeFilter unit tests"
else
    print_status 1 "DateRangeFilter unit tests"
fi

# Step 5: Run Service Tests
print_header "Step 5: Service Tests"

echo "Running recruitment analytics service tests..."
pytest tests/test_analytics_api.py::TestATSAnalytics -v --tb=short 2>&1 | tee -a /tmp/analytics_tests.log
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    print_status 0 "RecruitmentAnalyticsService tests"
else
    print_status 1 "RecruitmentAnalyticsService tests"
fi

echo "Running HR analytics service tests..."
pytest tests/test_analytics_api.py::TestHRAnalytics -v --tb=short 2>&1 | tee -a /tmp/analytics_tests.log
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    print_status 0 "HRAnalyticsService tests"
else
    print_status 1 "HRAnalyticsService tests"
fi

# Step 6: Run Export Tests
print_header "Step 6: Export Functionality Tests"

echo "Running export tests..."
pytest tests/test_analytics_api.py::TestExportFunctionality -v --tb=short 2>&1 | tee -a /tmp/analytics_tests.log
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    print_status 0 "Export functionality tests"
else
    print_status 1 "Export functionality tests"
fi

# Step 7: Run Date Range Tests
print_header "Step 7: Date Range Filtering Tests"

echo "Running date range filtering tests..."
pytest tests/test_analytics_api.py::TestDateRangeFiltering -v --tb=short 2>&1 | tee -a /tmp/analytics_tests.log
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    print_status 0 "Date range filtering tests"
else
    print_status 1 "Date range filtering tests"
fi

# Step 8: Run All Analytics Tests
print_header "Step 8: Complete Analytics Test Suite"

echo "Running all analytics tests with coverage..."
pytest tests/test_analytics_api.py -v --cov=analytics --cov-report=term-missing --tb=short 2>&1 | tee -a /tmp/analytics_tests.log
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    print_status 0 "Complete analytics test suite"
else
    print_status 1 "Complete analytics test suite"
fi

# Step 9: Functional Tests
print_header "Step 9: Functional Dashboard Tests"

echo "Running dashboard view tests..."
pytest tests/test_analytics_api.py::TestDashboardAnalytics -v --tb=short 2>&1 | tee -a /tmp/analytics_tests.log
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    print_status 0 "Dashboard functional tests"
else
    print_status 1 "Dashboard functional tests"
fi

# Step 10: Endpoint Tests
print_header "Step 10: API Endpoint Tests"

echo "Running analytics endpoints tests..."
pytest tests/test_analytics_api.py::TestAnalyticsEndpoints -v --tb=short 2>&1 | tee -a /tmp/analytics_tests.log
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    print_status 0 "API endpoint tests"
else
    print_status 1 "API endpoint tests"
fi

# Summary
print_header "TEST SUMMARY"

echo ""
echo "Total Tests Run: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Review the logs above.${NC}"
    echo "Full log saved to: /tmp/analytics_tests.log"
    exit 1
fi
