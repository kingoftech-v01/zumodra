#!/bin/bash

# Server API Testing Script
# Tests all critical API endpoints on zumodra.rhematek-solutions.com

SERVER_URL="https://zumodra.rhematek-solutions.com"
LOCALHOST_URL="http://localhost:8002"

# Use server URL by default, can override with LOCAL=1 ./test_server_api.sh
BASE_URL="${LOCAL:+$LOCALHOST_URL}"
BASE_URL="${BASE_URL:-$SERVER_URL}"

echo "========================================="
echo "Zumodra API Testing Script"
echo "========================================="
echo "Testing against: $BASE_URL"
echo "Date: $(date)"
echo ""

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0

# Function to test an endpoint
test_endpoint() {
    local name="$1"
    local endpoint="$2"
    local expected_status="$3"
    local auth_required="${4:-no}"

    echo -n "Testing $name... "

    if [ "$auth_required" = "yes" ]; then
        # Test without auth (should fail)
        response=$(curl -s -w "\n%{http_code}" "$BASE_URL$endpoint")
        status_code=$(echo "$response" | tail -n1)

        if [ "$status_code" = "401" ] || [ "$status_code" = "403" ]; then
            echo -e "${GREEN}PASS${NC} (correctly requires auth - $status_code)"
            ((PASSED++))
        else
            echo -e "${RED}FAIL${NC} (expected 401/403, got $status_code)"
            ((FAILED++))
        fi
    else
        # Test public endpoint
        response=$(curl -s -w "\n%{http_code}" "$BASE_URL$endpoint")
        status_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | sed '$d')

        if [ "$status_code" = "$expected_status" ]; then
            echo -e "${GREEN}PASS${NC} (status: $status_code)"
            ((PASSED++))
        else
            echo -e "${RED}FAIL${NC} (expected $expected_status, got $status_code)"
            echo "Response: $body" | head -c 200
            echo ""
            ((FAILED++))
        fi
    fi
}

echo "========================================="
echo "1. Health Check Endpoints"
echo "========================================="
test_endpoint "Health Check" "/health/" "200"
test_endpoint "Readiness Check" "/health/ready/" "200"
test_endpoint "Liveness Check" "/health/live/" "200"
echo ""

echo "========================================="
echo "2. Public API Endpoints (No Auth)"
echo "========================================="
test_endpoint "API Root" "/api/" "200"
test_endpoint "Careers API - Job List" "/api/v1/careers/jobs/" "200"
test_endpoint "Careers API - Page Config" "/api/v1/careers/page/" "200"
echo ""

echo "========================================="
echo "3. Authenticated API Endpoints"
echo "========================================="
test_endpoint "ATS Jobs API" "/api/v1/ats/jobs/" "401" "yes"
test_endpoint "HR Employees API" "/api/v1/hr/employees/" "401" "yes"
test_endpoint "Finance API" "/api/v1/finance/dashboard/" "401" "yes"
test_endpoint "Analytics API" "/api/v1/analytics/overview/" "401" "yes"
echo ""

echo "========================================="
echo "4. Public Pages (200 OK)"
echo "========================================="
test_endpoint "Homepage" "/" "200"
test_endpoint "About Page" "/about/" "200"
test_endpoint "Careers Landing" "/careers/" "200"
test_endpoint "Contact Page" "/contact/" "200"
test_endpoint "Pricing Page" "/pricing/" "200"
test_endpoint "Signup Type Selection" "/user/signup/choose/" "200"
echo ""

echo "========================================="
echo "5. Auth Pages (200 OK)"
echo "========================================="
test_endpoint "Login Page" "/accounts/login/" "200"
test_endpoint "Signup Page" "/accounts/signup/" "200"
echo ""

echo "========================================="
echo "Test Summary"
echo "========================================="
TOTAL=$((PASSED + FAILED))
echo "Total Tests: $TOTAL"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "\n${RED}✗ SOME TESTS FAILED${NC}"
    exit 1
fi
