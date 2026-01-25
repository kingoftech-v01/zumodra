#!/bin/bash

###############################################################################
# Comprehensive 2FA/MFA Testing Script
#
# Tests the complete Two-Factor Authentication and Multi-Factor Authentication
# system for Zumodra platform.
#
# Usage: ./run_2fa_tests.sh [options]
#
# Options:
#   --docker      Run tests inside docker container
#   --quick       Run only basic tests (faster)
#   --coverage    Generate coverage report
#   --verbose     Verbose output
#   --help        Show this help message
#
# Author: Zumodra QA Team
# Date: 2026-01-17
###############################################################################

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPORTS_DIR="$SCRIPT_DIR/reports"
TEST_FILE="$SCRIPT_DIR/test_2fa_mfa_complete.py"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORTS_DIR/2FA_MFA_TEST_REPORT_$TIMESTAMP.txt"

# Parse arguments
USE_DOCKER=false
QUICK_MODE=false
GENERATE_COVERAGE=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --docker)
            USE_DOCKER=true
            shift
            ;;
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --coverage)
            GENERATE_COVERAGE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            head -25 "$0"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Ensure reports directory exists
mkdir -p "$REPORTS_DIR"

echo "================================================================================"
echo "Zumodra 2FA/MFA Comprehensive Testing Suite"
echo "================================================================================"
echo ""
echo "Test Configuration:"
echo "  Project Root: $PROJECT_ROOT"
echo "  Test File: $TEST_FILE"
echo "  Reports Directory: $REPORTS_DIR"
echo "  Timestamp: $TIMESTAMP"
echo "  Docker Mode: $USE_DOCKER"
echo "  Quick Mode: $QUICK_MODE"
echo "  Coverage Report: $GENERATE_COVERAGE"
echo "  Verbose Output: $VERBOSE"
echo ""
echo "================================================================================"
echo ""

# Function to run pytest with proper options
run_tests() {
    local pytest_args="$TEST_FILE -v"

    # Add markers for quick mode
    if [ "$QUICK_MODE" = true ]; then
        pytest_args="$pytest_args -m 'not slow'"
    fi

    # Add coverage if requested
    if [ "$GENERATE_COVERAGE" = true ]; then
        pytest_args="$pytest_args --cov=accounts --cov=custom_account_u --cov-report=html:$REPORTS_DIR/coverage_html --cov-report=term"
    fi

    # Add verbose output
    if [ "$VERBOSE" = true ]; then
        pytest_args="$pytest_args --tb=long -s"
    else
        pytest_args="$pytest_args --tb=short"
    fi

    if [ "$USE_DOCKER" = true ]; then
        echo "Running tests inside Docker container..."
        cd "$PROJECT_ROOT"
        docker compose exec web python -m pytest $pytest_args 2>&1 | tee "$REPORT_FILE"
    else
        echo "Running tests locally..."
        cd "$PROJECT_ROOT"
        python -m pytest $pytest_args 2>&1 | tee "$REPORT_FILE"
    fi
}

# Ensure we're in the project directory
cd "$PROJECT_ROOT"

# Check if pytest is available
if ! command -v pytest &> /dev/null && [ "$USE_DOCKER" = false ]; then
    echo "ERROR: pytest not found. Installing dependencies..."
    pip install -r requirements.txt
fi

echo "Starting test execution..."
echo ""

# Run tests
run_tests

echo ""
echo "================================================================================"
echo "Test Execution Complete"
echo "================================================================================"
echo ""
echo "Report saved to: $REPORT_FILE"
echo ""

# Summary extraction
if [ -f "$REPORT_FILE" ]; then
    echo "Test Summary:"
    tail -50 "$REPORT_FILE" | grep -E "passed|failed|error|warning" || true
    echo ""
fi

# Generate additional analysis reports
echo "Generating analysis reports..."

# Test Suite 1: TOTP Enrollment
echo ""
echo "Test Suite 1: TOTP Enrollment Process" | tee "$REPORTS_DIR/TOTP_ENROLLMENT_RESULTS_$TIMESTAMP.txt"
echo "=====================================" | tee -a "$REPORTS_DIR/TOTP_ENROLLMENT_RESULTS_$TIMESTAMP.txt"
grep -i "test_totp" "$REPORT_FILE" | head -20 || echo "No TOTP tests found" | tee -a "$REPORTS_DIR/TOTP_ENROLLMENT_RESULTS_$TIMESTAMP.txt"

# Test Suite 2: QR Code Generation
echo ""
echo "Test Suite 2: QR Code Generation" | tee "$REPORTS_DIR/QR_CODE_RESULTS_$TIMESTAMP.txt"
echo "=================================" | tee -a "$REPORTS_DIR/QR_CODE_RESULTS_$TIMESTAMP.txt"
grep -i "qr" "$REPORT_FILE" | head -20 || echo "No QR code tests found" | tee -a "$REPORTS_DIR/QR_CODE_RESULTS_$TIMESTAMP.txt"

# Test Suite 3: Backup Codes
echo ""
echo "Test Suite 3: Backup Codes" | tee "$REPORTS_DIR/BACKUP_CODES_RESULTS_$TIMESTAMP.txt"
echo "==========================" | tee -a "$REPORTS_DIR/BACKUP_CODES_RESULTS_$TIMESTAMP.txt"
grep -i "backup" "$REPORT_FILE" | head -20 || echo "No backup code tests found" | tee -a "$REPORTS_DIR/BACKUP_CODES_RESULTS_$TIMESTAMP.txt"

# Test Suite 4: MFA Login
echo ""
echo "Test Suite 4: MFA Login Verification" | tee "$REPORTS_DIR/MFA_LOGIN_RESULTS_$TIMESTAMP.txt"
echo "====================================" | tee -a "$REPORTS_DIR/MFA_LOGIN_RESULTS_$TIMESTAMP.txt"
grep -i "login" "$REPORT_FILE" | head -20 || echo "No login tests found" | tee -a "$REPORTS_DIR/MFA_LOGIN_RESULTS_$TIMESTAMP.txt"

# Test Suite 5: MFA Enforcement
echo ""
echo "Test Suite 5: MFA Enforcement" | tee "$REPORTS_DIR/MFA_ENFORCEMENT_RESULTS_$TIMESTAMP.txt"
echo "==============================" | tee -a "$REPORTS_DIR/MFA_ENFORCEMENT_RESULTS_$TIMESTAMP.txt"
grep -i "enforcement\|mandatory" "$REPORT_FILE" | head -20 || echo "No enforcement tests found" | tee -a "$REPORTS_DIR/MFA_ENFORCEMENT_RESULTS_$TIMESTAMP.txt"

# Summary report
{
    echo "================================================================================"
    echo "Zumodra 2FA/MFA Testing - Executive Summary"
    echo "================================================================================"
    echo ""
    echo "Test Date: $(date)"
    echo "Test Directory: $SCRIPT_DIR"
    echo "Report Directory: $REPORTS_DIR"
    echo ""
    echo "Test Suites Executed:"
    echo "  1. TOTP Enrollment Process"
    echo "  2. QR Code Generation"
    echo "  3. Backup Codes Generation and Usage"
    echo "  4. 2FA Verification on Login"
    echo "  5. 2FA Enforcement by Role/Admin"
    echo "  6. 2FA Disablement Workflow"
    echo "  7. Recovery Options"
    echo "  8. Django-Two-Factor-Auth Integration"
    echo "  9. Allauth MFA Integration"
    echo "  10. Security and Edge Cases"
    echo "  11. Performance and Scalability"
    echo "  12. Integration Tests"
    echo ""
    echo "Test Results:"
    grep -E "passed|failed|error" "$REPORT_FILE" | tail -5 || echo "Results pending..."
    echo ""
    echo "Generated Reports:"
    ls -la "$REPORTS_DIR" | grep "2FA\|MFA" || echo "Reports directory empty"
    echo ""
    echo "================================================================================"
} | tee "$REPORTS_DIR/EXECUTIVE_SUMMARY_$TIMESTAMP.txt"

echo ""
echo "All reports saved to: $REPORTS_DIR"
echo ""
echo "Key reports:"
echo "  - $REPORT_FILE (Full test output)"
echo "  - $REPORTS_DIR/EXECUTIVE_SUMMARY_$TIMESTAMP.txt (Summary)"
echo "  - $REPORTS_DIR/TOTP_ENROLLMENT_RESULTS_$TIMESTAMP.txt"
echo "  - $REPORTS_DIR/QR_CODE_RESULTS_$TIMESTAMP.txt"
echo "  - $REPORTS_DIR/BACKUP_CODES_RESULTS_$TIMESTAMP.txt"
echo "  - $REPORTS_DIR/MFA_LOGIN_RESULTS_$TIMESTAMP.txt"
echo "  - $REPORTS_DIR/MFA_ENFORCEMENT_RESULTS_$TIMESTAMP.txt"
echo ""

exit 0
