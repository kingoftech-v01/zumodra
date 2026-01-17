#!/bin/bash

# Comprehensive RBAC Testing Script
# Tests the complete RBAC system for Zumodra
# Generated: 2026-01-16

set -e

PROJECT_DIR="/c/Users/techn/OneDrive/Documents/zumodra"
REPORT_DIR="${PROJECT_DIR}/tests_comprehensive/reports"
LOG_FILE="${REPORT_DIR}/rbac_test_execution.log"
SUMMARY_FILE="${REPORT_DIR}/rbac_test_summary.md"

# Create report directory
mkdir -p "${REPORT_DIR}"

# Initialize log
echo "========================================" > "$LOG_FILE"
echo "RBAC Testing Execution Report" >> "$LOG_FILE"
echo "Generated: $(date)" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Initialize summary
cat > "$SUMMARY_FILE" << 'EOF'
# RBAC Comprehensive Testing Report
Generated: 2026-01-16

## Test Categories

1. Role Creation and Assignment
2. Permission Enforcement on Views
3. Permission Enforcement on API Endpoints
4. Object-Level Permissions
5. Department-Based Access Control
6. Tenant Isolation Between Companies
7. Admin vs Regular User Permissions
8. RBAC Integration Tests

## Test Execution

EOF

echo "Starting comprehensive RBAC tests..." | tee -a "$LOG_FILE"

# Test 1: Role Creation and Assignment
echo "" | tee -a "$LOG_FILE"
echo "TEST 1: Role Creation and Assignment" | tee -a "$LOG_FILE"
echo "=====================================" | tee -a "$LOG_FILE"
cd "$PROJECT_DIR"
python -m pytest tests_comprehensive/test_rbac_complete.py::RoleCreationAndAssignmentTests -v --tb=short 2>&1 | tee -a "$LOG_FILE"
TEST1_RESULT=$?
echo "Test 1 Result: $TEST1_RESULT" >> "$LOG_FILE"

# Test 2: Permission Enforcement on Views
echo "" | tee -a "$LOG_FILE"
echo "TEST 2: Permission Enforcement on Views" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
python -m pytest tests_comprehensive/test_rbac_complete.py::PermissionEnforcementOnViewsTests -v --tb=short 2>&1 | tee -a "$LOG_FILE"
TEST2_RESULT=$?
echo "Test 2 Result: $TEST2_RESULT" >> "$LOG_FILE"

# Test 3: Permission Enforcement on API Endpoints
echo "" | tee -a "$LOG_FILE"
echo "TEST 3: Permission Enforcement on API Endpoints" | tee -a "$LOG_FILE"
echo "===============================================" | tee -a "$LOG_FILE"
python -m pytest tests_comprehensive/test_rbac_complete.py::PermissionEnforcementOnAPITests -v --tb=short 2>&1 | tee -a "$LOG_FILE"
TEST3_RESULT=$?
echo "Test 3 Result: $TEST3_RESULT" >> "$LOG_FILE"

# Test 4: Object-Level Permissions
echo "" | tee -a "$LOG_FILE"
echo "TEST 4: Object-Level Permissions" | tee -a "$LOG_FILE"
echo "=================================" | tee -a "$LOG_FILE"
python -m pytest tests_comprehensive/test_rbac_complete.py::ObjectLevelPermissionTests -v --tb=short 2>&1 | tee -a "$LOG_FILE"
TEST4_RESULT=$?
echo "Test 4 Result: $TEST4_RESULT" >> "$LOG_FILE"

# Test 5: Department-Based Access Control
echo "" | tee -a "$LOG_FILE"
echo "TEST 5: Department-Based Access Control" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
python -m pytest tests_comprehensive/test_rbac_complete.py::DepartmentBasedAccessControlTests -v --tb=short 2>&1 | tee -a "$LOG_FILE"
TEST5_RESULT=$?
echo "Test 5 Result: $TEST5_RESULT" >> "$LOG_FILE"

# Test 6: Tenant Isolation
echo "" | tee -a "$LOG_FILE"
echo "TEST 6: Tenant Isolation Between Companies" | tee -a "$LOG_FILE"
echo "==========================================" | tee -a "$LOG_FILE"
python -m pytest tests_comprehensive/test_rbac_complete.py::TenantIsolationTests -v --tb=short 2>&1 | tee -a "$LOG_FILE"
TEST6_RESULT=$?
echo "Test 6 Result: $TEST6_RESULT" >> "$LOG_FILE"

# Test 7: Admin vs Regular User Permissions
echo "" | tee -a "$LOG_FILE"
echo "TEST 7: Admin vs Regular User Permissions" | tee -a "$LOG_FILE"
echo "=========================================" | tee -a "$LOG_FILE"
python -m pytest tests_comprehensive/test_rbac_complete.py::AdminVsRegularUserPermissionsTests -v --tb=short 2>&1 | tee -a "$LOG_FILE"
TEST7_RESULT=$?
echo "Test 7 Result: $TEST7_RESULT" >> "$LOG_FILE"

# Test 8: RBAC Integration Tests
echo "" | tee -a "$LOG_FILE"
echo "TEST 8: RBAC Integration Tests" | tee -a "$LOG_FILE"
echo "==============================" | tee -a "$LOG_FILE"
python -m pytest tests_comprehensive/test_rbac_complete.py::RBACIntegrationTests -v --tb=short 2>&1 | tee -a "$LOG_FILE"
TEST8_RESULT=$?
echo "Test 8 Result: $TEST8_RESULT" >> "$LOG_FILE"

# Run all tests with coverage
echo "" | tee -a "$LOG_FILE"
echo "RUNNING ALL TESTS WITH COVERAGE" | tee -a "$LOG_FILE"
echo "================================" | tee -a "$LOG_FILE"
python -m pytest tests_comprehensive/test_rbac_complete.py -v --cov=accounts --cov=tenants --cov-report=html:${REPORT_DIR}/coverage --cov-report=term 2>&1 | tee -a "$LOG_FILE"
COVERAGE_RESULT=$?

# Summarize results
echo "" | tee -a "$LOG_FILE"
echo "SUMMARY" | tee -a "$LOG_FILE"
echo "=======" | tee -a "$LOG_FILE"
echo "Test 1 (Roles): $TEST1_RESULT" | tee -a "$LOG_FILE"
echo "Test 2 (Views): $TEST2_RESULT" | tee -a "$LOG_FILE"
echo "Test 3 (API): $TEST3_RESULT" | tee -a "$LOG_FILE"
echo "Test 4 (Object Level): $TEST4_RESULT" | tee -a "$LOG_FILE"
echo "Test 5 (Department): $TEST5_RESULT" | tee -a "$LOG_FILE"
echo "Test 6 (Tenant Isolation): $TEST6_RESULT" | tee -a "$LOG_FILE"
echo "Test 7 (Admin vs Regular): $TEST7_RESULT" | tee -a "$LOG_FILE"
echo "Test 8 (Integration): $TEST8_RESULT" | tee -a "$LOG_FILE"

# Update summary file
cat >> "$SUMMARY_FILE" << EOF

### Test Results

#### Test 1: Role Creation and Assignment
- Status: $([ $TEST1_RESULT -eq 0 ] && echo "PASSED" || echo "FAILED")
- Result Code: $TEST1_RESULT

#### Test 2: Permission Enforcement on Views
- Status: $([ $TEST2_RESULT -eq 0 ] && echo "PASSED" || echo "FAILED")
- Result Code: $TEST2_RESULT

#### Test 3: Permission Enforcement on API Endpoints
- Status: $([ $TEST3_RESULT -eq 0 ] && echo "PASSED" || echo "FAILED")
- Result Code: $TEST3_RESULT

#### Test 4: Object-Level Permissions
- Status: $([ $TEST4_RESULT -eq 0 ] && echo "PASSED" || echo "FAILED")
- Result Code: $TEST4_RESULT

#### Test 5: Department-Based Access Control
- Status: $([ $TEST5_RESULT -eq 0 ] && echo "PASSED" || echo "FAILED")
- Result Code: $TEST5_RESULT

#### Test 6: Tenant Isolation Between Companies
- Status: $([ $TEST6_RESULT -eq 0 ] && echo "PASSED" || echo "FAILED")
- Result Code: $TEST6_RESULT

#### Test 7: Admin vs Regular User Permissions
- Status: $([ $TEST7_RESULT -eq 0 ] && echo "PASSED" || echo "FAILED")
- Result Code: $TEST7_RESULT

#### Test 8: RBAC Integration Tests
- Status: $([ $TEST8_RESULT -eq 0 ] && echo "PASSED" || echo "FAILED")
- Result Code: $TEST8_RESULT

## Execution Log

See execution log for detailed output: \`rbac_test_execution.log\`

## Coverage Report

HTML coverage report generated at: \`coverage/index.html\`

EOF

echo "" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"
echo "Testing Complete!" | tee -a "$LOG_FILE"
echo "Report saved to: $REPORT_DIR" | tee -a "$LOG_FILE"
echo "========================================" | tee -a "$LOG_FILE"

# Copy execution log to summary
cp "$LOG_FILE" "${REPORT_DIR}/rbac_test_execution_detailed.log"

echo "Test execution complete!"
echo "Results saved to: $REPORT_DIR"
echo "Summary: $SUMMARY_FILE"
