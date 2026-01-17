# Document Management System Testing - Complete Instructions

## Overview

This document provides complete step-by-step instructions for testing the document management system on the Zumodra platform.

## What's Included

This test suite provides:

1. **Automated Test Runner** - Python script for comprehensive API testing
2. **Manual Testing Guide** - Step-by-step curl-based testing
3. **Test Reports** - Detailed JSON and markdown reports
4. **Documentation** - Complete API and feature documentation

## Getting Started

### Step 1: Prepare Environment

```bash
# Navigate to project directory
cd /root/zumodra
# or on Windows
cd C:\Users\techn\OneDrive\Documents\zumodra

# Verify Python is installed
python3 --version

# Install test dependencies
pip install requests

# Verify Docker is running
docker --version
docker compose --version
```

### Step 2: Start Zumodra Services

```bash
# Start all services
docker compose up -d

# Wait for services to be healthy (2-3 minutes)
# Check status
docker compose ps

# Verify service health
curl -v http://localhost:8002/health/
```

### Step 3: Choose Testing Method

#### Option A: Automated Testing (Recommended)

```bash
# Run the automated test suite
python tests_comprehensive/run_document_tests.py

# For verbose output
python tests_comprehensive/run_document_tests.py --verbose

# For custom server
python tests_comprehensive/run_document_tests.py --base-url http://your-server:8002
```

#### Option B: Manual Testing

```bash
# Follow the detailed guide
# Reference: tests_comprehensive/DOCUMENT_MANAGEMENT_TEST_GUIDE.md

# Use curl to test each endpoint
curl -X GET http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Test Execution Steps

### Complete Automated Test Flow

```bash
# 1. Start services
docker compose up -d

# 2. Wait for health check (optional)
sleep 10

# 3. Run tests
python tests_comprehensive/run_document_tests.py --verbose

# 4. View results
cat tests_comprehensive/reports/document_management_test_report.json | python -m json.tool

# 5. Check detailed report
cat tests_comprehensive/reports/DOCUMENT_MANAGEMENT_TEST_SUMMARY.md
```

### Expected Output

```
================================================================================
                 Document Management System - Comprehensive Test Suite
================================================================================

Checking service health at http://localhost:8002...
✓ Service is healthy

================================================================================
                            Authentication Setup
================================================================================

Attempting login...
✓ Login: PASS
✓ Post-Registration Login: PASS

================================================================================
                            Test Suite 1: Document Upload
================================================================================

✓ PDF Upload: PASS
✓ DOCX Upload: PASS
✓ PNG Upload: PASS
✓ Invalid File Rejection: PASS

================================================================================
                      Test Suite 2: Document Categorization
================================================================================

✓ Document Categorization: PASS

[... additional test suites ...]

================================================================================
                         Test Execution Summary
================================================================================

Total Tests:   30
Passed:        28
Failed:        2
Skipped:       0
Success Rate:  93.3%

Test Suites:
  upload                20.0/4 passed (100%)
  categorization        6/6 passed (100%)
  retrieval             3/3 passed (100%)
  esignature            2/2 passed (100%)
  expiration            3/3 passed (100%)
  permissions           3/3 passed (100%)
  templates             2/2 passed (100%)
  filtering             2/2 passed (100%)

Report saved to: tests_comprehensive/reports/document_management_test_report.json
```

## Detailed Test Breakdown

### Test Suite 1: Document Upload (4 tests)

**What it tests:**
- Upload PDF documents
- Upload DOCX documents
- Upload PNG images
- Rejection of invalid file types

**Success Criteria:**
- All supported formats accepted
- Invalid formats rejected
- File size limit enforced
- Metadata stored correctly

**If tests fail:**
- Check file upload endpoint: `/api/v1/hr/documents/`
- Verify file size limit is 10MB
- Check allowed file types in code
- Review upload error messages

### Test Suite 2: Document Categorization (6 tests)

**What it tests:**
- Documents can be categorized
- All 6 categories work (Offer Letter, Contract, NDA, Policy, Form, Other)
- Categories are properly stored and retrievable

**Success Criteria:**
- Each category accepts documents
- Category metadata is preserved
- Categories can be queried and filtered

**If tests fail:**
- Check DocumentTemplate.DocumentCategory choices
- Verify category field in EmployeeDocument model
- Test category filtering

### Test Suite 3: Document Retrieval & Search (3 tests)

**What it tests:**
- List all documents
- Search by title
- Get document details

**Success Criteria:**
- List endpoint returns paginated results
- Search finds documents by partial title match
- Detail endpoint shows all metadata including file URL

**If tests fail:**
- Check list endpoint: `/api/v1/hr/documents/`
- Verify search parameter: `?search=term`
- Check document detail view includes file URL

### Test Suite 4: E-Signature Workflow (2 tests)

**What it tests:**
- Documents can be flagged for signature
- Pending signatures are tracked

**Success Criteria:**
- `requires_signature` flag can be set
- Documents default to `pending_signature` status
- Pending signatures endpoint works

**If tests fail:**
- Check if `requires_signature` field exists
- Verify DocumentStatus choices include `pending_signature`
- Check pending_signatures endpoint implementation

### Test Suite 5: Document Expiration (3 tests)

**What it tests:**
- Expiration dates can be set
- Expiration tracking works
- Expired status is tracked

**Success Criteria:**
- Dates are stored in ISO 8601 format
- Expiration field is optional
- Expired documents are properly identified

**If tests fail:**
- Check expires_at field in EmployeeDocument
- Verify date format handling
- Check expiration status logic

### Test Suite 6: Access Permissions (3 tests)

**What it tests:**
- Users can only access their own documents
- Document owner verification works
- User-specific document endpoint works

**Success Criteria:**
- Authenticated users can access their documents
- Users cannot access other users' documents
- `my_documents` endpoint returns only user's documents

**If tests fail:**
- Check authentication requirement
- Verify permission checking in views
- Test employee field is filtered by user

### Test Suite 7: Document Templates (2 tests)

**What it tests:**
- Template listing works
- Template details are retrievable

**Success Criteria:**
- Templates endpoint returns template list
- Individual templates can be retrieved
- Template metadata is complete

**If tests fail:**
- Check template endpoint implementation
- Verify DocumentTemplate model exists
- Check template serializer

### Test Suite 8: Document Filtering (2 tests)

**What it tests:**
- Filtering by category works
- Filtering by status works

**Success Criteria:**
- Query parameter filtering works
- Multiple filters can be combined
- Results match filter criteria

**If tests fail:**
- Check filter implementation in viewset
- Verify filter backend configuration
- Test query parameter parsing

## Interpreting Results

### Success
When all tests pass (or mostly pass), you'll see:

```
Success Rate: 93.3%
[GREEN] Test Suite X: PASS
```

This indicates the document management system is working properly.

### Partial Success
When some tests fail, check:

1. Which test failed?
2. What's the error message?
3. Does the feature exist in code?
4. Is there a recent change that broke it?

### Complete Failure
If most tests fail:

1. Is the server running? `docker compose ps`
2. Is the database healthy? Check Docker logs
3. Are migrations applied? Check database
4. Are services responding? `curl http://localhost:8002/health/`

## Troubleshooting

### Common Issues and Solutions

#### Issue: "Connection refused"
```
Error: ConnectionError: Connection refused to localhost:8002
```

**Solution:**
```bash
# Check if services are running
docker compose ps

# Start services if not running
docker compose up -d

# Wait for web service to be healthy
sleep 30
docker compose ps
```

#### Issue: "Authentication failed"
```
Error: Login failed with status 401
```

**Solution:**
```bash
# Check if auth endpoint exists
curl http://localhost:8002/auth/login/

# Check if user can register
curl -X POST http://localhost:8002/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!",
    "password2": "TestPassword123!",
    "full_name": "Test User"
  }'
```

#### Issue: "404 Not Found on endpoint"
```
Error: HTTP 404 GET /api/v1/hr/documents/
```

**Solution:**
```bash
# Check URL routing
docker compose exec web python manage.py show_urls | grep document

# Verify HR app is installed
docker compose exec web python manage.py shell
>>> from django.apps import apps
>>> apps.is_installed('hr_core')
```

#### Issue: "File upload fails"
```
Error: File extension not allowed
```

**Solution:**
```bash
# Verify allowed extensions in model
docker compose exec web grep -n "allowed_extensions" hr_core/models.py

# Check max file size setting
docker compose exec web grep -n "FILE_UPLOAD_MAX" zumodra/settings.py
```

#### Issue: "Timeout errors"
```
Error: ReadTimeout: Service took too long to respond
```

**Solution:**
```bash
# Check service logs
docker compose logs web

# Check resource usage
docker compose stats

# Restart services
docker compose restart web
docker compose logs -f web
```

## Manual Testing via curl

If automated tests fail, test manually:

```bash
# 1. Get authentication token
TOKEN=$(curl -s -X POST http://localhost:8002/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testdoc@example.com",
    "password": "TestDocPassword123!"
  }' | python -c "import sys, json; print(json.load(sys.stdin).get('token', ''))")

echo "Token: $TOKEN"

# 2. Test document list
curl http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/json" | python -m json.tool

# 3. Test document upload
curl -X POST http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@sample.pdf" \
  -F "title=Test Document" \
  -F "category=form" | python -m json.tool

# 4. Check for errors in response
# Look for "status_code", "error", or "detail" fields
```

## Viewing Detailed Results

### JSON Report

```bash
# Pretty print the JSON report
cat tests_comprehensive/reports/document_management_test_report.json | python -m json.tool

# Count passing tests
cat tests_comprehensive/reports/document_management_test_report.json | \
  python -c "import sys, json; data=json.load(sys.stdin); print(f\"Passed: {data['passed']}/{data['total_tests']}\")"

# List all errors
cat tests_comprehensive/reports/document_management_test_report.json | \
  python -c "import sys, json; data=json.load(sys.stdin); [print(e) for e in data.get('errors', [])]"
```

### Markdown Report

```bash
# View the summary report
cat tests_comprehensive/reports/DOCUMENT_MANAGEMENT_TEST_SUMMARY.md

# View specific section
grep -A 20 "Test Suite 1" tests_comprehensive/reports/DOCUMENT_MANAGEMENT_TEST_SUMMARY.md
```

## Post-Testing Steps

### 1. Document Results

Save test results:
```bash
# Copy reports
cp tests_comprehensive/reports/document_management_test_report.json \
   reports/document_management_$(date +%Y%m%d_%H%M%S).json

# Create summary
echo "## Test Results - $(date)" > TESTING_RESULTS.md
cat tests_comprehensive/reports/DOCUMENT_MANAGEMENT_TEST_SUMMARY.md >> TESTING_RESULTS.md
```

### 2. Fix Any Issues

If tests failed:
```bash
# Review error details
python -m json.tool tests_comprehensive/reports/document_management_test_report.json

# Check logs for more details
docker compose logs web | grep -i error | head -20

# Fix issues and re-run tests
python tests_comprehensive/run_document_tests.py
```

### 3. Document Findings

Create a findings document:
```bash
cat > TESTING_FINDINGS.md << EOF
# Document Management System - Test Findings

## Date: $(date)
## Environment: Development
## Status: [PASS/FAIL]

### Summary
[Summary of findings]

### Issues Found
[List of issues]

### Recommendations
[List of recommendations]
EOF
```

## Reference Files

All test files are located in `tests_comprehensive/`:

| File | Purpose |
|------|---------|
| `run_document_tests.py` | Automated test runner |
| `test_document_management_comprehensive.py` | Full test suite source |
| `DOCUMENT_MANAGEMENT_TEST_GUIDE.md` | Manual testing guide |
| `README_TESTS.md` | Test suite documentation |
| `reports/DOCUMENT_MANAGEMENT_TEST_SUMMARY.md` | Detailed test report |
| `reports/document_management_test_report.json` | JSON test results |

## Schedules and Maintenance

### Weekly Testing
```bash
# Schedule weekly tests
0 8 * * 1 cd /root/zumodra && python tests_comprehensive/run_document_tests.py
```

### Before Production Deployments
```bash
# Always run full test suite before deploying
python tests_comprehensive/run_document_tests.py --verbose
```

### Monthly Report
```bash
# Generate monthly report
python tests_comprehensive/run_document_tests.py && \
cp tests_comprehensive/reports/document_management_test_report.json \
   reports/monthly/document_management_$(date +%Y-%m).json
```

## Support

### Getting Help

1. **Review Documentation**
   - Check `DOCUMENT_MANAGEMENT_TEST_GUIDE.md` for step-by-step instructions
   - Review `README_TESTS.md` for API details
   - Check `DOCUMENT_MANAGEMENT_TEST_SUMMARY.md` for known issues

2. **Check Logs**
   ```bash
   docker compose logs web | tail -100
   docker compose logs db | tail -50
   ```

3. **Test Specific Endpoint**
   ```bash
   curl -v http://localhost:8002/api/v1/hr/documents/ \
     -H "Authorization: Bearer TOKEN"
   ```

4. **Run Tests with Debug Info**
   ```bash
   python tests_comprehensive/run_document_tests.py --verbose
   ```

## Conclusion

This comprehensive test suite validates:

✓ Document upload functionality
✓ File type and size validation
✓ Document categorization
✓ Search and retrieval
✓ E-signature workflow
✓ Expiration tracking
✓ Access control
✓ Document templates
✓ Filtering and sorting

**Target Success Rate:** 90%+

**Expected Time:** 2-5 minutes for full test run

---

**Document Version:** 1.0
**Last Updated:** 2026-01-16
**Status:** Ready for Production Testing
