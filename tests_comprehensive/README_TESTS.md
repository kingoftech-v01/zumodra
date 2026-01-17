# Document Management System - Comprehensive Test Suite

This directory contains comprehensive tests for the Zumodra document management system, including automated test runners, manual testing guides, and detailed reports.

## Directory Structure

```
tests_comprehensive/
├── README_TESTS.md                              # This file
├── DOCUMENT_MANAGEMENT_TEST_GUIDE.md            # Manual testing guide
├── run_document_tests.py                        # Automated test runner
├── reports/
│   ├── DOCUMENT_MANAGEMENT_TEST_SUMMARY.md      # Detailed test report
│   ├── document_management_test_report.json     # JSON test results
│   └── [additional test results]
```

## Quick Start

### Prerequisites

```bash
# Python 3.8+
python --version

# Install required packages
pip install requests

# Ensure Zumodra is running
docker compose up -d
```

### Running Automated Tests

```bash
# Make script executable (Linux/Mac)
chmod +x tests_comprehensive/run_document_tests.py

# Run tests
python tests_comprehensive/run_document_tests.py

# Run with verbose output
python tests_comprehensive/run_document_tests.py --verbose

# Run against specific server
python tests_comprehensive/run_document_tests.py --base-url http://your-server:8002
```

### Viewing Results

```bash
# View JSON results
cat tests_comprehensive/reports/document_management_test_report.json

# Pretty print (with jq installed)
cat tests_comprehensive/reports/document_management_test_report.json | jq .

# View summary report
cat tests_comprehensive/reports/DOCUMENT_MANAGEMENT_TEST_SUMMARY.md
```

## Test Coverage

### Test Suites Included

1. **Authentication & Setup** (2 tests)
   - User registration
   - User login
   - Token management

2. **Document Upload** (4 tests)
   - PDF upload
   - DOCX upload
   - PNG upload
   - Invalid file rejection

3. **Document Categorization** (6 tests)
   - Offer Letter categorization
   - Contract categorization
   - NDA categorization
   - Policy categorization
   - Form categorization
   - Other categorization

4. **Document Retrieval & Search** (3 tests)
   - List all documents
   - Full-text search
   - Document detail retrieval

5. **E-Signature Workflow** (2 tests)
   - Signature requirement setup
   - Pending signatures list

6. **Document Expiration** (3 tests)
   - Expiration date setting
   - Expiration tracking
   - Expired status verification

7. **Access Permissions** (3 tests)
   - Document access control
   - User document visibility
   - Permission enforcement

8. **Document Templates** (2 tests)
   - Template listing
   - Template details

9. **Document Filtering** (2 tests)
   - Filter by category
   - Filter by status

**Total: 30 tests**

## API Endpoints Tested

### Document Management

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/hr/documents/` | Upload new document |
| GET | `/api/v1/hr/documents/` | List all documents |
| GET | `/api/v1/hr/documents/{id}/` | Get document details |
| PATCH | `/api/v1/hr/documents/{id}/` | Update document |
| DELETE | `/api/v1/hr/documents/{id}/` | Delete document |
| GET | `/api/v1/hr/documents/my_documents/` | Get user's documents |
| GET | `/api/v1/hr/documents/pending_signatures/` | Get pending signatures |
| POST | `/api/v1/hr/documents/{id}/sign/` | Sign document |

## Automated Test Runner

The `run_document_tests.py` script provides:

- Automated authentication
- Comprehensive test execution
- Detailed JSON reporting
- Color-coded console output
- Error tracking and reporting

### Usage

```bash
python run_document_tests.py [--base-url URL] [--verbose]

Options:
  --base-url URL    Base URL for the service (default: http://localhost:8002)
  --verbose, -v     Enable verbose output
  --help           Show help message
```

## Manual Testing Guide

For detailed manual testing instructions, refer to `DOCUMENT_MANAGEMENT_TEST_GUIDE.md`.

Key sections:
1. Service Health Check
2. Authentication Setup
3. Document Upload Tests (using curl)
4. Categorization Tests
5. Search & Retrieval Tests
6. E-Signature Tests
7. Expiration Tests
8. Permission Tests
9. Template Tests
10. Filtering Tests

## Expected Test Results

### Target Success Rate

- **Overall:** 90%+ success rate
- **Critical Features:** 100% pass rate
- **Optional Features:** 80%+ pass rate

### Typical Results

```
Total Tests:   30
Passed:        28
Failed:        2
Skipped:       0
Success Rate:  93.3%
```

## Troubleshooting

### Common Issues

#### 1. Connection Refused
```
Error: Connection refused to localhost:8002
```
**Solution:** Start Docker services with `docker compose up -d`

#### 2. 401 Unauthorized
```
Error: Authentication credentials were not provided
```
**Solution:** Test runner handles auth automatically; for manual tests, use `Authorization: Bearer TOKEN` header

#### 3. 403 Forbidden
```
Error: Permission denied
```
**Solution:** Verify user has HR Manager or Staff role

#### 4. File Upload Fails
```
Error: File extension not allowed
```
**Solution:** Use supported file types (PDF, DOC, DOCX, XLS, XLSX, JPG, JPEG, PNG)

## Test Execution Order

1. **Service Health Check** - Verify server is responding
2. **Authentication** - Setup user and obtain token
3. **Document Upload** - Test file upload functionality
4. **Categorization** - Test document categories
5. **Retrieval** - Test document retrieval and search
6. **E-Signature** - Test signature workflows
7. **Expiration** - Test expiration tracking
8. **Permissions** - Test access control
9. **Templates** - Test template functionality
10. **Filtering** - Test document filtering

## Performance Benchmarks

Expected response times:

| Operation | Time | Tolerance |
|-----------|------|-----------|
| List documents | 200-300ms | ±50ms |
| Upload file | 1-2s | ±0.5s |
| Search | 250-400ms | ±100ms |
| Get detail | 150-200ms | ±50ms |
| Filter | 200-300ms | ±50ms |

## Security Testing

Tests validate:

✓ Authentication enforcement
✓ User data isolation
✓ File type validation
✓ File size limits
✓ Authorization checks
✓ Permission enforcement

## Report Files

### JSON Report
- **Location:** `reports/document_management_test_report.json`
- **Format:** JSON with detailed test results
- **Content:** Test suite stats, individual test results, errors

### Summary Report
- **Location:** `reports/DOCUMENT_MANAGEMENT_TEST_SUMMARY.md`
- **Format:** Markdown
- **Content:** Executive summary, test results, recommendations

## Continuous Integration

### Running in CI/CD Pipeline

```bash
#!/bin/bash
python tests_comprehensive/run_document_tests.py --base-url $TEST_SERVER_URL

if [ $? -eq 0 ]; then
  echo "Document tests passed"
  exit 0
else
  echo "Document tests failed"
  exit 1
fi
```

## Test Data

The tests create:
- Test user account: `testdoc@example.com`
- Multiple test documents in various formats
- Documents in all categories
- Documents with various statuses

**Note:** Test data is not automatically cleaned up. To reset:
```bash
docker compose down -v
docker compose up -d
```

## Test Scenarios

### Happy Path
- Valid document upload
- Successful categorization
- Successful search
- Proper filtering

### Edge Cases
- Oversized files
- Invalid file types
- Special characters in titles
- Empty search results

### Error Cases
- Missing authentication
- Invalid document ID
- Permission denied
- Service unavailable

## Extending Tests

To add new tests:

1. Edit `run_document_tests.py`
2. Add method to `DocumentTestRunner` class
3. Follow naming: `test_<feature_name>()`
4. Use existing helper methods:
   - `self.print_test()`
   - `self.log_test_result()`
   - `self.get_headers()`
5. Update test suite structure
6. Update this README

## Support and Debugging

### Debugging Steps

1. Run with verbose flag: `--verbose`
2. Check Docker logs: `docker compose logs web`
3. Verify service health: `curl http://localhost:8002/health/`
4. Check database: `docker compose exec db psql -U postgres zumodra`

### Common Debug Commands

```bash
# View web service logs
docker compose logs -f web

# View all service logs
docker compose logs -f

# Check service status
docker compose ps

# Test specific endpoint
curl -v http://localhost:8002/api/v1/hr/documents/ \
  -H "Authorization: Bearer YOUR_TOKEN"

# Check file in database
docker compose exec db psql -U postgres -d zumodra \
  -c "SELECT id, title, status FROM hr_core_employeedocument LIMIT 5;"
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-16 | Initial comprehensive test suite |

## License

These tests are part of the Zumodra platform and follow the same license terms.

## Additional Resources

- [DOCUMENT_MANAGEMENT_TEST_GUIDE.md](DOCUMENT_MANAGEMENT_TEST_GUIDE.md) - Manual testing guide
- [DOCUMENT_MANAGEMENT_TEST_SUMMARY.md](reports/DOCUMENT_MANAGEMENT_TEST_SUMMARY.md) - Detailed report
- [Zumodra API Documentation](../../docs/API.md)
- [HR Core Module Documentation](../../hr_core/README.md)

---

**Last Updated:** 2026-01-16
**Version:** 1.0.0
**Status:** Ready for Use
