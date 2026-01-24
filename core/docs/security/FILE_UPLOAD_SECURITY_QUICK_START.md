# File Upload/Download Security Testing - Quick Start Guide

**Quick Reference for running file upload security tests**

---

## 1-Minute Setup

```bash
# Navigate to project
cd /c/Users/techn/OneDrive/Documents/zumodra

# Ensure Docker is running
docker-compose ps

# If services not running, start them
docker-compose up -d
```

## Run Tests (2 ways)

### Option A: Quick Test Run

```bash
# Run all security tests
pytest tests_comprehensive/test_file_upload_download_security.py -v -m security

# Run specific category
pytest tests_comprehensive/test_file_upload_download_security.py::TestFileTypeValidation -v

# Get summary
pytest tests_comprehensive/test_file_upload_download_security.py --tb=short -q
```

### Option B: Full Suite with Report

```bash
# Make script executable (once)
chmod +x tests_comprehensive/run_file_security_tests.sh

# Run complete suite
./tests_comprehensive/run_file_security_tests.sh

# Check results
ls -la tests_comprehensive/reports/
cat tests_comprehensive/reports/file_security_test_*.md
```

## What Gets Tested

| Test Category | Coverage | Status |
|---|---|---|
| **File Type Validation** | EXE, SH, PHP rejection; PNG/PDF acceptance | ✓ |
| **File Size Limits** | 5MB images, 10MB documents | ✓ |
| **Filename Sanitization** | Path traversal, null bytes, special chars | ✓ |
| **Path Traversal Prevention** | ../ escapes, encoded traversal | ✓ |
| **Access Control** | Authentication, tenant isolation | ✓ |
| **MIME Type Validation** | Magic bytes, type spoofing | ✓ |
| **Malware Scanning** | ClamAV config check (if enabled) | ✓ |
| **Security Headers** | X-Content-Type-Options, etc. | ✓ |

## Key Test Files

```
Test Suite:      test_file_upload_download_security.py (450+ lines)
Runner Script:   run_file_security_tests.sh
Full Guide:      FILE_UPLOAD_SECURITY_TEST_GUIDE.md
This Quick Start: FILE_UPLOAD_SECURITY_QUICK_START.md
```

## Common Issues & Fixes

### Issue: "Docker daemon is not running"

```bash
# Start Docker (or Docker Desktop on Mac/Windows)
docker-compose up -d

# Verify
docker ps
```

### Issue: "ModuleNotFoundError: No module named 'pytest_django'"

```bash
pip install pytest-django pytest-cov
```

### Issue: "Database migrations not applied"

```bash
python manage.py migrate
python manage.py migrate_schemas --shared
python manage.py migrate_schemas --tenant
```

### Issue: Tests timeout or hang

```bash
# Run with shorter timeout
pytest tests_comprehensive/test_file_upload_download_security.py --timeout=30

# Or skip slow tests
pytest tests_comprehensive/test_file_upload_download_security.py -m "not slow"
```

## Test Results Interpretation

### ✓ PASSED
Security control is working correctly. No action needed.

### ✗ FAILED
Vulnerability found. Review the error message and remediation section in the guide.

### ⊘ SKIPPED
Test not applicable to this environment (e.g., ClamAV not installed).

## Critical Findings

If any of these tests fail, treat as **HIGH PRIORITY**:

1. **TestFileTypeValidation::test_blocked_executable_upload FAILED**
   - Executable files can be uploaded
   - Risk: Remote code execution
   - Fix: Enable FileExtensionValidator

2. **TestPathTraversalPrevention::test_directory_traversal_upload FAILED**
   - Path traversal attack possible
   - Risk: Write to sensitive directories
   - Fix: Use Django's upload_to with safe path handling

3. **TestDownloadAccessControl::test_cross_tenant_download_blocked FAILED**
   - Cross-tenant file access possible
   - Risk: Data breach
   - Fix: Add tenant isolation checks

4. **TestFileSizeValidation::test_avatar_size_exceeds_limit FAILED**
   - Oversized files accepted
   - Risk: Storage exhaustion, DoS
   - Fix: Set FILE_UPLOAD_MAX_MEMORY_SIZE

## Next Steps

1. **Run the tests** using one of the methods above
2. **Review failed tests** in the generated reports
3. **Check the remediation guide** for fixes
4. **Implement fixes** in the code
5. **Re-run tests** to verify
6. **Document findings** for compliance

## File Locations

- **Test Code**: `/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/test_file_upload_download_security.py`
- **Test Reports**: `/c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive/reports/`
- **Django Settings**: `/c/Users/techn/OneDrive/Documents/zumodra/zumodra/settings.py`
- **Models**: `/c/Users/techn/OneDrive/Documents/zumodra/accounts/models.py`, `/jobs/models.py`

## Supported File Types by Module

| Module | Field | Allowed Types | Max Size |
|--------|-------|---|---|
| Accounts | avatar | PNG, JPG, GIF, WebP | 5 MB |
| Accounts | cv_file | PDF, DOC, DOCX, TXT, RTF | 10 MB |
| Accounts | transcript_file | PDF, DOC, DOCX | 10 MB |
| ATS | resume | PDF, DOC, DOCX, TXT, RTF | 10 MB |
| KYC | document_file | PDF, JPG, PNG | 50 MB |

## Performance Notes

- **Quick run**: 30-60 seconds
- **Full suite**: 2-5 minutes
- **With Docker startup**: 30-60 seconds additional

## Contact & Support

For issues or questions:
1. Check the full guide: `FILE_UPLOAD_SECURITY_TEST_GUIDE.md`
2. Review test source code: `test_file_upload_download_security.py`
3. Check logs: `tests_comprehensive/reports/test_output_*.log`

---

**Last Updated:** 2026-01-16
**Test Suite Version:** 1.0
**Status:** Production Ready
