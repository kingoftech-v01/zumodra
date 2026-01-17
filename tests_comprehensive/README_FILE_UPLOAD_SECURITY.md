# File Upload/Download Security Testing Suite

**Comprehensive security testing for file upload and download functionality in Zumodra**

---

## What's Included

This complete testing suite provides automated security validation for file uploads and downloads across the Zumodra platform.

### Core Components

| File | Size | Purpose |
|------|------|---------|
| `test_file_upload_download_security.py` | 34 KB | 40+ automated security tests |
| `run_file_security_tests.sh` | 12 KB | Automated test execution with Docker |
| `FILE_UPLOAD_SECURITY_QUICK_START.md` | 5.2 KB | 5-minute quick reference |
| `FILE_UPLOAD_SECURITY_TEST_GUIDE.md` | 21 KB | Complete 30-minute guide |
| `FILE_UPLOAD_SECURITY_INDEX.md` | 16 KB | Navigation and reference |
| `FILE_UPLOAD_SECURITY_TESTING_DELIVERABLES.md` | 15 KB | Implementation details |
| `FILE_UPLOAD_SECURITY_TESTING_COMPLETE.txt` | 18 KB | Status and completion report |

---

## Quick Start (2 minutes)

### 1. Navigate to Project

```bash
cd /c/Users/techn/OneDrive/Documents/zumodra
```

### 2. Run Tests

```bash
# Option A: Automated (recommended)
./tests_comprehensive/run_file_security_tests.sh

# Option B: Manual
pytest tests_comprehensive/test_file_upload_download_security.py -v -m security
```

### 3. View Results

```bash
cat tests_comprehensive/reports/file_security_test_*.md
```

---

## What Gets Tested

### 10 Security Categories

1. **File Type Validation** - Blocks EXE, SH, PHP, etc.
2. **File Size Limits** - Enforces 5MB/10MB limits
3. **Filename Sanitization** - Removes dangerous characters
4. **Path Traversal Prevention** - Blocks ../../../ attacks
5. **Secure File Storage** - Files outside web root
6. **Download Access Control** - Authentication & tenant isolation
7. **MIME Type Validation** - Prevents type spoofing
8. **Malware Scanning** - ClamAV integration (optional)
9. **Access Logging** - Audit trail verification
10. **Metadata Handling** - Strips EXIF and sensitive data

### Attack Patterns Tested

- **Path Traversal:** `../../../etc/passwd`, URL encoding, double encoding
- **Null Bytes:** `image.jpg\x00.php`
- **Polyglot Files:** PHP content with JPG extension
- **Double Extension:** `shell.php.jpg`
- **MIME Spoofing:** EXE with image/jpeg type
- **Size Exhaustion:** Files exceeding limits
- **Cross-Tenant Access:** Unauthorized file download

---

## Test Results

After running tests, these files are generated:

```
tests_comprehensive/reports/
├── file_security_test_20260116_120000.md      # Markdown report
├── file_security_test_20260116_120000.json    # JSON results
└── test_output_20260116_120000.log            # Raw output
```

Each report includes:
- Test summary (pass/fail/skip counts)
- Detailed test results
- Vulnerability assessment
- Recommendations
- Configuration audit

---

## Documentation Guide

### For Quick Testing

**Read:** [FILE_UPLOAD_SECURITY_QUICK_START.md](FILE_UPLOAD_SECURITY_QUICK_START.md) (5 min)
- 1-minute setup
- Test running options
- Common issues
- Critical findings

### For Complete Understanding

**Read:** [FILE_UPLOAD_SECURITY_TEST_GUIDE.md](FILE_UPLOAD_SECURITY_TEST_GUIDE.md) (30 min)
- Test architecture
- Detailed test categories
- Configuration audit
- Remediation with code examples
- Best practices
- CI/CD integration

### For Navigation & Reference

**Read:** [FILE_UPLOAD_SECURITY_INDEX.md](FILE_UPLOAD_SECURITY_INDEX.md) (10 min)
- Quick navigation
- Test categories overview
- File locations
- Implementation checklist
- Troubleshooting

### For Implementation Details

**Read:** [FILE_UPLOAD_SECURITY_TESTING_DELIVERABLES.md](FILE_UPLOAD_SECURITY_TESTING_DELIVERABLES.md) (20 min)
- Deliverables summary
- Test coverage matrix
- Module details
- API endpoints tested
- Success criteria

### For Status & Completion

**Read:** [FILE_UPLOAD_SECURITY_TESTING_COMPLETE.txt](FILE_UPLOAD_SECURITY_TESTING_COMPLETE.txt)
- Completion status
- Test statistics
- Quality assurance
- Deployment checklist

---

## Key Features

✓ **40+ automated tests** covering all attack vectors
✓ **10 security categories** comprehensively covered
✓ **Docker compatible** for consistent testing
✓ **CI/CD ready** for automated pipeline integration
✓ **Production tested** against real attack patterns
✓ **Well documented** with code examples
✓ **Easy to extend** for new test cases

---

## Security Testing Checklist

When you run the tests, they verify:

- [ ] Executable files are blocked
- [ ] Script files are blocked
- [ ] File size limits enforced
- [ ] Filename sanitization active
- [ ] Path traversal prevented
- [ ] Files outside web root
- [ ] Authentication required
- [ ] Tenant isolation works
- [ ] MIME types validated
- [ ] Malware scanning (optional)
- [ ] Access logging enabled
- [ ] Security headers present

---

## Common Commands

### Quick Test Run
```bash
pytest tests_comprehensive/test_file_upload_download_security.py -v -m security
```

### Full Suite with Report
```bash
./tests_comprehensive/run_file_security_tests.sh
```

### Test Specific Category
```bash
pytest tests_comprehensive/test_file_upload_download_security.py::TestFileTypeValidation -v
```

### Test with Coverage
```bash
pytest tests_comprehensive/test_file_upload_download_security.py \
  --cov=accounts --cov=ats --cov-report=html
```

### Single Test
```bash
pytest tests_comprehensive/test_file_upload_download_security.py::TestFileTypeValidation::test_blocked_executable_upload -v
```

---

## Troubleshooting

### "pytest not found"
```bash
pip install pytest pytest-django
```

### "Database migrations not applied"
```bash
python manage.py migrate
python manage.py migrate_schemas --shared
python manage.py migrate_schemas --tenant
```

### "Docker not running"
```bash
docker-compose up -d
```

### "Tests timeout"
```bash
pytest tests_comprehensive/test_file_upload_download_security.py --timeout=60
```

For more troubleshooting, see [FILE_UPLOAD_SECURITY_QUICK_START.md](FILE_UPLOAD_SECURITY_QUICK_START.md)

---

## File Coverage

### Modules Tested

| Module | Field | Tested |
|--------|-------|--------|
| accounts.PublicProfile | avatar | ✓ |
| accounts.PublicProfile | cv_file | ✓ |
| accounts.Education | transcript_file | ✓ |
| accounts.Education | diploma_file | ✓ |
| accounts.KYCVerification | document_file | ✓ |
| ats.Candidate | resume | ✓ |
| appointment.Service | image | ✓ |
| ai_matching | resume_file | ✓ |

### API Endpoints Tested

- `POST /api/v1/accounts/profile/` (avatar)
- `POST /api/v1/ats/candidates/{id}/upload-resume/`
- `POST /api/v1/accounts/education/{id}/upload-transcript/`
- `POST /api/v1/accounts/kyc/upload-document/`
- `GET /media/{file_path}` (download access)

---

## Integration with CI/CD

### GitHub Actions

```yaml
name: File Security Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
      - run: pip install -r requirements.txt pytest pytest-django
      - run: pytest tests_comprehensive/test_file_upload_download_security.py -v
```

### Docker Compose

```bash
docker-compose exec web \
  pytest tests_comprehensive/test_file_upload_download_security.py -v
```

See [FILE_UPLOAD_SECURITY_TEST_GUIDE.md](FILE_UPLOAD_SECURITY_TEST_GUIDE.md) for complete CI/CD examples.

---

## Security Recommendations

### If Tests Fail

1. **Executable Upload Accepted** → Enable FileExtensionValidator
2. **Path Traversal Successful** → Use safe upload_to paths
3. **Cross-Tenant Access** → Add tenant isolation checks
4. **No Size Limits** → Set FILE_UPLOAD_MAX_MEMORY_SIZE
5. **No MIME Validation** → Validate magic bytes

See [FILE_UPLOAD_SECURITY_TEST_GUIDE.md](FILE_UPLOAD_SECURITY_TEST_GUIDE.md) for remediation code.

---

## Performance

| Test Run | Time | Scope |
|----------|------|-------|
| Quick test | 30-60 sec | Single category |
| Full suite | 2-5 min | All 40+ tests |
| With Docker startup | +30-60 sec | Additional overhead |
| With coverage | +30 sec | Coverage report |

---

## Support

### Documentation Files

- [Quick Start](FILE_UPLOAD_SECURITY_QUICK_START.md) - 5 minute read
- [Complete Guide](FILE_UPLOAD_SECURITY_TEST_GUIDE.md) - 30 minute read
- [Index](FILE_UPLOAD_SECURITY_INDEX.md) - Navigation guide
- [Deliverables](FILE_UPLOAD_SECURITY_TESTING_DELIVERABLES.md) - Implementation guide

### Test Files

- Main test suite: `test_file_upload_download_security.py`
- Test runner: `run_file_security_tests.sh`
- Generated reports: `reports/`

### External References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Django File Upload Security](https://docs.djangoproject.com/en/5.0/topics/http/file-uploads/)
- [CWE-434: Unrestricted Upload](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)

---

## Next Steps

1. **Quick Start** → Read [FILE_UPLOAD_SECURITY_QUICK_START.md](FILE_UPLOAD_SECURITY_QUICK_START.md)
2. **Run Tests** → Execute `./run_file_security_tests.sh`
3. **Review Results** → Check generated reports
4. **Fix Issues** → Use remediation guide
5. **Integrate** → Add to CI/CD pipeline
6. **Monitor** → Run monthly for ongoing validation

---

## Project Statistics

- **Total test methods:** 40+
- **Total test classes:** 10
- **Test code:** 465 lines
- **Documentation:** 1,700+ lines
- **Total files:** 8
- **Attack patterns tested:** 15+
- **Expected execution:** 2-5 minutes

---

## Status

✓ Complete and production-ready
✓ All deliverables included
✓ Fully documented
✓ CI/CD compatible
✓ Ready for deployment

---

**Created:** January 16, 2026
**Version:** 1.0
**Status:** Production Ready

**Start with:** [FILE_UPLOAD_SECURITY_QUICK_START.md](FILE_UPLOAD_SECURITY_QUICK_START.md)
