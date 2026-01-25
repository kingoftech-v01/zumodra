# Data Export/Import Test Execution Guide

**Quick Reference for Running Export/Import Tests**

## Quick Start Commands

### Run All Tests (Recommended)
```bash
cd /c/Users/techn/OneDrive/Documents/zumodra
./tests_comprehensive/run_data_export_import_tests.sh
```

### Run Specific Test Category
```bash
# CSV Export Tests Only
./tests_comprehensive/run_data_export_import_tests.sh --csv-only

# Excel Export Tests Only
./tests_comprehensive/run_data_export_import_tests.sh --excel-only

# PDF Generation Tests Only
./tests_comprehensive/run_data_export_import_tests.sh --pdf-only

# Import Tests Only
./tests_comprehensive/run_data_export_import_tests.sh --import-only

# Validation Tests Only
./tests_comprehensive/run_data_export_import_tests.sh --validation-only

# Audit Logging Tests Only
./tests_comprehensive/run_data_export_import_tests.sh --audit-only

# Multi-Tenant Isolation Tests Only
./tests_comprehensive/run_data_export_import_tests.sh --isolation-only

# Performance Tests Only
./tests_comprehensive/run_data_export_import_tests.sh --performance
```

### Run with Additional Options
```bash
# Generate coverage report
./tests_comprehensive/run_data_export_import_tests.sh --coverage

# Verbose output
./tests_comprehensive/run_data_export_import_tests.sh --verbose

# Dry run (shows what would be tested)
./tests_comprehensive/run_data_export_import_tests.sh --dry-run

# Use existing services (skip Docker startup)
./tests_comprehensive/run_data_export_import_tests.sh --no-docker

# Run specific test by keyword
./tests_comprehensive/run_data_export_import_tests.sh -k TestCSVExport

# Show help
./tests_comprehensive/run_data_export_import_tests.sh --help
```

### Direct pytest Commands
```bash
# Run all export/import tests
pytest tests_comprehensive/test_data_export_import.py -v

# Run specific test class
pytest tests_comprehensive/test_data_export_import.py::TestCSVExport -v

# Run specific test method
pytest tests_comprehensive/test_data_export_import.py::TestCSVExport::test_csv_candidate_export -v

# Run with coverage
pytest tests_comprehensive/test_data_export_import.py --cov=ats --cov=hr_core --cov=analytics

# Run with HTML report
pytest tests_comprehensive/test_data_export_import.py --html=report.html --self-contained-html

# Run with JUnit XML (for CI/CD)
pytest tests_comprehensive/test_data_export_import.py --junit-xml=results.xml

# Run with markers
pytest tests_comprehensive/test_data_export_import.py -m integration

# Run with keyword filtering
pytest tests_comprehensive/test_data_export_import.py -k "csv or excel"

# Run with parallel execution (if pytest-xdist installed)
pytest tests_comprehensive/test_data_export_import.py -n auto
```

### Quick Test (No Docker Required)
```bash
python tests_comprehensive/quick_export_import_test.py
```

---

## Expected Output Examples

### CSV Export Test
```
✓ PASS: test_csv_candidate_export
  - Created 5 test candidates
  - Exported to CSV format
  - Verified 5 records in output
  - Validated field mapping

✓ PASS: test_csv_job_export
  - Created 3 test jobs
  - Exported to CSV format
  - Verified 3 records in output

✓ PASS: test_csv_export_with_filters
  - Created 10 candidates (5 linkedin, 5 direct)
  - Applied 'linkedin' filter
  - Verified 5 filtered records in output
```

### Import Test
```
✓ PASS: test_import_candidates_csv
  - Created temporary CSV file with 3 records
  - Ran import command
  - Verified 3 candidates created in database
  - Confirmed email addresses match

✓ PASS: test_import_jobs_csv
  - Created temporary CSV file with 3 jobs
  - Ran import command
  - Verified 3 jobs created in database
  - Confirmed job titles match
```

### Validation Test
```
✓ PASS: test_validate_email_uniqueness
  - Created existing candidate with email
  - Attempted duplicate import
  - Verified only 1 candidate exists
  - Duplicate prevention working

✓ PASS: test_validate_required_fields
  - Created CSV with missing required fields
  - Ran import command
  - Verified validation error raised
  - Import properly rejected
```

### Multi-Tenant Test
```
✓ PASS: test_tenant_data_isolation_on_export
  - Created 2 test tenants
  - Added 5 candidates to tenant 1
  - Added 3 candidates to tenant 2
  - Exported from tenant 1 (as user1)
  - Verified only 5 tenant1 candidates in export
  - Cross-tenant data correctly blocked
```

---

## Test Summary Report Format

```
============================================================
Zumodra Data Export & Import Testing Suite
============================================================

Test Results Summary:
- Total Tests: 60
- Passed: 60
- Failed: 0
- Skipped: 0
- Pass Rate: 100.0%

Test Breakdown:
- CSV Export Tests (3/3): ✓ PASS
- Excel Export Tests (2/2): ✓ PASS
- PDF Generation Tests (2/2): ✓ PASS
- Bulk Import Tests (2/2): ✓ PASS
- Import Validation Tests (3/3): ✓ PASS
- Data Integrity Tests (1/1): ✓ PASS
- Audit Logging Tests (2/2): ✓ PASS
- Multi-Tenant Isolation Tests (1/1): ✓ PASS
- Error Handling Tests (4/4): ✓ PASS
- Rate Limiting Tests (2/2): ✓ PASS
- Performance Tests (1/1): ✓ PASS

Coverage Analysis:
- ats module: 75%
- hr_core module: 65%
- analytics module: 60%
- integrations module: 80%
- Overall: 70%

Performance Results:
- CSV export (1000 records): 2.3 seconds ✓
- Excel export (1000 records): 6.8 seconds ✓
- PDF generation: 4.2 seconds ✓
- Bulk import (1000 records): 7.5 seconds ✓
- Large dataset export (1000+ records): 19.8 seconds ✓

Data Integrity Assessment:
- Field preservation: EXCELLENT ✓
- Data type consistency: EXCELLENT ✓
- Relationship preservation: GOOD ✓
- Cross-tenant isolation: EXCELLENT ✓

============================================================
OVERALL RESULT: ALL TESTS PASSED ✓
============================================================

Report saved to: tests_comprehensive/reports/export_import_report_*.html
Coverage report: tests_comprehensive/reports/coverage_export_import_*/
JUnit XML: tests_comprehensive/reports/export_import_junit_*.xml
```

---

## Troubleshooting Common Issues

### Issue: Docker Services Won't Start
```bash
# Check Docker is running
docker ps

# Check docker-compose file exists
ls -la docker-compose.yml

# Try manual startup
docker compose up -d

# Check logs
docker compose logs web

# Rebuild if needed
docker compose down
docker compose build
docker compose up -d
```

### Issue: Database Connection Failed
```bash
# Check PostgreSQL is healthy
docker compose exec db psql -U zumodra -d zumodra -c "SELECT 1"

# Reset migrations
docker compose exec web python manage.py migrate_schemas --shared --reset

# Check database exists
docker compose exec db psql -l | grep zumodra
```

### Issue: Test Data Not Found
```bash
# Verify demo tenant exists
docker compose exec web python manage.py shell -c "from tenants.models import Tenant; print(list(Tenant.objects.all()))"

# Create demo tenant if missing
docker compose exec web python manage.py bootstrap_demo_tenant

# Setup test data
docker compose exec web python manage.py setup_demo_data --num-jobs 10 --num-candidates 50
```

### Issue: Tests Timeout
```bash
# Increase pytest timeout
pytest tests_comprehensive/test_data_export_import.py --timeout=300

# Run single test category instead
./tests_comprehensive/run_data_export_import_tests.sh --csv-only

# Check system resources
docker stats
df -h
```

### Issue: Permission Denied
```bash
# Make scripts executable
chmod +x tests_comprehensive/run_data_export_import_tests.sh
chmod +x tests_comprehensive/quick_export_import_test.py

# Check file permissions
ls -la tests_comprehensive/test_data_export_import.py
```

---

## Test Data Setup

### Create Sample CSV Files for Manual Testing

**Candidates CSV** (save as `candidates.csv`):
```csv
first_name,last_name,email,phone_number,source
John,Doe,john.doe@example.com,555-0001,linkedin
Jane,Smith,jane.smith@example.com,555-0002,direct
Bob,Johnson,bob.johnson@example.com,555-0003,referral
Alice,Williams,alice.williams@example.com,555-0004,indeed
Charlie,Brown,charlie.brown@example.com,555-0005,glassdoor
```

**Jobs CSV** (save as `jobs.csv`):
```csv
title,description,category,status,salary_min,salary_max
Software Engineer,Build amazing software,Engineering,open,80000,120000
DevOps Engineer,Infrastructure and deployment,Engineering,open,90000,130000
Product Manager,Lead product development,Sales,draft,100000,150000
Data Scientist,Analyze complex datasets,Engineering,open,85000,125000
```

### Manual Import Commands
```bash
# Import candidates
python manage.py import_candidates_csv candidates.csv demo --dry-run
python manage.py import_candidates_csv candidates.csv demo

# Import jobs
python manage.py import_jobs_csv jobs.csv demo --dry-run
python manage.py import_jobs_csv jobs.csv demo

# Import with options
python manage.py import_candidates_csv candidates.csv demo --skip-duplicates --batch-size=10

# Update existing
python manage.py import_candidates_csv candidates.csv demo --update-existing
```

---

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Export/Import Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: zumodra
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Start services
        run: |
          docker compose up -d
          sleep 10

      - name: Run export/import tests
        run: |
          ./tests_comprehensive/run_data_export_import_tests.sh --coverage

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml

      - name: Upload test report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-reports
          path: tests_comprehensive/reports/
```

### GitLab CI Example
```yaml
export_import_tests:
  stage: test
  image: python:3.10
  services:
    - postgres:16
  variables:
    POSTGRES_DB: zumodra
    POSTGRES_PASSWORD: postgres
  script:
    - docker-compose up -d
    - sleep 10
    - ./tests_comprehensive/run_data_export_import_tests.sh --coverage
  artifacts:
    paths:
      - tests_comprehensive/reports/
    reports:
      junit: tests_comprehensive/reports/export_import_junit_*.xml
```

---

## Performance Baseline

### Expected Test Execution Times

**Quick Test** (quick_export_import_test.py):
- Total time: 30-60 seconds
- 8 test cases

**Standard Suite** (full test suite):
- Total time: 5-10 minutes
- 60+ test cases
- Includes all categories

**With Coverage**:
- Total time: 10-15 minutes
- Generates coverage report
- More detailed analysis

**With Docker Startup**:
- Add 30-60 seconds for Docker startup
- Add 10-20 seconds for service health checks
- Add 5-10 seconds for test data setup

### Sample Test Run Output
```
============================================================
Zumodra Data Export & Import Testing Suite
============================================================

[*] Checking Docker availability...
[✓] Docker is available

[*] Checking Docker Compose files...
[✓] Docker Compose files found

[*] Starting Docker services...
[✓] Docker services started

[*] Waiting for services to be healthy...
[✓] All services are healthy

[*] Setting up test data...
[✓] Test data setup complete

[*] Running tests: tests_comprehensive/test_data_export_import.py -v

tests_comprehensive/test_data_export_import.py::TestCSVExport::test_csv_candidate_export PASSED
tests_comprehensive/test_data_export_import.py::TestCSVExport::test_csv_job_export PASSED
tests_comprehensive/test_data_export_import.py::TestCSVExport::test_csv_export_with_filters PASSED
... (57 more tests)

============================================================
TEST SUMMARY
============================================================
Total Tests: 60
Passed: 60
Failed: 0
Skipped: 0
Pass Rate: 100.0%
============================================================

Report saved to: tests_comprehensive/reports/export_import_report_20260116_123456.html
JSON results saved to: tests_comprehensive/reports/export_import_results_20260116_123456.json
```

---

## Viewing Test Results

### HTML Report
```bash
# Open in browser
open tests_comprehensive/reports/export_import_report_*.html
# or
xdg-open tests_comprehensive/reports/export_import_report_*.html
```

### Coverage Report
```bash
open tests_comprehensive/reports/coverage_export_import_*/index.html
```

### JSON Results
```bash
# View results
cat tests_comprehensive/reports/export_import_results_*.json

# Parse with jq
jq '.summary' tests_comprehensive/reports/export_import_results_*.json
```

### JUnit XML (for CI/CD)
```bash
# View summary
grep -A 5 "testsuite" tests_comprehensive/reports/export_import_junit_*.xml
```

---

## Advanced Usage

### Run Tests in Parallel
```bash
# Install pytest-xdist
pip install pytest-xdist

# Run with multiple workers
pytest tests_comprehensive/test_data_export_import.py -n auto

# Or specify number of workers
pytest tests_comprehensive/test_data_export_import.py -n 4
```

### Debug Failing Test
```bash
# Run with print output
pytest tests_comprehensive/test_data_export_import.py -s

# Run with verbose output
pytest tests_comprehensive/test_data_export_import.py -vv

# Run with full traceback
pytest tests_comprehensive/test_data_export_import.py --tb=long

# Drop into debugger on failure
pytest tests_comprehensive/test_data_export_import.py --pdb

# Show local variables on failure
pytest tests_comprehensive/test_data_export_import.py -l
```

### Profile Test Performance
```bash
# Run with profiling
pytest tests_comprehensive/test_data_export_import.py --profile

# Generate performance report
pytest tests_comprehensive/test_data_export_import.py --benchmark

# Memory profiling
pytest tests_comprehensive/test_data_export_import.py --memprof
```

---

## Documentation Links

- **Main Test Suite**: `tests_comprehensive/test_data_export_import.py`
- **Test Guide**: `tests_comprehensive/DATA_EXPORT_IMPORT_TEST_GUIDE.md`
- **Summary Report**: `tests_comprehensive/reports/DATA_EXPORT_IMPORT_TESTING_SUMMARY.md`
- **Project Architecture**: `CLAUDE.md`
- **Main README**: `README.md`

---

## Support & Contact

**For issues with tests:**
1. Check test logs in `tests_comprehensive/reports/`
2. Run quick test: `python tests_comprehensive/quick_export_import_test.py`
3. Review test code comments in `test_data_export_import.py`
4. Check Docker service health: `docker compose ps`
5. Review troubleshooting section above

**For feature requests:**
1. Review `DATA_EXPORT_IMPORT_TEST_GUIDE.md` for existing features
2. Check recommendations section in testing summary
3. Verify with project team before implementation

---

**Last Updated**: January 16, 2026
**Version**: 1.0
**Status**: READY FOR USE

