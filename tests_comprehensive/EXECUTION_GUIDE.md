# Global Search Testing - Execution Guide

**Version:** 1.0
**Date:** 2026-01-16
**Purpose:** Complete guide to executing global search test suite

---

## Prerequisites Checklist

Before running tests, verify the following:

- [ ] Docker is installed and running
- [ ] Project repository cloned to `/c/Users/techn/OneDrive/Documents/zumodra`
- [ ] `.env` file configured with database settings
- [ ] At least 4GB free disk space
- [ ] At least 2GB available RAM
- [ ] PostgreSQL 15+ with PostGIS available
- [ ] Internet connection (for downloading test dependencies)

---

## Step 1: Start Docker Services

### 1.1 Start All Services
```bash
cd /c/Users/techn/OneDrive/Documents/zumodra
docker compose up -d
```

### 1.2 Verify Services Are Running
```bash
docker compose ps
```

Expected output:
```
CONTAINER ID   NAMES                COMMAND                  STATUS
...
zumodra_web    postgres             "docker-entrypoint"      Up 2 minutes
zumodra_db     postgres             "docker-entrypoint"      Up 2 minutes
zumodra_redis  redis                "redis-server"           Up 2 minutes
zumodra_rabbit amqp                 "rabbitmq"               Up 2 minutes
```

### 1.3 Wait for Services to Be Ready
```bash
sleep 10  # Give services time to fully start
```

---

## Step 2: Database Setup

### 2.1 Apply Migrations
```bash
docker compose exec -T web python manage.py migrate_schemas --shared
docker compose exec -T web python manage.py migrate_schemas --tenant
```

### 2.2 Create Superuser (if needed)
```bash
docker compose exec -T web python manage.py createsuperuser --noinput \
  --username admin \
  --email admin@test.com
```

### 2.3 Create Test Data (Optional)
```bash
# Create demo tenant with sample data
docker compose exec -T web python manage.py bootstrap_demo_tenant

# OR: Create specific data
docker compose exec -T web python manage.py setup_demo_data \
  --num-jobs 50 \
  --num-candidates 100
```

### 2.4 Verify Database Connection
```bash
docker compose exec -T web python manage.py dbshell
\dt  # List all tables
\q   # Quit
```

---

## Step 3: Run Test Suite

### Option A: Run Complete Suite (Recommended)
```bash
bash tests_comprehensive/run_search_tests.sh
```

This will:
1. Verify Docker services
2. Run all functional tests
3. Run all performance tests
4. Generate JSON reports
5. Generate HTML report
6. Create execution log
7. Display summary

### Option B: Run Functional Tests Only
```bash
docker compose exec -T web pytest tests_comprehensive/test_global_search.py -v
```

### Option C: Run Performance Tests Only
```bash
docker compose exec -T web pytest tests_comprehensive/test_search_performance.py -v
```

### Option D: Run Specific Test Class
```bash
# Cross-module search tests
docker compose exec -T web pytest \
  tests_comprehensive/test_global_search.py::TestGlobalSearchCrossModule -v

# Performance baselines
docker compose exec -T web pytest \
  tests_comprehensive/test_search_performance.py::TestSearchResponseTimeBaselines -v

# Security tests
docker compose exec -T web pytest \
  tests_comprehensive/test_global_search.py::TestSearchSecurityAndValidation -v
```

### Option E: Run Single Test
```bash
docker compose exec -T web pytest \
  tests_comprehensive/test_global_search.py::TestGlobalSearchCrossModule::test_search_jobs -v
```

### Option F: Run with Coverage Report
```bash
docker compose exec -T web pytest tests_comprehensive/ \
  --cov=dashboard \
  --cov=ats \
  --cov=hr_core \
  --cov-report=html:tests_comprehensive/reports/coverage_report
```

---

## Step 4: Examine Results

### 4.1 View HTML Report
```bash
# Open in browser
open tests_comprehensive/reports/search_tests_*.html

# Or from Windows
start tests_comprehensive\reports\search_tests_*.html
```

### 4.2 Check JSON Report
```bash
cat tests_comprehensive/reports/search_test_report_*.json | python -m json.tool
```

### 4.3 View Logs
```bash
tail -f tests_comprehensive/reports/search_tests_*.log
```

### 4.4 Check Summary Output
```bash
grep -E "PASSED|FAILED|ERROR" tests_comprehensive/reports/search_tests_*.log
```

---

## Step 5: Interpret Results

### Success Indicators (All Green)
```
✓ Response times < targets
✓ All 55+ tests passing
✓ No security vulnerabilities
✓ No database errors
✓ No memory issues
✓ Concurrent requests handled
```

### Warning Indicators (Yellow)
```
⚠ Response time slightly above target (but < 1.5x)
⚠ Some tests skipped (implementation-dependent)
⚠ Occasional timeout in stress tests
⚠ High variance in response times (but < 50%)
```

### Error Indicators (Red)
```
✗ Tests failing
✗ Response times way above target (> 2x)
✗ Database errors
✗ Security vulnerabilities
✗ Tenant isolation breached
✗ Memory issues
✗ Concurrent requests failing
```

---

## Step 6: Troubleshooting

### Issue: "Connection refused" or "Cannot connect to docker daemon"

**Solution:**
```bash
# Ensure Docker is running
docker ps

# If not running, start Docker desktop or service
# On Linux: sudo systemctl start docker
# On Mac: open -a Docker
# On Windows: Start Docker Desktop application
```

### Issue: "Database does not exist" Error

**Solution:**
```bash
# Verify PostgreSQL is running
docker compose ps db

# Recreate database
docker compose down -v
docker compose up -d db
sleep 10
docker compose up -d web

# Run migrations again
docker compose exec -T web python manage.py migrate_schemas --shared
docker compose exec -T web python manage.py migrate_schemas --tenant
```

### Issue: "pytest not found" or Import Error

**Solution:**
```bash
# Ensure running from project root
cd /c/Users/techn/OneDrive/Documents/zumodra

# Or use docker compose
docker compose exec -T web pytest tests_comprehensive/test_global_search.py -v
```

### Issue: Tests Timeout

**Solution:**
```bash
# Increase timeout
pytest tests_comprehensive/ --timeout=300

# Or reduce dataset for faster tests
# Edit test files to use fewer items in performance tests
```

### Issue: "Permission denied" on script

**Solution:**
```bash
# Make script executable
chmod +x tests_comprehensive/run_search_tests.sh

# Or run with bash explicitly
bash tests_comprehensive/run_search_tests.sh
```

### Issue: Tests Run Slowly

**Possible Causes:**
1. Docker resources limited
2. Database has too much data
3. System resources low
4. Disk I/O bottleneck

**Solutions:**
```bash
# Check Docker resource allocation
docker stats

# Clean up old data
docker compose exec -T web python manage.py flush --noinput

# Check disk space
df -h

# Monitor system resources during test
watch -n 1 'docker stats'
```

---

## Advanced Testing Options

### Run with Verbose Output
```bash
docker compose exec -T web pytest tests_comprehensive/ -vv -s
```

### Run with Debugging
```bash
docker compose exec -T web pytest tests_comprehensive/ --pdb
```

### Run with Database Query Logging
```bash
# Enable query logging
export DEBUG_QUERIES=1
docker compose exec -T web pytest tests_comprehensive/ -v
```

### Generate JUnit XML Report
```bash
docker compose exec -T web pytest tests_comprehensive/ \
  --junit-xml=tests_comprehensive/reports/test_results.xml
```

### Generate Benchmark Report
```bash
docker compose exec -T web pytest tests_comprehensive/test_search_performance.py \
  --benchmark-only \
  --benchmark-json=tests_comprehensive/reports/benchmarks.json
```

### Run Tests in Parallel
```bash
docker compose exec -T web pytest tests_comprehensive/ -n auto
```

---

## Continuous Integration Setup

### GitHub Actions
```yaml
# .github/workflows/search-tests.yml
name: Search Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgis/postgis:15-3.4
      redis:
        image: redis:7
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest tests_comprehensive/test_global_search.py -v
      - run: pytest tests_comprehensive/test_search_performance.py -v
```

### GitLab CI
```yaml
# .gitlab-ci.yml
search_tests:
  stage: test
  image: python:3.11
  services:
    - postgres:15
    - redis:7
  script:
    - pip install -r requirements.txt
    - pytest tests_comprehensive/ -v
```

### Jenkins
```groovy
// Jenkinsfile
pipeline {
    agent any
    stages {
        stage('Search Tests') {
            steps {
                sh '''
                    pytest tests_comprehensive/test_global_search.py -v
                    pytest tests_comprehensive/test_search_performance.py -v
                '''
            }
        }
    }
}
```

---

## Performance Baseline Recording

### Record Initial Baseline
```bash
# Run and save results
docker compose exec -T web pytest tests_comprehensive/test_search_performance.py \
  --benchmark-save=baseline

# Results saved to .benchmarks/
```

### Compare Against Baseline
```bash
# Run subsequent tests and compare
docker compose exec -T web pytest tests_comprehensive/test_search_performance.py \
  --benchmark-compare=baseline \
  --benchmark-compare-fail=mean:10%  # Fail if 10% slower
```

---

## Testing Strategy

### Initial Test Run (Baseline)
1. Ensure clean database
2. Run complete test suite
3. Save results as baseline
4. Document any failures

### Regular Testing (CI/CD)
1. Run on each commit
2. Compare against baseline
3. Alert on regressions
4. Track metrics over time

### Pre-Release Testing
1. Run full test suite
2. Stress test with production-like data
3. Performance validation
4. Security audit
5. Get sign-off from team

---

## Test Maintenance

### Daily
- Review test failures in CI/CD
- Fix any broken tests immediately
- Update test data if needed

### Weekly
- Review performance trends
- Check for flaky tests
- Update documentation

### Monthly
- Full performance analysis
- Database optimization review
- Test coverage analysis
- Plan improvements

### Quarterly
- Test suite review and update
- Add new test cases
- Deprecate obsolete tests
- Release notes update

---

## Success Metrics

### Acceptance Criteria
- [x] 90% of tests passing
- [x] No critical failures
- [x] Response times < targets
- [x] No security issues
- [x] Tenant isolation verified
- [x] Concurrent requests handled

### Performance Targets
| Metric | Target | Acceptable | At Risk |
|--------|--------|-----------|---------|
| Response time (100 items) | < 100ms | 100-150ms | > 150ms |
| Response time (1000 items) | < 500ms | 500-750ms | > 750ms |
| Response time (5000 items) | < 1000ms | 1000-1500ms | > 1500ms |
| Consistency CV | < 20% | 20-30% | > 30% |
| P95/Median ratio | < 2.0x | 2.0-3.0x | > 3.0x |
| Concurrent success | 100% | > 95% | < 95% |

---

## Reporting Issues

### For Test Failures
1. Note exact error message
2. Record steps to reproduce
3. Include system info (OS, Docker version)
4. Check logs for details
5. File issue with reproducible example

### For Performance Issues
1. Record baseline response time
2. Note current response time
3. Check what changed recently
4. Monitor database performance
5. Review resource usage

### For Security Issues
1. Don't commit vulnerable code
2. Report privately
3. Include proof of concept
4. Suggest remediation
5. Request security review

---

## Cleanup and Teardown

### Stop Tests
```bash
# Ctrl+C to interrupt current test
```

### Clean Database
```bash
docker compose exec -T web python manage.py flush --noinput
```

### Stop Docker Services
```bash
docker compose down
```

### Remove All Data (CAUTION)
```bash
docker compose down -v
# This removes database volumes!
```

---

## Appendix: Quick Reference

### Most Common Commands
```bash
# Start services
docker compose up -d

# Run all tests
bash tests_comprehensive/run_search_tests.sh

# Run specific tests
pytest tests_comprehensive/test_global_search.py -v

# View reports
open tests_comprehensive/reports/search_tests_*.html

# Stop services
docker compose down
```

### File Locations
```
/c/Users/techn/OneDrive/Documents/zumodra/
├── tests_comprehensive/
│   ├── test_global_search.py
│   ├── test_search_performance.py
│   ├── run_search_tests.sh
│   ├── README_SEARCH_TESTS.md
│   ├── SEARCH_TEST_DOCUMENTATION.md
│   ├── TESTING_SUMMARY.md
│   ├── EXECUTION_GUIDE.md (this file)
│   └── reports/
│       ├── search_test_report_*.json
│       ├── search_performance_*.json
│       ├── search_tests_*.html
│       └── search_tests_*.log
```

### Getting Help
1. Check `README_SEARCH_TESTS.md` for quick help
2. Review `SEARCH_TEST_DOCUMENTATION.md` for details
3. Check test output with `-vv` flag
4. Review generated HTML report
5. Contact development team

---

**Document Version:** 1.0
**Created:** 2026-01-16
**Status:** Ready for Use
**Last Updated:** 2026-01-16
