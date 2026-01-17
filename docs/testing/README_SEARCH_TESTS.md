# Global Search Functionality - Comprehensive Test Suite

## Quick Start

### Run All Tests
```bash
bash tests_comprehensive/run_search_tests.sh
```

### Run Specific Tests
```bash
# Functional tests
pytest tests_comprehensive/test_global_search.py -v

# Performance tests
pytest tests_comprehensive/test_search_performance.py -v

# Specific test class
pytest tests_comprehensive/test_global_search.py::TestGlobalSearchCrossModule -v

# Specific test method
pytest tests_comprehensive/test_global_search.py::TestGlobalSearchCrossModule::test_search_jobs -v
```

## Test Files

### 1. `test_global_search.py`
Comprehensive functional tests for search features:
- Cross-module search (jobs, candidates, employees, applications)
- Full-text search accuracy
- Filters and facets
- Result ranking
- Autocomplete/suggestions
- Advanced search operators
- Security (SQL injection, XSS, tenant isolation)
- Result formatting
- Sorting and ordering
- Pagination

**Total Tests:** 40+

### 2. `test_search_performance.py`
Performance and load testing:
- Response time baselines (empty db, 100/1000/5000 items)
- Response time consistency
- Caching effectiveness
- Memory usage analysis
- Concurrency testing (10 and 50 concurrent requests)
- Database performance
- Scalability testing

**Total Tests:** 15+

## Test Coverage

| Category | Tests | Status |
|----------|-------|--------|
| Cross-Module Search | 5 | ✓ |
| Full-Text Search | 6 | ✓ |
| Filters & Facets | 4 | ✓ |
| Result Ranking | 3 | ✓ |
| Performance | 6 | ✓ |
| Autocomplete | 3 | ✓ |
| Advanced Operators | 4 | ✓ |
| Security | 4 | ✓ |
| Result Formatting | 3 | ✓ |
| Sorting & Ordering | 4 | ✓ |
| Pagination | 2 | ✓ |
| Performance Baselines | 4 | ✓ |
| Consistency | 2 | ✓ |
| Caching | 1 | ✓ |
| Memory | 2 | ✓ |
| Concurrency | 2 | ✓ |
| DB Performance | 2 | ✓ |
| Scalability | 1 | ✓ |

## Prerequisites

1. **Docker Services Running**
   ```bash
   docker compose up -d
   ```

2. **Database Ready**
   ```bash
   docker compose exec web python manage.py migrate_schemas
   ```

3. **Test Environment**
   ```bash
   docker compose exec web python manage.py collectstatic --noinput
   ```

## Expected Results

### Performance Targets
```
Dataset Size        Target Response Time
≤ 100 items        < 100ms
100-1000 items     < 500ms
1000-5000 items    < 1000ms
5000+ items        < 2000ms (acceptable)
```

### Functional Tests
- All 40+ tests should pass
- No database errors
- No security vulnerabilities

### Performance Tests
- Response times meet targets
- Consistency coefficient < 30%
- Memory usage reasonable
- Concurrency handled gracefully

## Generated Reports

After running tests, reports are saved to `tests_comprehensive/reports/`:

```
search_test_report_YYYYMMDD_HHMMSS.json      # Detailed test results
search_performance_YYYYMMDD_HHMMSS.json      # Performance metrics
search_tests_YYYYMMDD_HHMMSS.html            # HTML report
search_tests_YYYYMMDD_HHMMSS.log             # Execution log
```

## Understanding the Reports

### JSON Reports
- Detailed test results with pass/fail/skip status
- Performance metrics for each test
- Error messages and stack traces
- Timing information

### HTML Report
- Executive summary
- Test categories and coverage
- Performance metrics dashboard
- Key findings and recommendations
- Improvement suggestions

### Log File
- Raw pytest output
- Database queries (if enabled)
- Print statements and debug info
- Full error traces

## Common Test Scenarios

### Scenario 1: Verify Basic Search Works
```bash
pytest tests_comprehensive/test_global_search.py::TestGlobalSearchCrossModule -v
```
**What it tests:** Search across jobs, candidates, employees, applications

### Scenario 2: Performance Baseline
```bash
pytest tests_comprehensive/test_search_performance.py::TestSearchResponseTimeBaselines -v
```
**What it tests:** Response times with various dataset sizes

### Scenario 3: Security Verification
```bash
pytest tests_comprehensive/test_global_search.py::TestSearchSecurityAndValidation -v
```
**What it tests:** SQL injection, XSS, tenant isolation, permissions

### Scenario 4: Concurrent Load Testing
```bash
pytest tests_comprehensive/test_search_performance.py::TestSearchConcurrency -v
```
**What it tests:** Multiple simultaneous requests

### Scenario 5: Memory Efficiency
```bash
pytest tests_comprehensive/test_search_performance.py::TestSearchMemoryUsage -v
```
**What it tests:** Result limiting and N+1 query prevention

## Debugging Failed Tests

### View Detailed Output
```bash
pytest tests_comprehensive/test_global_search.py -vv -s
```

### Run with Debugging
```bash
pytest tests_comprehensive/test_global_search.py --pdb
```

### Show Database Queries
```bash
pytest tests_comprehensive/test_global_search.py --tb=short -v
```

### Run Single Test
```bash
pytest tests_comprehensive/test_global_search.py::TestGlobalSearchCrossModule::test_search_jobs -v
```

## Performance Metrics Explained

### Response Time
- **Target:** Time from request to response
- **Good:** < 100ms for small datasets
- **Acceptable:** < 500ms for medium datasets
- **Poor:** > 1000ms (needs optimization)

### Consistency (Coefficient of Variation)
- **Target:** < 30%
- **Calculation:** (Standard Deviation / Mean) × 100
- **Good:** < 20% (very consistent)
- **Acceptable:** 20-30% (consistent)
- **Poor:** > 30% (inconsistent)

### P95 Latency
- **Target:** 95th percentile response time
- **Good:** < 3x median response time
- **Indicates:** How bad the worst 5% of requests are

### Memory Usage
- **Target:** < 100MB per search request
- **Metric:** Results limited to 10 per category
- **Indicates:** Memory efficiency with large result sets

### Query Count
- **Target:** Constant regardless of result count
- **Good:** 5-10 queries max
- **Indicates:** No N+1 query problems

## Optimization Tips

### If Tests are Slow

1. **Check database size**
   - May need to clean old data
   - Archive inactive records

2. **Verify indexes exist**
   - Run: `python manage.py sqlsequencereset ats | psql`
   - Or: Check Django indexes are applied

3. **Monitor concurrent connections**
   - May be hitting connection limit
   - Increase pool size if needed

### If Tests are Failing

1. **Check database state**
   - Ensure migrations are complete
   - Verify test data is created

2. **Check service health**
   - Verify Redis is running
   - Verify PostgreSQL is accessible
   - Check RabbitMQ if using Celery

3. **Review recent code changes**
   - Search view may have been modified
   - Database schema may have changed
   - Permissions may have changed

## CI/CD Integration

### GitHub Actions
```yaml
- name: Run Search Tests
  run: |
    pytest tests_comprehensive/test_global_search.py -v
    pytest tests_comprehensive/test_search_performance.py -v
```

### GitLab CI
```yaml
search_tests:
  script:
    - pytest tests_comprehensive/test_global_search.py -v
    - pytest tests_comprehensive/test_search_performance.py -v
```

### Jenkins
```groovy
stage('Search Tests') {
    steps {
        sh 'pytest tests_comprehensive/test_global_search.py -v'
        sh 'pytest tests_comprehensive/test_search_performance.py -v'
    }
}
```

## Advanced Usage

### Run with Coverage
```bash
pytest tests_comprehensive/ \
    --cov=dashboard \
    --cov=ats \
    --cov=hr_core \
    --cov-report=html
```

### Run with Markers
```bash
# Run only integration tests
pytest tests_comprehensive/ -m integration

# Run only security tests
pytest tests_comprehensive/ -k security
```

### Generate JUnit Report
```bash
pytest tests_comprehensive/ \
    --junit-xml=tests_comprehensive/reports/test_results.xml
```

### Generate Coverage Report
```bash
pytest tests_comprehensive/ \
    --cov --cov-report=html:tests_comprehensive/reports/coverage
```

## Troubleshooting

### "Connection refused" Error
```bash
# Ensure Docker services are running
docker compose up -d
docker compose ps
```

### "Database does not exist" Error
```bash
# Create database and run migrations
docker compose exec web python manage.py migrate_schemas --shared
docker compose exec web python manage.py migrate_schemas --tenant
```

### "Import Error" for Test Modules
```bash
# Ensure you're in the project root directory
cd /path/to/zumodra
pytest tests_comprehensive/test_global_search.py -v
```

### Tests Timeout
```bash
# Increase timeout
pytest tests_comprehensive/ --timeout=300
```

### "Permission denied" on run_search_tests.sh
```bash
# Make script executable
chmod +x tests_comprehensive/run_search_tests.sh
```

## Additional Resources

- **Full Documentation:** See `SEARCH_TEST_DOCUMENTATION.md`
- **Test Code:** `test_global_search.py`, `test_search_performance.py`
- **Dashboard Views:** `dashboard/template_views.py`
- **API Viewsets:** `dashboard/api/viewsets.py`

## Support

For issues or questions:

1. Check this README first
2. Review `SEARCH_TEST_DOCUMENTATION.md` for detailed info
3. Look at test output and error messages
4. Contact the development team

## Version History

- **v1.0** (2026-01-16) - Initial comprehensive test suite
  - 40+ functional tests
  - 15+ performance tests
  - Full documentation
  - Automated reporting

---

**Last Updated:** 2026-01-16
**Maintainer:** Zumodra Development Team
**Status:** Active
