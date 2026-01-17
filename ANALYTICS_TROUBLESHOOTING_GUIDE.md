# Analytics and Reporting System - Troubleshooting Guide

**Last Updated:** 2026-01-16

---

## Table of Contents

1. [Common Issues](#common-issues)
2. [Error Messages](#error-messages)
3. [Performance Issues](#performance-issues)
4. [Export Problems](#export-problems)
5. [Data Issues](#data-issues)
6. [Setup and Configuration](#setup-and-configuration)
7. [Debug Commands](#debug-commands)
8. [Log Analysis](#log-analysis)

---

## Common Issues

### Issue 1: Dashboard Returns 403 Forbidden

**Symptoms:**
- User sees "403 Forbidden" or "Permission Denied" when accessing dashboard
- Error occurs for specific users but not others

**Root Causes:**
- User role doesn't have dashboard permission
- Tenant association missing
- Permission cache not cleared

**Solutions:**

**Option A: Check User Role**
```bash
# SSH into web container
docker compose exec web bash

# Check user role
python manage.py shell
>>> from django.contrib.auth import get_user_model
>>> User = get_user_model()
>>> user = User.objects.get(username='username')
>>> print(user.groups.all())
>>> print(user.is_staff)
>>> print(user.is_superuser)
```

**Option B: Check Tenant Association**
```bash
python manage.py shell
>>> from tenants.models import TenantUser
>>> from django.contrib.auth import get_user_model
>>> User = get_user_model()
>>> user = User.objects.get(username='username')
>>> tenant_users = TenantUser.objects.filter(user=user)
>>> print(list(tenant_users))
```

**Option C: Clear Permission Cache**
```bash
# Clear Redis cache
docker compose exec redis redis-cli FLUSHDB

# Or from Django
python manage.py shell
>>> from django.core.cache import cache
>>> cache.clear()
```

**Option D: Grant Analytics Permission**
```bash
python manage.py shell
>>> from django.contrib.auth.models import Permission, Group
>>> from django.contrib.auth import get_user_model
>>> User = get_user_model()
>>> user = User.objects.get(username='username')
>>> # Add to appropriate group
>>> group = Group.objects.get(name='Recruiter')  # or 'HR Manager'
>>> user.groups.add(group)
>>> user.save()
```

---

### Issue 2: Dashboard Shows No Data

**Symptoms:**
- Dashboard loads but all metrics show 0
- Quick stats are empty
- Charts show no data

**Root Causes:**
- No data exists in the system
- Data filters applied (date range too narrow)
- Database connection issue
- Model migrations not run

**Solutions:**

**Option A: Verify Data Exists**
```bash
# Check if there are jobs, applications, etc.
python manage.py shell
>>> from ats.models import JobPosting, Application, Candidate
>>> print(f"Jobs: {JobPosting.objects.count()}")
>>> print(f"Applications: {Application.objects.count()}")
>>> print(f"Candidates: {Candidate.objects.count()}")
```

**Option B: Seed Demo Data**
```bash
# Create demo tenant with sample data
docker compose exec web python manage.py bootstrap_demo_tenant

# Or add more data
docker compose exec web python manage.py setup_demo_data \
    --num-jobs 20 \
    --num-candidates 100
```

**Option C: Check Date Range**
```bash
# On dashboard, ensure date range is appropriate
# For new system with today's data, use "Last 30 Days"
# For testing, use "Last Year"
```

**Option D: Verify Migrations**
```bash
# Check if all migrations are applied
docker compose exec web python manage.py showmigrations analytics

# Run migrations if needed
docker compose exec web python manage.py migrate_schemas --shared
docker compose exec web python manage.py migrate_schemas --tenant
```

---

### Issue 3: Charts Not Rendering

**Symptoms:**
- Chart areas are blank or show errors
- Console shows JavaScript errors
- Charts render briefly then disappear

**Root Causes:**
- Chart.js library not loaded
- Data format incorrect for chart library
- JavaScript error preventing rendering
- CSS not applied

**Solutions:**

**Option A: Verify Chart.js Loaded**
```
1. Open browser DevTools (F12)
2. Go to Console tab
3. Type: console.log(typeof Chart)
4. Should return: "function" (if loaded correctly)
5. If undefined, Chart.js is not loaded
```

**Option B: Check Static Files**
```bash
# Collect static files
docker compose exec web python manage.py collectstatic --noinput

# Verify Chart.js exists
ls -la staticfiles/assets/js/vendor/ | grep -i chart
```

**Option C: Debug Chart Data**
```
1. Open browser DevTools
2. Go to Network tab
3. Look for API request (e.g., /api/funnel/)
4. Click on response
5. Verify JSON structure includes labels and datasets
```

**Option D: Check for JavaScript Errors**
```
1. Open browser DevTools
2. Console tab
3. Look for red error messages
4. Common errors:
   - "Chart is not defined" - Chart.js not loaded
   - "Cannot read property 'getContext'" - DOM element issue
   - "data is not iterable" - Data format incorrect
```

**Option E: Clear Browser Cache**
```
1. Press Ctrl+Shift+Delete (Windows) or Cmd+Shift+Delete (Mac)
2. Clear cache/cookies
3. Reload page
```

---

### Issue 4: Export Takes Too Long or Times Out

**Symptoms:**
- Export starts but never completes
- Browser shows timeout error
- Server logs show long-running process

**Root Causes:**
- Large dataset being exported
- Server resources exhausted
- Export format (PDF) requires chart rendering
- Database query slow

**Solutions:**

**Option A: Reduce Export Scope**
```
- Apply narrower date range (e.g., 1 month instead of 1 year)
- Export specific report type instead of full dashboard
- Export CSV instead of PDF (faster)
```

**Option B: Check Server Resources**
```bash
# Check CPU/Memory usage
docker stats

# Expected:
# - CPU: < 80%
# - Memory: < 80% of container limit
```

**Option C: Increase Timeout**
```python
# In settings.py or settings_security.py
# Increase timeout for export views
REQUEST_TIMEOUT = 120  # 2 minutes
```

**Option D: Optimize Database Queries**
```bash
# Enable query logging
python manage.py shell
>>> from django.conf import settings
>>> settings.DEBUG = True
>>> from django.db import connection, reset_queries
>>> reset_queries()
>>> # Run your analytics query
>>> from analytics.services import ReportingService
>>> service = ReportingService()
>>> report = service.generate_recruiting_report()
>>> for query in connection.queries:
...     print(query['time'], query['sql'])
```

**Option E: Export Smaller Chunks**
```
- Use API to export specific metrics one at a time
- Combine results manually
- Or wait for async export feature (if available)
```

---

### Issue 5: Export File is Corrupted or Won't Open

**Symptoms:**
- Export file downloads but cannot open
- Excel says "file is corrupted"
- PDF reader cannot open file
- CSV appears to be text instead of data

**Root Causes:**
- File not fully downloaded
- Incorrect Content-Type header
- Export service failed silently
- Browser or app interpretation issue

**Solutions:**

**Option A: Verify File Downloaded Completely**
```
1. Check file size - should be > 1KB
2. If file is exactly 0 bytes or very small, export failed
3. Check browser console for errors during download
```

**Option B: Check File Type**
```bash
# On Linux/Mac
file ~/Downloads/report.xlsx
file ~/Downloads/report.pdf
file ~/Downloads/report.csv

# Should show:
# - xlsx: Microsoft Excel 2007+ Workbook
# - pdf: PDF document
# - csv: ASCII text
```

**Option C: Try Different Export Format**
```
- If Excel doesn't work, try CSV
- If PDF doesn't work, try Excel
- CSV is most reliable (plain text)
```

**Option D: Manually Check Export Endpoint**
```bash
# Test CSV export via curl
curl -X POST http://localhost:8002/api/v1/analytics/export/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format":"csv","report_type":"recruitment"}' \
  -o export.csv

# Check if content looks reasonable
head export.csv
```

**Option E: Check Server Logs**
```bash
# Look for export-related errors
docker compose logs web | grep -i "export\|error" | tail -20
```

---

## Error Messages

### Error: "ImportError: No module named 'analytics'"

**Cause:** Analytics app not in INSTALLED_APPS

**Solution:**
```python
# In settings.py
INSTALLED_APPS = [
    # ...
    'analytics',
    # ...
]
```

---

### Error: "ModuleNotFoundError: No module named 'reportlab'"

**Cause:** ReportLab library not installed for PDF generation

**Solution:**
```bash
# Install reportlab
pip install reportlab

# Or update requirements
pip install -r requirements.txt

# Update Docker image
docker compose build web
```

---

### Error: "OperationalError: no such table: analytics_recruitment_metric"

**Cause:** Analytics migrations not run

**Solution:**
```bash
# Run migrations
docker compose exec web python manage.py migrate_schemas --shared
docker compose exec web python manage.py migrate_schemas --tenant

# Verify
docker compose exec web python manage.py showmigrations analytics
```

---

### Error: "ValueError: time data does not match format '%Y-%m-%d'"

**Cause:** Date parameter in wrong format

**Solution:**
```
- Use format: YYYY-MM-DD
- Example: 2024-01-15 (correct)
- Not: 01/15/2024 (wrong)
- Not: 2024-1-15 (wrong - needs zero-padding)
```

---

### Error: "IntegrityError: duplicate key value violates unique constraint"

**Cause:** Duplicate metric records

**Solution:**
```bash
# Clean up duplicates
python manage.py shell
>>> from analytics.models import RecruitmentMetric
>>> # Remove duplicates, keeping most recent
>>> duplicates = RecruitmentMetric.objects.values('tenant', 'period_type', 'period_start').annotate(count=Count('id')).filter(count__gt=1)
>>> for dup in duplicates:
...     metric = RecruitmentMetric.objects.filter(
...         tenant=dup['tenant'],
...         period_type=dup['period_type'],
...         period_start=dup['period_start']
...     ).order_by('-created_at')
...     # Delete all except the first
...     metric[1:].delete()
```

---

## Performance Issues

### Issue: Dashboard Loads Slowly

**Diagnosis:**

```bash
# Check server response time
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8002/dashboard/

# Monitor server resources during load
docker stats zumodra_web

# Check database queries
docker compose logs web | grep -i "slow query"
```

**Solutions:**

1. **Enable Caching:**
```python
# settings.py
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://redis:6379/0',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Use cache in analytics
ANALYTICS_CACHE_TTL = 3600  # 1 hour
```

2. **Optimize Queries:**
```python
# In analytics/services.py
# Use select_related for foreign keys
# Use prefetch_related for reverse relations
# Limit queryset size

from django.db.models import Prefetch
jobs = JobPosting.objects.select_related('tenant').prefetch_related(
    Prefetch('applications_set', queryset=Application.objects.filter(status='hired'))
)
```

3. **Index Database:**
```bash
# Run index migrations
docker compose exec web python manage.py migrate

# Manually check indexes
docker compose exec db psql -U postgres -d zumodra -c "
  SELECT * FROM pg_indexes
  WHERE tablename LIKE 'analytics%'
  OR tablename LIKE 'ats%';"
```

4. **Add Celery Task for Background Calculation:**
```python
# Create periodic task to pre-calculate metrics
from celery import shared_task

@shared_task
def refresh_analytics_cache():
    from analytics.services import DashboardDataService
    service = DashboardDataService()
    service.refresh_cache(dashboard_type='all')
    return 'Cache refreshed'
```

---

### Issue: High Memory Usage During Export

**Diagnosis:**

```bash
# Monitor memory during export
docker stats zumodra_web

# Check process memory
docker compose exec web ps aux | grep python
```

**Solutions:**

1. **Stream CSV Export:**
```python
# Use generator instead of loading all data at once
def export_csv_stream(queryset, fields):
    for obj in queryset.iterator(chunk_size=1000):
        yield [getattr(obj, field) for field in fields]
```

2. **Paginate Large Exports:**
```python
# Export in pages
page_size = 1000
total = queryset.count()
for page_num in range(0, total, page_size):
    start = page_num
    end = page_num + page_size
    page_data = queryset[start:end]
    # Process page
```

3. **Increase Server Resources:**
```yaml
# docker-compose.yml
web:
  deploy:
    resources:
      limits:
        memory: 2G  # Increase from 1G
```

---

## Export Problems

### Issue: CSV Export Has Encoding Issues

**Symptoms:**
- Special characters display as garbled text
- Excel shows encoding warning

**Solution:**

```python
# Ensure UTF-8 encoding
response = HttpResponse(
    content_type='text/csv; charset=utf-8'
)
response['Content-Disposition'] = 'attachment; filename="export.csv"'

# Add BOM for Excel compatibility
response.write('\ufeff')  # UTF-8 BOM

# Then write CSV content
writer = csv.writer(response)
```

---

### Issue: PDF Export Missing Charts

**Symptoms:**
- PDF generated but charts are blank
- Export completes but no visualizations

**Solution:**

```bash
# Verify Chart.js rendering library is available
# Try using alternative libraries

pip install weasyprint  # For HTML to PDF conversion
# or
pip install pdfkit  # For wkhtmltopdf

# In settings:
PDF_RENDER_BACKEND = 'weasyprint'  # or 'wkhtmltopdf'
```

---

## Data Issues

### Issue: Metrics Don't Match Actual Data

**Diagnosis:**

```bash
# Compare calculated vs actual
python manage.py shell
>>> from ats.models import JobPosting
>>> from analytics.models import RecruitmentMetric
>>>
>>> # Actual jobs
>>> actual_jobs = JobPosting.objects.filter(status='open').count()
>>> print(f"Actual open jobs: {actual_jobs}")
>>>
>>> # Calculated metric
>>> metric = RecruitmentMetric.objects.latest('created_at')
>>> print(f"Metric open jobs: {metric.open_jobs}")
>>>
>>> # If different, recalculate
>>> if actual_jobs != metric.open_jobs:
...     from analytics.services import RecruitmentAnalyticsService
...     service = RecruitmentAnalyticsService()
...     new_metric = service.calculate_recruitment_metric()
...     print(f"Recalculated: {new_metric.open_jobs}")
```

**Solutions:**

1. **Force Recalculation:**
```bash
python manage.py shell
>>> from analytics.services import DashboardDataService
>>> service = DashboardDataService()
>>> service.refresh_cache(dashboard_type='all')
```

2. **Delete Stale Metrics:**
```bash
python manage.py shell
>>> from analytics.models import RecruitmentMetric
>>> from datetime import datetime, timedelta
>>>
>>> # Delete metrics older than 7 days
>>> cutoff = datetime.now() - timedelta(days=7)
>>> RecruitmentMetric.objects.filter(created_at__lt=cutoff).delete()
```

---

### Issue: Diversity Metrics Show Incorrect Counts

**Symptoms:**
- Diversity percentages don't add up to 100%
- Counts are suppressed for all categories

**Cause:** Anonymization threshold too high

**Solution:**

```python
# In analytics/services.py
class DiversityAnalyticsService:
    MIN_COUNT_FOR_DISCLOSURE = 5  # Anonymize counts < 5

    # Increase threshold if needed
    MIN_COUNT_FOR_DISCLOSURE = 1  # Show all counts (less private)
```

---

## Setup and Configuration

### Initial Setup Checklist

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set environment variables
export DEBUG=True
export ANALYTICS_CACHE_TTL=3600

# 3. Run migrations
python manage.py migrate_schemas --shared
python manage.py migrate_schemas --tenant

# 4. Create demo data
python manage.py bootstrap_demo_tenant
python manage.py setup_demo_data --num-jobs 20 --num-candidates 100

# 5. Collect static files
python manage.py collectstatic --noinput

# 6. Create admin user (if needed)
python manage.py createsuperuser

# 7. Start server
python manage.py runserver 0.0.0.0:8000
```

---

### Configuration Options

```python
# settings.py

# Analytics Settings
ANALYTICS_CACHE_TTL = 3600  # Cache time in seconds
ANALYTICS_USE_REDIS = True  # Use Redis for caching
ANALYTICS_DB_CACHE_FALLBACK = True  # Use DB if Redis unavailable
ANALYTICS_PAGINATION_SIZE = 20  # Items per page
ANALYTICS_EXPORT_MAX_SIZE = 50000000  # Max export file (50MB)

# Export Settings
PDF_RENDER_BACKEND = 'reportlab'  # or 'weasyprint'
EXCEL_MAX_COLUMNS = 100
EXCEL_MAX_ROWS = 1000000

# Diversity Analytics
DIVERSITY_MIN_COUNT = 5  # Minimum count before anonymization
DIVERSITY_ANONYMIZE = True  # Enable anonymization
```

---

## Debug Commands

### View All Analytics Data

```bash
python manage.py shell
>>> from analytics.models import *
>>>
>>> # Recruitment metrics
>>> RecruitmentMetric.objects.count()
>>> RecruitmentMetric.objects.latest('created_at')
>>>
>>> # Diversity metrics
>>> DiversityMetric.objects.count()
>>>
>>> # HR metrics
>>> EmployeeRetentionMetric.objects.count()
```

---

### Clear All Cache

```bash
python manage.py shell
>>> from django.core.cache import cache
>>> cache.clear()
>>> print("Cache cleared")

# Or via Redis
docker compose exec redis redis-cli FLUSHDB
```

---

### Regenerate All Metrics

```bash
python manage.py shell
>>> from analytics.services import (
...     RecruitmentAnalyticsService,
...     HRAnalyticsService,
...     DashboardDataService
... )
>>>
>>> # Recruitment
>>> rec_service = RecruitmentAnalyticsService()
>>> rec_metric = rec_service.calculate_recruitment_metric()
>>> print(f"Created recruitment metric: {rec_metric.id}")
>>>
>>> # Dashboard
>>> dash_service = DashboardDataService()
>>> dash_service.refresh_cache(dashboard_type='all')
>>> print("Dashboard cache refreshed")
```

---

### Monitor Metrics Calculation

```bash
# Watch logs while calculating
docker compose logs -f web | grep analytics

# In another terminal, trigger calculation
docker compose exec web python manage.py shell
>>> from analytics.tasks import refresh_all_metrics
>>> refresh_all_metrics.apply()
```

---

## Log Analysis

### Common Log Patterns

```bash
# Find errors
docker compose logs web | grep -i error

# Find warnings
docker compose logs web | grep -i warning

# Find analytics-specific logs
docker compose logs web | grep -i analytics

# Follow logs in real-time
docker compose logs -f web
```

---

### Analyzing Performance Logs

```bash
# Find slow queries
docker compose logs db | grep "duration:"

# Find timeout errors
docker compose logs web | grep -i timeout

# Monitor request times
docker compose logs web | grep "completed in"
```

---

### Enabling Debug Logging

```python
# settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': 'logs/analytics.log',
        },
    },
    'loggers': {
        'analytics': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
        },
    },
}
```

---

## Support and Resources

### Documentation
- `/analytics/README.md` - Analytics module overview
- `/dashboard/README.md` - Dashboard module overview
- `CLAUDE.md` - Project guidelines and conventions

### Related Commands

```bash
# Run analytics tests
pytest tests/test_analytics_api.py -v

# Check system health
python manage.py health_check --full

# Database statistics
docker compose exec db psql -U postgres -d zumodra \
  -c "SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) FROM pg_tables WHERE schemaname='public' ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC LIMIT 10;"

# Check cache status
docker compose exec redis redis-cli INFO stats
```

---

## Quick Reference

| Issue | Command |
|-------|---------|
| Clear cache | `docker compose exec redis redis-cli FLUSHDB` |
| Reload migrations | `docker compose exec web python manage.py migrate_schemas --tenant` |
| Seed demo data | `docker compose exec web python manage.py bootstrap_demo_tenant` |
| View logs | `docker compose logs web` |
| Run shell | `docker compose exec web python manage.py shell` |
| Force rebuild | `docker compose build --no-cache web` |

---

**End of Troubleshooting Guide**
