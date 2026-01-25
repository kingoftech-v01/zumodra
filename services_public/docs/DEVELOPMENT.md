# Development Guide - Services Public

This guide provides detailed instructions for developing, testing, and maintaining the services_public app.

## Table of Contents

- [Setup](#setup)
- [Architecture](#architecture)
- [Development Workflow](#development-workflow)
- [Database Migrations](#database-migrations)
- [Testing](#testing)
- [Debugging](#debugging)
- [Common Tasks](#common-tasks)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Setup

### Prerequisites

- Python 3.10+
- PostgreSQL 14+ with PostGIS extension
- Redis 6+ (for Celery and Channels)
- Node.js 16+ (for frontend assets, optional)

### Installation

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install PostGIS extension:**
   ```bash
   psql -U postgres -d zumodra
   CREATE EXTENSION IF NOT EXISTS postgis;
   ```

3. **Run database migrations:**
   ```bash
   # Public schema (shared)
   python manage.py migrate_schemas --shared

   # All tenant schemas
   python manage.py migrate_schemas
   ```

4. **Create test data (optional):**
   ```bash
   python manage.py create_test_services
   ```

5. **Start Celery worker:**
   ```bash
   celery -A zumodra worker -l info
   ```

6. **Start Celery beat (for scheduled tasks):**
   ```bash
   celery -A zumodra beat -l info
   ```

7. **Start Channels/Daphne (for WebSocket):**
   ```bash
   daphne -b 0.0.0.0 -p 8001 zumodra.asgi:application
   ```

8. **Start Django development server:**
   ```bash
   python manage.py runserver
   ```

### Environment Variables

Required environment variables:

```bash
# Database
DATABASE_URL=postgres://user:pass@localhost/zumodra

# Redis (Celery + Channels)
REDIS_URL=redis://localhost:6379/0

# Channels
CHANNEL_LAYERS_BACKEND=channels_redis.core.RedisChannelLayer

# Security
SECRET_KEY=your-secret-key
DEBUG=True

# PostGIS (optional, auto-detected)
POSTGIS_VERSION=3.2
```

## Architecture

### Multi-Tenant Design

```
┌─────────────────────────────────────────────┐
│            Public Schema                    │
│  ┌───────────────────────────────────────┐  │
│  │  PublicService (denormalized catalog) │  │
│  │  - PublicServiceImage                 │  │
│  │  - PublicServicePricingTier           │  │
│  │  - PublicServicePortfolio             │  │
│  │  - PublicServiceReview                │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
                    ▲
                    │ Celery sync
                    │
┌─────────────────────────────────────────────┐
│         Tenant Schema (tenant1)             │
│  ┌───────────────────────────────────────┐  │
│  │  Service (source of truth)            │  │
│  │  - ServiceImage                       │  │
│  │  - ServicePricingTier                 │  │
│  │  - ProviderPortfolio                  │  │
│  │  - ServiceReview                      │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

### Data Flow

1. **Create/Update Service in Tenant Schema**
   - User creates/updates service with `is_public=True`
   - Django `post_save` signal fires

2. **Signal Handler**
   - Check schema context (prevent circular signals)
   - Validate sync conditions
   - Queue Celery task

3. **Celery Task**
   - Switch to tenant schema
   - Fetch service + related data
   - Validate sync conditions
   - Switch to public schema
   - Create/update PublicService
   - Sync related models

4. **WebSocket Broadcast**
   - Notify connected clients of updates
   - Send updated data to map/list views

### Sync Conditions

A service is synced to the public catalog only if ALL conditions are met:

```python
# In ServicePublicSyncService.sync_conditions
[
    lambda s: s.is_public is True,              # Service marked public
    lambda s: s.is_active is True,              # Service active
    lambda s: s.provider is not None,           # Has provider
    lambda s: s.provider.marketplace_enabled is True,  # Provider enabled
    lambda s: s.provider.is_active is True,     # Provider active
    lambda s: s.provider.user.is_active is True # User active
]
```

## Development Workflow

### Making Changes

1. **Models**: Edit `services_public/models.py` or `services/models.py`
2. **Create Migration**: `python manage.py makemigrations services_public services`
3. **Apply Migration**: `python manage.py migrate_schemas --shared` (for public) or `python manage.py migrate_schemas` (for tenants)
4. **Test**: Write tests in `services_public/tests/`
5. **Commit**: Git commit with descriptive message

### Adding New Fields to Sync

To add a new field to the sync process:

1. **Add field to PublicService model:**
   ```python
   # services_public/models.py
   class PublicService(models.Model):
       new_field = models.CharField(max_length=100)
   ```

2. **Add field mapping:**
   ```python
   # core/sync/service_sync.py
   class ServicePublicSyncService(PublicSyncService):
       def __init__(self):
           self.field_mapping = {
               # ...
               'new_field': lambda s: s.source_field,
           }
   ```

3. **Create and run migration:**
   ```bash
   python manage.py makemigrations services_public
   python manage.py migrate_schemas --shared
   ```

4. **Re-sync existing services:**
   ```bash
   python manage.py shell
   >>> from services.tasks import resync_stale_catalog_entries
   >>> resync_stale_catalog_entries.delay(hours=0)  # Re-sync all
   ```

### Adding New Filters

To add a new filter to the catalog:

1. **Update filter logic:**
   ```python
   # services_public/utils.py
   def apply_filters(queryset, request):
       # ...
       new_filter = request.GET.get('new_filter')
       if new_filter:
           queryset = queryset.filter(field=new_filter)
       return queryset
   ```

2. **Update template:**
   ```django
   <!-- services_public/templates/services/list.html -->
   <select name="new_filter">
       <option value="">All</option>
       <!-- options -->
   </select>
   ```

3. **Update WebSocket consumer:**
   ```python
   # services_public/consumers.py
   async def apply_filters_async(self, filters):
       # Include new filter in queryset
   ```

4. **Update JavaScript:**
   ```javascript
   // services_public/static/services_public/js/filter-handler.js
   // Add new filter to getFilters() method
   ```

## Database Migrations

### Creating Migrations

```bash
# For services_public (public schema)
python manage.py makemigrations services_public

# For services (tenant schemas)
python manage.py makemigrations services
```

### Applying Migrations

```bash
# Public schema only
python manage.py migrate_schemas --shared

# Tenant schemas only
python manage.py migrate_schemas --tenant

# All schemas (public + tenants)
python manage.py migrate_schemas
```

### Migration Best Practices

- **Always create indexes** for foreign keys and frequently queried fields
- **Use GIN indexes** for JSONField full-text search
- **Use GIST indexes** for PostGIS geographic queries
- **Add database constraints** for data integrity
- **Test migrations** on a copy of production data first
- **Squash migrations** periodically to reduce complexity

Example migration with indexes:

```python
# services_public/migrations/0001_initial.py
from django.db import migrations, models
import django.contrib.gis.db.models as gis_models

class Migration(migrations.Migration):
    operations = [
        migrations.CreateModel(
            name='PublicService',
            fields=[
                # ... fields
            ],
            options={
                'db_table': 'public_service_catalog',
                'indexes': [
                    models.Index(fields=['service_uuid'], name='idx_service_uuid'),
                    models.Index(fields=['category_slug', 'is_active'], name='idx_category_active'),
                    models.Index(fields=['price', 'currency'], name='idx_price'),
                    gis_models.GISIndex(fields=['location'], name='idx_location'),
                ],
            },
        ),
    ]
```

## Testing

### Running Tests

```bash
# All tests
pytest services_public/tests/

# Specific test file
pytest services_public/tests/test_views.py

# Specific test class
pytest services_public/tests/test_views.py::TestServiceListView

# Specific test method
pytest services_public/tests/test_views.py::TestServiceListView::test_filter_by_category

# With coverage
pytest services_public/tests/ --cov=services_public --cov-report=html

# Verbose output
pytest services_public/tests/ -v

# Stop on first failure
pytest services_public/tests/ -x

# Parallel execution (requires pytest-xdist)
pytest services_public/tests/ -n auto
```

### Test Coverage

View coverage report:

```bash
# Generate HTML report
pytest --cov=services_public --cov-report=html

# Open in browser
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

Target coverage by file:
- models.py: 95%+
- views.py: 90%+
- tasks.py: 95%+
- signals.py: 100%
- consumers.py: 85%+
- utils.py: 90%+

### Writing Tests

Test structure example:

```python
# services_public/tests/test_models.py
import pytest
from django.contrib.gis.geos import Point
from services_public.models import PublicService

@pytest.mark.django_db
class TestPublicService:
    """Tests for PublicService model."""

    def test_create_service(self):
        """Test creating a PublicService entry."""
        service = PublicService.objects.create(
            service_uuid=uuid.uuid4(),
            tenant_id=1,
            tenant_schema_name='tenant1',
            name='Test Service',
            # ... other fields
        )
        assert service.id is not None
        assert service.name == 'Test Service'

    def test_location_distance_query(self):
        """Test PostGIS distance queries."""
        service1 = PublicService.objects.create(
            # ...
            location=Point(-73.5673, 45.5017)  # Montreal
        )
        service2 = PublicService.objects.create(
            # ...
            location=Point(-74.0060, 40.7128)  # New York
        )

        from django.contrib.gis.measure import D
        nearby = PublicService.objects.filter(
            location__distance_lte=(service1.location, D(km=50))
        )

        assert service1 in nearby
        assert service2 not in nearby
```

## Debugging

### Django Debug Toolbar

Install and configure:

```bash
pip install django-debug-toolbar
```

```python
# settings.py
INSTALLED_APPS += ['debug_toolbar']
MIDDLEWARE += ['debug_toolbar.middleware.DebugToolbarMiddleware']
INTERNAL_IPS = ['127.0.0.1']
```

### Logging

Enable detailed logging:

```python
# settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'services_public': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
        'core.sync': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}
```

### Celery Debugging

Monitor Celery tasks:

```bash
# Start Celery with verbose logging
celery -A zumodra worker -l debug

# Monitor with Flower
pip install flower
celery -A zumodra flower

# Open http://localhost:5555
```

### WebSocket Debugging

Test WebSocket connection:

```javascript
// Browser console
const ws = new WebSocket('ws://localhost:8000/ws/services-catalog/');
ws.onopen = () => console.log('Connected');
ws.onmessage = (e) => console.log('Message:', JSON.parse(e.data));
ws.send(JSON.stringify({
    action: 'filter',
    filters: { category: 'design' }
}));
```

### Database Query Debugging

Log all SQL queries:

```python
# settings.py (development only!)
LOGGING['loggers']['django.db.backends'] = {
    'handlers': ['console'],
    'level': 'DEBUG',
}
```

Count queries in view:

```python
from django.test.utils import override_settings
from django.db import connection

@override_settings(DEBUG=True)
def test_view_queries():
    connection.queries_log.clear()
    # ... run view
    print(f"Queries executed: {len(connection.queries)}")
    for query in connection.queries:
        print(query['sql'])
```

## Common Tasks

### Bulk Sync All Services

```python
# Python shell
from services.tasks import bulk_sync_tenant_services
from tenants.models import Tenant

for tenant in Tenant.objects.all():
    bulk_sync_tenant_services.delay(tenant.id)
```

### Clear Catalog and Re-Sync

```python
# Python shell
from services_public.models import PublicService
from services.tasks import bulk_sync_tenant_services
from tenants.models import Tenant

# Clear all catalog entries
PublicService.objects.all().delete()

# Re-sync all tenants
for tenant in Tenant.objects.all():
    bulk_sync_tenant_services.delay(tenant.id)
```

### Update Stale Entries

```python
# Python shell
from services.tasks import resync_stale_catalog_entries

# Re-sync entries older than 24 hours
resync_stale_catalog_entries.delay(hours=24)

# Force re-sync all entries
resync_stale_catalog_entries.delay(hours=0)
```

### Clean Orphaned Entries

```python
# Python shell
from services.tasks import cleanup_orphaned_catalog_entries

cleanup_orphaned_catalog_entries.delay()
```

### Manually Sync Single Service

```python
# Python shell
from services.tasks import sync_service_to_public_catalog_task
from services.models import Service

service = Service.objects.get(pk=1)
sync_service_to_public_catalog_task.delay(
    str(service.uuid),
    'tenant1',  # tenant schema name
    1  # tenant ID
)
```

## Best Practices

### Code Style

- **Follow PEP 8** for Python code
- **Use type hints** for function signatures
- **Write docstrings** (Google style) for all public functions/classes
- **Use meaningful variable names** (no single-letter variables except loop counters)
- **Maximum line length**: 100 characters

### Performance

- **Use `.only()` and `.defer()`** to load minimal fields
- **Use `.select_related()`** for foreign keys (1:1, 1:N)
- **Use `.prefetch_related()`** for reverse foreign keys (M:N)
- **Add database indexes** for frequently queried fields
- **Cache expensive queries** (use Django cache framework)
- **Paginate large result sets** (never load all records)
- **Use `bulk_create()` and `bulk_update()`** for batch operations

### Security

- **Sanitize HTML** before storing (use nh3 or bleach)
- **Validate user input** on all public endpoints
- **Use parameterized queries** (Django ORM does this automatically)
- **Never expose sensitive data** in public catalog
- **Rate limit public endpoints** (use Django Ratelimit)
- **Validate file uploads** (check file type, size, content)

### Testing

- **Write tests first** (TDD approach)
- **Test edge cases** (empty data, null values, large datasets)
- **Mock external dependencies** (Celery tasks, WebSocket, external APIs)
- **Use fixtures** for reusable test data
- **Test both success and failure** paths
- **Aim for 90%+ coverage** (but 100% coverage ≠ bug-free)

## Troubleshooting

### Services Not Appearing in Catalog

**Symptom**: Service marked `is_public=True` but not visible in catalog

**Check:**
1. Signal fired: Check Celery logs for task queuing
2. Task executed: Check Celery worker logs
3. Sync conditions: Verify all conditions met (provider enabled, active, etc.)
4. Database: Check PublicService table directly

```sql
SELECT * FROM public_service_catalog WHERE service_uuid = 'xxx';
```

**Solution**: Manually trigger sync:
```python
from services.tasks import sync_service_to_public_catalog_task
sync_service_to_public_catalog_task.delay(service_uuid, schema, tenant_id)
```

### Circular Signal Errors

**Symptom**: RecursionError or infinite signal loops

**Cause**: Signal firing in public schema and triggering more signals

**Solution**: Signals already guarded with schema check:
```python
if connection.schema_name == get_public_schema_name():
    return  # Skip in public schema
```

### WebSocket Connection Fails

**Symptom**: WebSocket shows "disconnected" immediately

**Check:**
1. Channels/Daphne running: `ps aux | grep daphne`
2. Redis running: `redis-cli ping`
3. Channels layer configured: Check `settings.CHANNEL_LAYERS`
4. CORS settings: Check allowed origins

**Solution**: Restart Daphne and Redis:
```bash
redis-cli FLUSHALL
daphne -b 0.0.0.0 -p 8001 zumodra.asgi:application
```

### Celery Tasks Not Running

**Symptom**: Tasks queued but never execute

**Check:**
1. Celery worker running: `celery -A zumodra inspect active`
2. Celery connected to Redis: Check worker logs
3. Task registered: `celery -A zumodra inspect registered`

**Solution**: Restart Celery worker:
```bash
pkill -9 celery
celery -A zumodra worker -l info
```

### PostGIS Queries Failing

**Symptom**: "GEOS geometry operations require GDAL" or similar

**Check:**
1. PostGIS installed: `SELECT PostGIS_version();`
2. GDAL installed: `gdalinfo --version`
3. GEOS installed: `geos-config --version`

**Solution**: Install PostGIS dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install postgis postgresql-14-postgis-3

# macOS
brew install postgis gdal

# Create extension
psql -U postgres -d zumodra -c "CREATE EXTENSION postgis;"
```

### Migration Conflicts

**Symptom**: "Conflicting migrations detected"

**Solution**: Merge migrations:
```bash
python manage.py makemigrations --merge services_public
```

Or delete conflicting migration and recreate:
```bash
# BE CAREFUL - only in development!
rm services_public/migrations/0002_conflict.py
python manage.py makemigrations services_public
```

## Additional Resources

- [Django Documentation](https://docs.djangoproject.com/)
- [Django-Tenants Documentation](https://django-tenants.readthedocs.io/)
- [Celery Documentation](https://docs.celeryproject.org/)
- [Django Channels Documentation](https://channels.readthedocs.io/)
- [PostGIS Documentation](https://postgis.net/documentation/)
- [Leaflet.js Documentation](https://leafletjs.com/)

## Getting Help

- **Internal**: Contact the development team
- **Issues**: File an issue in the project repository
- **Pull Requests**: Submit PRs with tests and documentation

---

**Last Updated**: 2026-01-24

**Maintainers**: Zumodra Development Team
