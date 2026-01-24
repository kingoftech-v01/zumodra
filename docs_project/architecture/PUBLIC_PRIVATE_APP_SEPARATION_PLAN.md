# Public/Private App Separation Architecture Plan

**Created:** 2026-01-17
**Status:** In Progress
**Priority:** High - Solves tenant context requirement for public browsing

---

## Executive Summary

**Problem:** Public job and service browsing currently requires tenant context, showing "you should be in a tenant to see jobs available" error when users try to browse public catalogs.

**Solution:** Separate public and private apps completely:
- **Public Apps** (`ats_public`, `services_public`) - No tenant context required, browse-only
- **Private Apps** (`ats`, `services`) - Tenant-isolated, full CRUD operations
- **Sync Mechanism** - Django signals + Celery tasks automatically sync public ↔ private

**Benefits:**
- ✅ Public browsing works without tenant context
- ✅ Complete schema isolation between public and private data
- ✅ Security: private data never exposed to public
- ✅ Performance: denormalized public catalog optimized for browsing
- ✅ Scalability: public catalog can be cached/replicated independently

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      PUBLIC SCHEMA                           │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │   ats_public     │         │ services_public  │         │
│  │                  │         │                  │         │
│  │ - PublicJobCatalog│         │ - PublicProvider │         │
│  │ - Read-only      │         │ - Read-only      │         │
│  │ - Denormalized   │         │ - Denormalized   │         │
│  │ - No auth        │         │ - No auth        │         │
│  └──────────────────┘         └──────────────────┘         │
└─────────────────────────────────────────────────────────────┘
                    ▲                         ▲
                    │                         │
              Django Signals + Celery Tasks (Sync)
                    │                         │
                    ▼                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    TENANT SCHEMAS                            │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │      ats         │         │    services      │         │
│  │                  │         │                  │         │
│  │ - JobPosting     │         │ - ServiceProvider│         │
│  │ - Application    │         │ - ServiceListing │         │
│  │ - Interview      │         │ - Contract       │         │
│  │ - Full CRUD      │         │ - Full CRUD      │         │
│  │ - Tenant-isolated│         │ - Tenant-isolated│         │
│  └──────────────────┘         └──────────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

---

## Apps to Create

### 1. **ats_public** - Public Job Catalog

**Location:** `jobs_public/`

**Purpose:** Browse public job listings without tenant context

**Models:**
```python
class PublicJobCatalog(models.Model):
    """Denormalized public job listing for browsing."""
    # Identity
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    jobposting_uuid = models.UUIDField(unique=True, db_index=True)

    # Source tenant info
    tenant_id = models.IntegerField(db_index=True)
    tenant_schema_name = models.CharField(max_length=100, db_index=True)
    company_name = models.CharField(max_length=255)
    company_logo_url = models.URLField(blank=True)

    # Job details
    title = models.CharField(max_length=255, db_index=True)
    description_html = models.TextField()  # Sanitized HTML
    employment_type = models.CharField(max_length=50, db_index=True)
    location_city = models.CharField(max_length=100, db_index=True)
    location_state = models.CharField(max_length=100)
    location_country = models.CharField(max_length=100, db_index=True)
    is_remote = models.BooleanField(default=False, db_index=True)

    # Salary (optional)
    salary_min = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    salary_max = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    salary_currency = models.CharField(max_length=3, default='USD')

    # Categories & Skills (denormalized for fast filtering)
    category_names = models.JSONField(default=list)  # ["Engineering", "Product"]
    category_slugs = models.JSONField(default=list, db_index=True)  # ["engineering", "product"]
    required_skills = models.JSONField(default=list)  # ["Python", "Django", "React"]

    # Metadata
    published_at = models.DateTimeField(db_index=True)
    synced_at = models.DateTimeField(auto_now=True)

    # Application URL (redirects to tenant domain)
    application_url = models.URLField()  # https://acme.zumodra.com/careers/jobs/123/apply/

    class Meta:
        db_table = 'ats_public_job_catalog'
        indexes = [
            models.Index(fields=['title']),
            models.Index(fields=['location_city', 'location_state']),
            models.Index(fields=['employment_type', 'is_remote']),
            models.Index(fields=['-published_at']),
        ]
        ordering = ['-published_at']
```

**Views:**
- `PublicJobListView` - Browse all public jobs (filterable by location, type, remote, skills)
- `PublicJobDetailView` - View single job detail (redirects to tenant for apply)
- `PublicJobSearchView` - Full-text search across job titles, descriptions
- `PublicCompanyJobsView` - All jobs from a specific company

**URLs:**
```python
# ats_public/urls.py
urlpatterns = [
    path('jobs/', PublicJobListView.as_view(), name='job_list'),
    path('jobs/<uuid:jobposting_uuid>/', PublicJobDetailView.as_view(), name='job_detail'),
    path('jobs/search/', PublicJobSearchView.as_view(), name='job_search'),
    path('companies/<str:tenant_schema>/jobs/', PublicCompanyJobsView.as_view(), name='company_jobs'),
]
```

**API:**
```python
# ats_public/api/views.py
class PublicJobViewSet(ReadOnlyModelViewSet):
    """Read-only API for public job catalog."""
    queryset = PublicJobCatalog.objects.all()
    serializer_class = PublicJobCatalogSerializer
    permission_classes = [AllowAny]  # No authentication required
    filterset_fields = ['employment_type', 'is_remote', 'location_country', 'location_city']
    search_fields = ['title', 'description_html', 'company_name']
    ordering_fields = ['published_at', 'title', 'salary_min']
```

---

### 2. **services_public** - Public Service Catalog

**Location:** `services_public/`

**Purpose:** Browse public service providers/listings without tenant context

**Models:**
```python
class PublicServiceCatalog(models.Model):
    """Denormalized public service listing for marketplace browsing."""
    # Identity
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    service_uuid = models.UUIDField(unique=True, db_index=True)

    # Source tenant info
    tenant_id = models.IntegerField(db_index=True)
    tenant_schema_name = models.CharField(max_length=100, db_index=True)
    provider_name = models.CharField(max_length=255, db_index=True)
    provider_avatar_url = models.URLField(blank=True)

    # Service details
    title = models.CharField(max_length=255, db_index=True)
    description_html = models.TextField()  # Sanitized HTML
    service_type = models.CharField(max_length=100, db_index=True)

    # Location
    location_city = models.CharField(max_length=100, db_index=True)
    location_state = models.CharField(max_length=100)
    location_country = models.CharField(max_length=100, db_index=True)
    location = models.PointField(geography=True, null=True, blank=True)  # PostGIS for geo queries
    can_work_remotely = models.BooleanField(default=False, db_index=True)

    # Pricing
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    currency = models.CharField(max_length=3, default='USD')

    # Categories & Skills
    category_names = models.JSONField(default=list)
    category_slugs = models.JSONField(default=list, db_index=True)
    skills = models.JSONField(default=list)  # ["Python", "Django", "React"]

    # Stats (denormalized for performance)
    rating_avg = models.DecimalField(max_digits=3, decimal_places=2, null=True, blank=True)
    total_reviews = models.IntegerField(default=0)
    completed_jobs_count = models.IntegerField(default=0)

    # Metadata
    published_at = models.DateTimeField(db_index=True)
    synced_at = models.DateTimeField(auto_now=True)

    # Booking URL (redirects to tenant domain)
    booking_url = models.URLField()  # https://acme.zumodra.com/services/123/book/

    class Meta:
        db_table = 'services_public_catalog'
        indexes = [
            models.Index(fields=['title']),
            models.Index(fields=['service_type', 'can_work_remotely']),
            models.Index(fields=['location_city', 'location_state']),
            models.Index(fields=['-rating_avg', '-total_reviews']),
            models.Index(fields=['-published_at']),
        ]
        ordering = ['-published_at']
```

**Views:**
- `PublicServiceListView` - Browse all public services
- `PublicServiceDetailView` - View single service detail
- `PublicServiceSearchView` - Search services by title, description, skills
- `PublicNearbyServicesView` - Geo-search for nearby services (PostGIS)

**API:**
```python
# services_public/api/views.py
class PublicServiceViewSet(ReadOnlyModelViewSet):
    """Read-only API for public service catalog."""
    queryset = PublicServiceCatalog.objects.all()
    serializer_class = PublicServiceCatalogSerializer
    permission_classes = [AllowAny]
    filterset_fields = ['service_type', 'can_work_remotely', 'location_country']
    search_fields = ['title', 'description_html', 'provider_name']
    ordering_fields = ['published_at', 'rating_avg', 'hourly_rate']
```

---

## Sync Mechanism

### Django Signals Approach

**File:** `ats/signals.py` (updated)

```python
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.db import connection
from .models import JobPosting
from .tasks import sync_job_to_public, remove_job_from_public


@receiver(post_save, sender=JobPosting)
def sync_job_on_save(sender, instance, created, **kwargs):
    """Sync job to public catalog when saved."""
    # Only sync if job is published on career page
    if instance.published_on_career_page and not instance.is_internal_only:
        # Pass tenant schema name to Celery task
        from django.db import connection
        tenant_schema = connection.schema_name

        # Trigger async sync (run in background)
        sync_job_to_public.delay(str(instance.id), tenant_schema)
    else:
        # Job is private, remove from public catalog if exists
        remove_job_from_public.delay(str(instance.id), connection.schema_name)


@receiver(post_delete, sender=JobPosting)
def remove_job_on_delete(sender, instance, **kwargs):
    """Remove job from public catalog when deleted."""
    from django.db import connection
    remove_job_from_public.delay(str(instance.id), connection.schema_name)
```

**File:** `services/signals.py` (updated)

```python
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.db import connection
from .models import ServiceProvider, ServiceListing
from .tasks import sync_service_to_public, remove_service_from_public


@receiver(post_save, sender=ServiceListing)
def sync_service_on_save(sender, instance, created, **kwargs):
    """Sync service to public catalog when saved."""
    # Only sync if service is marked public
    if instance.is_public and instance.is_active:
        from django.db import connection
        tenant_schema = connection.schema_name

        sync_service_to_public.delay(str(instance.id), tenant_schema)
    else:
        remove_service_from_public.delay(str(instance.id), connection.schema_name)


@receiver(post_delete, sender=ServiceListing)
def remove_service_on_delete(sender, instance, **kwargs):
    """Remove service from public catalog when deleted."""
    from django.db import connection
    remove_service_from_public.delay(str(instance.id), connection.schema_name)
```

---

### Celery Tasks

**File:** `ats_public/tasks.py` (new)

```python
from celery import shared_task
from django.db import connection
from django_tenants.utils import get_tenant_model
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def sync_job_to_public(self, job_id, tenant_schema_name):
    """
    Sync a job from tenant schema to public catalog.

    Args:
        job_id: UUID of JobPosting in tenant schema
        tenant_schema_name: Schema name of source tenant
    """
    from ats.models import JobPosting
    from ats_public.models import PublicJobCatalog
    from tenants.context import public_schema_context

    try:
        # Step 1: Switch to tenant schema and fetch job
        Tenant = get_tenant_model()
        tenant = Tenant.objects.get(schema_name=tenant_schema_name)
        connection.set_tenant(tenant)

        job = JobPosting.objects.get(id=job_id)

        # Step 2: Extract data for public catalog
        catalog_data = {
            'jobposting_uuid': job.uuid,
            'tenant_id': tenant.id,
            'tenant_schema_name': tenant_schema_name,
            'company_name': tenant.name,
            'company_logo_url': tenant.logo.url if tenant.logo else '',
            'title': job.title,
            'description_html': sanitize_html(job.description),
            'employment_type': job.employment_type,
            'location_city': job.location_city or '',
            'location_state': job.location_state or '',
            'location_country': job.location_country or '',
            'is_remote': job.is_remote,
            'salary_min': job.salary_min,
            'salary_max': job.salary_max,
            'salary_currency': job.salary_currency or 'USD',
            'category_names': [cat.name for cat in job.categories.all()],
            'category_slugs': [cat.slug for cat in job.categories.all()],
            'required_skills': job.required_skills or [],
            'published_at': job.published_at or job.created_at,
            'application_url': f"https://{tenant.domain_url}/careers/jobs/{job.uuid}/apply/",
        }

        # Step 3: Switch to public schema and update catalog
        with public_schema_context():
            PublicJobCatalog.objects.update_or_create(
                jobposting_uuid=job.uuid,
                defaults=catalog_data
            )

        logger.info(f"Synced job {job.uuid} to public catalog from {tenant_schema_name}")
        return {'status': 'success', 'job_uuid': str(job.uuid)}

    except JobPosting.DoesNotExist:
        logger.error(f"Job {job_id} not found in {tenant_schema_name}")
        return {'status': 'error', 'reason': 'job_not_found'}
    except Exception as e:
        logger.error(f"Failed to sync job {job_id}: {e}", exc_info=True)
        raise self.retry(exc=e)


@shared_task(bind=True)
def remove_job_from_public(self, job_id, tenant_schema_name):
    """Remove job from public catalog."""
    from ats_public.models import PublicJobCatalog
    from tenants.context import public_schema_context

    try:
        # Switch to tenant to get UUID
        Tenant = get_tenant_model()
        tenant = Tenant.objects.get(schema_name=tenant_schema_name)
        connection.set_tenant(tenant)

        from ats.models import JobPosting
        job = JobPosting.objects.get(id=job_id)
        job_uuid = job.uuid

        # Remove from public catalog
        with public_schema_context():
            deleted_count, _ = PublicJobCatalog.objects.filter(
                jobposting_uuid=job_uuid
            ).delete()

        logger.info(f"Removed job {job_uuid} from public catalog ({deleted_count} entries)")
        return {'status': 'success', 'deleted_count': deleted_count}

    except Exception as e:
        logger.error(f"Failed to remove job {job_id}: {e}", exc_info=True)
        return {'status': 'error', 'reason': str(e)}


def sanitize_html(html_content):
    """Sanitize HTML to prevent XSS."""
    import nh3
    return nh3.clean(
        html_content,
        tags={'p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'h2', 'h3'},
        attributes={'a': {'href'}},
        link_rel='nofollow noopener noreferrer'
    )
```

**File:** `services_public/tasks.py` (new) - Similar structure for services

---

## Settings Configuration

**File:** `zumodra/settings_tenants.py`

```python
# Apps in SHARED_APPS (available in public schema)
SHARED_APPS = [
    'django_tenants',
    'tenants',
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admin',
    'django.contrib.gis',  # PostGIS support

    # PUBLIC CATALOG APPS (no tenant context required)
    'ats_public',          # ← NEW: Public job catalog
    'services_public',     # ← NEW: Public service catalog
    'careers',             # Public company pages
    'blog',                # Public blog

    # ... other shared apps
]

# Apps in TENANT_APPS (tenant-isolated)
TENANT_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.admin',

    # PRIVATE TENANT APPS
    'ats',                 # Private ATS system
    'services',            # Private service management
    'hr_core',
    'finance',
    'messages_sys',
    'notifications',
    'analytics',

    # ... other tenant apps
]
```

---

## URL Routing

**File:** `zumodra/urls.py`

```python
from django.urls import path, include

urlpatterns = [
    # Public catalog URLs (no tenant required)
    path('browse/jobs/', include('ats_public.urls', namespace='ats_public')),
    path('browse/services/', include('services_public.urls', namespace='services_public')),

    # Public APIs
    path('api/public/jobs/', include('ats_public.api.urls')),
    path('api/public/services/', include('services_public.api.urls')),

    # Tenant-specific URLs (require tenant context)
    path('app/jobs/', include('ats.urls_frontend', namespace='ats')),
    path('app/services/', include('services.urls_frontend', namespace='services')),
    path('api/v1/jobs/', include('ats.api.urls')),
    path('api/v1/services/', include('services.api.urls')),

    # ... other URLs
]
```

---

## Migration Strategy

### Phase 1: Create Public Apps Structure

1. **Create ats_public app**
   ```bash
   python manage.py startapp ats_public
   ```

2. **Create services_public app**
   ```bash
   python manage.py startapp services_public
   ```

3. **Add to SHARED_APPS** in settings_tenants.py

4. **Create models** (PublicJobCatalog, PublicServiceCatalog)

5. **Run migrations**
   ```bash
   python manage.py migrate_schemas --shared
   ```

### Phase 2: Implement Sync Tasks

1. Create `ats_public/tasks.py` with sync_job_to_public and remove_job_from_public
2. Create `services_public/tasks.py` with sync_service_to_public and remove_service_from_public
3. Update `ats/signals.py` to trigger sync tasks
4. Update `services/signals.py` to trigger sync tasks

### Phase 3: Create Public Views

1. Create `ats_public/views.py` with PublicJobListView, PublicJobDetailView
2. Create `services_public/views.py` with PublicServiceListView, PublicServiceDetailView
3. Create `ats_public/urls.py` and `services_public/urls.py`
4. Create templates in `templates/jobs_public/` and `templates/services_public/`

### Phase 4: Create Public APIs

1. Create `ats_public/api/views.py` with PublicJobViewSet
2. Create `services_public/api/views.py` with PublicServiceViewSet
3. Create `ats_public/api/serializers.py` and `services_public/api/serializers.py`
4. Create `ats_public/api/urls.py` and `services_public/api/urls.py`

### Phase 5: Initial Sync

1. Create management command to sync existing data:
   ```bash
   python manage.py sync_all_public_catalogs
   ```

2. This command will:
   - Iterate through all tenants
   - Find all public jobs/services
   - Sync to public catalog

### Phase 6: Testing

1. Test public browsing without authentication
2. Test tenant-specific CRUD operations
3. Test sync on create/update/delete
4. Test signal triggers and Celery tasks
5. Verify no tenant context errors

---

## Expected Outcomes

**Before:**
- ❌ Public job browsing requires tenant context
- ❌ "You should be in a tenant to see jobs available" error
- ❌ Confusion between public and private data

**After:**
- ✅ Public job/service browsing works without tenant context
- ✅ Clear separation: public catalog (browse) vs private apps (manage)
- ✅ Automatic sync keeps public catalog up-to-date
- ✅ Performance: denormalized public catalog optimized for search/filter
- ✅ Security: private tenant data never exposed to public

---

## File Structure

```
zumodra/
├── ats_public/              # NEW: Public job catalog app
│   ├── __init__.py
│   ├── models.py           # PublicJobCatalog model
│   ├── views.py            # Public job list/detail views
│   ├── urls.py             # /browse/jobs/ URLs
│   ├── tasks.py            # Sync tasks
│   ├── admin.py            # Admin for catalog management
│   ├── api/
│   │   ├── views.py        # PublicJobViewSet
│   │   ├── serializers.py
│   │   └── urls.py
│   └── management/
│       └── commands/
│           └── sync_all_jobs.py
│
├── services_public/         # NEW: Public service catalog app
│   ├── __init__.py
│   ├── models.py           # PublicServiceCatalog model
│   ├── views.py
│   ├── urls.py
│   ├── tasks.py
│   ├── admin.py
│   ├── api/
│   │   ├── views.py
│   │   ├── serializers.py
│   │   └── urls.py
│   └── management/
│       └── commands/
│           └── sync_all_services.py
│
├── ats/                     # EXISTING: Private Jobs app (updated signals)
│   ├── signals.py          # UPDATED: Trigger sync tasks
│   └── ...
│
├── services/                # EXISTING: Private services app (updated signals)
│   ├── signals.py          # UPDATED: Trigger sync tasks
│   └── ...
│
├── templates/
│   ├── ats_public/         # NEW: Public job catalog templates
│   │   ├── job_list.html
│   │   ├── job_detail.html
│   │   └── job_search.html
│   └── services_public/    # NEW: Public service catalog templates
│       ├── service_list.html
│       ├── service_detail.html
│       └── nearby_services.html
│
└── zumodra/
    ├── settings_tenants.py  # UPDATED: Add ats_public, services_public to SHARED_APPS
    └── urls.py              # UPDATED: Add public catalog URLs
```

---

## Next Steps

1. ✅ Create this architecture plan
2. ⏳ Create `ats_public` app structure
3. ⏳ Create `services_public` app structure
4. ⏳ Implement sync tasks and signals
5. ⏳ Create public views and templates
6. ⏳ Create public APIs
7. ⏳ Run migrations
8. ⏳ Initial sync of existing data
9. ⏳ Test public browsing without tenant context
10. ⏳ Deploy to production

---

**Status:** Ready for implementation
**Estimated Effort:** 6-8 hours for both apps
**Risk:** Low - additive change, doesn't modify existing functionality
