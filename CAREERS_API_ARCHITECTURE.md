# Careers API Architecture Analysis

## Summary

The careers API is currently **non-functional** for public (non-tenant) access. This document explains why and outlines the path forward.

## Current State

### What Works
- **Tenant-specific careers functionality**: JobListing, career pages, and applications work correctly within tenant schemas
- **Tenant careers tables**: All careers tables exist and function properly in tenant schemas (demo, demo_company, etc.)
- **Tenant careers admin**: Tenant users can create and manage job listings in their own schemas

### What Doesn't Work
- **Public careers API endpoints** (`/api/v1/careers/jobs/`, `/api/v1/careers/page/`, etc.) - Return **500 errors**
- **Cross-tenant job browsing**: Public users cannot browse jobs from all tenants
- **Public job applications**: Cannot submit applications without tenant context

## Root Cause

The careers app has extensive **foreign key dependencies** on ATS models:

### Foreign Keys in careers/models.py:
```python
class JobListing(models.Model):
    job = models.OneToOneField('ats.JobPosting', ...)  # Line 576

class PublicApplication(models.Model):
    ats_candidate = models.ForeignKey('ats.Candidate', ...)  # Line 766
    ats_application = models.ForeignKey('ats.Application', ...)  # Line 772
```

### The Problem:
1. ATS models (JobPosting, Candidate, Application) exist in **tenant schemas**
2. When careers is in SHARED_APPS (public schema), these foreign keys **fail** because:
   - PostgreSQL doesn't support cross-schema foreign keys
   - Django tries to JOIN careers_joblisting (public) with ats_jobposting (tenant) → **fails**

### Attempts Made:
1. ✅ **Moved careers to SHARED_APPS** - Migration succeeded
2. ❌ **Manually created careers tables in public schema** - Tables created but queries fail
3. ❌ **Tried to remove FK constraints** - Too many code dependencies (150+ references to `.job.title`, `job__category`, etc.)
4. ✅ **Reverted to TENANT_APPS** - Original state restored

## Solution: Implement PublicJobCatalog

The proper solution is to create a **dedicated public catalog model** that aggregates jobs from all tenants.

### Architecture:

```
┌─────────────────────────────────────────────────────────────┐
│ PUBLIC SCHEMA                                                │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  PublicJobCatalog Model (tenants/models.py)                 │
│  ├─ id (PK)                                                  │
│  ├─ job_id (UUID) - references tenant JobPosting            │
│  ├─ tenant_schema (str) - which tenant owns this job        │
│  ├─ title, description, location, salary (denormalized)     │
│  ├─ company_name, is_active, published_at                   │
│  └─ ... (all fields needed for public browsing)             │
│                                                               │
│  Synced via Celery task when JobPosting is created/updated  │
│                                                               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ TENANT SCHEMA (demo, demo_company, etc.)                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  JobPosting (ats/models.py)                                  │
│  ├─ Signal: post_save                                        │
│  └─ Triggers: sync_to_public_catalog()                       │
│                                                               │
│  JobListing (careers/models.py)                              │
│  └─ Links to JobPosting via FK                               │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Steps:

#### 1. Create PublicJobCatalog Model (`tenants/models.py`)
```python
class PublicJobCatalog(models.Model):
    """
    Denormalized public job catalog for cross-tenant browsing.
    Synced from tenant JobPostings via Celery tasks.
    """
    job_id = models.UUIDField(unique=True, db_index=True)
    tenant_schema = models.CharField(max_length=100, db_index=True)

    # Denormalized fields from JobPosting
    title = models.CharField(max_length=200)
    description = models.TextField()
    location = models.CharField(max_length=200)
    job_type = models.CharField(max_length=50)
    salary_min = models.DecimalField(max_digits=12, decimal_places=2, null=True)
    salary_max = models.DecimalField(max_digits=12, decimal_places=2, null=True)
    company_name = models.CharField(max_length=200)

    # Publishing control
    is_active = models.BooleanField(default=True)
    published_at = models.DateTimeField()
    expires_at = models.DateTimeField(null=True)

    # Metadata
    view_count = models.PositiveIntegerField(default=0)
    application_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'public_job_catalog'
        ordering = ['-published_at']
        indexes = [
            models.Index(fields=['is_active', 'published_at']),
            models.Index(fields=['tenant_schema', 'is_active']),
            models.Index(fields=['job_type']),
            models.Index(fields=['location']),
        ]
```

#### 2. Create Sync Service (`core/sync/job_sync.py`)
```python
class JobCatalogSyncService:
    """Sync JobPosting → PublicJobCatalog"""

    @classmethod
    def sync_job(cls, job_posting):
        """Sync a single job to public catalog"""
        from tenants.models import PublicJobCatalog
        from django_tenants.utils import get_tenant_model, schema_context

        tenant = get_tenant_model().objects.get(schema_name=connection.schema_name)

        PublicJobCatalog.objects.update_or_create(
            job_id=job_posting.id,
            defaults={
                'tenant_schema': tenant.schema_name,
                'title': job_posting.title,
                'description': job_posting.description,
                'location': job_posting.location,
                'job_type': job_posting.job_type,
                'salary_min': job_posting.salary_min,
                'salary_max': job_posting.salary_max,
                'company_name': tenant.name,
                'is_active': job_posting.status == 'open',
                'published_at': job_posting.created_at,
                'expires_at': job_posting.expires_at,
            }
        )

    @classmethod
    def remove_job(cls, job_id):
        """Remove job from public catalog"""
        from tenants.models import PublicJobCatalog
        PublicJobCatalog.objects.filter(job_id=job_id).delete()
```

#### 3. Create Celery Tasks (`ats/tasks.py`)
```python
@shared_task
def sync_job_to_public_catalog(job_id):
    """Async task to sync JobPosting → PublicJobCatalog"""
    from ats.models import JobPosting
    from core.sync.job_sync import JobCatalogSyncService

    try:
        job = JobPosting.objects.get(id=job_id)
        if job.published_on_career_page:
            JobCatalogSyncService.sync_job(job)
    except JobPosting.DoesNotExist:
        pass

@shared_task
def remove_job_from_public_catalog(job_id):
    """Async task to remove job from PublicJobCatalog"""
    from core.sync.job_sync import JobCatalogSyncService
    JobCatalogSyncService.remove_job(job_id)
```

#### 4. Connect Signals (`ats/signals.py`)
```python
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from ats.models import JobPosting
from ats.tasks import sync_job_to_public_catalog, remove_job_from_public_catalog

@receiver(post_save, sender=JobPosting)
def sync_job_on_save(sender, instance, **kwargs):
    """
    Trigger async Celery task to sync JobPosting to PublicJobCatalog.

    Workflow:
    1. JobPosting created/updated in tenant schema
    2. Signal triggers Celery task
    3. Update or create entry in PublicJobCatalog (public schema)
    """
    if instance.published_on_career_page and instance.status == 'open':
        sync_job_to_public_catalog.delay(str(instance.id))
    else:
        # Remove from public catalog if unpublished or closed
        remove_job_from_public_catalog.delay(str(instance.id))

@receiver(post_delete, sender=JobPosting)
def remove_job_on_delete(sender, instance, **kwargs):
    """
    Trigger async Celery task to remove job from PublicJobCatalog.
    """
    remove_job_from_public_catalog.delay(str(instance.id))
```

#### 5. Update Careers API Views (`careers/views.py`)
```python
class PublicJobListingListView(CORSMixin, generics.ListAPIView):
    """
    Public job listing list view.
    Lists all active, published jobs from PublicJobCatalog.
    """
    serializer_class = PublicJobCatalogSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [PublicViewThrottle]
    allow_cors = True

    def get_queryset(self):
        """Return active jobs from public catalog"""
        from tenants.models import PublicJobCatalog
        from django.utils import timezone

        now = timezone.now()
        return PublicJobCatalog.objects.filter(
            is_active=True,
            published_at__lte=now
        ).exclude(
            expires_at__lt=now
        )
```

#### 6. Create Management Command (`core/management/commands/sync_public_catalogs.py`)
```python
from django.core.management.base import BaseCommand
from django_tenants.utils import get_tenant_model, schema_context
from core.sync.job_sync import JobCatalogSyncService

class Command(BaseCommand):
    help = 'Sync all tenant data to public catalogs'

    def handle(self, *args, **options):
        """Sync jobs from all tenants to PublicJobCatalog"""
        from ats.models import JobPosting

        tenants = get_tenant_model().objects.exclude(schema_name='public')

        for tenant in tenants:
            with schema_context(tenant.schema_name):
                jobs = JobPosting.objects.filter(
                    status='open',
                    published_on_career_page=True
                )

                self.stdout.write(f"Syncing {jobs.count()} jobs from {tenant.schema_name}")

                for job in jobs:
                    JobCatalogSyncService.sync_job(job)

        self.stdout.write(self.style.SUCCESS('✓ Sync complete'))
```

## Migration Path

1. **Create PublicJobCatalog model**
2. **Run migrations**: `python manage.py migrate_schemas --shared`
3. **Implement sync service** (core/sync/job_sync.py)
4. **Add Celery tasks** (ats/tasks.py)
5. **Connect signals** (ats/signals.py)
6. **Update careers API views** to use PublicJobCatalog
7. **Run initial sync**: `python manage.py sync_public_catalogs`
8. **Test public API endpoints**

## Benefits

✅ **Clean separation**: Tenant data stays in tenant schemas, public catalog in public schema
✅ **No FK constraints**: PublicJobCatalog is denormalized, no cross-schema references
✅ **Fast public queries**: Pre-aggregated data, no dynamic cross-schema queries
✅ **Scalable**: Celery async tasks handle sync, no blocking operations
✅ **Flexible**: Can add public-specific fields (view_count, featured, etc.)
✅ **Eventually consistent**: Public catalog updates asynchronously when jobs change

## Current Workaround

Until PublicJobCatalog is implemented:

1. **Public careers API returns 500 errors** - Expected behavior
2. **Tenant careers work normally** - Within tenant dashboard/admin
3. **No cross-tenant job browsing** - Not possible yet

## Timeline Estimate

- **Model creation**: 1 hour
- **Sync service implementation**: 2 hours
- **Signal/task integration**: 1 hour
- **API view updates**: 2 hours
- **Testing**: 2 hours
- **Total**: ~8 hours

## References

- ATS models: [ats/models.py:643-865](ats/models.py#L643-L865)
- Careers models: [careers/models.py:570-900](careers/models.py#L570-L900)
- Careers views: [careers/views.py:139-240](careers/views.py#L139-L240)
- Django-tenants docs: https://django-tenants.readthedocs.io/

---

**Status**: 🔴 Public careers API non-functional, awaiting PublicJobCatalog implementation
**Priority**: High (blocks public job browsing feature)
**Assigned**: TBD
