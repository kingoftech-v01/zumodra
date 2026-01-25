# Django App Structure Standards

**Author:** Backend Lead Developer
**Date:** January 16, 2026
**Sprint:** Days 1-5 (January 16-21, 2026)
**Status:** ✅ **APPROVED STANDARDS**

---

## Purpose

This document defines the standardized structure for all Django apps in the Zumodra platform. Following these standards ensures consistency, maintainability, and makes onboarding new developers faster.

---

## Standard App Structure

Every Django app in the Zumodra platform MUST follow this structure:

```
app_name/
├── __init__.py
├── apps.py                      # AppConfig with signal registration in ready()
├── models.py                    # All models in single file
├── admin.py                     # Django admin configuration
├── forms.py                     # Django forms (if template views exist)
├── serializers.py               # DRF serializers
├── template_views.py            # HTMX/template-based views (CBV pattern)
├── urls_frontend.py             # Frontend template URL routing
├── signals.py                   # Django signals (imported in apps.py ready())
├── tasks.py                     # Celery tasks (if needed)
├── api/                         # API subdirectory (REQUIRED)
│   ├── __init__.py
│   ├── urls.py                  # API URL routing
│   └── viewsets.py              # DRF ViewSets
├── management/
│   └── commands/                # Custom management commands
│       └── *.py
├── migrations/                  # Database migrations
├── tests/                       # Test directory (REQUIRED)
│   ├── __init__.py
│   ├── test_models.py
│   ├── test_api.py
│   ├── test_views.py
│   └── test_*.py
├── templatetags/                # Custom template tags (optional)
│   ├── __init__.py
│   └── *_tags.py
└── README.md                    # App documentation (REQUIRED)
```

### Optional Files (Add as Needed)

- `permissions.py` - Custom permission classes
- `filters.py` - django-filter FilterSets
- `services.py` - Business logic layer
- `managers.py` - Custom model managers
- `validators.py` - Custom validators
- `querysets.py` - Custom querysets
- `consumers.py` - WebSocket consumers (PLURAL filename)
- `routing.py` - WebSocket routing

---

## Installed Apps Organization

### Shared Apps (Public Schema)
Located in `SHARED_APPS` in `settings.py`:
- `django_tenants` - Multi-tenancy framework (MUST be first)
- `custom_account_u` - Custom user model (shared across tenants)
- `tenants` - Tenant management
- `main` - Public-facing site
- `allauth` + social providers - Authentication
- `django_otp` + plugins - Two-factor authentication
- Security apps (`axes`, `admin_honeypot`)
- Wagtail CMS suite

### Tenant Apps (Tenant Schemas)
Core business logic apps (isolated per tenant):
- `accounts` - User profiles, KYC, trust scores
- `ats` - Applicant Tracking System
- `hr_core` - HR operations
- `services` - Freelance marketplace
- `finance` - Payments, subscriptions, escrow
- `messages_sys` - Real-time messaging
- `notifications` - Multi-channel notifications
- `careers` - Public career pages
- `ai_matching` - AI-powered matching
- `integrations` - Third-party integrations
- `dashboard` - Main dashboard
- `analytics` - Analytics and reporting
- `core` - Core utilities (tenant-aware)
- `api` - API routing app

---

## Core Patterns

### 1. AppConfig Pattern (apps.py)

**REQUIRED:** All apps must register signals in the `ready()` method.

```python
from django.apps import AppConfig

class AtsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ats'
    verbose_name = 'Applicant Tracking System'

    def ready(self):
        import ats.signals  # noqa
```

### 2. Model Organization

**Standard:** Single `models.py` file with all models.

**All tenant-aware models MUST inherit from `TenantAwareModel`:**

```python
from core.db.models import TenantAwareModel, TenantSoftDeleteModel

class JobPosting(TenantAwareModel):
    """Job posting model - automatically scoped to current tenant."""
    title = models.CharField(max_length=255)
    status = models.CharField(max_length=20)
    # ...

class Candidate(TenantSoftDeleteModel):
    """Candidate model with soft delete support."""
    first_name = models.CharField(max_length=100)
    # ...
```

**For large apps (>2000 lines):** Split domain logic into separate files:
- `offers.py` - Offer-specific logic
- `pipelines.py` - Pipeline logic
- `scheduling.py` - Interview scheduling
- `workflows.py` - Workflow definitions
- Keep model definitions in `models.py`

### 3. Serializer Organization

**Standard:** Single `serializers.py` file with all serializers.

**Naming Conventions:**
- List serializers: `*ListSerializer` (minimal fields)
- Detail serializers: `*DetailSerializer` (all fields + nested)
- Create serializers: `*CreateSerializer` (write-only)
- Update serializers: `*UpdateSerializer` (optional)
- Action serializers: `*ActionSerializer` (for custom actions)

**Example:**

```python
from rest_framework import serializers
from core.serializers import TenantAwareModelSerializer

class JobPostingListSerializer(TenantAwareModelSerializer):
    """Minimal fields for list views."""
    class Meta:
        model = JobPosting
        fields = ['uuid', 'title', 'status', 'created_at']

class JobPostingDetailSerializer(TenantAwareModelSerializer):
    """All fields + nested data for detail views."""
    category = JobCategorySerializer(read_only=True)
    applications_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = JobPosting
        fields = '__all__'

class JobPostingCreateSerializer(TenantAwareModelSerializer):
    """Write-only serializer for creation."""
    class Meta:
        model = JobPosting
        fields = ['title', 'description', 'category', 'job_type']
```

**For apps with 50+ serializers:** Split into modules:

```
app_name/serializers/
├── __init__.py
├── jobs.py
├── candidates.py
├── interviews.py
└── offers.py
```

### 4. View Organization

**REQUIRED: API Subdirectory Pattern**

All apps MUST use the `api/` subdirectory for API ViewSets:

```python
# app_name/api/viewsets.py
from rest_framework import viewsets
from core.viewsets import SecureTenantViewSet

class JobPostingViewSet(SecureTenantViewSet):
    """Job posting API endpoints."""
    queryset = JobPosting.objects.all()
    serializer_class = JobPostingDetailSerializer

    def get_serializer_class(self):
        if self.action == 'list':
            return JobPostingListSerializer
        return JobPostingDetailSerializer
```

**Template Views:** Use `template_views.py` for CBV serving HTML:

```python
# app_name/template_views.py
from django.views.generic import ListView, DetailView
from core.views import TenantRequiredMixin

class JobListView(TenantRequiredMixin, ListView):
    model = JobPosting
    template_name = 'ats/job_list.html'
    context_object_name = 'jobs'
```

### 5. URL Organization

**REQUIRED: Dual URL Files**

1. `api/urls.py` - API routing with DRF DefaultRouter
2. `urls_frontend.py` - Template views with path()

**Example API URLs:**

```python
# app_name/api/urls.py
from rest_framework.routers import DefaultRouter
from .viewsets import JobPostingViewSet

router = DefaultRouter()
router.register('jobs', JobPostingViewSet, basename='job')

urlpatterns = router.urls
```

**Example Frontend URLs:**

```python
# app_name/urls_frontend.py
from django.urls import path
from . import template_views as views

app_name = 'ats'

urlpatterns = [
    path('jobs/', views.JobListView.as_view(), name='job-list'),
    path('jobs/<uuid:pk>/', views.JobDetailView.as_view(), name='job-detail'),
    path('jobs/create/', views.JobCreateView.as_view(), name='job-create'),
]
```

See [URL_CONVENTIONS.md](URL_CONVENTIONS.md) for complete URL naming standards.

### 6. Signal Pattern

**REQUIRED:** All signals in `signals.py`, auto-imported in `apps.py`.

```python
# app_name/signals.py
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from .models import Application, ApplicationActivity

@receiver(post_save, sender=Application)
def log_application_created(sender, instance, created, **kwargs):
    """Automatically log application creation."""
    if created:
        ApplicationActivity.objects.create(
            application=instance,
            activity_type='CREATED',
            description=f'Application created for {instance.candidate}'
        )

# app_name/apps.py
class AtsConfig(AppConfig):
    # ...
    def ready(self):
        import ats.signals  # noqa - registers all signals
```

### 7. Celery Tasks Pattern

**Standard:** All tasks in `tasks.py`.

```python
# app_name/tasks.py
from celery import shared_task

@shared_task(bind=True, max_retries=3)
def sync_job_to_catalog_task(self, job_uuid, tenant_schema, tenant_id):
    """Sync job to public catalog with tenant context."""
    try:
        # Task implementation
        pass
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))
```

**Task Routing:** Configure in `settings.py`:

```python
CELERY_TASK_ROUTES = {
    'ats.tasks.*': {'queue': 'ats'},
    'hr_core.tasks.*': {'queue': 'hr'},
    'finance.tasks.*': {'queue': 'payments'},
    'notifications.tasks.*': {'queue': 'notifications'},
}
```

### 8. Admin Pattern

**REQUIRED:** All models must be registered in Django admin.

```python
# app_name/admin.py
from django.contrib import admin
from .models import JobPosting, Candidate

@admin.register(JobPosting)
class JobPostingAdmin(admin.ModelAdmin):
    list_display = ['title', 'status', 'job_type', 'created_at']
    list_filter = ['status', 'job_type', 'created_at']
    search_fields = ['title', 'description']
    readonly_fields = ['uuid', 'created_at', 'updated_at']
```

### 9. Template Organization

**Structure:**

```
templates/
├── base/                        # Base templates
│   ├── unified_base.html        # Main base template
│   └── dashboard_base.html      # Dashboard base
├── components/                  # Reusable components
├── ats/                         # App-specific templates
│   ├── job_list.html
│   ├── job_detail.html
│   ├── job_form.html
│   └── partials/                # HTMX partials
│       ├── _candidate_card.html
│       └── _application_row.html
└── emails/                      # Email templates
    └── ats/
        └── interview_invite.html
```

**Naming Convention:**
- Main templates: `{model}_list.html`, `{model}_detail.html`, `{model}_form.html`
- Partials: `partials/_*.html` (underscore prefix)
- HTMX endpoints serve partials

### 10. Test Organization

**REQUIRED:** All apps must have `tests/` directory.

```
app_name/tests/
├── __init__.py
├── test_models.py              # Model tests
├── test_api.py                 # API endpoint tests
├── test_views.py               # Template view tests
├── test_permissions.py         # Permission tests
└── test_workflows.py           # Workflow/integration tests
```

**Minimum Coverage:** 70% (target 80% for production)

### 11. README Pattern

**REQUIRED:** Every app must have a README.md with:

```markdown
# App Name

## Overview
Brief description of the app's purpose.

## Key Features
- [ ] Feature 1 (In Development)
- [x] Feature 2 (Completed)

## Architecture

### Models
- Model1 - Description
- Model2 - Description

### Views
- API ViewSets in `api/viewsets.py`
- Template views in `template_views.py`

### URLs
- API: `/api/v1/app/`
- Frontend: `/app/app/`

## Integration Points
- Dependencies on other apps
- External services

## Testing
Coverage target: 80%

## Performance Considerations
Key optimizations or concerns.

## Contributing
Guidelines for developers.
```

---

## Multi-Tenancy Requirements

### Base Models

**ALWAYS use tenant-aware base models:**

```python
from core.db.models import TenantAwareModel, TenantSoftDeleteModel

# For models that should be tenant-scoped
class MyModel(TenantAwareModel):
    pass

# For models with soft delete
class MyDeletableModel(TenantSoftDeleteModel):
    pass
```

**Benefits:**
- Automatic tenant scoping in all queries
- Prevents cross-tenant data leaks
- Soft delete with tenant context

### Custom Managers

**For non-TenantAwareModel classes** that access tenant through FK:

```python
from core.db.managers import TenantAwareManager

class Interview(models.Model):
    application = models.ForeignKey('Application', on_delete=models.CASCADE)

    objects = TenantAwareManager()  # Automatically scopes via application.tenant
```

### ViewSets

**ALWAYS use SecureTenantViewSet for APIs:**

```python
from core.viewsets import SecureTenantViewSet, SecureReadOnlyViewSet, AdminOnlyViewSet

# Standard tenant-scoped CRUD
class JobPostingViewSet(SecureTenantViewSet):
    queryset = JobPosting.objects.all()
    serializer_class = JobPostingSerializer

# Read-only tenant-scoped
class JobCategoryViewSet(SecureReadOnlyViewSet):
    queryset = JobCategory.objects.all()
    serializer_class = JobCategorySerializer

# Admin-only (staff users)
class SystemConfigViewSet(AdminOnlyViewSet):
    queryset = SystemConfig.objects.all()
    serializer_class = SystemConfigSerializer
```

---

## WebSocket Apps

For apps with real-time features (like `messages_sys`, `notifications`):

**Additional Files:**
- `consumers.py` (PLURAL) - WebSocket consumer classes
- `routing.py` - WebSocket URL routing

**Example:**

```python
# app_name/consumers.py
from channels.generic.websocket import AsyncJsonWebsocketConsumer

class ChatConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        await self.accept()
        # Implementation

# app_name/routing.py
from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/chat/<uuid:conversation_id>/', consumers.ChatConsumer.as_asgi()),
]
```

---

## Domain-Specific Logic Files

When domain logic becomes too large (>2000 lines in models.py), split into:

**Example from ATS:**
- `advanced_reports.py` - Complex reporting logic
- `aggregations.py` - Query aggregations
- `automation.py` - Workflow automation
- `offers.py` - Offer-specific business logic
- `pipelines.py` - Pipeline management logic
- `scheduling.py` - Interview scheduling logic
- `scoring.py` - AI scoring algorithms
- `workflows.py` - Workflow definitions

**Keep model definitions in `models.py`**, move business logic methods to appropriate files.

---

## Migration Checklist for Existing Apps

### Older Apps (ats, hr_core, some services)

These apps use the old pattern with ViewSets in root `views.py`. To migrate:

1. **Create `api/` subdirectory:**
   ```bash
   mkdir app_name/api
   touch app_name/api/__init__.py
   ```

2. **Move ViewSets:**
   ```bash
   # Move views.py → api/viewsets.py
   mv app_name/views.py app_name/api/viewsets.py
   ```

3. **Create `api/urls.py`:**
   ```python
   # Extract router code from old urls.py
   from rest_framework.routers import DefaultRouter
   from .viewsets import *

   router = DefaultRouter()
   # Register viewsets
   urlpatterns = router.urls
   ```

4. **Update imports:**
   - Find all imports of `from app_name.views import *`
   - Change to `from app_name.api.viewsets import *`

5. **Update tests:**
   - Update test imports
   - Verify all tests pass

### Apps Missing Tests

Create `tests/` directory with standard files:

```bash
mkdir app_name/tests
touch app_name/tests/__init__.py
touch app_name/tests/test_models.py
touch app_name/tests/test_api.py
touch app_name/tests/test_views.py
```

### Apps Missing README

Copy template from another app and customize.

---

## Coding Standards

### Python Style
- **Formatter:** Black (120 char line length)
- **Import sorter:** isort
- **Linters:** flake8, pylint
- CI enforces all style checks

### Naming Conventions
- **Models:** PascalCase (e.g., `JobPosting`, `UserProfile`)
- **Functions/methods:** snake_case (e.g., `get_active_jobs`, `send_notification`)
- **Constants:** UPPER_SNAKE_CASE (e.g., `MAX_FILE_SIZE`, `DEFAULT_TIMEOUT`)
- **Private methods:** `_leading_underscore`

### Docstrings
- All public classes, methods, and functions MUST have docstrings
- Format: Google-style docstrings

```python
def schedule_interview(application, interview_type, scheduled_at):
    """Schedule an interview for an application.

    Args:
        application (Application): The application to schedule for
        interview_type (str): Type of interview (phone, video, onsite)
        scheduled_at (datetime): When to schedule the interview

    Returns:
        Interview: The created interview instance

    Raises:
        ValidationError: If scheduled_at is in the past
    """
    # Implementation
```

---

## Security Checklist

- [ ] All models inherit from `TenantAwareModel` or use custom tenant-aware managers
- [ ] All ViewSets inherit from `SecureTenantViewSet` or similar
- [ ] No raw SQL queries (use ORM or parameterized queries)
- [ ] Input validation on all serializers
- [ ] Permission classes on all ViewSets
- [ ] No hardcoded secrets (use environment variables)
- [ ] SSRF protection on all URL inputs (use `core.validators`)
- [ ] File upload validation (size, type, content)

---

## Performance Checklist

- [ ] Database indexes on frequently queried fields
- [ ] `select_related()` for ForeignKey lookups
- [ ] `prefetch_related()` for ManyToMany/reverse FK
- [ ] Pagination on all list views (API and templates)
- [ ] Caching for expensive queries (use `TenantCache`)
- [ ] Celery tasks for long-running operations
- [ ] Avoid N+1 queries (use Django Debug Toolbar in dev)

---

## Example: Creating a New App

```bash
# 1. Create app
python manage.py startapp new_app

# 2. Create standard structure
mkdir new_app/api
mkdir new_app/tests
mkdir new_app/management
mkdir new_app/management/commands

touch new_app/api/__init__.py
touch new_app/api/urls.py
touch new_app/api/viewsets.py
touch new_app/template_views.py
touch new_app/urls_frontend.py
touch new_app/signals.py
touch new_app/tasks.py
touch new_app/tests/__init__.py
touch new_app/tests/test_models.py
touch new_app/tests/test_api.py
touch new_app/README.md

# 3. Update apps.py with signal registration
# 4. Add to TENANT_APPS in settings.py
# 5. Create models inheriting from TenantAwareModel
# 6. Create ViewSets inheriting from SecureTenantViewSet
# 7. Write tests
# 8. Run makemigrations and migrate
```

---

## References

- [URL Conventions](URL_CONVENTIONS.md)
- [Architecture Overview](ARCHITECTURE.md)
- [Multi-Tenancy Guide](../tenants/README.md)
- [Core Utilities](../core/README.md)
- [Testing Guide](TESTING.md)

---

**Version:** 1.0
**Last Updated:** January 16, 2026
**Maintainer:** Backend Lead Developer
**Status:** Living Document - Update as patterns evolve
