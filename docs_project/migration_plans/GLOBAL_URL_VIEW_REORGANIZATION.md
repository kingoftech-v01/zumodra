# Global URL & View Reorganization Plan

**Version**: 1.0
**Created**: 2026-01-17
**Status**: MANDATORY - All existing apps MUST be reorganized
**Priority**: HIGH

---

## Executive Summary

**Objective**: Force ALL existing apps in Zumodra to follow the new URL and View conventions.

**Current Problem**:
- ❌ Inconsistent URL patterns across apps
- ❌ Mixed template_views and API views in same file
- ❌ No standardized namespace structure
- ❌ Some apps missing frontend or API layer
- ❌ Confusing app names (e.g., `custom_account_u`, `messages_sys`)

**Target State**:
- ✅ All apps follow dual-layer architecture (API + Frontend)
- ✅ Separate `template_views.py` and `views.py` files
- ✅ Standardized namespaces: `frontend:app:view` and `api:v1:app:resource`
- ✅ Single `urls.py` with clear API/Frontend sections
- ✅ Simple, descriptive app names

---

## App Inventory & Status

### Apps Requiring Reorganization

| App Name | Current Status | Rename To | Priority | Complexity |
|----------|---------------|-----------|----------|------------|
| `custom_account_u` | ❌ Confusing name | `users` | HIGH | Medium |
| `messages_sys` | ❌ Confusing name | `messaging` | HIGH | Medium |
| `ats` | ⚠️ Mixed views | Keep | HIGH | Medium |
| `ats_public` | ⚠️ Mixed views | Keep | HIGH | Low |
| `hr_core` | ⚠️ Mixed views | `hr` | HIGH | Medium |
| `services` | ⚠️ Mixed views | Keep | HIGH | Medium |
| `services_public` | ⚠️ Mixed views | Keep | HIGH | Low |
| `tenants` | ⚠️ Mixed views | Keep | HIGH | Medium |
| `accounts` | ✅ Already reorganized | Keep | - | - |
| `finance` | ⚠️ Mixed views | Keep | MEDIUM | Medium |
| `dashboard` | ⚠️ Mixed views | Keep | HIGH | Low |
| `dashboard_service` | ❌ Duplicate/unclear | `dashboard` (merge) | HIGH | High |
| `analytics` | ⚠️ Mixed views | Keep | MEDIUM | Low |
| `integrations` | ⚠️ Mixed views | Keep | MEDIUM | Medium |
| `notifications` | ⚠️ Mixed views | Keep | MEDIUM | Low |
| `appointment` | ⚠️ Mixed views | `appointments` | MEDIUM | Medium |
| `blog` | ⚠️ Mixed views | Keep | LOW | Low |
| `careers` | ⚠️ Mixed views | Keep | MEDIUM | Low |
| `ai_matching` | ⚠️ Mixed views | Keep | MEDIUM | Medium |
| `configurations` | ⚠️ Mixed views | `config` | LOW | Low |
| `marketing` | ⚠️ Mixed views | Keep | LOW | Low |
| `newsletter` | ⚠️ Mixed views | Keep | LOW | Low |
| `security` | ⚠️ Mixed views | Keep | HIGH | Low |

**Legend**:
- ✅ = Already follows convention
- ⚠️ = Needs reorganization (views mixed)
- ❌ = Needs renaming + reorganization

---

## Reorganization Steps

### Phase 0: Preparation (1-2 days)

**0.1 Backup Everything**
```bash
# Create backup branch
git checkout -b backup/pre-url-reorganization
git tag v2.2-pre-url-reorganization
git push origin backup/pre-url-reorganization
git push origin v2.2-pre-url-reorganization

# Working branch
git checkout -b refactor/global-url-view-reorganization
```

**0.2 Create Inventory Script**
```python
# scripts/inventory_views.py
"""
Inventory all views across all apps to understand reorganization scope.
"""
import os
from pathlib import Path

def inventory_app_views(app_path):
    """Analyze views in an app."""
    views_py = app_path / 'views.py'
    template_views_py = app_path / 'template_views.py'

    has_views = views_py.exists()
    has_template_views = template_views_py.exists()

    # Count API vs template views
    api_views = 0
    template_views = 0

    if has_views:
        content = views_py.read_text()
        api_views = content.count('class') + content.count('def')

    if has_template_views:
        content = template_views_py.read_text()
        template_views = content.count('def')

    return {
        'has_views': has_views,
        'has_template_views': has_template_views,
        'api_views': api_views,
        'template_views': template_views,
        'needs_split': has_views and not has_template_views
    }

# Run inventory
apps = [...]
for app in apps:
    info = inventory_app_views(Path(app))
    print(f"{app}: {info}")
```

### Phase 1: Rename Apps (2-3 days)

**Apps to Rename**:

1. `custom_account_u` → `users`
2. `messages_sys` → `messaging`
3. `hr_core` → `hr`
4. `appointment` → `appointments`
5. `configurations` → `config`

**Rename Process** (for each app):

```bash
# 1. Rename directory
mv custom_account_u users

# 2. Update app config
# users/apps.py
class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users'  # Updated

# 3. Find and replace across entire codebase
grep -r "custom_account_u" . --exclude-dir=".git" | wc -l  # Count references
find . -type f -name "*.py" -exec sed -i 's/custom_account_u/users/g' {} +

# 4. Update settings.py
# INSTALLED_APPS: 'custom_account_u' → 'users'
# AUTH_USER_MODEL: 'custom_account_u.CustomUser' → 'users.CustomUser'

# 5. Create migration for ContentType references
python manage.py makemigrations --empty users

# In migration:
from django.contrib.contenttypes.models import ContentType

def update_content_types(apps, schema_editor):
    ContentType.objects.filter(app_label='custom_account_u').update(app_label='users')

# 6. Update all imports
# Old: from custom_account_u.models import CustomUser
# New: from users.models import CustomUser

# 7. Run migrations
python manage.py migrate

# 8. Run tests
pytest users/tests/
```

**Critical Files to Update** (per rename):
- `settings.py` - INSTALLED_APPS, AUTH_USER_MODEL
- `urls.py` (main) - Include paths
- All `models.py` - Import statements
- All `views.py` - Import statements
- All `serializers.py` - Import statements
- All `tests/` - Import statements
- All `templates/` - templatetag references

### Phase 2: Split Views (1-2 days per app)

**For Each App** (e.g., `ats`):

**2.1 Analyze Existing views.py**
```bash
# Count API views (ViewSets, APIView)
grep -E "(ViewSet|APIView)" ats/views.py | wc -l

# Count template views (render\()
grep "render(" ats/views.py | wc -l
```

**2.2 Create template_views.py**
```bash
# Extract all template-based views
# Look for functions that call render() or return HttpResponse with templates
```

**2.3 Move Template Views**
```python
# ats/template_views.py (NEW FILE)
"""
ATS Template Views - Frontend HTML views.

This module provides template-based views for the ATS system:
- Job posting management (list, create, edit, delete)
- Candidate browsing and detail pages
- Interview scheduling and management
- Pipeline board (Kanban view)
- Offer management

All views render HTML templates using Django's render().
Uses HTMX for dynamic interactions and Alpine.js for client-side reactivity.

URL Namespace: frontend:ats:*
"""

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

from .models import JobPosting, Candidate, Interview, Application

# Move all template views here
# Example:

@login_required
def job_list(request):
    """
    List all job postings with filtering and search.

    Features:
    - Search by title, description
    - Filter by status, category, location
    - Sort by created_at, applications_count
    - Pagination (20 per page)

    Template: ats/job_list.html
    Context:
        - jobs: Paginated queryset
        - search: Search query
        - filters: Applied filters
        - total_count: Total jobs
    """
    # Implementation...
    pass

# ... all other template views
```

**2.4 Keep API Views in views.py**
```python
# ats/views.py (CLEANED - API ONLY)
"""
Jobs API Views - REST API endpoints.

This module provides REST API views using Django Rest Framework:
- Job posting CRUD and actions
- Candidate management
- Interview scheduling
- Application workflow
- Pipeline management

All views return JSON responses.
API URL namespace: api:v1:jobs:*
"""

from rest_framework import viewsets, status, filters, permissions
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import JobPosting, Candidate, Interview
from .serializers import (
    JobPostingSerializer,
    CandidateSerializer,
    InterviewSerializer
)

# Keep only ViewSets and APIViews
# Example:

class JobPostingViewSet(viewsets.ModelViewSet):
    """
    ViewSet for job posting CRUD operations.

    Provides:
    - list: GET /api/v1/jobs/job-postings/
    - retrieve: GET /api/v1/jobs/job-postings/{uuid}/
    - create: POST /api/v1/jobs/job-postings/
    - update: PUT/PATCH /api/v1/jobs/job-postings/{uuid}/
    - destroy: DELETE /api/v1/jobs/job-postings/{uuid}/

    Custom actions:
    - publish: POST /api/v1/jobs/job-postings/{uuid}/publish/
    - duplicate: POST /api/v1/jobs/job-postings/{uuid}/duplicate/
    """
    # Implementation...
    pass

# ... all other ViewSets
```

**2.5 Update urls.py**
```python
# ats/urls.py (REORGANIZED)
"""
ATS URLs - Frontend and API routing.

This module configures URL patterns for:
- Frontend HTML views (template_views.py)
- REST API endpoints (views.py with DRF)

URL Namespaces:
- Frontend: frontend:ats:view_name
- API: api:v1:jobs:resource-name
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import template_views  # Frontend views
from . import views           # API views

# ============================================================================
# API ROUTER (DRF ViewSets)
# ============================================================================

api_router = DefaultRouter()

api_router.register(r'job-postings', views.JobPostingViewSet, basename='job-posting')
api_router.register(r'candidates', views.CandidateViewSet, basename='candidate')
api_router.register(r'interviews', views.InterviewViewSet, basename='interview')
api_router.register(r'applications', views.ApplicationViewSet, basename='application')

# ============================================================================
# API URLPATTERNS
# ============================================================================

api_urlpatterns = [
    path('', include(api_router.urls)),

    # Custom API endpoints (non-ViewSet)
    # path('bulk-import/', views.BulkImportAPIView.as_view(), name='bulk-import'),
]

# ============================================================================
# FRONTEND URLPATTERNS
# ============================================================================

frontend_urlpatterns = [
    # Job Postings
    path('jobs/', template_views.job_list, name='job_list'),
    path('jobs/create/', template_views.job_create, name='job_create'),
    path('jobs/<uuid:pk>/', template_views.job_detail, name='job_detail'),
    path('jobs/<uuid:pk>/edit/', template_views.job_update, name='job_update'),
    path('jobs/<uuid:pk>/delete/', template_views.job_delete, name='job_delete'),
    path('jobs/<uuid:pk>/duplicate/', template_views.job_duplicate, name='job_duplicate'),
    path('jobs/<uuid:pk>/publish/', template_views.job_publish, name='job_publish'),

    # Candidates
    path('candidates/', template_views.candidate_list, name='candidate_list'),
    path('candidates/<uuid:pk>/', template_views.candidate_detail, name='candidate_detail'),

    # Interviews
    path('interviews/', template_views.interview_list, name='interview_list'),
    path('interviews/<uuid:pk>/', template_views.interview_detail, name='interview_detail'),
    path('interviews/<uuid:pk>/reschedule/', template_views.interview_reschedule, name='interview_reschedule'),

    # Pipeline
    path('pipeline/', template_views.pipeline_board, name='pipeline_board'),
]

# ============================================================================
# APP URL CONFIGURATION
# ============================================================================

app_name = 'ats'

urlpatterns = [
    # API URLs: /api/v1/jobs/
    path('api/', include((api_urlpatterns, 'api'))),

    # Frontend URLs: /jobs/
    path('', include((frontend_urlpatterns, 'frontend'))),
]
```

**2.6 Update All URL References**
```python
# Old references in templates:
{% url 'ats:job_list' %}

# New references:
{% url 'ats:frontend:job_list' %}

# Old API references:
reverse('ats:job-posting-list')

# New API references:
reverse('ats:api:job-posting-list')
```

### Phase 3: Merge dashboard_service (3-5 days)

**Problem**: `dashboard_service` is redundant with `dashboard`

**Investigation**:
```bash
# Compare what's in each
ls -la dashboard/
ls -la dashboard_service/

# Check dependencies
grep -r "dashboard_service" . --exclude-dir=".git"
grep -r "from dashboard_service" . --exclude-dir=".git"
```

**Merge Process**:

1. **Analyze Models**
```python
# If dashboard_service has unique models
# Move to dashboard/models.py

# If models conflict
# Create migration to merge data
```

2. **Move Views**
```python
# dashboard_service/views.py → dashboard/views.py (API)
# dashboard_service/template_views.py → dashboard/template_views.py

# Avoid naming conflicts by prefixing
# service_statistics → service_layer_statistics
```

3. **Merge URLs**
```python
# dashboard/urls.py
# Include dashboard_service routes under /services/ or similar
```

4. **Update Imports**
```python
# Find all imports
grep -r "from dashboard_service" . --exclude-dir=".git"

# Replace with
# from dashboard.services import ...
```

5. **Remove from INSTALLED_APPS**
```python
# settings.py
TENANT_APPS = [
    # 'dashboard_service',  # REMOVED - merged into dashboard
    'dashboard',
]
```

6. **Delete Directory**
```bash
rm -rf dashboard_service/
```

### Phase 4: Standardize All Apps (10-15 days)

**For Each Remaining App**, apply this checklist:

**Checklist per App**:

```markdown
## App: {app_name}

### File Structure
- [ ] Create `template_views.py` if not exists
- [ ] Move template views from `views.py` to `template_views.py`
- [ ] Keep only API views in `views.py`
- [ ] Update `urls.py` with API/Frontend sections
- [ ] Add comprehensive docstrings to all views

### URL Organization
- [ ] Create `api_urlpatterns` list
- [ ] Create `frontend_urlpatterns` list
- [ ] Register ViewSets in `api_router`
- [ ] Use nested namespaces: `path('api/', include((api_urlpatterns, 'api')))`
- [ ] Use nested namespaces: `path('', include((frontend_urlpatterns, 'frontend')))`

### View Documentation
- [ ] All template views have docstrings with:
  - Features list
  - Template name
  - Context variables
  - Access requirements
- [ ] All API views have docstrings with:
  - Endpoint list
  - Custom actions
  - Filters/Search/Ordering
  - Permissions

### Dynamic Data
- [ ] Template views use filtering
- [ ] Template views use search
- [ ] Template views use pagination
- [ ] API views use DjangoFilterBackend
- [ ] API views use SearchFilter
- [ ] API views use OrderingFilter

### Update References
- [ ] Update all `{% url %}` tags in templates
- [ ] Update all `reverse()` calls in Python
- [ ] Update all URL references in tests
- [ ] Update all documentation

### Testing
- [ ] Run app tests: `pytest {app_name}/tests/`
- [ ] Run full test suite: `pytest`
- [ ] Manual testing of all frontend pages
- [ ] Manual testing of all API endpoints
```

### Phase 5: Documentation Update (2-3 days)

**5.1 Update Main Documentation**
- [ ] Update `CLAUDE.md` with new URL patterns
- [ ] Update API documentation
- [ ] Update developer guides
- [ ] Create migration guide for external developers

**5.2 Update All README files**
```bash
# For each app, update README.md
# Example: ats/README.md

# ATS (Applicant Tracking System)

## URLs

### API Endpoints
- List jobs: `GET /api/v1/jobs/job-postings/`
- Namespace: `api:v1:jobs:job-posting-list`

### Frontend Pages
- Browse jobs: `GET /jobs/jobs/`
- Namespace: `frontend:ats:job_list`

## Views
- API Views: `ats/views.py` (ViewSets)
- Template Views: `ats/template_views.py` (HTML)
```

**5.3 Create Migration Changelog**
```markdown
# CHANGELOG_URL_REORGANIZATION.md

## Breaking Changes

### URL Namespace Changes
All URL namespaces now use nested structure:

**Before**:
- `ats:job_list` → Job listing page
- `ats:job-posting-list` → API endpoint

**After**:
- `frontend:ats:job_list` → Job listing page
- `api:v1:jobs:job-posting-list` → API endpoint

### App Renames
- `custom_account_u` → `users`
- `messages_sys` → `messaging`
- `hr_core` → `hr`
- `appointment` → `appointments`
- `configurations` → `config`

### Migration Guide
... detailed steps for external code ...
```

---

## Implementation Order (Priority-Based)

### Week 1: HIGH Priority Apps
1. ✅ `accounts` (Already done - FreelancerProfile)
2. `users` (rename from custom_account_u)
3. `ats` (split views)
4. `ats_public` (split views)

### Week 2: HIGH Priority Apps
5. `hr` (rename from hr_core, split views)
6. `services` (split views)
7. `services_public` (split views)
8. `dashboard` + `dashboard_service` (merge + split)

### Week 3: MEDIUM Priority Apps
9. `tenants` (split views)
10. `messaging` (rename from messages_sys, split views)
11. `finance` (split views)
12. `appointments` (rename from appointment, split views)

### Week 4: MEDIUM/LOW Priority Apps
13. `analytics` (split views)
14. `integrations` (split views)
15. `notifications` (split views)
16. `careers` (split views)
17. `ai_matching` (split views)

### Week 5: LOW Priority Apps
18. `blog` (split views)
19. `config` (rename from configurations, split views)
20. `marketing` (split views)
21. `newsletter` (split views)
22. `security` (split views)

---

## Validation & Testing

### Automated Validation Script

```python
# scripts/validate_url_convention.py
"""
Validate that all apps follow the URL convention.
"""

import os
from pathlib import Path

def validate_app(app_path):
    """Validate an app follows conventions."""
    errors = []

    # Check file structure
    if not (app_path / 'template_views.py').exists():
        errors.append(f"Missing template_views.py")

    if not (app_path / 'views.py').exists():
        errors.append(f"Missing views.py")

    if not (app_path / 'urls.py').exists():
        errors.append(f"Missing urls.py")

    # Check urls.py structure
    urls_content = (app_path / 'urls.py').read_text()

    if 'api_urlpatterns' not in urls_content:
        errors.append(f"Missing api_urlpatterns in urls.py")

    if 'frontend_urlpatterns' not in urls_content:
        errors.append(f"Missing frontend_urlpatterns in urls.py")

    if "include((api_urlpatterns, 'api'))" not in urls_content:
        errors.append(f"Missing nested API namespace")

    if "include((frontend_urlpatterns, 'frontend'))" not in urls_content:
        errors.append(f"Missing nested frontend namespace")

    # Check views.py (should only have API views)
    views_content = (app_path / 'views.py').read_text()

    if 'render(' in views_content:
        errors.append(f"views.py contains template views (should be in template_views.py)")

    return errors

# Run validation
apps = Path('.').glob('*/')
for app in apps:
    if app.is_dir() and (app / 'models.py').exists():
        errors = validate_app(app)
        if errors:
            print(f"\n❌ {app.name}:")
            for error in errors:
                print(f"   - {error}")
        else:
            print(f"✅ {app.name}")
```

### Testing Checklist

**After Each App Reorganization**:
- [ ] Run app tests: `pytest {app}/tests/ -v`
- [ ] Test all frontend pages manually
- [ ] Test all API endpoints with Postman/curl
- [ ] Check URL reversal works: `python manage.py shell`
  ```python
  from django.urls import reverse
  reverse('frontend:jobs:job_list')
  reverse('api:v1:jobs:job-posting-list')
  ```
- [ ] Verify no broken template URLs
- [ ] Check admin still works

**After All Reorganization**:
- [ ] Run full test suite: `pytest -v`
- [ ] Run with coverage: `pytest --cov`
- [ ] Manual QA of all major features
- [ ] Load testing
- [ ] Check database migrations all applied

---

## Rollback Plan

### Per-App Rollback
```bash
# If reorganization of specific app fails
git checkout main -- {app_name}/
git reset HEAD {app_name}/
```

### Full Rollback
```bash
# If entire reorganization needs rollback
git checkout backup/pre-url-reorganization
git checkout -b main-restored
# Manual review and selective merge
```

---

## Success Criteria

**This reorganization is complete when**:

1. ✅ All apps have separate `template_views.py` and `views.py`
2. ✅ All apps use nested namespaces (`frontend:app:*` and `api:v1:app:*`)
3. ✅ No confusing app names (all renamed)
4. ✅ `dashboard_service` merged into `dashboard`
5. ✅ All tests passing (100% of previous test count)
6. ✅ All templates updated with new namespaces
7. ✅ All documentation updated
8. ✅ Validation script passes 100%

---

## Notes

- **CRITICAL**: This is a breaking change for any external code using URLs
- **Timeline**: 4-5 weeks with 1-2 developers
- **Risk**: HIGH - touches every app
- **Benefit**: MASSIVE improvement in code organization and maintainability
- **Backward Compatibility**: NONE - clean break for better architecture

**This reorganization makes Zumodra's codebase world-class and maintainable.**
