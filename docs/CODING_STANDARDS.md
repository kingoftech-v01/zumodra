# Coding Standards

**Author:** Backend Lead Developer
**Date:** January 16, 2026
**Sprint:** Days 1-5 (January 16-21, 2026)
**Status:** ✅ **APPROVED STANDARDS**

---

## Purpose

This document defines coding standards for the Zumodra platform. All developers must follow these standards to ensure code quality, consistency, and maintainability.

---

## Table of Contents

1. [Python Style](#python-style)
2. [Django Patterns](#django-patterns)
3. [API Design](#api-design)
4. [Frontend/Templates](#frontend-templates)
5. [Security](#security)
6. [Performance](#performance)
7. [Testing](#testing)
8. [Documentation](#documentation)
9. [Git Workflow](#git-workflow)
10. [Code Review](#code-review)

---

## Python Style

### Formatting

**Tool:** Black (line length: 120 characters)

```bash
# Format all Python files
black . --line-length 120

# Check formatting without changes
black . --check --line-length 120
```

**Tool:** isort (import sorting)

```bash
# Sort imports
isort .

# Check import sorting
isort . --check-only
```

### Linting

**Tools:** flake8, pylint

```bash
# Run flake8
flake8 . --max-line-length=120 --extend-ignore=E203,W503

# Run pylint
pylint apps/
```

**CI Enforcement:** All PRs must pass Black, isort, flake8, and pylint checks.

### Naming Conventions

```python
# Classes: PascalCase
class JobPosting:
    pass

class UserProfile:
    pass

# Functions, methods, variables: snake_case
def get_active_jobs():
    pass

def send_notification(user_id, message_text):
    pass

user_count = 10
application_status = 'pending'

# Constants: UPPER_SNAKE_CASE
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
DEFAULT_TIMEOUT = 30
API_VERSION = 'v1'

# Private methods/attributes: _leading_underscore
class User:
    def _internal_method(self):
        pass

    def _calculate_score(self):
        pass

# Protected (subclass use): Single underscore
class BaseModel:
    def _validate_data(self):
        """Protected method for subclass validation."""
        pass

# Name mangling (truly private): __double_underscore
class Secret:
    def __encrypt(self):
        """Truly private method with name mangling."""
        pass
```

### Type Hints

**Required:** All public functions, methods, and class attributes must have type hints.

```python
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime
from django.db.models import QuerySet

# Function type hints
def get_job_by_id(job_id: UUID) -> Optional['JobPosting']:
    """Retrieve job by UUID."""
    try:
        return JobPosting.objects.get(uuid=job_id)
    except JobPosting.DoesNotExist:
        return None

# Method type hints
class JobService:
    def create_job(
        self,
        title: str,
        description: str,
        job_type: str,
        salary_min: Optional[int] = None,
        salary_max: Optional[int] = None
    ) -> 'JobPosting':
        """Create a new job posting."""
        return JobPosting.objects.create(
            title=title,
            description=description,
            job_type=job_type,
            salary_min=salary_min,
            salary_max=salary_max
        )

    def get_active_jobs(self) -> QuerySet['JobPosting']:
        """Get all active jobs."""
        return JobPosting.objects.filter(status='active')

    def get_job_stats(self) -> Dict[str, Any]:
        """Get job statistics."""
        return {
            'total': JobPosting.objects.count(),
            'active': JobPosting.objects.filter(status='active').count(),
            'closed': JobPosting.objects.filter(status='closed').count()
        }
```

### Docstrings

**Required:** All public classes, methods, and functions must have docstrings.

**Format:** Google-style docstrings

```python
def schedule_interview(
    application: 'Application',
    interview_type: str,
    scheduled_at: datetime,
    interviewers: List['User'],
    location: Optional[str] = None
) -> 'Interview':
    """Schedule an interview for an application.

    Creates an interview instance, sends calendar invites to interviewers,
    and notifies the candidate.

    Args:
        application: The application to schedule an interview for
        interview_type: Type of interview (phone, video, onsite)
        scheduled_at: When to schedule the interview
        interviewers: List of users who will conduct the interview
        location: Physical location or video conference URL (optional)

    Returns:
        Interview: The created interview instance with all participants added

    Raises:
        ValidationError: If scheduled_at is in the past
        ValueError: If interview_type is invalid
        PermissionError: If user doesn't have permission to schedule

    Example:
        >>> application = Application.objects.get(uuid='...')
        >>> interviewers = [User.objects.get(id=1), User.objects.get(id=2)]
        >>> interview = schedule_interview(
        ...     application=application,
        ...     interview_type='video',
        ...     scheduled_at=datetime(2026, 1, 20, 10, 0),
        ...     interviewers=interviewers,
        ...     location='https://zoom.us/j/123456789'
        ... )
    """
    # Implementation
    pass
```

### Imports

**Order (enforced by isort):**

```python
# 1. Standard library imports
import os
import sys
from datetime import datetime, timedelta
from typing import Optional, List
from uuid import UUID

# 2. Third-party imports
import redis
from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from rest_framework import serializers, viewsets

# 3. Local application imports
from core.db.models import TenantAwareModel
from core.permissions import IsTenantMember
from .models import JobPosting, Application
from .services import JobService
from .tasks import sync_job_to_catalog_task
```

**Import Style:**

```python
# Good: Explicit imports
from django.contrib.auth import get_user_model
from rest_framework.decorators import action
from rest_framework.response import Response

# Avoid: Star imports (except in __init__.py)
from django.db.models import *  # Bad

# Exception: Common aggregates/functions
from django.db.models import Count, Q, F, Prefetch  # OK
```

---

## Django Patterns

### Models

**Always inherit from tenant-aware base models:**

```python
from core.db.models import TenantAwareModel, TenantSoftDeleteModel
from django.db import models
from uuid import uuid4

class JobPosting(TenantAwareModel):
    """Job posting model - automatically scoped to current tenant.

    Attributes:
        uuid: Unique identifier
        title: Job title
        description: Job description
        status: Current status (draft, active, closed)
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """
    uuid = models.UUIDField(default=uuid4, editable=False, unique=True)
    title = models.CharField(max_length=255, help_text="Job title")
    description = models.TextField(help_text="Full job description")
    status = models.CharField(
        max_length=20,
        choices=[
            ('draft', 'Draft'),
            ('active', 'Active'),
            ('closed', 'Closed')
        ],
        default='draft'
    )

    class Meta:
        db_table = 'ats_job_postings'
        verbose_name = 'Job Posting'
        verbose_name_plural = 'Job Postings'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['uuid']),
        ]

    def __str__(self) -> str:
        return f"{self.title} ({self.get_status_display()})"

    def save(self, *args, **kwargs):
        """Override save to add custom logic."""
        # Custom validation
        if self.status == 'active' and not self.description:
            raise ValueError("Active jobs must have a description")

        super().save(*args, **kwargs)

        # Post-save actions (consider using signals instead)
        if self.status == 'active':
            from .tasks import sync_job_to_catalog_task
            sync_job_to_catalog_task.delay(str(self.uuid))
```

**Model Guidelines:**
- Use `uuid` for primary keys (better for distributed systems)
- Add `help_text` to all fields
- Use `choices` for status fields
- Add database indexes for frequently queried fields
- Use `select_related()` and `prefetch_related()` to avoid N+1 queries
- Override `__str__()` for readable representation

### Managers and QuerySets

**Custom managers for reusable queries:**

```python
from django.db import models
from core.db.managers import TenantAwareManager

class JobPostingQuerySet(models.QuerySet):
    """Custom queryset for job postings."""

    def active(self):
        """Get only active jobs."""
        return self.filter(status='active')

    def closed(self):
        """Get only closed jobs."""
        return self.filter(status='closed')

    def with_application_count(self):
        """Annotate with application count."""
        return self.annotate(application_count=models.Count('applications'))

    def with_full_details(self):
        """Prefetch all related data for detail views."""
        return self.select_related(
            'category',
            'created_by'
        ).prefetch_related(
            'applications',
            'applications__candidate',
            'interviews'
        )

class JobPostingManager(TenantAwareManager):
    """Custom manager for job postings."""

    def get_queryset(self):
        """Return custom queryset."""
        return JobPostingQuerySet(self.model, using=self._db)

    def active(self):
        """Get active jobs."""
        return self.get_queryset().active()

    def create_job(self, **kwargs):
        """Create job with defaults."""
        kwargs.setdefault('status', 'draft')
        return self.create(**kwargs)

class JobPosting(TenantAwareModel):
    # ... fields ...

    objects = JobPostingManager()

    class Meta:
        # ... meta ...
```

**Usage:**

```python
# Get all active jobs
active_jobs = JobPosting.objects.active()

# Get active jobs with application counts
jobs_with_counts = JobPosting.objects.active().with_application_count()

# Get job with all details for detail view
job = JobPosting.objects.with_full_details().get(uuid=job_uuid)
```

### Views & ViewSets

**API ViewSets:**

```python
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from core.viewsets import SecureTenantViewSet
from .models import JobPosting, Application
from .serializers import (
    JobPostingListSerializer,
    JobPostingDetailSerializer,
    JobPostingCreateSerializer
)

class JobPostingViewSet(SecureTenantViewSet):
    """Job posting API endpoints.

    Provides CRUD operations for job postings plus custom actions.
    Automatically scoped to current tenant.
    """
    queryset = JobPosting.objects.all()
    filterset_fields = ['status', 'job_type', 'category']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'title', 'application_count']

    def get_queryset(self):
        """Optimize queryset based on action."""
        queryset = super().get_queryset()

        if self.action == 'list':
            # Minimal data for list view
            queryset = queryset.select_related('category')
        elif self.action == 'retrieve':
            # Full data for detail view
            queryset = queryset.with_full_details()

        return queryset

    def get_serializer_class(self):
        """Return appropriate serializer for action."""
        if self.action == 'list':
            return JobPostingListSerializer
        elif self.action == 'create':
            return JobPostingCreateSerializer
        return JobPostingDetailSerializer

    @action(detail=True, methods=['post'])
    def publish(self, request, pk=None):
        """Publish a draft job posting.

        Changes status from draft to active and triggers catalog sync.
        """
        job = self.get_object()

        if job.status != 'draft':
            return Response(
                {'error': 'Only draft jobs can be published'},
                status=status.HTTP_400_BAD_REQUEST
            )

        job.status = 'active'
        job.save()

        serializer = self.get_serializer(job)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def dashboard_stats(self, request):
        """Get job posting statistics for dashboard."""
        stats = {
            'total': self.get_queryset().count(),
            'active': self.get_queryset().active().count(),
            'draft': self.get_queryset().filter(status='draft').count(),
            'closed': self.get_queryset().closed().count(),
        }
        return Response(stats)
```

**Template Views (CBV):**

```python
from django.views.generic import ListView, DetailView, CreateView
from django.contrib.auth.mixins import LoginRequiredMixin
from core.views import TenantRequiredMixin
from .models import JobPosting
from .forms import JobPostingForm

class JobListView(LoginRequiredMixin, TenantRequiredMixin, ListView):
    """List all job postings."""
    model = JobPosting
    template_name = 'ats/job_list.html'
    context_object_name = 'jobs'
    paginate_by = 20

    def get_queryset(self):
        """Filter queryset based on request parameters."""
        queryset = super().get_queryset()

        # Filter by status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)

        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                models.Q(title__icontains=search) |
                models.Q(description__icontains=search)
            )

        return queryset.with_application_count()

    def get_context_data(self, **kwargs):
        """Add extra context."""
        context = super().get_context_data(**kwargs)
        context['status_filter'] = self.request.GET.get('status', '')
        context['search_query'] = self.request.GET.get('search', '')
        context['job_counts'] = {
            'total': JobPosting.objects.count(),
            'active': JobPosting.objects.active().count(),
            'draft': JobPosting.objects.filter(status='draft').count(),
        }
        return context
```

### Serializers

```python
from rest_framework import serializers
from core.serializers import TenantAwareModelSerializer
from .models import JobPosting, Application

class JobPostingListSerializer(TenantAwareModelSerializer):
    """Minimal serializer for list views."""
    application_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = JobPosting
        fields = ['uuid', 'title', 'status', 'job_type', 'created_at', 'application_count']
        read_only_fields = ['uuid', 'created_at']

class JobPostingDetailSerializer(TenantAwareModelSerializer):
    """Complete serializer for detail views."""
    category = JobCategorySerializer(read_only=True)
    applications = ApplicationListSerializer(many=True, read_only=True)
    application_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = JobPosting
        fields = '__all__'
        read_only_fields = ['uuid', 'created_at', 'updated_at']

class JobPostingCreateSerializer(TenantAwareModelSerializer):
    """Write-only serializer for creation."""

    class Meta:
        model = JobPosting
        fields = ['title', 'description', 'job_type', 'category', 'salary_min', 'salary_max']

    def validate_title(self, value):
        """Validate title is not empty."""
        if not value.strip():
            raise serializers.ValidationError("Title cannot be empty")
        return value.strip()

    def validate(self, data):
        """Cross-field validation."""
        if data.get('salary_min') and data.get('salary_max'):
            if data['salary_min'] > data['salary_max']:
                raise serializers.ValidationError(
                    "Minimum salary cannot be greater than maximum salary"
                )
        return data
```

---

## API Design

### REST Principles

**URLs:**
- Use plural nouns: `/api/v1/jobs/`, not `/api/v1/job/`
- Use hyphens: `/api/v1/time-off-requests/`, not `/api/v1/time_off_requests/`
- No trailing slashes in requests (DRF handles both)

**HTTP Methods:**
- GET: Retrieve resource(s)
- POST: Create new resource
- PUT: Full update of resource
- PATCH: Partial update of resource
- DELETE: Delete resource

**Status Codes:**
- 200 OK: Successful GET, PATCH, PUT
- 201 Created: Successful POST
- 204 No Content: Successful DELETE
- 400 Bad Request: Validation error
- 401 Unauthorized: Not authenticated
- 403 Forbidden: Authenticated but no permission
- 404 Not Found: Resource doesn't exist
- 500 Internal Server Error: Server error

### Response Format

**Success Response:**

```json
{
    "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "title": "Senior Python Developer",
    "status": "active",
    "created_at": "2026-01-16T10:00:00Z"
}
```

**List Response (with pagination):**

```json
{
    "count": 100,
    "next": "https://api.example.com/api/v1/jobs/?page=2",
    "previous": null,
    "results": [
        {
            "uuid": "...",
            "title": "..."
        }
    ]
}
```

**Error Response:**

```json
{
    "detail": "Error message here",
    "code": "error_code",
    "field_errors": {
        "email": ["This field is required"],
        "salary_min": ["Must be a positive number"]
    }
}
```

### Pagination

**Always paginate list endpoints:**

```python
# In ViewSet
pagination_class = PageNumberPagination
paginate_by = 20  # Default page size
max_paginate_by = 100  # Maximum allowed
```

### Filtering & Search

```python
from django_filters import rest_framework as filters

class JobPostingViewSet(SecureTenantViewSet):
    # Basic filtering
    filterset_fields = ['status', 'job_type', 'category']

    # Search
    search_fields = ['title', 'description', 'requirements']

    # Ordering
    ordering_fields = ['created_at', 'title', 'salary_min']
    ordering = ['-created_at']  # Default ordering
```

**Usage:**
```
GET /api/v1/jobs/?status=active&job_type=full_time
GET /api/v1/jobs/?search=python
GET /api/v1/jobs/?ordering=-created_at
```

### Authentication & Permissions

```python
from rest_framework.permissions import IsAuthenticated
from core.permissions import IsTenantMember, IsRecruiterOrAbove

class JobPostingViewSet(SecureTenantViewSet):
    permission_classes = [IsAuthenticated, IsTenantMember, IsRecruiterOrAbove]

    def get_permissions(self):
        """Different permissions per action."""
        if self.action in ['list', 'retrieve']:
            return [IsAuthenticated(), IsTenantMember()]
        elif self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [IsAuthenticated(), IsTenantMember(), IsRecruiterOrAbove()]
        return super().get_permissions()
```

---

## Frontend/Templates

### Template Structure

```django
{% extends "base/unified_base.html" %}
{% load static %}

{% block title %}Job Listings{% endblock %}

{% block extra_css %}
<link rel="stylesheet" href="{% static 'css/ats/jobs.css' %}">
{% endblock %}

{% block content %}
<div class="container mx-auto px-4 py-8">
    <h1 class="text-3xl font-bold mb-6">Job Listings</h1>

    <!-- Content here -->
</div>
{% endblock %}

{% block extra_js %}
<script src="{% static 'js/ats/jobs.js' %}"></script>
{% endblock %}
```

### HTMX Patterns

**Load content on trigger:**

```django
<div hx-get="{% url 'frontend:dashboard:htmx-quick-stats' %}"
     hx-trigger="load"
     hx-swap="innerHTML">
    <p class="text-gray-500">Loading stats...</p>
</div>
```

**Form submission:**

```django
<form hx-post="{% url 'frontend:ats:job-create' %}"
      hx-target="#job-list"
      hx-swap="beforeend">
    {% csrf_token %}
    <!-- Form fields -->
    <button type="submit">Create Job</button>
</form>
```

**Infinite scroll:**

```django
<div id="job-list">
    {% for job in jobs %}
        {% include 'ats/partials/_job_card.html' %}
    {% endfor %}
</div>

{% if page_obj.has_next %}
<div hx-get="{% url 'frontend:ats:job-list' %}?page={{ page_obj.next_page_number }}"
     hx-trigger="revealed"
     hx-swap="afterend">
    Loading more...
</div>
{% endif %}
```

### Alpine.js Patterns

**Component with state:**

```html
<div x-data="{ open: false }">
    <button @click="open = !open">Toggle</button>
    <div x-show="open" x-transition>
        Content here
    </div>
</div>
```

**Dropdown:**

```html
<div x-data="{ open: false }" @click.away="open = false">
    <button @click="open = !open">
        Actions
    </button>
    <div x-show="open" x-transition>
        <a href="#">Edit</a>
        <a href="#">Delete</a>
    </div>
</div>
```

### Tailwind CSS

**Use utility classes:**

```html
<!-- Good: Utility classes -->
<div class="bg-white shadow-md rounded-lg p-6 mb-4">
    <h2 class="text-2xl font-bold text-gray-900 mb-2">Title</h2>
    <p class="text-gray-600">Description</p>
</div>

<!-- Avoid: Inline styles -->
<div style="background: white; padding: 24px;">  <!-- Bad -->
```

---

## Security

### Input Validation

**Always validate user input:**

```python
from core.validators import validate_url_no_ssrf

class ServiceSerializer(serializers.ModelSerializer):
    website_url = serializers.URLField(
        required=False,
        validators=[validate_url_no_ssrf]  # Prevent SSRF attacks
    )

    def validate_email(self, value):
        """Validate email format."""
        if not value:
            raise serializers.ValidationError("Email is required")
        # Additional validation
        return value.lower()
```

### SQL Injection Prevention

**Always use ORM or parameterized queries:**

```python
# Good: ORM
jobs = JobPosting.objects.filter(status='active', title__icontains=search_term)

# Good: Parameterized query
from django.db import connection
cursor = connection.cursor()
cursor.execute("SELECT * FROM jobs WHERE status = %s", [status])

# BAD: String formatting (SQL injection risk)
cursor.execute(f"SELECT * FROM jobs WHERE status = '{status}'")  # NEVER DO THIS
```

### XSS Prevention

**Templates auto-escape by default:**

```django
<!-- Auto-escaped (safe) -->
{{ user_input }}

<!-- Manual escaping (if needed) -->
{{ user_input|escape }}

<!-- Mark as safe ONLY if you trust the content -->
{{ trusted_html|safe }}

<!-- Use bleach for user HTML -->
{% load bleach_tags %}
{{ user_html|bleach }}
```

### CSRF Protection

**Always include CSRF token in forms:**

```django
<form method="post">
    {% csrf_token %}
    <!-- Form fields -->
</form>
```

**For AJAX requests:**

```javascript
// Get CSRF token from cookie
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

const csrftoken = getCookie('csrftoken');

// Include in fetch
fetch(url, {
    method: 'POST',
    headers: {
        'X-CSRFToken': csrftoken
    },
    body: JSON.stringify(data)
});
```

### Permission Checks

**Always check permissions:**

```python
from django.core.exceptions import PermissionDenied

def delete_job(request, job_id):
    job = get_object_or_404(JobPosting, uuid=job_id)

    # Check permission
    if not request.user.has_perm('ats.delete_jobposting'):
        raise PermissionDenied

    job.delete()
    return redirect('job_list')
```

---

## Performance

### Database Queries

**Avoid N+1 queries:**

```python
# Bad: N+1 query
jobs = JobPosting.objects.all()
for job in jobs:
    print(job.category.name)  # Triggers query for each job

# Good: Use select_related for FK
jobs = JobPosting.objects.select_related('category').all()
for job in jobs:
    print(job.category.name)  # No additional queries

# Good: Use prefetch_related for M2M/reverse FK
jobs = JobPosting.objects.prefetch_related('applications').all()
for job in jobs:
    print(job.applications.count())  # No additional queries
```

### Caching

**Use tenant-aware caching:**

```python
from core.cache import TenantCache

def get_job_stats():
    """Get job statistics with caching."""
    cache_key = 'job_stats'
    stats = TenantCache.get(cache_key)

    if stats is None:
        stats = {
            'total': JobPosting.objects.count(),
            'active': JobPosting.objects.active().count(),
        }
        TenantCache.set(cache_key, stats, timeout=300)  # 5 minutes

    return stats
```

### Indexing

**Add indexes for frequently queried fields:**

```python
class JobPosting(TenantAwareModel):
    # ... fields ...

    class Meta:
        indexes = [
            models.Index(fields=['status', 'created_at']),  # Composite index
            models.Index(fields=['uuid']),  # Single field index
            models.Index(fields=['-created_at']),  # Descending index
        ]
```

### Pagination

**Always paginate large datasets:**

```python
from django.core.paginator import Paginator

def job_list(request):
    jobs = JobPosting.objects.all()
    paginator = Paginator(jobs, 20)  # 20 items per page

    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'jobs.html', {'page_obj': page_obj})
```

---

## Testing

### Test Organization

```
app_name/tests/
├── __init__.py
├── test_models.py              # Model tests
├── test_api.py                 # API endpoint tests
├── test_views.py               # Template view tests
├── test_permissions.py         # Permission tests
├── test_services.py            # Service layer tests
└── test_workflows.py           # End-to-end workflow tests
```

### Model Tests

```python
from django.test import TestCase
from .models import JobPosting

class JobPostingModelTests(TestCase):
    def setUp(self):
        """Set up test data."""
        self.job = JobPosting.objects.create(
            title='Python Developer',
            description='Test job',
            status='draft'
        )

    def test_job_creation(self):
        """Test job can be created."""
        self.assertEqual(self.job.title, 'Python Developer')
        self.assertEqual(self.job.status, 'draft')

    def test_job_str_representation(self):
        """Test string representation."""
        expected = f"Python Developer (Draft)"
        self.assertEqual(str(self.job), expected)

    def test_active_job_requires_description(self):
        """Test active job validation."""
        self.job.description = ''
        self.job.status = 'active'

        with self.assertRaises(ValueError):
            self.job.save()
```

### API Tests

```python
from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

class JobPostingAPITests(APITestCase):
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)

        self.job = JobPosting.objects.create(
            title='Python Developer',
            description='Test job',
            status='active'
        )

    def test_list_jobs(self):
        """Test listing jobs."""
        url = reverse('api:v1:ats:job-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)

    def test_create_job(self):
        """Test creating a job."""
        url = reverse('api:v1:ats:job-list')
        data = {
            'title': 'New Job',
            'description': 'New job description',
            'job_type': 'full_time'
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(JobPosting.objects.count(), 2)

    def test_publish_job(self):
        """Test publishing a draft job."""
        self.job.status = 'draft'
        self.job.save()

        url = reverse('api:v1:ats:job-publish', args=[self.job.uuid])
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, 'active')
```

### Coverage

**Minimum:** 70% coverage (target 80%+)

```bash
# Run tests with coverage
pytest --cov=apps --cov-report=html --cov-report=term

# View HTML report
open htmlcov/index.html
```

---

## Documentation

### Code Comments

**When to comment:**
- Complex algorithms
- Non-obvious business logic
- Workarounds for bugs
- Performance optimizations
- Security considerations

**Good comments:**

```python
# Calculate trust score based on verification status and user activity
# Score ranges from 0-100, where 100 is fully verified with high activity
trust_score = base_score + verification_bonus + activity_bonus

# WORKAROUND: Django 5.2 has a bug with select_related on multi-tenant models
# See: https://github.com/django/django/issues/12345
# TODO: Remove this workaround when Django 5.3 is released
jobs = JobPosting.objects.all()  # Cannot use select_related here
```

**Bad comments:**

```python
# Increment counter
counter += 1  # Obvious from code

# Get jobs
jobs = JobPosting.objects.all()  # Doesn't add value
```

### README Files

**Every app must have a README:**

```markdown
# App Name

## Overview
Brief description

## Models
- Model1 - Description
- Model2 - Description

## API Endpoints
- GET /api/v1/jobs/ - List jobs
- POST /api/v1/jobs/ - Create job

## Views
- JobListView - List jobs
- JobDetailView - Job detail

## Permissions
- View jobs: All tenant members
- Create jobs: Recruiters and above

## Testing
- Coverage: 85%
- Run tests: pytest apps/ats/tests/
```

---

## Git Workflow

### Branch Naming

```
feature/add-interview-scheduling
fix/job-duplicate-bug
refactor/api-serializers
docs/update-readme
chore/upgrade-dependencies
```

### Commit Messages

**Format:** `type(scope): description`

```
feat(ats): add interview scheduling feature
fix(api): resolve N+1 query in job listing
refactor(serializers): simplify job serializer
docs(readme): update installation instructions
test(ats): add tests for job workflow
chore(deps): upgrade Django to 5.2.7
```

### Pull Requests

**PR Title:** Same as commit message format

**PR Description Template:**

```markdown
## Summary
Brief description of changes

## Changes
- Change 1
- Change 2

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Screenshots (if applicable)
[Add screenshots]

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No security vulnerabilities
```

---

## Code Review

### Reviewer Checklist

**Functionality:**
- [ ] Code does what it claims
- [ ] Edge cases handled
- [ ] Error handling appropriate

**Code Quality:**
- [ ] Follows coding standards
- [ ] No code duplication
- [ ] Clear variable names
- [ ] Appropriate comments

**Performance:**
- [ ] No N+1 queries
- [ ] Appropriate indexes
- [ ] Caching where needed
- [ ] Pagination on large datasets

**Security:**
- [ ] Input validation
- [ ] Permission checks
- [ ] No SQL injection risk
- [ ] No XSS vulnerabilities
- [ ] CSRF protection

**Testing:**
- [ ] Tests added/updated
- [ ] Tests pass
- [ ] Good coverage

**Documentation:**
- [ ] Code documented
- [ ] README updated
- [ ] API docs updated

### Review Comments

**Good:**
- "Consider caching this query for better performance"
- "Add an index on this field since it's frequently queried"
- "This could cause an N+1 query. Use select_related?"

**Avoid:**
- "This is wrong" (too vague)
- "I don't like this" (subjective)

---

## Tools & Automation

### Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

### CI/CD Checks

All PRs must pass:
- [ ] Black formatting
- [ ] isort import sorting
- [ ] flake8 linting
- [ ] pylint checks
- [ ] All tests passing
- [ ] 70%+ coverage
- [ ] Security scan (bandit)

---

## References

- [App Structure](APP_STRUCTURE.md)
- [URL Conventions](URL_CONVENTIONS.md)
- [Architecture](ARCHITECTURE.md)
- [Settings](SETTINGS.md)

---

**Version:** 1.0
**Last Updated:** January 16, 2026
**Maintainer:** Backend Lead Developer
**Status:** Living Document - Update as patterns evolve
