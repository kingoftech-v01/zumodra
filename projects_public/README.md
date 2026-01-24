# Projects Public Catalog

> **Cross-tenant public project browsing without authentication**

The `projects_public` app provides a denormalized, read-only catalog of all published projects across all tenants in the Zumodra platform. This enables users to browse project opportunities without logging in or knowing which tenant posted them.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Models](#models)
- [API Endpoints](#api-endpoints)
- [Sync Mechanism](#sync-mechanism)
- [Usage Examples](#usage-examples)
- [Performance](#performance)

## Overview

### Purpose

The projects public catalog serves multiple purposes:

1. **Discovery**: Users can browse all available project opportunities across tenants
2. **SEO**: Public project listings are indexable by search engines
3. **Performance**: Denormalized data enables fast queries without tenant context switching
4. **Privacy**: Sensitive data is excluded; only public-safe information is synced

### How It Works

```
┌─────────────────┐
│ Tenant Project  │
│ (projects app)  │
└────────┬────────┘
         │ Signal: post_save
         ↓
┌─────────────────┐
│  Celery Task    │
│  (async sync)   │
└────────┬────────┘
         │ Denormalize data
         ↓
┌─────────────────┐
│ Public Catalog  │
│ (public schema) │
└─────────────────┘
```

### Key Features

- **No Authentication Required**: Anyone can browse
- **Cross-Tenant Search**: Find projects across all companies
- **Geographic Queries**: PostGIS-powered location search
- **Full-Text Search**: Fast search on title/description
- **Automatic Sync**: Real-time updates via Celery
- **Read-Only**: Catalog cannot be modified directly

## Architecture

### Database Schema

The `projects_public` app lives in the **public schema** (SHARED_APPS), not in tenant schemas. This allows querying across all tenants without schema switching.

```
Public Schema (public)
├── projects_public_catalog      # Main catalog table
└── projects_public_stats        # Aggregated statistics
```

### Data Flow

1. **Company publishes project** in `projects` app (tenant schema)
2. **Django signal fires** on `Project.save()`
3. **Celery task queued** to sync data
4. **Worker denormalizes** project data
5. **PublicProjectCatalog entry** created/updated in public schema
6. **Public API** serves denormalized data

### Security Model

- **No write access**: Catalog is read-only
- **Redirect to tenant**: Actions redirect to tenant subdomain
- **HTML sanitization**: All text fields sanitized (nh3)
- **PII exclusion**: Contact info, internal notes excluded
- **CORS-enabled**: Public API accessible from any origin

## Models

### PublicProjectCatalog

Denormalized project catalog entry.

```python
class PublicProjectCatalog(models.Model):
    """
    Public catalog entry for cross-tenant project browsing.
    Synced from tenant projects via Celery tasks.
    """
    # Source tracking
    tenant_id = models.IntegerField(db_index=True)
    tenant_project_id = models.IntegerField()
    tenant_schema = models.CharField(max_length=63)

    # Identifiers
    uuid = models.UUIDField(unique=True, db_index=True)

    # Project info
    title = models.CharField(max_length=255, db_index=True)
    description = models.TextField()
    short_description = models.CharField(max_length=500, blank=True)
    category_name = models.CharField(max_length=100, db_index=True)
    category_slug = models.SlugField(max_length=120, db_index=True)

    # Requirements
    required_skills = models.JSONField(default=list)
    experience_level = models.CharField(max_length=20, db_index=True)

    # Timeline
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    estimated_duration_weeks = models.PositiveIntegerField(null=True)
    deadline = models.DateTimeField(null=True, blank=True)

    # Budget
    budget_type = models.CharField(max_length=20, db_index=True)
    budget_min = models.DecimalField(max_digits=10, decimal_places=2, db_index=True)
    budget_max = models.DecimalField(max_digits=10, decimal_places=2, db_index=True)
    budget_currency = models.CharField(max_length=3, default='CAD')

    # Location
    location_type = models.CharField(max_length=20, db_index=True)
    location_city = models.CharField(max_length=100, blank=True, db_index=True)
    location_country = models.CharField(max_length=100, blank=True, db_index=True)
    location_coordinates = gis_models.PointField(geography=True, null=True)

    # Company info
    company_name = models.CharField(max_length=255, db_index=True)
    company_logo_url = models.URLField(blank=True)
    company_domain = models.CharField(max_length=253)

    # Proposal stats
    max_proposals = models.PositiveIntegerField(default=20)
    proposal_count = models.PositiveIntegerField(default=0)
    proposal_deadline = models.DateTimeField(null=True, blank=True)

    # Status
    is_open = models.BooleanField(default=True, db_index=True)
    is_featured = models.BooleanField(default=False, db_index=True)

    # Sync metadata
    published_at = models.DateTimeField(db_index=True)
    synced_at = models.DateTimeField(auto_now=True)

    # URLs
    project_url = models.URLField()
    application_url = models.URLField()

    # SEO
    meta_title = models.CharField(max_length=60, blank=True)
    meta_description = models.CharField(max_length=160, blank=True)

    class Meta:
        db_table = 'projects_public_catalog'
        indexes = [
            models.Index(fields=['category_slug', '-published_at']),
            models.Index(fields=['location_country', 'location_city']),
            models.Index(fields=['budget_min', 'budget_max']),
            models.Index(fields=['-is_featured', '-published_at']),
            models.Index(fields=['is_open', 'experience_level']),
        ]
        ordering = ['-published_at']
```

### PublicProjectStats

Aggregated statistics for analytics.

```python
class PublicProjectStats(models.Model):
    """Daily statistics snapshot for public projects."""
    snapshot_date = models.DateField(unique=True, db_index=True)

    # Overall counts
    total_projects = models.PositiveIntegerField(default=0)
    open_projects = models.PositiveIntegerField(default=0)
    total_companies = models.PositiveIntegerField(default=0)

    # By category
    by_category = models.JSONField(default=dict)
    by_country = models.JSONField(default=dict)
    by_budget_range = models.JSONField(default=dict)

    # Averages
    avg_budget = models.DecimalField(max_digits=10, decimal_places=2, null=True)
    avg_duration_weeks = models.DecimalField(max_digits=5, decimal_places=2, null=True)
    avg_proposals_per_project = models.DecimalField(max_digits=5, decimal_places=2, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

## API Endpoints

### Base URL
```
/api/v1/public/projects/
```

### Available Endpoints

#### List Projects
```
GET /api/v1/public/projects/
```

**Query Parameters:**
```
?category_slug=web-development
?experience_level=SENIOR
?budget_type=FIXED
?location_type=REMOTE
?location_country=Canada
?location_city=Toronto
?search=website redesign
?is_open=true
?is_featured=true
?ordering=-published_at
?limit=20
?offset=0
```

**Response:**
```json
{
  "count": 150,
  "next": "http://api.example.com/api/v1/public/projects/?offset=20",
  "previous": null,
  "results": [
    {
      "uuid": "123e4567-e89b-12d3-a456-426614174000",
      "title": "Redesign E-commerce Website",
      "short_description": "Complete redesign of our online store with modern UX",
      "category_name": "Web Development",
      "category_slug": "web-development",
      "required_skills": ["React", "Node.js", "PostgreSQL"],
      "experience_level": "SENIOR",
      "budget_type": "FIXED",
      "budget_min": "15000.00",
      "budget_max": "20000.00",
      "budget_currency": "CAD",
      "location_type": "REMOTE",
      "company_name": "TechCorp Inc.",
      "company_logo_url": "https://...",
      "estimated_duration_weeks": 12,
      "deadline": "2026-06-30T23:59:59Z",
      "proposal_count": 5,
      "max_proposals": 15,
      "is_open": true,
      "is_featured": false,
      "published_at": "2026-01-15T10:30:00Z",
      "project_url": "https://techcorp.zumodra.com/projects/123e4567.../",
      "application_url": "https://techcorp.zumodra.com/projects/123e4567.../apply/"
    }
  ]
}
```

#### Project Detail
```
GET /api/v1/public/projects/{uuid}/
```

**Response:**
```json
{
  "uuid": "123e4567-e89b-12d3-a456-426614174000",
  "tenant_project_id": 42,
  "tenant_id": 5,
  "tenant_schema": "techcorp",
  "title": "Redesign E-commerce Website",
  "description": "Full project description with all details...",
  "short_description": "Complete redesign of our online store",
  "category_name": "Web Development",
  "category_slug": "web-development",
  "required_skills": ["React", "Node.js", "PostgreSQL", "AWS"],
  "experience_level": "SENIOR",
  "start_date": "2026-03-01",
  "end_date": "2026-05-31",
  "estimated_duration_weeks": 12,
  "deadline": "2026-02-28T23:59:59Z",
  "budget_type": "FIXED",
  "budget_min": "15000.00",
  "budget_max": "20000.00",
  "budget_currency": "CAD",
  "location_type": "REMOTE",
  "location_city": null,
  "location_country": null,
  "company_name": "TechCorp Inc.",
  "company_logo_url": "https://...",
  "company_domain": "techcorp.zumodra.com",
  "max_proposals": 15,
  "proposal_count": 5,
  "proposal_deadline": "2026-02-20T23:59:59Z",
  "is_open": true,
  "is_featured": false,
  "published_at": "2026-01-15T10:30:00Z",
  "synced_at": "2026-01-17T12:00:00Z",
  "meta_title": "Redesign E-commerce Website - TechCorp Inc.",
  "meta_description": "Complete redesign of online store with modern UX...",
  "project_url": "https://techcorp.zumodra.com/projects/123e4567.../",
  "application_url": "https://techcorp.zumodra.com/projects/123e4567.../apply/"
}
```

#### Statistics
```
GET /api/v1/public/projects/stats/
```

**Response:**
```json
{
  "total_count": 150,
  "open_count": 87,
  "featured_count": 12,
  "by_category": {
    "Web Development": 45,
    "Mobile Apps": 32,
    "Design": 28
  },
  "by_country": {
    "Canada": 68,
    "United States": 52,
    "United Kingdom": 30
  },
  "by_budget_range": {
    "< $5,000": 35,
    "$5,000 - $15,000": 65,
    "$15,000 - $50,000": 40,
    "> $50,000": 10
  },
  "avg_budget": "12500.00",
  "avg_duration_weeks": 8
}
```

#### Featured Projects
```
GET /api/v1/public/projects/featured/
```

Returns projects marked as featured.

#### Recent Projects
```
GET /api/v1/public/projects/recent/
```

Returns 20 most recently published projects.

## Sync Mechanism

### Sync Trigger

Projects are synced when:
- Project is published (`is_published=True` and `status=OPEN`)
- Project is updated while published
- Project is unpublished (entry removed from catalog)

### Sync Task

```python
# projects/tasks.py
@shared_task(bind=True, max_retries=3)
def sync_project_to_public_catalog(self, project_id):
    """
    Sync project to public catalog (denormalize).
    Runs asynchronously via Celery.
    """
    from projects.models import Project
    from projects_public.models import PublicProjectCatalog
    from django_tenants.utils import schema_context

    try:
        # Fetch project from tenant schema
        project = Project.objects.get(id=project_id)

        # Prepare denormalized data
        catalog_data = {
            'uuid': project.uuid,
            'tenant_project_id': project.id,
            'tenant_id': project.tenant.id,
            'tenant_schema': project.tenant.schema_name,
            'title': project.title,
            'description': sanitize_html(project.description),
            'category_name': project.category.name if project.category else '',
            'category_slug': project.category.slug if project.category else '',
            'required_skills': project.required_skills,
            'budget_min': project.budget_min,
            'budget_max': project.budget_max,
            'company_name': project.tenant.name,
            'company_logo_url': project.tenant.logo.url if project.tenant.logo else '',
            'company_domain': project.tenant.domain_url,
            'published_at': project.published_at,
            'project_url': f"https://{project.tenant.domain_url}/projects/{project.uuid}/",
            'application_url': f"https://{project.tenant.domain_url}/projects/{project.uuid}/apply/",
            # ... all other fields
        }

        # Switch to public schema and update catalog
        with schema_context('public'):
            PublicProjectCatalog.objects.update_or_create(
                tenant_id=project.tenant.id,
                tenant_project_id=project.id,
                defaults=catalog_data
            )

        # Mark project as synced
        project.published_to_catalog = True
        project.save(update_fields=['published_to_catalog'])

    except Exception as exc:
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=2 ** self.request.retries)
```

### Removal Task

```python
@shared_task
def remove_project_from_catalog(project_id, tenant_id):
    """Remove project from public catalog when unpublished."""
    with schema_context('public'):
        PublicProjectCatalog.objects.filter(
            tenant_id=tenant_id,
            tenant_project_id=project_id
        ).delete()
```

## Usage Examples

### Example 1: Browse Projects (No Auth)

```javascript
// Frontend JavaScript - no authentication required
fetch('https://api.zumodra.com/api/v1/public/projects/?location_type=REMOTE&budget_max=10000')
  .then(response => response.json())
  .then(data => {
    data.results.forEach(project => {
      console.log(`${project.title} - ${project.company_name}`);
    });
  });
```

### Example 2: Search Projects

```python
# Search for React projects
import requests

response = requests.get(
    'https://api.zumodra.com/api/v1/public/projects/',
    params={
        'search': 'React',
        'experience_level': 'MID',
        'is_open': 'true',
        'ordering': '-published_at',
    }
)

projects = response.json()['results']
for project in projects:
    print(f"{project['title']} - Budget: ${project['budget_min']}-${project['budget_max']}")
```

### Example 3: Geographic Search

```python
from projects_public.models import PublicProjectCatalog
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import D

# Find projects near Toronto
user_location = Point(-79.3832, 43.6532, srid=4326)  # Toronto coordinates

nearby_projects = PublicProjectCatalog.objects.filter(
    location_coordinates__distance_lte=(user_location, D(km=50)),
    is_open=True
).order_by('location_coordinates__distance')
```

## Performance

### Optimization Strategies

1. **Denormalization**: All joins pre-computed
2. **Indexing**: Strategic indexes on filter fields
3. **Caching**: Redis caching on popular queries
4. **Read Replicas**: Separate read database for catalog
5. **CDN**: Static responses cached at edge

### Expected Performance

- **List endpoint**: < 50ms (with caching)
- **Detail endpoint**: < 20ms
- **Search queries**: < 100ms (full-text)
- **Geographic queries**: < 150ms (PostGIS)

### Monitoring

```python
# Check sync lag
from projects_public.models import PublicProjectCatalog
from django.utils import timezone
from datetime import timedelta

stale_entries = PublicProjectCatalog.objects.filter(
    synced_at__lt=timezone.now() - timedelta(hours=1)
).count()

print(f"Stale entries (>1h old): {stale_entries}")
```

## SEO Optimization

### Meta Tags

Each project has pre-computed SEO meta tags:

```python
project.meta_title = f"{project.title} - {project.company_name}"
project.meta_description = project.short_description[:160]
```

### Sitemap Integration

Projects are automatically included in sitemap:

```xml
<url>
  <loc>https://careers.zumodra.com/projects/123e4567.../</loc>
  <lastmod>2026-01-15</lastmod>
  <changefreq>weekly</changefreq>
  <priority>0.8</priority>
</url>
```

## Related Apps

- [`projects/`](../projects/) - Main projects app (tenant-aware)
- [`services_public/`](../services_public/) - Service provider catalog
- [`jobs_public/`](../jobs_public/) - Job listings catalog
- [`tenants/`](../tenants/) - Tenant management

## Admin Interface

Admins can view (but not edit) the public catalog via Django admin at `/admin/projects_public/`.

Read-only fields ensure data integrity - all changes must go through the sync mechanism.

---

**Status**: Active
**Schema**: Public (SHARED_APPS)
**Last Updated**: January 2026
**Maintainers**: Zumodra Platform Team
