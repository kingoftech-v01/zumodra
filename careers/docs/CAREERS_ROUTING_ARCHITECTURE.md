# Careers Routing Architecture

## Overview

Zumodra has **TWO separate careers implementations** that serve different purposes:

1. **Public Schema** - Aggregated job marketplace (all tenants)
2. **Tenant Schema** - Company-specific career pages (single tenant)

This document explains why both exist, how they work, and how to maintain them.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER ACCESSES                                │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   Which Domain?        │
                    └────────────────────────┘
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
    ┌───────────────────────┐   ┌───────────────────────┐
    │  Main Domain          │   │  Tenant Subdomain     │
    │  zumodra.com          │   │  acme.zumodra.com     │
    │  (Public Schema)      │   │  (Tenant Schema)      │
    └───────────────────────┘   └───────────────────────┘
                │                           │
                ▼                           ▼
    ┌───────────────────────┐   ┌───────────────────────┐
    │ urls_public.py        │   │ urls.py               │
    │ /careers/             │   │ /careers/             │
    └───────────────────────┘   └───────────────────────┘
                │                           │
                ▼                           ▼
    ┌───────────────────────┐   ┌───────────────────────┐
    │ main/views.py         │   │ careers/              │
    │                       │   │ template_views.py     │
    │ - public_careers_     │   │                       │
    │   landing()           │   │ - CareerSiteHomeView  │
    │ - public_careers_map()│   │ - BrowseJobsMapView   │
    │ - public_companies_   │   │ - BrowseCompaniesView │
    │   grid()              │   │ - BrowseCompanies     │
    │ - public_companies_   │   │   MapView             │
    │   map()               │   │                       │
    └───────────────────────┘   └───────────────────────┘
                │                           │
                ▼                           ▼
    ┌───────────────────────┐   ┌───────────────────────┐
    │ Data Source:          │   │ Data Source:          │
    │ PublicJobCatalog      │   │ JobListing            │
    │ (public schema)       │   │ (tenant schema)       │
    │                       │   │                       │
    │ All jobs from ALL     │   │ Jobs from ONE         │
    │ companies/tenants     │   │ company/tenant        │
    └───────────────────────┘   └───────────────────────┘
```

---

## Public Schema Implementation

### Purpose
- **Job Marketplace**: Browse ALL jobs from ALL companies
- **Company Directory**: Discover companies hiring on Zumodra
- **Cross-tenant Search**: Find jobs across entire platform

### Location
- **URLs**: `zumodra/urls_public.py`
- **Views**: `main/views.py`
- **Data**: `tenants.models.PublicJobCatalog` (public schema)

### URL Patterns
```python
# Public schema: /careers/
/careers/                      → public_careers_landing (grid)
/careers/jobs/                 → public_careers_landing (grid)
/careers/browse/               → public_careers_landing (grid)
/careers/browse/map/           → public_careers_map (map)
/careers/companies/            → public_companies_grid (grid)
/careers/companies/map/        → public_companies_map (map)
```

### Views
```python
# main/views.py
def public_careers_landing(request):
    """Grid view - aggregates jobs from PublicJobCatalog"""
    jobs = PublicJobCatalog.objects.filter(published_at__lte=now)
    return render(request, 'careers/browse_jobs.html', context)

def public_careers_map(request):
    """Map view - same data, map template"""
    jobs = PublicJobCatalog.objects.filter(coordinates__isnull=False)
    return render(request, 'careers/browse_jobs_map.html', context)

def public_companies_grid(request):
    """Company directory - grid view"""
    companies = Tenant.objects.filter(published_jobs__isnull=False)
    return render(request, 'careers/browse_companies.html', context)

def public_companies_map(request):
    """Company directory - map view"""
    companies = Tenant.objects.filter(company_coordinates__isnull=False)
    return render(request, 'careers/browse_companies_map.html', context)
```

### Data Sync
- Jobs are synced from tenant schemas to `PublicJobCatalog` via signals
- Only jobs with `published_on_career_page=True` and `is_internal_only=False` are synced
- Denormalized for performance (title, location, salary, etc.)

---

## Tenant Schema Implementation

### Purpose
- **Company Career Page**: Branded career portal for ONE company
- **Recruitment Pipeline**: Company-specific application workflows
- **Internal Jobs**: Can include internal-only positions

### Location
- **URLs**: `zumodra/urls.py` → `careers/urls.py`
- **Views**: `careers/template_views.py`
- **Data**: `careers.models.JobListing` (tenant schema)

### URL Patterns
```python
# Tenant schema: /careers/ (on tenant subdomain)
/careers/                      → CareerSiteHomeView (grid)
/careers/jobs/                 → CareerSiteHomeView (grid)
/careers/browse/               → CareerSiteHomeView (grid)
/careers/browse/map/           → BrowseJobsMapView (map)
/careers/companies/            → BrowseCompaniesView (grid)
/careers/companies/map/        → BrowseCompaniesMapView (map)
```

### Views
```python
# careers/template_views.py
class CareerSiteHomeView(TemplateView):
    """Grid view - shows JobListing for THIS tenant only"""
    template_name = 'careers/browse_jobs.html'

    def get_context_data(self, **kwargs):
        jobs = JobListing.objects.filter(tenant=current_tenant)
        return context

class BrowseJobsMapView(TemplateView):
    """Map view - same data, map template"""
    template_name = 'careers/browse_jobs_map.html'

class BrowseCompaniesView(TemplateView):
    """Shows OTHER companies (marketplace feature)"""
    template_name = 'careers/browse_companies.html'

class BrowseCompaniesMapView(TemplateView):
    """Company browsing - map view"""
    template_name = 'careers/browse_companies_map.html'
```

---

## Templates

Both implementations **use the same templates**:

- `templates/careers/browse_jobs.html` - Job grid view
- `templates/careers/browse_jobs_map.html` - Job map view
- `templates/careers/browse_companies.html` - Company grid view
- `templates/careers/browse_companies_map.html` - Company map view

### Context Differences

#### Public Schema Context
```python
context = {
    'jobs': QuerySet[PublicJobCatalog],  # All tenants
    'view_mode': 'grid' or 'map',
    'categories': [...],
    'locations': [...],
}
```

#### Tenant Schema Context
```python
context = {
    'jobs': QuerySet[JobListing],  # Current tenant only
    'view_mode': 'grid' or 'map',
    'career_page': CareerPage,  # Branding settings
    'categories': [...],
    'locations': [...],
}
```

---

## Navigation Links

### Public Header (`templates/components/public_header.html`)
```django
<a href="{% url 'careers:job_list' %}">Browse Jobs</a>
<a href="{% url 'careers:browse_companies' %}">Browse Companies</a>
```

### FreelanHub Header (`templates/components/freelanhub_header.html`)
```django
<a href="{% url 'careers:home' %}">Browse Jobs</a>
<a href="{% url 'careers:browse_companies' %}">Browse Companies</a>
```

**IMPORTANT**: All navigation uses the `careers:` namespace. Django automatically resolves to:
- Public schema URLs if on main domain
- Tenant schema URLs if on tenant subdomain

---

## When to Edit Which File

### Scenario: Add New Filter to Job Search

**Edit BOTH implementations:**

1. **Public Schema**: `main/views.py`
   - Update `public_careers_landing()` to filter `PublicJobCatalog`
   - Update `public_careers_map()` for map view

2. **Tenant Schema**: `careers/template_views.py`
   - Update `CareerSiteHomeView` to filter `JobListing`
   - Update `BrowseJobsMapView` for map view

3. **Templates**: `templates/careers/browse_jobs.html`
   - Update filter UI to show new filter option

### Scenario: Add New View Mode (e.g., List View)

**Edit BOTH implementations:**

1. **Public Schema**:
   - Add `public_careers_list()` in `main/views.py`
   - Add URL in `urls_public.py`

2. **Tenant Schema**:
   - Add `BrowseJobsListView` in `careers/template_views.py`
   - Add URL in `careers/urls.py`

3. **Templates**:
   - Create `templates/careers/browse_jobs_list.html`
   - Update `_filter_bar.html` to include List toggle

---

## Common Pitfalls

### ❌ "I updated the tenant view but public schema still shows old version"

**Solution**: You only updated `careers/template_views.py`. Also update `main/views.py`.

### ❌ "NoReverseMatch: 'careers:browse_jobs_map' not found"

**Solution**: Check which schema you're on:
- If public schema: Add URL to `urls_public.py`
- If tenant schema: Add URL to `careers/urls.py`

### ❌ "My changes work on acme.zumodra.com but not zumodra.com"

**Solution**: You only updated tenant schema. Also update public schema in `main/views.py`.

### ❌ "Why do we have two implementations? Can we combine them?"

**NO**. They serve different purposes:
- **Public**: Cross-tenant job marketplace (all companies)
- **Tenant**: Company-specific career portal (one company)

Combining them would break multi-tenancy and lose the marketplace feature.

---

## Testing Both Implementations

### Test Public Schema
```bash
# Access main domain
curl http://localhost:8002/careers/
curl http://localhost:8002/careers/browse/map/
curl http://localhost:8002/careers/companies/
```

### Test Tenant Schema
```bash
# Access tenant subdomain
curl http://acme.localhost:8002/careers/
curl http://acme.localhost:8002/careers/browse/map/
curl http://acme.localhost:8002/careers/companies/
```

---

## Summary

| Aspect | Public Schema | Tenant Schema |
|--------|--------------|---------------|
| **Domain** | zumodra.com | acme.zumodra.com |
| **Purpose** | Job marketplace | Company career page |
| **Data Source** | PublicJobCatalog | JobListing |
| **Scope** | All tenants | Single tenant |
| **Views Location** | main/views.py | careers/template_views.py |
| **URLs Location** | urls_public.py | careers/urls.py |
| **Templates** | Same templates | Same templates |
| **Navigation** | careers:* namespace | careers:* namespace |

**Key Takeaway**: When you add a feature to careers (like grid/map views), you must update BOTH implementations to keep them in sync.

---

**Last Updated**: 2026-01-11
**Author**: Rhematek Solutions
**Related Commits**:
- 9c8e409 - feat: add FreelanceHub-style job browsing with grid and map views (tenant)
- 1100589 - feat: add FreelanceHub-style company browsing with grid and map views (tenant)
- a0aaf1d - feat: add grid/map views for public schema careers and companies (public)
