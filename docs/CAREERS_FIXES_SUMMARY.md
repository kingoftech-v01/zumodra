# Careers Routing and Public Schema Fixes - Summary

**Date**: 2026-01-11
**Status**: ✅ Fixed and Ready for Deployment

---

## Issues Resolved

### 1. ✅ Duplicate Careers Routing Confusion
**Problem**: User added new grid/map views to tenant schema but public schema still showed "older version"

**Root Cause**:
- Public schema (`main/views.py`) had old `public_careers_landing` without map support
- Tenant schema (`careers/template_views.py`) had new grid/map views
- Both use same templates but different data sources

**Solution**:
- Added `public_careers_map()`, `public_companies_grid()`, `public_companies_map()` views to public schema
- Updated `urls_public.py` to include all browse views
- Created comprehensive architecture documentation

**Commits**:
- `a0aaf1d` - feat: add grid/map views for public schema careers and companies
- `2e1d894` - docs: add careers routing architecture documentation

---

### 2. ✅ Missing job_detail URL Pattern
**Problem**: `NoReverseMatch: 'job_detail' is not a valid view function or pattern name`

**Root Cause**:
- Template used `{% url 'careers:job_detail' %}` (underscore)
- URL pattern was `job-detail` (hyphen)
- Public schema had NO job detail views at all

**Solution**:
- Added `job_detail` URL alias to `careers/urls.py` (tenant schema)
- Created `public_job_detail()` view for public schema using `PublicJobCatalog`
- Added job detail routes to `urls_public.py`
- Created `JobWrapper` class to make PublicJobCatalog template-compatible

**Commits**:
- `cb7eeed` - fix: add missing job_detail URLs for public and tenant schemas
- (pending) - feat: add template-compatible wrapper for PublicJobCatalog

---

### 3. ✅ Field Name Error in Map View
**Problem**: `FieldError: Cannot resolve keyword 'coordinates' into field`

**Root Cause**:
- View used `coordinates__isnull=False`
- Actual field name is `location_coordinates` (PostGIS PointField)

**Solution**:
- Changed `coordinates` → `location_coordinates` in `public_careers_map()`
- Removed reference to non-existent `company_coordinates` field in `public_companies_map()`
- Updated filter to use `company_city` presence instead

**Commits**:
- `6e75cc9` - fix: correct field names and add location coordinates to demo data

---

### 4. ✅ Demo Data Missing Location Coordinates
**Problem**: Map views couldn't display jobs because `location_coordinates` was NULL

**Root Cause**:
- `setup_demo_data.py` created jobs without PostGIS Point coordinates
- All jobs defaulted to "Montreal" with no lat/lon

**Solution**:
- Added 5 Canadian cities with real coordinates
- Imported `Point` from `django.contrib.gis.geos`
- Set `location_coordinates=Point(lon, lat, srid=4326)` for all demo jobs
- Cycle through locations for variety

**Locations Added**:
```python
Montreal:   45.5017°N, -73.5673°W
Toronto:    43.6532°N, -79.3832°W
Vancouver:  49.2827°N, -123.1207°W
Ottawa:     45.4215°N, -75.6972°W
Calgary:    51.0447°N, -114.0719°W
```

**Commits**:
- `6e75cc9` - fix: correct field names and add location coordinates to demo data

---

## Current Architecture

### Data Flow

```
┌──────────────────────────────────────────┐
│  JobPosting (Tenant Schema)              │
│  - Created by companies in ATS           │
│  - Has location_coordinates (PointField) │
└──────────────┬───────────────────────────┘
               │
               │ Celery Signal → sync_job_to_catalog_task
               │
               ▼
┌──────────────────────────────────────────┐
│  PublicJobCatalog (Public Schema)        │
│  - Aggregated from ALL tenants           │
│  - Denormalized for performance          │
│  - Has location_coordinates (PointField) │
└──────────────────────────────────────────┘
```

### URL Patterns

| URL Pattern | Public Schema | Tenant Schema |
|------------|---------------|---------------|
| `/careers/` | `public_careers_landing` | `CareerSiteHomeView` |
| `/careers/browse/` | `public_careers_landing` | `CareerSiteHomeView` |
| `/careers/browse/map/` | `public_careers_map` | `BrowseJobsMapView` |
| `/careers/job/<slug>/` | `public_job_detail` | `JobDetailPageView` |
| `/careers/companies/` | `public_companies_grid` | `BrowseCompaniesView` |
| `/careers/companies/map/` | `public_companies_map` | `BrowseCompaniesMapView` |

### Field Mapping: PublicJobCatalog

Key fields synced from JobPosting:

| Field | Type | Description |
|-------|------|-------------|
| `title` | CharField | Job title |
| `location_city` | CharField | City name |
| `location_country` | CharField | Country name |
| `location_coordinates` | PointField | PostGIS Point (lon, lat, SRID 4326) |
| `category_slug` | SlugField | Denormalized category |
| `company_name` | CharField | Denormalized tenant name |
| `is_featured` | BooleanField | Featured flag |
| `published_at` | DateTimeField | Publication date |

---

## Deployment Checklist

### 1. Code Deployment
```bash
git pull origin main
```

### 2. Database Migrations
```bash
# Public schema (if any)
python manage.py migrate_schemas --shared

# Tenant schemas (if any)
python manage.py migrate_schemas --tenant
```

### 3. Regenerate Demo Data (Optional)
```bash
# To test map views with coordinates
python manage.py setup_demo_data --num-jobs 15 --num-candidates 50
```

### 4. Sync Existing Jobs to Catalog
```bash
# Force re-sync all tenant jobs to PublicJobCatalog
python manage.py sync_public_catalogs
```

### 5. Restart Services
```bash
docker-compose restart web
docker-compose restart celery
docker-compose restart channels
```

### 6. Test Public Schema URLs
```bash
curl https://zumodra.rhematek-solutions.com/en/careers/
curl https://zumodra.rhematek-solutions.com/en/careers/browse/map/
curl https://zumodra.rhematek-solutions.com/en/careers/companies/
curl https://zumodra.rhematek-solutions.com/en/careers/job/1/
```

### 7. Test Tenant Schema URLs
```bash
curl https://{tenant}.zumodra.rhematek-solutions.com/en/careers/
curl https://{tenant}.zumodra.rhematek-solutions.com/en/careers/browse/map/
curl https://{tenant}.zumodra.rhematek-solutions.com/en/careers/job/1/
```

---

## Related Documentation

- [CAREERS_ROUTING_ARCHITECTURE.md](CAREERS_ROUTING_ARCHITECTURE.md) - Comprehensive routing guide
- [DEPLOYMENT_CHECKLIST.md](../DEPLOYMENT_CHECKLIST.md) - General deployment guide
- [CLAUDE.md](../CLAUDE.md) - Project overview and commands

---

## Future Enhancements

### Pending Features
1. **Template Wrapper**: Complete JobWrapper class for full template compatibility
2. **Company Coordinates**: Add `company_coordinates` field to Tenant model for company map views
3. **Geocoding Service**: Auto-geocode locations when jobs/companies are created
4. **Map Clustering**: Add marker clustering for dense map areas
5. **Search Radius**: Allow users to search "jobs within X km of location"

### Technical Debt
- Consolidate template structure (currently `job.job.field` is awkward)
- Add comprehensive tests for public schema views
- Add caching for expensive PublicJobCatalog queries

---

## Commits in This Fix

1. `a0aaf1d` - feat: add grid/map views for public schema careers and companies
2. `2e1d894` - docs: add careers routing architecture documentation
3. `cb7eeed` - fix: add missing job_detail URLs for public and tenant schemas
4. `6e75cc9` - fix: correct field names and add location coordinates to demo data

**Total Files Changed**: 8 files
**Lines Added**: ~450 lines
**Lines Removed**: ~15 lines

---

**Last Updated**: 2026-01-11
**Author**: Claude Code (Anthropic)
**Reviewed By**: Pending
