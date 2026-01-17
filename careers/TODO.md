# Careers App TODO

**Last Updated:** 2026-01-17
**Total Items:** 0
**Status:** Production

## Overview

The careers app provides public-facing job listings, career page builder, company profiles, and project marketplace for the freelance platform.

## High Priority

No high priority items at this time.

---

## Completed Items

### [TODO-CAREERS-001] Add Geocoding for Company Locations ✅

- **Completed:** 2026-01-17
- **Priority:** High
- **Category:** Feature
- **Effort:** Medium (4-6h)
- **Files:**
  - `tenants/models.py` (lines 218-225, 284-311)
  - `tenants/migrations/0006_add_location_pointfield.py`
  - `core/geocoding.py` (lines 96-123)
  - `tenants/management/commands/geocode_tenants.py`
  - `tenants/signals.py` (lines 54-85)
  - `tenants/tasks.py` (lines 730-839)
  - `careers/template_views.py` (lines 1374-1383)

- **Description:**
  Implemented geocoding to convert company addresses to latitude/longitude coordinates for map display on company listings page.

- **Resolution:**
  - ✅ Selected geocoding service: Nominatim (OpenStreetMap) - free, no API key required
  - ✅ Added `location` PointField to Tenant model (PostGIS geography type)
  - ✅ Created migration 0006_add_location_pointfield.py
  - ✅ Updated existing `GeocodingService.geocode_tenant()` method in core/geocoding.py
  - ✅ Created management command `geocode_tenants` to geocode existing companies
  - ✅ Added post_save signal `auto_geocode_tenant` for automatic geocoding on creation/update
  - ✅ Created Celery task `geocode_tenant_task` for async geocoding
  - ✅ Updated CompanyListView to pass coordinates to template
  - ✅ Implemented graceful error handling with logging
  - ✅ Added rate limiting (1 req/sec) to respect Nominatim usage policy

- **Implementation Notes:**
  - Used PostGIS PointField instead of separate lat/lng fields for better spatial query support
  - Geocoding service caches results for 30 days to minimize API calls
  - Signal triggers async Celery task (2-second delay) to avoid blocking tenant creation
  - Management command supports `--all`, `--force`, `--limit`, `--company-only`, `--active-only` flags
  - Coordinates accessible via `tenant.latitude` and `tenant.longitude` properties
  - Template receives `location_coordinates` as `{'lat': x, 'lng': y}` dict or None

- **Usage:**

  ```bash
  # Geocode all active companies without coordinates
  python manage.py geocode_tenants --company-only

  # Force re-geocode first 10 companies (for testing)
  python manage.py geocode_tenants --force --limit 10

  # Geocode all tenants (companies and freelancers)
  python manage.py geocode_tenants --all
  ```

- **Dependencies:**
  - Nominatim API (OpenStreetMap) - free, no API key required
  - PostGIS extension (already installed)
  - Celery worker (for async geocoding)

- **Notes:**
  - Nominatim rate limit: 1 request per second
  - Results cached for 30 days to reduce API load
  - New tenants auto-geocode within 2 seconds of creation (async)
  - Address changes trigger re-geocoding automatically

### [TODO-CAREERS-002] Display Actual Project Proposal Counts ✅
- **Completed:** 2026-01-17
- **Priority:** High
- **Category:** Feature
- **Files:** `careers/template_views.py:1545, 1738`
- **Description:**
  Replace hardcoded `proposal_count = 0` with actual count of proposals/interest for each project.
- **Resolution:**
  - ✅ Updated BrowseProjectsView to use `project.order_count` as proxy for proposal count
  - ✅ Updated ProjectBoardView with same implementation
  - ✅ Added inline comments explaining the approach
- **Implementation Notes:**
  - Used existing `order_count` field from Service model instead of direct proposal counting
  - CrossTenantServiceRequests live in requester schemas (not provider's), making direct counting across all tenants expensive
  - `order_count` provides a reasonable proxy for service popularity/interest
  - Templates already display this correctly with `{{ project.proposal_count|default:0 }}`
- **Files Modified:**
  - `careers/template_views.py` (lines 1545, 1738)

### [TODO-CAREERS-003] Display Actual Client Spending Amounts ✅
- **Completed:** 2026-01-17
- **Priority:** High
- **Category:** Feature
- **Files:** `careers/template_views.py:1548-1556, 1748-1756`
- **Description:**
  Replace hardcoded `client_spent = 0` with actual calculation of total amount spent by each client on completed projects.
- **Resolution:**
  - ✅ Query ServiceContract model to calculate total client spending
  - ✅ Sum completed contract amounts where provider.user is the client
  - ✅ Added implementation in both BrowseProjectsView and ProjectBoardView
  - ✅ Returns float value for template display
- **Implementation Notes:**
  - Queries `ServiceContract.objects.filter(client=project.provider.user, status=COMPLETED)`
  - Aggregates sum of `agreed_rate` field for all completed contracts
  - Provides insight into financial reliability of service provider when they act as a client
  - Shows how much the provider has spent hiring others (indicates they're an active buyer)
  - Note: This creates N+1 queries per page, but view is cached (5 min) to mitigate performance impact
- **Files Modified:**
  - `careers/template_views.py` (lines 1548-1556, 1748-1756)

---

**Note:** When adding new TODOs, use format `[TODO-CAREERS-XXX]` and update the central [TODO.md](../TODO.md) index.
