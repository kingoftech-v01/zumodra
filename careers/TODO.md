# Careers App TODO

**Last Updated:** 2026-01-17
**Total Items:** 1
**Status:** Production

## Overview
The careers app provides public-facing job listings, career page builder, company profiles, and project marketplace for the freelance platform.

## High Priority

### [TODO-CAREERS-001] Add Geocoding for Company Locations
- **Priority:** High
- **Category:** Feature
- **Status:** Not Started
- **Effort:** Medium (4-6h)
- **File:** `careers/template_views.py:1374`
- **Description:**
  Implement geocoding to convert company addresses to latitude/longitude coordinates for map display on company listings page.
- **Context:**
  Currently `location_coordinates` is set to `None` in the CompanyListView, preventing companies from being displayed on interactive maps. Users expect to see company locations on a map view.
- **Acceptance Criteria:**
  - [ ] Select geocoding service (Google Maps API, Mapbox, or PostGIS built-in)
  - [ ] Add `latitude` and `longitude` fields to Tenant model (for companies)
  - [ ] Create migration for new fields
  - [ ] Implement geocoding function that accepts address components (city, country)
  - [ ] Geocode existing companies via management command
  - [ ] Auto-geocode new companies on save (post_save signal)
  - [ ] Display companies on map with accurate markers in template
  - [ ] Handle geocoding failures gracefully (log error, keep existing data)
  - [ ] Add rate limiting to avoid API quota issues
- **Dependencies:**
  - API key for geocoding service (if not using PostGIS)
  - PostGIS extension already installed for PostgreSQL
- **Notes:**
  - PostGIS has built-in geocoding via extensions (tiger geocoder)
  - Consider caching geocoding results to minimize API calls
  - May want to geocode in background task (Celery) to avoid blocking

---

## Completed Items

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
