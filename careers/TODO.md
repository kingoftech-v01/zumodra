# Careers App TODO

**Last Updated:** 2026-01-16
**Total Items:** 3
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

### [TODO-CAREERS-002] Display Actual Project Proposal Counts
- **Priority:** High
- **Category:** Feature
- **Status:** Not Started
- **Effort:** Small (1-2h)
- **Files:** `careers/template_views.py:1545, 1735`
- **Description:**
  Replace hardcoded `proposal_count = 0` with actual count of proposals submitted for each project.
- **Context:**
  Two views (ProjectListView and ProjectBoardView) display project listings but show 0 proposals for all projects. Users need to see actual proposal counts to gauge project interest.
- **Acceptance Criteria:**
  - [ ] Add annotation to queryset counting related proposals
  - [ ] Use `annotate(proposal_count=Count('proposals'))` in both views
  - [ ] Verify Proposal model has ForeignKey to ServiceListing/Project
  - [ ] Update template to display actual count
  - [ ] Add test coverage for proposal count accuracy
- **Dependencies:**
  - Proposal model relationship to ServiceListing/Project
- **Notes:**
  - Found in lines 1545 and 1735 of template_views.py
  - Both views process projects similarly, consider DRY refactor

### [TODO-CAREERS-003] Display Actual Client Spending Amounts
- **Priority:** High
- **Category:** Feature
- **Status:** Not Started
- **Effort:** Medium (3-4h)
- **Files:** `careers/template_views.py:1546, 1736`
- **Description:**
  Replace hardcoded `client_spent = 0` with actual calculation of total amount spent by each client on completed projects.
- **Context:**
  Project listings show client spending as $0, preventing freelancers from assessing client reliability and budget capacity.
- **Acceptance Criteria:**
  - [ ] Query finance/payment records to calculate total client spending
  - [ ] Sum completed contract amounts per client (project.provider)
  - [ ] Use `annotate()` with `Sum()` aggregation on related payments
  - [ ] Handle currency conversion if multi-currency support exists
  - [ ] Cache spending totals (expensive query) with TTL
  - [ ] Display formatted amount in template (e.g., "$12,345")
  - [ ] Add test coverage for spending calculation
- **Dependencies:**
  - finance app models (Contract, Payment, or similar)
  - Relationship between Tenant (client) and completed contracts
- **Notes:**
  - Found in lines 1546 and 1736 of template_views.py
  - May be expensive query - consider caching or background updates
  - Only count completed/paid contracts, not pending

---

## Completed Items
_Completed TODOs will be moved here with completion date._

---

**Note:** When adding new TODOs, use format `[TODO-CAREERS-XXX]` and update the central [TODO.md](../TODO.md) index.
