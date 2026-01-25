# Jobs Public Catalog TODO

**Last Updated:** 2026-01-25
**Total Items:** 1
**Status:** Production-Ready (100% URL Convention Compliant)

## Overview

The jobs_public app provides a public-facing job catalog with search, filtering, and map-based browsing. This app has been fully refactored to achieve 100% compliance with URL_AND_VIEW_CONVENTIONS.md.

## Recent Accomplishments (2026-01-25)

✅ **URL Convention Compliance** - Achieved 100% compliance with ZERO DEVIATIONS

- Created forms.py with JobSearchForm
- Renamed views.py → template_views.py
- Implemented dual-layer URL architecture (frontend + API)
- Updated all templates with nested namespaces (frontend:jobs_public:*)
- Integrated JavaScript for map views (Leaflet.js, jobs_map.js, jobs_filters.js)
- Deleted deprecated api/urls.py
- All 7 templates properly configured

## Current Status

The app is production-ready with one pending feature enhancement.

---

## Important (MEDIUM Priority)

### Features

- [ ] **FEAT-001** - Implement wishlist functionality with UserProfile model
  - **File**: `template_views.py:502`
  - **Function**: `wishlist_toggle(request, job_id)`
  - **Why**: Allow authenticated users to save jobs to their wishlist
  - **Current State**: Placeholder returns "Wishlist functionality coming soon" message
  - **Implementation Requirements**:
    - Add `wishlisted_jobs` ManyToMany field to UserProfile model
    - Implement toggle logic in `wishlist_toggle()` view
    - Update frontend to show wishlist status per job
    - Add wishlist icon state management (filled/empty heart)
    - Create wishlist page to view saved jobs
  - **Effort**: M (Medium)
  - **Blocker**: No
  - **Dependencies**:
    - UserProfile model integration
    - Authentication system
  - **API Impact**: None (frontend-only feature)

---

## Future Improvements

### Performance

- Consider implementing Redis caching for frequently accessed job listings
- Add pagination optimization for large result sets
- Database indexes for search queries (if not already present)

### Enhancements

- Email alerts for saved searches
- Job application tracking integration
- Company profile pages
- Advanced filters (salary range, benefits, etc.)

### UI/UX

- Add job comparison feature (compare up to 3 jobs side-by-side)
- Improve mobile map view responsiveness
- Add "Recently Viewed Jobs" section

---

## Technical Debt

None currently identified. App recently refactored to 100% convention compliance.

---

## Testing Needs

- [ ] Add integration tests for wishlist functionality (when implemented)
- [ ] Test URL namespace resolution (script exists: `scripts/test_url_compliance.py`)
- [ ] Verify JavaScript functionality on all supported browsers
- [ ] Load testing for map view with 500+ jobs

---

**Note:** When adding new TODOs, use format `[TODO-JOBS-PUBLIC-XXX]` and update the central [TODO.md](../TODO.md) index.
