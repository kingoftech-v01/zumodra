# ATS App Changelog

## [2026-01-16] - Website Testing & Issue Documentation

### Testing Completed
- Tested all public and protected ATS pages on demo-company tenant
- Status: Most pages working correctly with proper authentication redirects

### Working Features
- Job list page (`/app/ats/jobs/`): Proper auth redirect
- Candidate list page (`/app/ats/candidates/`): Proper auth redirect
- Pipeline board: Accessible after authentication
- Interview management: Accessible after authentication
- Offer management: Accessible after authentication

### Issues Identified
1. **500 Errors on Some URLs**:
   - `/ats/applications/` returns 500 instead of redirect
   - `/ats/pipeline/` returns 500 instead of redirect
   - Root cause: Likely incorrect URL routing or missing views

2. **Branding Issue** (affects all pages):
   - All pages display "FreelanHub" branding instead of "Zumodra"
   - Fix required: Update templates and static assets

### Correct URL Structure
All ATS URLs should be under `/app/ats/` prefix:
- Jobs: `/app/ats/jobs/`
- Candidates: `/app/ats/candidates/`
- Pipeline: `/app/ats/pipeline/`
- Interviews: `/app/ats/interviews/`
- Offers: `/app/ats/offers/`

---

## [2026-01-15] - Test Suite Fixes

### Fixed
- `test_category_unique_slug_per_tenant`: Use model directly instead of factory
- `test_accept_offer`: Call refresh_from_db() after offer acceptance
- `test_job_salary_validation`: Use factory.build() instead of factory()
- Signal handlers: Use getattr(connection, 'schema_name', 'public') for test compatibility

### Test Results
- 125 ATS tests passing
- All workflow tests passing
- Integration tests passing
- Security tests passing

---

## [Earlier Changes]

### Complete ATS Implementation
- Job posting management (create, edit, duplicate, delete)
- Candidate management (profiles, CVs, applications)
- Interview scheduling (schedule, reschedule, cancel, feedback)
- Offer management (create, send, accept, decline)
- Pipeline management (custom stages, drag-and-drop)
- Application workflows (status tracking, stage progression)
- Background checks integration (Checkr, Sterling)
- Email notifications for all major events
- Audit logging for compliance

### Features
- Multi-stage recruitment pipelines
- Customizable application stages
- Interview calendar integration
- Candidate scoring and evaluation
- Bulk actions (approve, reject, archive)
- Advanced filtering and search
- Export to CSV/PDF
- Email template customization
- Slack integration for notifications
- API endpoints for all major operations
