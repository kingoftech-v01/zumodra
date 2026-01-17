# Dashboard Testing Quick Reference Guide
**Environment:** https://demo-company.zumodra.rhematek-solutions.com
**Created:** 2026-01-16

## Current Status: ⚠️ SERVER DOWN (502 Bad Gateway)

The production environment is currently experiencing a **502 Bad Gateway** error. The Django backend service is not running. Testing cannot proceed until this is resolved.

## Quick Start (When Server is Operational)

### Option 1: Automated Testing with Playwright (Recommended)

```bash
# Install dependencies (one-time)
pip install playwright
playwright install

# Run comprehensive dashboard tests
python test_dashboard_comprehensive.py

# Results saved to:
# - test_results/dashboard/dashboard_test_results.json
# - test_results/dashboard/dashboard_test_results.txt
# - test_results/dashboard/*.png (screenshots)
```

### Option 2: HTTP Testing with Requests

```bash
# Run HTTP-based tests
python test_main_dashboard.py

# Results saved to:
# - test_results/dashboard/dashboard_test_report.json
```

## Dashboard URLs to Test

| URL | Purpose | Expected Result |
|-----|---------|----------------|
| `/app/dashboard/` | Main dashboard | Stats, activity, interviews widgets |
| `/app/dashboard/search/?q=test` | Global search | Results across jobs, candidates, employees |
| `/app/dashboard/htmx/quick-stats/` | HTMX stats widget | HTML fragment with statistics |
| `/app/dashboard/htmx/recent-activity/` | HTMX activity feed | HTML fragment with notifications |
| `/app/dashboard/htmx/upcoming-interviews/` | HTMX interviews | HTML fragment with interview list |
| `/app/dashboard/account-settings/` | Account settings | Redirect to allauth settings |
| `/app/dashboard/help/` | Help page | Help content |

## Test User Credentials

### Primary
```
Email: testuser@demo.com
Password: TestPass123!
```

### Fallback Options
```
admin@demo-company.com / admin123
admin@demo.com / admin123
test@demo-company.com / testpass123
```

## Manual Testing Checklist

### Main Dashboard (`/app/dashboard/`)
- [ ] Page loads without errors (200 status)
- [ ] Quick stats cards display:
  - [ ] Open jobs count
  - [ ] Total candidates
  - [ ] New candidates this week
  - [ ] Active applications
  - [ ] Pending interviews
  - [ ] Total employees
  - [ ] Pending time-off requests
- [ ] Recent activity widget shows notifications
- [ ] Upcoming interviews widget shows next 7 days
- [ ] Navigation menu works
- [ ] User profile dropdown accessible

### Global Search (`/app/dashboard/search/`)
- [ ] Search input field present
- [ ] Searching for "test" returns results
- [ ] Results categorized by:
  - [ ] Jobs
  - [ ] Candidates
  - [ ] Employees
  - [ ] Applications
- [ ] Total count displayed
- [ ] Links to detail pages work

### HTMX Endpoints
All HTMX endpoints should:
- [ ] Return HTML fragments (NOT full pages)
- [ ] Return 200 status code
- [ ] Include `HX-Request: true` header in request
- [ ] Render properly when loaded into page

### Security
- [ ] Unauthenticated users redirected to login
- [ ] Tenant isolation enforced (only see own tenant data)
- [ ] CSRF protection on forms
- [ ] No sensitive data in client-side code

### Performance
- [ ] Dashboard loads in <2 seconds
- [ ] HTMX endpoints respond in <500ms
- [ ] Search responds in <1 second
- [ ] No console errors in browser

## Code Locations

```
Dashboard Views:     dashboard/template_views.py
Dashboard URLs:      dashboard/urls_frontend.py (primary)
Dashboard Templates: templates/dashboard/
Test Scripts:        test_main_dashboard.py
                    test_dashboard_comprehensive.py
Test Results:       test_results/dashboard/
```

## Known Issues

### Server Infrastructure
- **502 Bad Gateway** - Django backend not running
- Nginx operational but cannot proxy to backend
- Affects ALL application endpoints

### How to Resolve

```bash
# SSH to server
ssh user@demo-company.zumodra.rhematek-solutions.com

# Check services
docker ps

# Start services if stopped
docker-compose up -d

# Check logs
docker-compose logs web --tail=100
docker-compose logs nginx --tail=100

# Restart if needed
docker-compose restart web channels
```

## Dashboard Architecture

### View Classes
```python
DashboardView          # Main dashboard with widgets
SearchView             # Global search endpoint
QuickStatsView         # HTMX quick stats refresh
RecentActivityView     # HTMX recent activity feed
UpcomingInterviewsView # HTMX upcoming interviews
AccountSettingsView    # Account settings redirect
HelpView               # Help page
```

### Mixins Used
- `LoginRequiredMixin` - Ensures authentication
- `TenantViewMixin` - Provides tenant isolation
- `TemplateView` - Renders templates
- `View` - Generic view base class

### Templates
```
dashboard/index.html                        # Main dashboard (tenant users)
dashboard/public_user_dashboard.html        # Dashboard for public users
dashboard/help.html                         # Help page
dashboard/partials/_search_results.html     # Search results HTMX
dashboard/partials/_quick_stats.html        # Stats widget HTMX
dashboard/partials/_recent_activity.html    # Activity feed HTMX
dashboard/partials/_upcoming_interviews.html # Interviews HTMX
```

## Test Reports Generated

### Files Created
1. **DASHBOARD_TEST_FINDINGS.md** - Comprehensive findings document
2. **test_main_dashboard.py** - Requests-based test script
3. **test_dashboard_comprehensive.py** - Playwright test script

### Expected Output Files (When Tests Run)
1. **dashboard_test_results.json** - Machine-readable results
2. **dashboard_test_results.txt** - Human-readable report
3. **Screenshots:** 00-07 PNG files for each tested URL

## Next Actions

### For System Administrator
1. Investigate 502 Bad Gateway error
2. Restart Django backend services
3. Verify database connectivity
4. Check migration status
5. Notify tester when resolved

### For Tester (After Resolution)
1. Run `python test_dashboard_comprehensive.py`
2. Review screenshots for UI issues
3. Check JSON report for errors/warnings
4. Manually verify HTMX functionality
5. Test with different user roles
6. Document any bugs found

## Support

For issues or questions:
- Review code: `dashboard/template_views.py`
- Check logs: `docker-compose logs web`
- Review findings: `test_results/dashboard/DASHBOARD_TEST_FINDINGS.md`

---
**Last Updated:** 2026-01-16
**Status:** Awaiting server restoration
