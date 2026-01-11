# Dashboard App

## Overview

Provides the main landing page and dashboard interface for all user types with role-specific widgets, quick statistics, recent activity, and global search functionality.

## Key Features

- **Role-Based Dashboards**: Different views for PDG, HR, Recruiter, Employee
- **Quick Stats**: Real-time metrics (jobs, candidates, applications, employees)
- **Recent Activity**: Timeline of recent platform actions
- **Upcoming Interviews**: Interview schedule widget
- **Global Search**: Search across jobs, candidates, employees
- **Quick Actions**: Context-aware action buttons

## Views

| View | Description | Template |
|------|-------------|----------|
| `DashboardView` | Main dashboard | `dashboard/index.html` |
| `QuickStatsView` | HTMX stats widget | `dashboard/partials/_quick_stats.html` |
| `RecentActivityView` | Activity feed | `dashboard/partials/_recent_activity.html` |
| `UpcomingInterviewsView` | Interview widget | `dashboard/partials/_upcoming_interviews.html` |
| `SearchView` | Global search | `dashboard/search_results.html` |

## URL Structure

```python
frontend:dashboard:index
frontend:dashboard:global-search
frontend:dashboard:htmx-quick-stats
frontend:dashboard:htmx-recent-activity
frontend:dashboard:htmx-upcoming-interviews
```

## Dashboard Widgets

### Quick Stats Card
- Open Jobs count with link
- Total Candidates with weekly trend
- Active Applications count
- Pending Interviews count
- Total Employees (HR view)
- Pending Time-Off requests (HR view)

### Recent Activity Feed
- Application status changes
- Interview schedules
- Offer sends/accepts
- Employee actions
- Time-off approvals

### Upcoming Interviews Widget
- Next 5 interviews
- Candidate name and job
- Date/time display
- Quick action buttons

### Quick Actions
- Create Job (Recruiter)
- Add Candidate (Recruiter)
- Request Time-Off (Employee)
- Approve Leaves (Manager)

## Role-Based Content

### PDG/CEO Dashboard
- Company-wide metrics
- All departments
- Financial overview
- Strategic KPIs

### HR Manager Dashboard
- HR metrics
- Employee directory link
- Time-off pending approvals
- Onboarding tasks

### Recruiter Dashboard
- ATS metrics
- Pipeline overview
- Interview schedule
- Candidate pool stats

### Employee Dashboard
- Personal time-off balance
- Team directory
- Company announcements
- Personal tasks

## Integration Points

- **ATS**: Job and candidate statistics
- **HR Core**: Employee and time-off metrics
- **Services**: Active contracts
- **Notifications**: Activity feed
- **Analytics**: Dashboard metrics

## Future Improvements

### High Priority

1. **Customizable Dashboards**
   - Drag-and-drop widgets
   - Saved layouts
   - Widget library
   - Personal preferences

2. **Advanced Analytics Widgets**
   - Charts and graphs
   - Trend analysis
   - Predictive metrics
   - Comparison views

3. **Real-Time Updates**
   - WebSocket live updates
   - Auto-refresh stats
   - Push notifications
   - Live activity feed

4. **Dashboard Templates**
   - Role-based templates
   - Industry templates
   - Best practice layouts
   - Import/export layouts

5. **Mobile Dashboard**
   - Mobile-optimized views
   - Touch-friendly widgets
   - PWA support
   - Offline mode

### Medium Priority

6. **Collaboration Features**: Shared dashboards, team views
7. **Export & Reporting**: PDF exports, scheduled reports
8. **Alerts & Notifications**: Dashboard-based alerts
9. **Data Filters**: Time range selection, department filters
10. **Favorites**: Quick access to frequent actions

## Testing

```
tests/
├── test_dashboard_views.py
├── test_dashboard_widgets.py
├── test_dashboard_permissions.py
└── test_global_search.py
```

## Performance

- Redis caching for statistics
- HTMX partial updates
- Lazy loading of widgets
- Pagination for activity feed

---

**Status:** Production
