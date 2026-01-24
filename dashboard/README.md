# Dashboard App

## Overview

Main dashboard with quick stats, recent activity, and global search.

**Schema**: TENANT

## Views

- **DashboardIndexView**: Main dashboard with widgets
- **GlobalSearchView**: Search across all tenant entities
- **QuickStatsView**: Real-time statistics (HTMX)
- **RecentActivityView**: Recent tenant activity feed
- **UpcomingInterviewsView**: Interview schedule

## Features

- Quick stats (jobs, candidates, applications, employees)
- Global search (jobs, candidates, services, employees)
- Recent activity feed
- Upcoming interviews/appointments
- HTMX-powered dynamic updates
- Customizable widgets

## API Endpoints

### Dashboard
- **GET** `/api/v1/dashboard/overview/` - Dashboard summary
- **GET** `/api/v1/dashboard/quick-stats/` - Quick statistics
- **GET** `/api/v1/dashboard/recent-activity/` - Activity feed

### Search
- **GET** `/api/v1/dashboard/search/?q=query` - Global search
- **GET** `/api/v1/dashboard/search/?type=jobs&q=query` - Filtered search

### Widgets
- **GET** `/api/v1/dashboard/widgets/upcoming-interviews/`
- **GET** `/api/v1/dashboard/widgets/ats-metrics/`
- **GET** `/api/v1/dashboard/widgets/hr-metrics/`

## HTMX Partials

- `/app/dashboard/htmx/quick-stats/` - Real-time stats update
- `/app/dashboard/htmx/recent-activity/` - Activity feed refresh
- `/app/dashboard/htmx/upcoming-interviews/` - Interview updates

## Permissions

- `IsDashboardAdmin`: Access to admin widgets
- All authenticated tenant users can view dashboard

## Tasks (Celery)

- `daily_dashboard_cleanup`: Clean old activity records

## Testing

```bash
pytest dashboard/tests/
```

## Customization

Dashboard widgets can be customized per tenant via settings.
