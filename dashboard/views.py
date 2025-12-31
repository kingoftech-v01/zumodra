"""
Dashboard Views Module.

This module re-exports the class-based views from template_views.py.
The legacy function-based views have been deprecated in favor of
secure, tenant-aware class-based views.

For new views, use LoginRequiredMixin and TenantViewMixin pattern.
"""

from .template_views import (
    DashboardView,
    SearchView,
    QuickStatsView,
    RecentActivityView,
    UpcomingInterviewsView,
)

__all__ = [
    'DashboardView',
    'SearchView',
    'QuickStatsView',
    'RecentActivityView',
    'UpcomingInterviewsView',
]
