"""
Dashboard URL Configuration.

This module defines the URL patterns for the dashboard app.
All views require authentication and tenant awareness.
"""

from django.urls import path, include
from .views import (
    DashboardView,
    SearchView,
    QuickStatsView,
    RecentActivityView,
    UpcomingInterviewsView,
)

app_name = 'dashboard'

urlpatterns = [
    # Main dashboard
    path('', DashboardView.as_view(), name='index'),

    # Search endpoint (HTMX)
    path('search/', SearchView.as_view(), name='search'),

    # Widget refresh endpoints (HTMX)
    path('quick-stats/', QuickStatsView.as_view(), name='quick_stats'),
    path('recent-activity/', RecentActivityView.as_view(), name='recent_activity'),
    path('upcoming-interviews/', UpcomingInterviewsView.as_view(), name='upcoming_interviews'),

    # Sub-module includes (deprecated - redirects to main apps)
    # path('service/', include('dashboard_service.urls')),  # REMOVED: Use /services/ instead
    path('account/', include('custom_account_u.urls')),
]
