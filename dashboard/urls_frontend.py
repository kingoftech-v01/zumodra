"""
Dashboard Frontend URL Configuration.

Routes for dashboard template views and HTMX endpoints.
"""

from django.urls import path

from .template_views import (
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

    # Global search
    path('search/', SearchView.as_view(), name='global-search'),

    # HTMX endpoints for dashboard widgets
    path('htmx/quick-stats/', QuickStatsView.as_view(), name='htmx-quick-stats'),
    path('htmx/recent-activity/', RecentActivityView.as_view(), name='htmx-recent-activity'),
    path('htmx/upcoming-interviews/', UpcomingInterviewsView.as_view(), name='htmx-upcoming-interviews'),
]
