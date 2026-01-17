"""
Dashboard API URLs.
"""

from django.urls import path

from .viewsets import (
    DashboardOverviewView,
    QuickStatsView,
    SearchView,
    UpcomingInterviewsView,
    RecentActivityView,
    ATSMetricsView,
    HRMetricsView,
)

app_name = 'dashboard'

urlpatterns = [
    # Main dashboard overview
    path('overview/', DashboardOverviewView.as_view(), name='overview'),

    # Quick stats widget
    path('quick-stats/', QuickStatsView.as_view(), name='quick-stats'),

    # Global search
    path('search/', SearchView.as_view(), name='search'),

    # Upcoming interviews
    path('interviews/', UpcomingInterviewsView.as_view(), name='interviews'),

    # Recent activity
    path('activity/', RecentActivityView.as_view(), name='activity'),

    # Module-specific metrics
    path('metrics/ats/', ATSMetricsView.as_view(), name='ats-metrics'),
    path('metrics/hr/', HRMetricsView.as_view(), name='hr-metrics'),
]
