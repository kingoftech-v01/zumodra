"""
Analytics URL Configuration

This module defines URL patterns for:
- Template-based dashboard views
- REST API endpoints for analytics dashboards
- Report export endpoints

Cycle 7 additions:
- Main dashboard endpoint with caching
- Time to hire detailed metrics
- Source analytics
- Funnel analytics
- Trend analytics
- Report management and export
"""

from django.urls import path
from . import views

app_name = 'analytics'

# ==================== TEMPLATE-BASED VIEWS ====================
# These are the original dashboard views that render HTML templates

template_patterns = [
    path('dashboard/', views.analytics_dashboard, name='dashboard'),
    path('provider/', views.provider_analytics, name='provider_analytics'),
    path('client/', views.client_analytics, name='client_analytics'),
]

# ==================== API ENDPOINTS ====================
# REST API endpoints for analytics data

api_patterns = [
    # Main dashboard APIs
    path('api/recruitment/', views.RecruitmentDashboardView.as_view(), name='api_recruitment_dashboard'),
    path('api/diversity/', views.DiversityDashboardView.as_view(), name='api_diversity_dashboard'),
    path('api/hr/', views.HRDashboardView.as_view(), name='api_hr_dashboard'),
    path('api/executive/', views.ExecutiveSummaryView.as_view(), name='api_executive_summary'),

    # Specific analytics APIs
    path('api/funnel/', views.HiringFunnelView.as_view(), name='api_hiring_funnel'),
    path('api/sources/', views.SourceEffectivenessView.as_view(), name='api_source_effectiveness'),
    path('api/time-to-hire/', views.TimeToHireAnalyticsView.as_view(), name='api_time_to_hire'),
    path('api/retention/', views.RetentionAnalyticsView.as_view(), name='api_retention'),
    path('api/performance/', views.PerformanceAnalyticsView.as_view(), name='api_performance'),
    path('api/time-off/', views.TimeOffAnalyticsView.as_view(), name='api_time_off'),

    # Export and utility APIs
    path('api/export/', views.ExportReportView.as_view(), name='api_export_report'),
    path('api/refresh-cache/', views.RefreshCacheView.as_view(), name='api_refresh_cache'),

    # List views for metric models
    path('api/metrics/recruitment/', views.RecruitmentMetricListView.as_view(), name='api_recruitment_metrics_list'),
    path('api/metrics/diversity/', views.DiversityMetricListView.as_view(), name='api_diversity_metrics_list'),
    path('api/metrics/funnel/', views.HiringFunnelMetricListView.as_view(), name='api_funnel_metrics_list'),
    path('api/metrics/time-to-hire/', views.TimeToHireMetricListView.as_view(), name='api_time_to_hire_metrics_list'),
    path('api/metrics/sources/', views.SourceEffectivenessMetricListView.as_view(), name='api_source_metrics_list'),
    path('api/metrics/retention/', views.EmployeeRetentionMetricListView.as_view(), name='api_retention_metrics_list'),
    path('api/metrics/time-off/', views.TimeOffAnalyticsListView.as_view(), name='api_time_off_metrics_list'),
    path('api/metrics/performance/', views.PerformanceDistributionListView.as_view(), name='api_performance_metrics_list'),
]

# ==================== CYCLE 7 - ENHANCED API ====================
# New REST API endpoints with caching and chart-ready data

cycle7_patterns = [
    # Main Dashboard (with caching)
    # GET: Get all dashboard metrics, charts, activity
    path(
        'api/dashboard/',
        views.DashboardView.as_view(),
        name='api_dashboard'
    ),

    # Time to Hire (detailed metrics)
    # GET: Get detailed time-to-hire breakdown
    path(
        'api/time-to-hire/',
        views.TimeToHireView.as_view(),
        name='api_time_to_hire_detail'
    ),

    # Source Analytics (ROI and effectiveness)
    # GET: Get source effectiveness metrics
    path(
        'api/sources/',
        views.SourceAnalyticsView.as_view(),
        name='api_sources_detail'
    ),

    # Funnel Analytics (conversion rates)
    # GET: Get funnel data with bottleneck analysis
    path(
        'api/funnel/',
        views.FunnelAnalyticsView.as_view(),
        name='api_funnel_detail'
    ),

    # Trend Analytics (chart-ready data)
    # GET: Get trend data for charts
    path(
        'api/trends/',
        views.TrendAnalyticsView.as_view(),
        name='api_trends'
    ),

    # Reports Management
    # GET: List available reports
    # POST: Generate a new report
    path(
        'api/reports/',
        views.ReportsView.as_view(),
        name='api_reports'
    ),

    # Report Export
    # GET: Export report to PDF/Excel
    path(
        'api/reports/<uuid:report_id>/export/',
        views.ReportExportView.as_view(),
        name='api_report_export'
    ),
]

# Combine all URL patterns
urlpatterns = template_patterns + api_patterns + cycle7_patterns
