"""
Analytics Frontend URL Configuration.

Routes for analytics template views and HTMX endpoints.
"""

from django.urls import path

from .template_views import (
    # Dashboard
    AnalyticsDashboardView,

    # Funnel and pipeline
    FunnelChartView,
    PipelineAnalyticsView,

    # Reports
    ReportsView,
    ReportGenerateView,

    # Chart endpoints
    ApplicationsTrendChartView,
    HiresByDepartmentChartView,
    SourcePerformanceChartView,
)

app_name = 'analytics'

urlpatterns = [
    # ===== MAIN DASHBOARD =====
    path('', AnalyticsDashboardView.as_view(), name='dashboard'),

    # ===== REPORTS =====
    path('reports/', ReportsView.as_view(), name='reports'),
    path('reports/<str:report_type>/', ReportGenerateView.as_view(), name='report-generate'),

    # ===== HTMX CHART ENDPOINTS =====
    path('htmx/funnel/', FunnelChartView.as_view(), name='htmx-funnel-chart'),
    path('htmx/pipeline/', PipelineAnalyticsView.as_view(), name='htmx-pipeline-analytics'),
    path('htmx/applications-trend/', ApplicationsTrendChartView.as_view(), name='htmx-applications-trend'),
    path('htmx/hires-by-department/', HiresByDepartmentChartView.as_view(), name='htmx-hires-by-department'),
    path('htmx/source-performance/', SourcePerformanceChartView.as_view(), name='htmx-source-performance'),
]
