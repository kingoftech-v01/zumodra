"""
Security App URLs - Template views for security dashboard.
"""

from django.urls import path

from .views import (
    SecurityDashboardView,
    AuditLogsListView,
    SessionsListView,
)

app_name = 'security'

urlpatterns = [
    path('', SecurityDashboardView.as_view(), name='dashboard'),
    path('audit-logs/', AuditLogsListView.as_view(), name='audit-logs'),
    path('sessions/', SessionsListView.as_view(), name='sessions'),
]
