"""
URL Configuration for Privacy Module

This module defines URL patterns for privacy-related views:
- Privacy dashboard
- Consent management
- Data Subject Requests
- Data export
- API endpoints
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from core.privacy.views import (
    ConsentViewSet,
    DataSubjectRequestViewSet,
    PrivacyDashboardView,
    DataExportView,
    ConsentFormView,
    PrivacyPolicyView,
    AdminDSRListView,
)

app_name = 'privacy'

# API Router
router = DefaultRouter()
router.register('consents', ConsentViewSet, basename='consent')
router.register('requests', DataSubjectRequestViewSet, basename='dsr')

urlpatterns = [
    # Dashboard
    path('dashboard/', PrivacyDashboardView.as_view(), name='dashboard'),

    # Consent management
    path('consent/', ConsentFormView.as_view(), name='consent_all'),
    path('consent/<str:consent_type>/', ConsentFormView.as_view(), name='consent'),

    # Data export
    path('export/', DataExportView.as_view(), name='export'),
    path('export/<uuid:pk>/download/', DataExportView.as_view(), name='download_export'),

    # Privacy policy
    path('policy/', PrivacyPolicyView.as_view(), name='policy'),
    path('policy/<str:version>/', PrivacyPolicyView.as_view(), name='policy_version'),

    # Data Subject Requests (web UI)
    path('requests/new/', DataSubjectRequestViewSet.as_view({'post': 'create', 'get': 'list'}), name='request_create'),

    # Admin views
    path('admin/dsrs/', AdminDSRListView.as_view(), name='admin_dsr_list'),

    # API endpoints
    path('api/', include(router.urls)),
]
