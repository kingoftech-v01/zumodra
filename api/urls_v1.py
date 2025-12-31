"""
API v1 URL Configuration for Zumodra

This module consolidates all API v1 endpoints with proper namespacing:
- /api/v1/tenants/ - Multi-tenant management
- /api/v1/accounts/ - User accounts and authentication
- /api/v1/ats/ - Applicant Tracking System
- /api/v1/hr/ - Human Resources core
- /api/v1/careers/ - Public career pages and admin
- /api/v1/analytics/ - Analytics and reporting
- /api/v1/integrations/ - Third-party integrations
- /api/v1/notifications/ - Notification system
- /api/v1/ai/ - AI matching and recommendations
- /api/v1/services/ - Services marketplace (legacy)
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
    TokenBlacklistView,
)

# Import viewsets from the original api app for services marketplace
from .viewsets import (
    DServiceCategoryViewSet,
    DServiceProviderProfileViewSet,
    DServiceViewSet,
    DServiceRequestViewSet,
    DServiceProposalViewSet,
    DServiceContractViewSet,
    DServiceCommentViewSet,
    AppointmentViewSet,
    CompanyViewSet,
)


# ==================== Services Marketplace Router ====================
# Original API endpoints for the services marketplace

services_router = DefaultRouter()
services_router.register(r'categories', DServiceCategoryViewSet, basename='service-category')
services_router.register(r'providers', DServiceProviderProfileViewSet, basename='service-provider')
services_router.register(r'services', DServiceViewSet, basename='service')
services_router.register(r'requests', DServiceRequestViewSet, basename='service-request')
services_router.register(r'proposals', DServiceProposalViewSet, basename='service-proposal')
services_router.register(r'contracts', DServiceContractViewSet, basename='service-contract')
services_router.register(r'comments', DServiceCommentViewSet, basename='service-comment')
services_router.register(r'appointments', AppointmentViewSet, basename='appointment')
services_router.register(r'companies', CompanyViewSet, basename='company')


app_name = 'api_v1'

urlpatterns = [
    # ==================== Authentication ====================
    # JWT Token endpoints
    path('auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('auth/token/blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),

    # ==================== Multi-Tenant Management ====================
    # /api/v1/tenants/ - Tenant, subscription, billing, domains
    path('tenants/', include('tenants.urls')),

    # ==================== User Accounts ====================
    # /api/v1/accounts/ - User registration, profiles, KYC, consent
    path('accounts/', include('accounts.urls')),

    # ==================== Applicant Tracking System ====================
    # /api/v1/ats/ - Jobs, candidates, applications, interviews, offers
    path('ats/', include('ats.urls')),

    # ==================== Human Resources Core ====================
    # /api/v1/hr/ - Employees, time-off, onboarding, documents, reviews
    path('hr/', include('hr_core.urls')),

    # ==================== Careers (Public + Admin) ====================
    # /api/v1/careers/ - Public job listings and admin management
    path('careers/', include('careers.urls')),

    # ==================== Analytics & Reporting ====================
    # /api/v1/analytics/ - Dashboards, reports, metrics
    path('analytics/', include('analytics.urls')),

    # ==================== Third-Party Integrations ====================
    # /api/v1/integrations/ - External service integrations
    path('integrations/', include('integrations.urls')),

    # ==================== Notifications ====================
    # /api/v1/notifications/ - In-app and push notifications
    path('notifications/', include('notifications.urls')),

    # ==================== AI Matching ====================
    # /api/v1/ai/ - AI-powered matching and recommendations
    path('ai/', include('ai_matching.urls')),

    # ==================== Services Marketplace ====================
    # /api/v1/marketplace/ - Original services marketplace endpoints
    path('marketplace/', include(services_router.urls)),
]


"""
API v1 Endpoints Summary:
=========================

Authentication (JWT):
- POST /api/v1/auth/token/           - Obtain JWT token pair
- POST /api/v1/auth/token/refresh/   - Refresh access token
- POST /api/v1/auth/token/verify/    - Verify token validity
- POST /api/v1/auth/token/blacklist/ - Blacklist refresh token (logout)

Tenants (/api/v1/tenants/):
- Plans, domains, invitations, settings, billing, webhooks
- See tenants.urls for full endpoint list

Accounts (/api/v1/accounts/):
- User registration, login, profiles, KYC, consent
- See accounts.urls for full endpoint list

ATS (/api/v1/ats/):
- Job postings, candidates, applications, interviews, offers
- See ats.urls for full endpoint list

HR Core (/api/v1/hr/):
- Employees, time-off, onboarding, documents, performance
- See hr_core.urls for full endpoint list

Careers (/api/v1/careers/):
- Public: Job listings, applications (no auth required)
- Admin: Career pages, listings management
- See careers.urls for full endpoint list

Analytics (/api/v1/analytics/):
- Dashboard, provider analytics, client analytics
- See analytics.urls for full endpoint list

Integrations (/api/v1/integrations/):
- Third-party service integrations (LinkedIn, etc.)
- See integrations.urls for full endpoint list

Notifications (/api/v1/notifications/):
- List, mark read, preferences, count
- See notifications.urls for full endpoint list

AI Matching (/api/v1/ai/):
- Match candidates, jobs, parse resumes, bias check
- See ai_matching.urls for full endpoint list

Marketplace (/api/v1/marketplace/):
- Services, providers, requests, proposals, contracts
- Original services marketplace functionality
"""
