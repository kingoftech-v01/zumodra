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
    ServiceCategoryViewSet,
    ServiceProviderViewSet,
    ServiceViewSet,
    ClientRequestViewSet,
    ServiceProposalViewSet,
    ServiceContractViewSet,
    ServiceReviewViewSet,
    AppointmentViewSet,
    CompanyViewSet,
)


# ==================== Services Marketplace Router ====================
# Original API endpoints for the services marketplace

services_router = DefaultRouter()
services_router.register(r'categories', ServiceCategoryViewSet, basename='service-category')
services_router.register(r'providers', ServiceProviderViewSet, basename='service-provider')
services_router.register(r'services', ServiceViewSet, basename='service')
services_router.register(r'requests', ClientRequestViewSet, basename='service-request')
services_router.register(r'proposals', ServiceProposalViewSet, basename='service-proposal')
services_router.register(r'contracts', ServiceContractViewSet, basename='service-contract')
services_router.register(r'comments', ServiceReviewViewSet, basename='service-comment')
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

    # ==================== Public Catalogs ====================
    # /api/v1/public/jobs/ - Public job catalog (cross-tenant browsing, no auth)
    # /api/v1/public/providers/ - Public service provider catalog (cross-tenant, no auth)
    path('public/', include('ats_public.api.urls')),
    path('public/', include('services_public.api.urls')),

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

    # ==================== Finance & Payments ====================
    # /api/v1/finance/ - Payments, subscriptions, invoices, escrow, Stripe Connect
    path('finance/', include('finance.api.urls')),

    # ==================== Messages ====================
    # /api/v1/messages/ - Conversations, messages, contacts (REST complement to WebSocket)
    path('messages/', include('messages_sys.api.urls')),

    # ==================== Configurations ====================
    # /api/v1/configurations/ - Skills, companies, sites, departments, roles, FAQs
    path('configurations/', include('configurations.api.urls')),

    # ==================== Marketing ====================
    # /api/v1/marketing/ - Visit tracking, prospects, newsletters, analytics
    path('marketing/', include('marketing.api.urls')),

    # ==================== Security ====================
    # /api/v1/security/ - Audit logs, security events, sessions, failed logins
    path('security/', include('security.api.urls')),

    # ==================== Services (New Marketplace API) ====================
    # /api/v1/services/ - Full services marketplace CRUD with filters
    path('services/', include('services.api.urls')),

    # ==================== Blog ====================
    # /api/v1/blog/ - Blog posts, categories, comments, tags
    path('blog/', include('blog.api.urls')),

    # ==================== Newsletter ====================
    # /api/v1/newsletter/ - Newsletters, subscriptions, campaigns
    path('newsletter/', include('newsletter.api.urls')),

    # ==================== Appointment ====================
    # /api/v1/appointment/ - Appointment booking system
    path('appointment/', include('appointment.api.urls')),

    # ==================== Dashboard ====================
    # /api/v1/dashboard/ - Dashboard widgets and metrics
    path('dashboard/', include('dashboard.api.urls')),
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

Public Catalogs (/api/v1/public/):
- GET /api/v1/public/jobs/ - Browse public job listings (cross-tenant, no auth)
- GET /api/v1/public/jobs/{id}/ - Get job details
- GET /api/v1/public/jobs/featured/ - Featured jobs
- GET /api/v1/public/jobs/search/?q=keyword - Search jobs
- GET /api/v1/public/providers/ - Browse service providers (cross-tenant, no auth)
- GET /api/v1/public/providers/{id}/ - Get provider details
- GET /api/v1/public/providers/verified/ - Verified providers
- GET /api/v1/public/providers/top_rated/ - Top-rated providers
- GET /api/v1/public/providers/nearby/?lat=x&lng=y&radius=50 - Geographic search
- GET /api/v1/public/providers/search/?q=keyword - Search providers

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

Finance (/api/v1/finance/):
- Payments, subscriptions, invoices, refunds
- Escrow transactions, disputes, payouts
- Stripe Connect: connected accounts, payouts, transfers
- See finance.api.urls for full endpoint list

Messages (/api/v1/messages/):
- Conversations, messages (REST complement to WebSocket)
- Contacts, friend requests, block lists
- User status, message search
- See messages_sys.api.urls for full endpoint list

Configurations (/api/v1/configurations/):
- Skills, companies, sites, departments, roles
- FAQs, testimonials, partnerships, trusted companies
- See configurations.api.urls for full endpoint list

Marketing (/api/v1/marketing/):
- Visit tracking, prospects, newsletters
- Conversions, analytics, subscriber management
- See marketing.api.urls for full endpoint list

Security (/api/v1/security/):
- Audit logs, security events, failed logins
- User sessions, password reset requests
- Security analytics and monitoring
- See security.api.urls for full endpoint list

Services (/api/v1/services/):
- Categories, tags, providers, services
- Client requests, proposals, contracts
- Reviews, messages, analytics
- See services.api.urls for full endpoint list

Blog (/api/v1/blog/):
- Blog posts (Wagtail-backed)
- Categories, comments, tags
- Featured posts, related posts
- See blog.api.urls for full endpoint list

Newsletter (/api/v1/newsletter/):
- Newsletters, subscriptions
- Messages, articles, submissions
- Campaign management
- See newsletter.api.urls for full endpoint list

Appointment (/api/v1/appointment/):
- Services, staff members
- Appointments, bookings
- Working hours, days off, config
- See appointment.api.urls for full endpoint list

Dashboard (/api/v1/dashboard/):
- Overview, quick stats
- Global search, upcoming interviews
- ATS/HR metrics, activity feed
- See dashboard.api.urls for full endpoint list
"""
