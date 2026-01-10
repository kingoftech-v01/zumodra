"""
Tenants URLs - REST API routing for tenant management.

This module defines URL patterns for:
- /plans/ - Public plan information
- /tenant/ - Tenant management (owner only)
- /settings/ - Tenant settings
- /domains/ - Custom domain management
- /invitations/ - User invitations
- /usage/ - Usage statistics
- /audit-logs/ - Audit logging
- /onboarding/ - Setup wizard
- /subscription/ - Subscription management
- /billing-portal/ - Stripe billing portal
- /features/ - Feature flag checks
- /webhooks/stripe/ - Stripe webhooks
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views
from .views import (
    PlanViewSet,
    TenantViewSet,
    TenantSettingsViewSet,
    DomainViewSet,
    TenantInvitationViewSet,
    TenantUsageView,
    AuditLogViewSet,
    TenantOnboardingView,
    SubscriptionView,
    BillingPortalView,
    StripeWebhookView,
    FeatureFlagView,
)

# Create router and register viewsets
router = DefaultRouter()
router.register(r'plans', PlanViewSet, basename='plan')
router.register(r'domains', DomainViewSet, basename='domain')
router.register(r'invitations', TenantInvitationViewSet, basename='invitation')
router.register(r'audit-logs', AuditLogViewSet, basename='audit-log')

app_name = 'tenants'

urlpatterns = [
    # Router URLs (ViewSets)
    path('', include(router.urls)),

    # Tenant management (single tenant context)
    path('tenant/', TenantViewSet.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update'
    }), name='tenant-detail'),
    path('tenant/public/', TenantViewSet.as_view({
        'get': 'public'
    }), name='tenant-public'),

    # Tenant settings
    path('settings/', TenantSettingsViewSet.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update'
    }), name='settings-detail'),
    path('settings/security/', TenantSettingsViewSet.as_view({
        'get': 'security',
        'patch': 'security'
    }), name='settings-security'),
    path('settings/integrations/', TenantSettingsViewSet.as_view({
        'get': 'integrations',
        'patch': 'integrations'
    }), name='settings-integrations'),

    # Usage statistics
    path('usage/', TenantUsageView.as_view(), name='usage'),

    # Onboarding wizard
    path('onboarding/', TenantOnboardingView.as_view(), name='onboarding'),

    # Subscription management
    path('subscription/', SubscriptionView.as_view(), name='subscription'),
    path('billing-portal/', BillingPortalView.as_view(), name='billing-portal'),

    # Feature flags
    path('features/', FeatureFlagView.as_view(), name='features'),

    # Stripe webhooks (no auth required)
    path('webhooks/stripe/', StripeWebhookView.as_view(), name='stripe-webhook'),

    # EIN verification endpoints
    path('verify/ein/', views.submit_ein_verification, name='submit-ein'),
    path('verify/ein/status/', views.get_ein_verification_status, name='ein-verification-status'),
]

"""
API Endpoints Available:

Plans (Public):
- GET /api/tenants/plans/ - List all active plans
- GET /api/tenants/plans/{slug}/ - Get plan details
- GET /api/tenants/plans/compare/ - Compare plans (feature matrix)
- GET /api/tenants/plans/{slug}/features/ - Get plan features

Tenant Management (Owner Only):
- GET /api/tenants/tenant/ - Get current tenant details
- PUT /api/tenants/tenant/ - Update tenant details
- PATCH /api/tenants/tenant/ - Partial update
- GET /api/tenants/tenant/public/ - Get public tenant info

Tenant Settings:
- GET /api/tenants/settings/ - Get all settings
- PUT /api/tenants/settings/ - Update settings
- PATCH /api/tenants/settings/ - Partial update
- GET /api/tenants/settings/security/ - Get security settings
- PATCH /api/tenants/settings/security/ - Update security settings
- GET /api/tenants/settings/integrations/ - Get integration settings
- PATCH /api/tenants/settings/integrations/ - Update integration settings

Custom Domains (Admin Only):
- GET /api/tenants/domains/ - List domains
- POST /api/tenants/domains/ - Add domain
- DELETE /api/tenants/domains/{id}/ - Remove domain
- POST /api/tenants/domains/{id}/set_primary/ - Set primary domain
- POST /api/tenants/domains/{id}/verify/ - Get verification info

Invitations:
- GET /api/tenants/invitations/ - List invitations
- POST /api/tenants/invitations/ - Create invitation
- POST /api/tenants/invitations/{id}/resend/ - Resend invitation
- POST /api/tenants/invitations/{id}/revoke/ - Revoke invitation
- POST /api/tenants/invitations/accept/ - Accept invitation (with token)

Usage Statistics:
- GET /api/tenants/usage/ - Get current usage vs limits
- POST /api/tenants/usage/ - Force refresh usage

Audit Logs (Read-Only):
- GET /api/tenants/audit-logs/ - List audit logs
- GET /api/tenants/audit-logs/{id}/ - Get log details
- GET /api/tenants/audit-logs/export/ - Export logs to CSV

Onboarding:
- GET /api/tenants/onboarding/ - Get onboarding status
- POST /api/tenants/onboarding/ - Submit onboarding data

Subscription (Billing Permission):
- GET /api/tenants/subscription/ - Get subscription status
- POST /api/tenants/subscription/ - Create checkout session
- PUT /api/tenants/subscription/ - Upgrade/downgrade
- DELETE /api/tenants/subscription/ - Cancel subscription

Billing Portal:
- POST /api/tenants/billing-portal/ - Create billing portal session

Feature Flags:
- GET /api/tenants/features/ - Get all feature flags
- POST /api/tenants/features/ - Check specific feature

Webhooks:
- POST /api/tenants/webhooks/stripe/ - Stripe webhook endpoint

Query Parameters:
- Audit Logs: ?action=create&resource_type=User&start_date=2024-01-01&end_date=2024-12-31
- Invitations: ?status=pending&role=admin
- Domains: Standard pagination

Authentication:
- All endpoints require JWT authentication except:
  - Plans (public)
  - Stripe webhooks (signature verification)
"""
