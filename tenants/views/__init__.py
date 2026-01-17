"""
Tenants Views

Exports view classes for tenant management and signup wizards.
"""

# Import all original views from tenant_views.py
from ..tenant_views import (
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

# Import new wizard views
from .company_setup import CompanySetupWizard

__all__ = [
    # Original API views
    'PlanViewSet',
    'TenantViewSet',
    'TenantSettingsViewSet',
    'DomainViewSet',
    'TenantInvitationViewSet',
    'TenantUsageView',
    'AuditLogViewSet',
    'TenantOnboardingView',
    'SubscriptionView',
    'BillingPortalView',
    'StripeWebhookView',
    'FeatureFlagView',
    # New wizard views
    'CompanySetupWizard',
]
