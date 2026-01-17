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
    submit_ein_verification,
    get_ein_verification_status,
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
    # View functions
    'submit_ein_verification',
    'get_ein_verification_status',
    # New wizard views
    'CompanySetupWizard',
]
