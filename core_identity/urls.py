from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .account_views import (
    launch_kyc_view,
    public_profile_view,
    profile_sync_settings_list,
    profile_sync_settings_edit,
    trigger_manual_sync,
    view_other_public_profile,
    public_profile_search,
)
from core_identity.api.views import PublicProfileViewSet, ProfileFieldSyncViewSet

# Import wizard views
from core_identity.views import (
    SignupTypeSelectionView,
    PublicProfileSetupView,
    FreelancerOnboardingWizard,
)
from core_identity.views.waitlist import (
    WaitlistCountdownView,
    WaitlistStatusAPIView,
)
from tenants.views import CompanySetupWizard

# API Router
router = DefaultRouter()
router.register(r'profile/public', PublicProfileViewSet, basename='publicprofile')
router.register(r'profile/sync-settings', ProfileFieldSyncViewSet, basename='profilefieldsync')

app_name = 'core_identity'

urlpatterns = [
    # API endpoints
    path('api/', include(router.urls)),

    # KYC endpoint (Onfido integration - see core/integrations/kyc.py)
    path('kyc/launch/', launch_kyc_view, name='launch_kyc'),
    # REMOVED (2026-01-17): iDenfy stub URLs - consolidated on Onfido only

    # Multi-tier Signup Wizards
    path('signup/choose/', SignupTypeSelectionView.as_view(), name='signup_type_selection'),
    path('signup/company/', CompanySetupWizard.as_view(), name='company_setup_wizard'),
    path('signup/freelancer/', FreelancerOnboardingWizard.as_view(), name='freelancer_onboarding_wizard'),
    path('signup/profile/', PublicProfileSetupView.as_view(), name='public_profile_setup'),

    # Waitlist System
    path('waitlist/countdown/', WaitlistCountdownView.as_view(), name='waitlist_countdown'),
    path('api/v1/waitlist/status/', WaitlistStatusAPIView.as_view(), name='waitlist_status_api'),

    # Stripe Connect callbacks (for freelancers)
    # path('freelancer/stripe/refresh/', StripeConnectRefreshView.as_view(), name='stripe_connect_refresh'),
    # path('freelancer/stripe/return/', StripeConnectReturnView.as_view(), name='stripe_connect_return'),

    # PublicProfile views
    path('profile/', public_profile_view, name='public_profile'),
    path('profile/<uuid:profile_uuid>/', view_other_public_profile, name='view_public_profile'),
    path('profile/search/', public_profile_search, name='profile_search'),

    # Profile Sync Settings
    path('sync-settings/', profile_sync_settings_list, name='sync_settings_list'),
    path('sync-settings/<uuid:tenant_uuid>/', profile_sync_settings_edit, name='sync_settings_edit'),
    path('sync-settings/<uuid:tenant_uuid>/trigger/', trigger_manual_sync, name='trigger_sync'),
]
