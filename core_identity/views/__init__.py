"""
Custom Account Views

Exports all view classes and functions for easy importing.
"""

# Import all original views from account_views.py
from ..account_views import (
    launch_kyc_view,
    public_profile_view,
    profile_sync_settings_list,
    profile_sync_settings_edit,
    trigger_manual_sync,
    view_other_public_profile,
    public_profile_search,
)

# Import new wizard views
from .signup_type import SignupTypeSelectionView
from .public_profile_setup import PublicProfileSetupView
from .freelancer_onboarding import FreelancerOnboardingWizard

__all__ = [
    # Original view functions
    'launch_kyc_view',
    'public_profile_view',
    'profile_sync_settings_list',
    'profile_sync_settings_edit',
    'trigger_manual_sync',
    'view_other_public_profile',
    'public_profile_search',
    # New wizard views
    'SignupTypeSelectionView',
    'PublicProfileSetupView',
    'FreelancerOnboardingWizard',
]
