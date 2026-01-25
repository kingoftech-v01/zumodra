"""
Tenant Profiles API Module

Provides REST API endpoints for user accounts, authentication, and profile management.
"""

from .views import *  # noqa

__all__ = [
    'TenantUserViewSet',
    'UserProfileViewSet',
    'KYCVerificationViewSet',
    'ProgressiveConsentViewSet',
    'DataAccessLogViewSet',
    'LoginHistoryViewSet',
    'RegisterView',
    'LoginView',
    'LogoutView',
    'CurrentUserView',
    'PasswordChangeView',
    'SecurityQuestionView',
    'TrustScoreViewSet',
    'EmploymentVerificationViewSet',
    'EmploymentVerificationResponseView',
    'EducationVerificationViewSet',
    'ReviewViewSet',
    'CandidateCVViewSet',
    'StudentProfileViewSet',
    'FreelancerProfileViewSet',
    'TenantProfileViewSet',
    'submit_kyc_verification',
    'submit_cv_verification',
    'get_verification_status',
    'get_submitted_documents',
]
