"""
Accounts Frontend URL Configuration.

Routes for accounts template views and HTMX endpoints.
"""

from django.urls import path

from .template_views import (
    # Dashboard
    VerificationDashboardView,

    # KYC Verification
    KYCStartView,
    KYCStatusView,
    KYCListView,

    # Employment Verification
    EmploymentListView,
    EmploymentAddView,
    EmploymentDetailView,
    EmploymentRequestVerificationView,
    EmploymentVerificationResponseView,

    # Education Verification
    EducationListView,
    EducationAddView,
    EducationDetailView,
    EducationUploadTranscriptView,

    # Trust Score
    TrustScoreView,

    # HTMX Partials
    HTMXVerificationCardView,
    HTMXTrustScoreBadgeView,
)

app_name = 'accounts'

urlpatterns = [
    # ===== VERIFICATION DASHBOARD =====
    path('verification/', VerificationDashboardView.as_view(), name='verification-dashboard'),

    # ===== KYC VERIFICATION =====
    path('verification/kyc/', KYCListView.as_view(), name='kyc-list'),
    path('verification/kyc/start/', KYCStartView.as_view(), name='kyc-start'),
    path('verification/kyc/<uuid:uuid>/', KYCStatusView.as_view(), name='kyc-status'),

    # ===== EMPLOYMENT VERIFICATION =====
    path('verification/employment/', EmploymentListView.as_view(), name='employment-list'),
    path('verification/employment/add/', EmploymentAddView.as_view(), name='employment-add'),
    path('verification/employment/<uuid:uuid>/', EmploymentDetailView.as_view(), name='employment-detail'),
    path(
        'verification/employment/<uuid:uuid>/request/',
        EmploymentRequestVerificationView.as_view(),
        name='employment-request-verification'
    ),

    # ===== EDUCATION VERIFICATION =====
    path('verification/education/', EducationListView.as_view(), name='education-list'),
    path('verification/education/add/', EducationAddView.as_view(), name='education-add'),
    path('verification/education/<uuid:uuid>/', EducationDetailView.as_view(), name='education-detail'),
    path(
        'verification/education/<uuid:uuid>/upload/',
        EducationUploadTranscriptView.as_view(),
        name='education-upload-transcript'
    ),

    # ===== TRUST SCORE =====
    path('trust-score/', TrustScoreView.as_view(), name='trust-score'),

    # ===== HTMX ENDPOINTS =====
    path(
        'htmx/verification/<str:verification_type>/<uuid:uuid>/',
        HTMXVerificationCardView.as_view(),
        name='htmx-verification-card'
    ),
    path('htmx/trust-badge/', HTMXTrustScoreBadgeView.as_view(), name='htmx-trust-badge'),
]

# ===== PUBLIC VERIFICATION RESPONSE ENDPOINTS =====
# These are included separately as they don't require authentication
public_urlpatterns = [
    path(
        'verify/employment/<str:token>/',
        EmploymentVerificationResponseView.as_view(),
        name='employment-verification-response'
    ),
]
