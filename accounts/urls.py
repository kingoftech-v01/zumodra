"""
Accounts URLs - REST API routing with DRF Router.

This module configures URL patterns for the accounts REST API:
- ViewSet routes via DefaultRouter
- Authentication endpoints (register, login, logout)
- Current user endpoint
- Password and security management
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views
from .views import (
    TenantUserViewSet,
    UserProfileViewSet,
    KYCVerificationViewSet,
    ProgressiveConsentViewSet,
    DataAccessLogViewSet,
    LoginHistoryViewSet,
    RegisterView,
    LoginView,
    LogoutView,
    CurrentUserView,
    PasswordChangeView,
    SecurityQuestionView,
    # New ViewSets for trust/verification models
    TrustScoreViewSet,
    EmploymentVerificationViewSet,
    EmploymentVerificationResponseView,
    EducationVerificationViewSet,
    ReviewViewSet,
    CandidateCVViewSet,
    StudentProfileViewSet,
)

# Create router and register ViewSets
router = DefaultRouter()

# Tenant user management
router.register(r'tenant-users', TenantUserViewSet, basename='tenant-user')

# User profiles
router.register(r'profiles', UserProfileViewSet, basename='profile')

# KYC verification
router.register(r'kyc', KYCVerificationViewSet, basename='kyc')

# Progressive consent
router.register(r'consents', ProgressiveConsentViewSet, basename='consent')

# Audit logs (read-only)
router.register(r'access-logs', DataAccessLogViewSet, basename='access-log')

# Login history (read-only)
router.register(r'login-history', LoginHistoryViewSet, basename='login-history')

# Trust System
router.register(r'trust-scores', TrustScoreViewSet, basename='trust-score')

# Employment Verification
router.register(r'employment-verifications', EmploymentVerificationViewSet, basename='employment-verification')

# Education Verification
router.register(r'education-verifications', EducationVerificationViewSet, basename='education-verification')

# Reviews
router.register(r'reviews', ReviewViewSet, basename='review')

# Candidate CVs
router.register(r'cvs', CandidateCVViewSet, basename='candidate-cv')

# Student Profiles
router.register(r'student-profiles', StudentProfileViewSet, basename='student-profile')

app_name = 'accounts'

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),

    # Current user endpoints
    path('me/', CurrentUserView.as_view(), name='current-user'),
    path('me/password/', PasswordChangeView.as_view(), name='password-change'),
    path('me/security-questions/', SecurityQuestionView.as_view(), name='security-questions'),

    # Public verification response endpoint (no authentication required)
    path(
        'verify/employment/',
        EmploymentVerificationResponseView.as_view(),
        name='employment-verification-response'
    ),

    # User verification endpoints (CV, KYC)
    path('verify/kyc/', views.submit_kyc_verification, name='submit-kyc'),
    path('verify/cv/', views.submit_cv_verification, name='submit-cv'),
    path('verify/status/', views.get_verification_status, name='verification-status'),
    path('verify/documents/', views.get_submitted_documents, name='verification-documents'),

    # Router URLs (ViewSets)
    path('', include(router.urls)),
]


"""
API Endpoints Available:
========================

Authentication:
--------------
POST /api/accounts/auth/register/          - Register new user account
    Request: {email, username, first_name, last_name, password, password_confirm, profile_type}
    Response: {user: {...}, tokens: {access, refresh}}

POST /api/accounts/auth/login/             - Login with email/password
    Request: {email, password}
    Response: {user: {...}, tokens: {access, refresh}}

POST /api/accounts/auth/logout/            - Logout (blacklist refresh token)
    Request: {refresh}
    Response: {status: 'logged out'}


Current User:
-------------
GET    /api/accounts/me/                   - Get current user details
PUT    /api/accounts/me/                   - Update current user (full)
PATCH  /api/accounts/me/                   - Update current user (partial)
POST   /api/accounts/me/password/          - Change password
    Request: {old_password, new_password, new_password_confirm}

GET    /api/accounts/me/security-questions/    - List security questions
POST   /api/accounts/me/security-questions/    - Add security question
DELETE /api/accounts/me/security-questions/    - Remove security question


Tenant Users (tenant-scoped):
-----------------------------
GET    /api/accounts/tenant-users/              - List tenant members
POST   /api/accounts/tenant-users/              - Add user to tenant (admin)
GET    /api/accounts/tenant-users/{uuid}/       - Get tenant user details
PUT    /api/accounts/tenant-users/{uuid}/       - Update tenant user (admin)
PATCH  /api/accounts/tenant-users/{uuid}/       - Partial update (admin)
DELETE /api/accounts/tenant-users/{uuid}/       - Remove from tenant (soft delete)

GET    /api/accounts/tenant-users/me/           - Get current user's tenant membership
POST   /api/accounts/tenant-users/{uuid}/deactivate/   - Deactivate user
POST   /api/accounts/tenant-users/{uuid}/reactivate/   - Reactivate user
POST   /api/accounts/tenant-users/{uuid}/update_role/  - Update user role
    Request: {role: 'admin'|'hr_manager'|'recruiter'|etc}

Filters: ?role=admin&is_active=true&department=1
Search: ?search=email@example.com
Ordering: ?ordering=-joined_at


User Profiles:
--------------
GET    /api/accounts/profiles/             - List profiles (own or admin)
GET    /api/accounts/profiles/{uuid}/      - Get profile details
PUT    /api/accounts/profiles/{uuid}/      - Update profile
PATCH  /api/accounts/profiles/{uuid}/      - Partial update profile

GET    /api/accounts/profiles/me/          - Get own profile
PUT    /api/accounts/profiles/me/          - Update own profile
PATCH  /api/accounts/profiles/me/          - Partial update own profile

Filters: ?profile_type=candidate&country=CA
Search: ?search=keyword


KYC Verification:
-----------------
GET    /api/accounts/kyc/                  - List KYC verifications
POST   /api/accounts/kyc/                  - Submit new verification request
    Request: {verification_type, level, document_type, document_country, document_expiry}
GET    /api/accounts/kyc/{uuid}/           - Get verification details
GET    /api/accounts/kyc/my_status/        - Get current user's KYC status summary

POST   /api/accounts/kyc/{uuid}/verify/    - Admin: Verify submission
    Request: {confidence_score, notes, verified_data}
POST   /api/accounts/kyc/{uuid}/reject/    - Admin: Reject submission
    Request: {rejection_reason, notes}

Filters: ?status=verified&verification_type=identity&level=standard
Ordering: ?ordering=-created_at


Progressive Consent:
--------------------
GET    /api/accounts/consents/             - List consents (given or received)
GET    /api/accounts/consents/{uuid}/      - Get consent details

POST   /api/accounts/consents/request_consent/     - Request consent from user
    Request: {data_subject_id, data_category, purpose, context_type?, context_id?, expires_in_days?}

POST   /api/accounts/consents/respond/     - Grant or deny consent request
    Request: {consent_uuid, action: 'grant'|'deny'}

POST   /api/accounts/consents/revoke/      - Revoke granted consent
    Request: {consent_uuid}

GET    /api/accounts/consents/pending/     - Get pending requests for current user
GET    /api/accounts/consents/granted/     - Get active granted consents

Filters: ?status=granted&data_category=contact
Ordering: ?ordering=-requested_at


Data Access Logs (read-only audit):
-----------------------------------
GET    /api/accounts/access-logs/                  - List access logs
GET    /api/accounts/access-logs/{uuid}/           - Get log entry details
GET    /api/accounts/access-logs/my_data_accessed/ - Logs of who accessed your data

Filters: ?data_category=contact&accessor=123
Ordering: ?ordering=-accessed_at


Login History (read-only security):
-----------------------------------
GET    /api/accounts/login-history/        - List login history
GET    /api/accounts/login-history/{id}/   - Get login entry details
GET    /api/accounts/login-history/recent/ - Recent login attempts (last 20)
GET    /api/accounts/login-history/failed/ - Failed login attempts (last 50)

Filters: ?result=success|failed|blocked
Ordering: ?ordering=-timestamp


Trust Scores:
-------------
GET    /api/accounts/trust-scores/              - List trust scores (admin: all, user: own)
GET    /api/accounts/trust-scores/{uuid}/       - Get trust score details
GET    /api/accounts/trust-scores/me/           - Get current user's trust score
POST   /api/accounts/trust-scores/recalculate/  - Recalculate current user's trust score

Filters: ?trust_level=verified&is_id_verified=true&is_career_verified=true
Ordering: ?ordering=-overall_score


Employment Verifications:
-------------------------
GET    /api/accounts/employment-verifications/                     - List employment records
POST   /api/accounts/employment-verifications/                     - Add new employment entry
    Request: {company_name, job_title, start_date, end_date?, is_current, employment_type,
              description?, hr_contact_email?, hr_contact_name?, hr_contact_phone?, company_domain?}
GET    /api/accounts/employment-verifications/{uuid}/              - Get employment details
PUT    /api/accounts/employment-verifications/{uuid}/              - Update employment entry
PATCH  /api/accounts/employment-verifications/{uuid}/              - Partial update
DELETE /api/accounts/employment-verifications/{uuid}/              - Delete (unverified only)
POST   /api/accounts/employment-verifications/{uuid}/request_verification/  - Send verification request

Public endpoint (no auth):
POST   /api/accounts/verify/employment/                            - Submit verification response
    Request: {token, dates_confirmed, title_confirmed, eligible_for_rehire?,
              performance_rating?, verifier_name, verifier_email, notes?}

Filters: ?status=verified&is_current=true&employment_type=full_time
Search: ?search=company_name
Ordering: ?ordering=-start_date


Education Verifications:
------------------------
GET    /api/accounts/education-verifications/                      - List education records
POST   /api/accounts/education-verifications/                      - Add new education entry
    Request: {institution_name, institution_type, degree_type, field_of_study,
              start_date, end_date?, is_current, graduated, gpa?, honors?,
              registrar_email?, institution_domain?, student_id?}
GET    /api/accounts/education-verifications/{uuid}/               - Get education details
PUT    /api/accounts/education-verifications/{uuid}/               - Update education entry
PATCH  /api/accounts/education-verifications/{uuid}/               - Partial update
DELETE /api/accounts/education-verifications/{uuid}/               - Delete (unverified only)
POST   /api/accounts/education-verifications/{uuid}/upload_transcript/     - Upload transcript
    Request: {transcript_file} (multipart/form-data)
POST   /api/accounts/education-verifications/{uuid}/request_verification/  - Send to registrar

Filters: ?status=verified&degree_type=bachelor&graduated=true
Search: ?search=institution_name
Ordering: ?ordering=-end_date


Reviews:
--------
GET    /api/accounts/reviews/                     - List reviews (given/received or admin)
POST   /api/accounts/reviews/                     - Create new review
    Request: {reviewee_id, review_type, context_type?, context_id?,
              overall_rating (1-5), communication_rating?, professionalism_rating?,
              quality_rating?, timeliness_rating?, would_recommend?, would_work_again?,
              title?, content, pros?, cons?}
GET    /api/accounts/reviews/{uuid}/              - Get review details
GET    /api/accounts/reviews/for_user/?user_id=X  - Get published reviews for a user
GET    /api/accounts/reviews/given/               - Reviews given by current user
GET    /api/accounts/reviews/received/            - Reviews received by current user
POST   /api/accounts/reviews/{uuid}/dispute/      - Dispute a review (reviewee only)
    Request: {response (min 50 chars), evidence?: [{...}]}
POST   /api/accounts/reviews/{uuid}/respond/      - Add response (reviewee only)
    Request: {response (10-2000 chars)}

Filters: ?status=published&review_type=emp_to_cand&overall_rating=5&is_negative=false
Ordering: ?ordering=-created_at


Candidate CVs (Multi-CV System):
--------------------------------
GET    /api/accounts/cvs/                         - List own CVs
POST   /api/accounts/cvs/                         - Create new CV
    Request: {name, is_primary?, status?, target_job_types?, target_industries?,
              target_keywords?, summary?, headline?, skills?, highlighted_skills?,
              included_experiences?, experience_order?, included_education?,
              projects?, certifications?, cv_file?}
GET    /api/accounts/cvs/{uuid}/                  - Get CV details
PUT    /api/accounts/cvs/{uuid}/                  - Update CV
PATCH  /api/accounts/cvs/{uuid}/                  - Partial update
DELETE /api/accounts/cvs/{uuid}/                  - Delete CV
POST   /api/accounts/cvs/{uuid}/set_primary/      - Set as primary CV
GET    /api/accounts/cvs/primary/                 - Get primary CV
POST   /api/accounts/cvs/best_match/              - Get best CV for a job
    Request: {job_description, job_keywords?: [...]}

Filters: ?status=active&is_primary=true
Search: ?search=headline
Ordering: ?ordering=-is_primary,-updated_at


Student Profiles (Co-op Ecosystem):
-----------------------------------
GET    /api/accounts/student-profiles/                - List student profiles (admin/hiring: all)
POST   /api/accounts/student-profiles/                - Create student profile
    Request: {student_type, program_type, institution_name, institution_type?,
              institution_email_domain?, student_email?, student_id?,
              program_name, faculty?, major, minor?, expected_graduation?,
              current_year?, current_term?, coop_sequence?, work_terms_completed?,
              work_terms_required?, next_work_term_start?, next_work_term_end?,
              gpa?, gpa_scale?, skills?, interests?, preferred_industries?,
              preferred_locations?, remote_preference?, work_authorization?,
              work_permit_expiry?, coordinator_name?, coordinator_email?}
GET    /api/accounts/student-profiles/{uuid}/         - Get profile details
PUT    /api/accounts/student-profiles/{uuid}/         - Update profile
PATCH  /api/accounts/student-profiles/{uuid}/         - Partial update
DELETE /api/accounts/student-profiles/{uuid}/         - Delete profile
GET/POST/PUT/PATCH /api/accounts/student-profiles/me/ - Get/Create/Update own profile
GET    /api/accounts/student-profiles/{uuid}/coop_terms/   - List co-op terms for profile
GET    /api/accounts/student-profiles/my_coop_terms/       - List own co-op terms

Filters: ?student_type=university&program_type=coop&enrollment_status=active
Search: ?search=institution_name
Ordering: ?ordering=-expected_graduation


Standard Query Parameters:
--------------------------
Pagination:
  ?page=2                    - Page number
  ?page_size=20              - Results per page (default varies)

Filtering:
  ?field=value               - Exact match
  ?field__in=val1,val2       - Multiple values

Searching:
  ?search=keyword            - Search across configured fields

Ordering:
  ?ordering=field            - Ascending
  ?ordering=-field           - Descending
  ?ordering=field1,-field2   - Multiple fields


Role Choices for TenantUser:
----------------------------
- owner        : Owner/PDG (full access)
- admin        : Administrator
- hr_manager   : HR Manager
- recruiter    : Recruiter
- hiring_manager : Hiring Manager
- employee     : Employee
- viewer       : Viewer (read-only)


Data Category Choices for Consent:
----------------------------------
- basic        : Basic Info (Name, Title)
- contact      : Contact Info (Email, Phone)
- resume       : Resume/CV
- detailed     : Detailed Profile
- personal     : Personal Info (DOB, Address)
- sensitive    : Sensitive Data (NAS, Medical)
- references   : References
- salary       : Salary Expectations
- background   : Background Check Results


KYC Verification Types:
-----------------------
- identity     : Identity Verification
- address      : Address Verification
- employment   : Employment Verification
- education    : Education Verification
- background   : Background Check
- business     : Business Verification


KYC Levels:
-----------
- basic        : Basic (Email + Phone)
- standard     : Standard (ID Verification)
- enhanced     : Enhanced (Background Check)
- complete     : Complete (Full Verification)
"""
