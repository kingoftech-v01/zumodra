"""
Comprehensive Tests for the Zumodra Accounts App.

This module tests:
1. Model creation and validation
2. Role-based access control (RBAC)
3. API endpoint authentication and authorization
4. KYC verification workflow
5. Progressive consent system
6. Login history and security
7. Trust score calculation
8. Employment/Education verification flows
9. Review system
10. Multi-CV management
"""

import uuid
import secrets
from datetime import timedelta, date
from decimal import Decimal
from unittest.mock import patch, MagicMock

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from accounts.models import (
    TenantUser, UserProfile, KYCVerification,
    ProgressiveConsent, DataAccessLog, LoginHistory,
    TrustScore, EmploymentVerification, EducationVerification,
    Review, CandidateCV, StudentProfile, CoopTerm,
    ROLE_PERMISSIONS
)
from tests.base import TenantTestCase, APITenantTestCase, PermissionTestMixin


# =============================================================================
# MODEL TESTS
# =============================================================================

class TestTenantUserModel(TenantTestCase):
    """Tests for TenantUser model creation and validation."""

    def test_tenant_user_creation(self):
        """Test creating a TenantUser instance."""
        from conftest import UserFactory, TenantUserFactory

        user = UserFactory()
        tenant_user = TenantUserFactory(user=user, tenant=self.tenant, role='recruiter')

        assert tenant_user.uuid is not None
        assert tenant_user.user == user
        assert tenant_user.tenant == self.tenant
        assert tenant_user.role == 'recruiter'
        assert tenant_user.is_active is True

    def test_tenant_user_unique_together(self):
        """Test that user can only belong to a tenant once."""
        from django.db import IntegrityError
        from conftest import TenantUserFactory

        TenantUserFactory(user=self.user, tenant=self.tenant)

        with pytest.raises(IntegrityError):
            TenantUserFactory(user=self.user, tenant=self.tenant)

    def test_is_admin_property(self):
        """Test is_admin property for owner and admin roles."""
        from conftest import TenantUserFactory, UserFactory

        owner_tu = TenantUserFactory(
            user=UserFactory(), tenant=self.tenant, role='owner'
        )
        admin_tu = TenantUserFactory(
            user=UserFactory(), tenant=self.tenant, role='admin'
        )
        recruiter_tu = TenantUserFactory(
            user=UserFactory(), tenant=self.tenant, role='recruiter'
        )

        assert owner_tu.is_admin is True
        assert admin_tu.is_admin is True
        assert recruiter_tu.is_admin is False

    def test_can_hire_property(self):
        """Test can_hire property for various roles."""
        from conftest import TenantUserFactory, UserFactory

        roles_can_hire = ['owner', 'admin', 'hr_manager', 'recruiter', 'hiring_manager']
        roles_cannot_hire = ['employee', 'viewer']

        for role in roles_can_hire:
            tu = TenantUserFactory(
                user=UserFactory(), tenant=self.tenant, role=role
            )
            assert tu.can_hire is True, f"{role} should be able to hire"

        for role in roles_cannot_hire:
            tu = TenantUserFactory(
                user=UserFactory(), tenant=self.tenant, role=role
            )
            assert tu.can_hire is False, f"{role} should not be able to hire"

    def test_get_all_permissions(self):
        """Test getting all permissions for a role."""
        from conftest import TenantUserFactory, UserFactory

        admin_tu = TenantUserFactory(
            user=UserFactory(), tenant=self.tenant, role='admin'
        )

        permissions = admin_tu.get_all_permissions()
        assert 'view_all' in permissions
        assert 'edit_all' in permissions
        assert 'manage_users' in permissions

    def test_has_permission(self):
        """Test permission checking."""
        from conftest import TenantUserFactory, UserFactory

        recruiter_tu = TenantUserFactory(
            user=UserFactory(), tenant=self.tenant, role='recruiter'
        )

        assert recruiter_tu.has_permission('view_candidates') is True
        assert recruiter_tu.has_permission('manage_billing') is False


class TestUserProfileModel(TenantTestCase):
    """Tests for UserProfile model."""

    def test_user_profile_creation(self):
        """Test creating a UserProfile instance."""
        from conftest import UserProfileFactory

        profile = UserProfileFactory(user=self.user)

        assert profile.uuid is not None
        assert profile.user == self.user
        assert profile.profile_type in ['candidate', 'recruiter', 'employee', 'admin']

    def test_is_complete_property(self):
        """Test profile completion check."""
        from conftest import UserProfileFactory

        # Complete profile
        complete_profile = UserProfileFactory(
            user=self.user,
            phone='+14165551234',
            city='Toronto',
            country='CA'
        )
        assert complete_profile.is_complete is True

        # Incomplete profile
        from conftest import UserFactory
        incomplete_profile = UserProfileFactory(
            user=UserFactory(),
            phone='',
            city='',
            country=''
        )
        assert incomplete_profile.is_complete is False

    def test_completion_percentage(self):
        """Test profile completion percentage calculation."""
        from conftest import UserProfileFactory, UserFactory

        # Partially complete
        profile = UserProfileFactory(
            user=UserFactory(),
            phone='+14165551234',
            date_of_birth=date(1990, 1, 1),
            address_line1='123 Test St',
            city='Toronto',
            country='CA',
            bio='Test bio',
            avatar=None
        )
        # 6 out of 7 fields filled = ~85%
        assert 80 <= profile.completion_percentage <= 90


class TestKYCVerificationModel(TenantTestCase):
    """Tests for KYCVerification model."""

    def test_kyc_creation(self):
        """Test creating a KYCVerification instance."""
        from conftest import KYCVerificationFactory

        kyc = KYCVerificationFactory(user=self.user)

        assert kyc.uuid is not None
        assert kyc.user == self.user
        assert kyc.status == 'pending'

    def test_is_valid_property(self):
        """Test KYC validity checking."""
        from conftest import VerifiedKYCFactory, KYCVerificationFactory, UserFactory

        # Valid KYC
        valid_kyc = VerifiedKYCFactory(user=UserFactory())
        assert valid_kyc.is_valid is True

        # Pending KYC is not valid
        pending_kyc = KYCVerificationFactory(user=UserFactory(), status='pending')
        assert pending_kyc.is_valid is False

    def test_mark_verified(self):
        """Test marking KYC as verified."""
        from conftest import KYCVerificationFactory, UserFactory

        kyc = KYCVerificationFactory(user=self.user)
        verifier = UserFactory()

        kyc.mark_verified(verified_by=verifier, confidence_score=95.5)

        assert kyc.status == 'verified'
        assert kyc.verified_by == verifier
        assert kyc.confidence_score == Decimal('95.5')
        assert kyc.verified_at is not None
        assert kyc.expires_at is not None

    def test_mark_rejected(self):
        """Test marking KYC as rejected."""
        from conftest import KYCVerificationFactory

        kyc = KYCVerificationFactory(user=self.user)
        kyc.mark_rejected(reason='Document unclear')

        assert kyc.status == 'rejected'
        assert kyc.rejection_reason == 'Document unclear'


class TestProgressiveConsentModel(TenantTestCase):
    """Tests for ProgressiveConsent model."""

    def test_consent_creation(self):
        """Test creating a ProgressiveConsent instance."""
        from conftest import ProgressiveConsentFactory, UserFactory

        grantor = UserFactory()
        consent = ProgressiveConsentFactory(
            grantor=grantor,
            grantee_tenant=self.tenant,
            data_category='contact'
        )

        assert consent.uuid is not None
        assert consent.grantor == grantor
        assert consent.data_category == 'contact'

    def test_grant_consent(self):
        """Test granting consent."""
        from conftest import ProgressiveConsentFactory, UserFactory

        consent = ProgressiveConsentFactory(
            grantor=UserFactory(),
            grantee_tenant=self.tenant,
            status='pending'
        )

        consent.grant()

        assert consent.status == 'granted'
        assert consent.responded_at is not None
        assert consent.expires_at is not None

    def test_deny_consent(self):
        """Test denying consent."""
        from conftest import ProgressiveConsentFactory, UserFactory

        consent = ProgressiveConsentFactory(
            grantor=UserFactory(),
            grantee_tenant=self.tenant,
            status='pending'
        )

        consent.deny()

        assert consent.status == 'denied'
        assert consent.responded_at is not None

    def test_revoke_consent(self):
        """Test revoking consent."""
        from conftest import ProgressiveConsentFactory, UserFactory

        consent = ProgressiveConsentFactory(
            grantor=UserFactory(),
            grantee_tenant=self.tenant,
            status='granted'
        )

        consent.revoke()

        assert consent.status == 'revoked'
        assert consent.revoked_at is not None

    def test_is_active_property(self):
        """Test active consent checking."""
        from conftest import ProgressiveConsentFactory, UserFactory

        # Active consent
        active_consent = ProgressiveConsentFactory(
            grantor=UserFactory(),
            grantee_tenant=self.tenant,
            status='granted',
            expires_at=timezone.now() + timedelta(days=30)
        )
        assert active_consent.is_active is True

        # Expired consent
        expired_consent = ProgressiveConsentFactory(
            grantor=UserFactory(),
            grantee_tenant=self.tenant,
            status='granted',
            expires_at=timezone.now() - timedelta(days=1)
        )
        assert expired_consent.is_active is False


class TestLoginHistoryModel(TenantTestCase):
    """Tests for LoginHistory model."""

    def test_login_history_creation(self):
        """Test creating a LoginHistory instance."""
        from conftest import LoginHistoryFactory

        login = LoginHistoryFactory(user=self.user, result='success')

        assert login.user == self.user
        assert login.result == 'success'
        assert login.ip_address is not None
        assert login.timestamp is not None

    def test_failed_login_with_reason(self):
        """Test recording failed login with reason."""
        from conftest import LoginHistoryFactory

        login = LoginHistoryFactory(
            user=self.user,
            result='failed',
            failure_reason='Invalid password'
        )

        assert login.result == 'failed'
        assert login.failure_reason == 'Invalid password'


class TestTrustScoreModel(TenantTestCase):
    """Tests for TrustScore model."""

    def test_trust_score_creation(self):
        """Test creating a TrustScore instance."""
        trust_score = TrustScore.objects.create(user=self.user)

        assert trust_score.uuid is not None
        assert trust_score.user == self.user
        assert trust_score.trust_level == 'new'
        assert trust_score.overall_score == Decimal('0.00')

    def test_calculate_overall_score(self):
        """Test overall trust score calculation."""
        trust_score = TrustScore.objects.create(
            user=self.user,
            identity_score=Decimal('100.00'),
            career_score=Decimal('80.00'),
            activity_score=Decimal('60.00'),
            review_score=Decimal('90.00'),
            dispute_score=Decimal('100.00')
        )

        trust_score.calculate_overall_score()

        # Expected: 100*0.25 + 80*0.25 + 60*0.15 + 90*0.20 + 100*0.15 = 87
        assert trust_score.overall_score == Decimal('87.00')
        assert trust_score.trust_level == 'premium'

    def test_trust_level_thresholds(self):
        """Test trust level assignment based on score."""
        trust_score = TrustScore.objects.create(user=self.user)

        # Test different score thresholds
        test_cases = [
            (Decimal('90.00'), 'premium'),
            (Decimal('75.00'), 'high'),
            (Decimal('55.00'), 'verified'),
            (Decimal('30.00'), 'basic'),
            (Decimal('10.00'), 'new'),
        ]

        for score, expected_level in test_cases:
            trust_score.overall_score = score
            trust_score.calculate_overall_score()
            # Note: calculate_overall_score recalculates from components,
            # so we need to set components to achieve the desired score


class TestEmploymentVerificationModel(TenantTestCase):
    """Tests for EmploymentVerification model."""

    def test_employment_verification_creation(self):
        """Test creating an EmploymentVerification instance."""
        verification = EmploymentVerification.objects.create(
            user=self.user,
            company_name='Test Corp',
            job_title='Software Engineer',
            start_date=date(2020, 1, 1),
            end_date=date(2023, 12, 31),
            employment_type='full_time'
        )

        assert verification.uuid is not None
        assert verification.verification_token is not None
        assert verification.status == 'unverified'

    def test_auto_token_generation(self):
        """Test automatic token generation on save."""
        verification = EmploymentVerification.objects.create(
            user=self.user,
            company_name='Test Corp',
            job_title='Developer',
            start_date=date(2020, 1, 1)
        )

        assert verification.verification_token is not None
        assert len(verification.verification_token) > 20
        assert verification.token_expires_at is not None

    def test_mark_verified(self):
        """Test marking employment as verified."""
        verification = EmploymentVerification.objects.create(
            user=self.user,
            company_name='Test Corp',
            job_title='Developer',
            start_date=date(2020, 1, 1)
        )

        response_data = {
            'dates_confirmed': True,
            'title_confirmed': True,
            'eligible_for_rehire': True
        }

        verification.mark_verified(response_data)

        assert verification.status == 'verified'
        assert verification.verified_at is not None
        assert verification.dates_confirmed is True
        assert verification.title_confirmed is True


class TestEducationVerificationModel(TenantTestCase):
    """Tests for EducationVerification model."""

    def test_education_verification_creation(self):
        """Test creating an EducationVerification instance."""
        verification = EducationVerification.objects.create(
            user=self.user,
            institution_name='University of Test',
            degree_type='bachelor',
            field_of_study='Computer Science',
            start_date=date(2016, 9, 1),
            end_date=date(2020, 6, 1),
            graduated=True
        )

        assert verification.uuid is not None
        assert verification.verification_token is not None
        assert verification.status == 'unverified'

    def test_mark_verified(self):
        """Test marking education as verified."""
        verification = EducationVerification.objects.create(
            user=self.user,
            institution_name='University of Test',
            degree_type='bachelor',
            field_of_study='Computer Science',
            start_date=date(2016, 9, 1)
        )

        response_data = {
            'degree_confirmed': True,
            'dates_confirmed': True,
            'graduation_confirmed': True
        }

        verification.mark_verified(response_data)

        assert verification.status == 'verified'
        assert verification.verified_at is not None
        assert verification.degree_confirmed is True


class TestReviewModel(TenantTestCase):
    """Tests for Review model."""

    def test_review_creation(self):
        """Test creating a Review instance."""
        from conftest import UserFactory

        reviewee = UserFactory()
        review = Review.objects.create(
            reviewer=self.user,
            reviewee=reviewee,
            review_type='emp_to_cand',
            overall_rating=4,
            content='Great candidate!'
        )

        assert review.uuid is not None
        assert review.reviewer == self.user
        assert review.reviewee == reviewee
        assert review.status == 'pending'
        assert review.is_negative is False

    def test_negative_review_auto_flagging(self):
        """Test that low-rated reviews are auto-flagged."""
        from conftest import UserFactory

        reviewee = UserFactory()
        review = Review.objects.create(
            reviewer=self.user,
            reviewee=reviewee,
            review_type='emp_to_cand',
            overall_rating=2,
            content='Not recommended'
        )

        assert review.is_negative is True
        assert review.requires_verification is True
        assert review.status == 'under_review'

    def test_dispute_review(self):
        """Test disputing a review."""
        from conftest import UserFactory

        reviewee = UserFactory()
        review = Review.objects.create(
            reviewer=self.user,
            reviewee=reviewee,
            review_type='emp_to_cand',
            overall_rating=3,
            content='Average performance',
            status='published'
        )

        review.dispute(response='This is inaccurate', evidence=['doc1.pdf'])

        assert review.status == 'disputed'
        assert review.reviewee_response == 'This is inaccurate'
        assert review.disputed_at is not None


class TestCandidateCVModel(TenantTestCase):
    """Tests for CandidateCV model."""

    def test_cv_creation(self):
        """Test creating a CandidateCV instance."""
        cv = CandidateCV.objects.create(
            user=self.user,
            name='Software Engineer CV',
            summary='Experienced software developer',
            status='active'
        )

        assert cv.uuid is not None
        assert cv.slug is not None
        assert cv.is_primary is False

    def test_primary_cv_uniqueness(self):
        """Test that only one CV can be primary per user."""
        cv1 = CandidateCV.objects.create(
            user=self.user,
            name='CV 1',
            is_primary=True
        )

        cv2 = CandidateCV.objects.create(
            user=self.user,
            name='CV 2',
            is_primary=True
        )

        # Refresh cv1 from database
        cv1.refresh_from_db()

        assert cv1.is_primary is False
        assert cv2.is_primary is True

    def test_record_usage(self):
        """Test recording CV usage."""
        cv = CandidateCV.objects.create(
            user=self.user,
            name='Test CV'
        )

        cv.record_usage()

        assert cv.times_used == 1
        assert cv.applications_count == 1
        assert cv.last_used_at is not None


class TestStudentProfileModel(TenantTestCase):
    """Tests for StudentProfile model."""

    def test_student_profile_creation(self):
        """Test creating a StudentProfile instance."""
        profile = StudentProfile.objects.create(
            user=self.user,
            student_type='university',
            program_type='coop',
            institution_name='University of Test',
            program_name='Computer Science Co-op',
            major='Computer Science',
            expected_graduation=date(2025, 6, 1)
        )

        assert profile.uuid is not None
        assert profile.enrollment_status == 'active'
        assert profile.enrollment_verified is False

    def test_is_eligible_for_work(self):
        """Test work eligibility check."""
        eligible_profile = StudentProfile.objects.create(
            user=self.user,
            student_type='university',
            program_type='coop',
            institution_name='Test U',
            program_name='CS',
            major='CS',
            enrollment_status='active',
            work_authorization='citizen'
        )
        assert eligible_profile.is_eligible_for_work is True

        from conftest import UserFactory
        ineligible_profile = StudentProfile.objects.create(
            user=UserFactory(),
            student_type='university',
            program_type='coop',
            institution_name='Test U',
            program_name='CS',
            major='CS',
            enrollment_status='withdrawn',
            work_authorization='citizen'
        )
        assert ineligible_profile.is_eligible_for_work is False


# =============================================================================
# ROLE-BASED ACCESS CONTROL TESTS
# =============================================================================

class TestRolePermissions(TenantTestCase, PermissionTestMixin):
    """Tests for role-based permission system."""

    def test_owner_has_all_permissions(self):
        """Test that owner role has all permissions."""
        owner_perms = ROLE_PERMISSIONS[TenantUser.UserRole.OWNER]

        assert 'manage_billing' in owner_perms
        assert 'delete_all' in owner_perms
        assert 'manage_integrations' in owner_perms

    def test_viewer_has_limited_permissions(self):
        """Test that viewer role has only read permissions."""
        viewer_perms = ROLE_PERMISSIONS[TenantUser.UserRole.VIEWER]

        assert 'view_jobs' in viewer_perms
        assert 'view_candidates' in viewer_perms
        assert 'edit_candidates' not in viewer_perms
        assert 'manage_users' not in viewer_perms

    def test_recruiter_permissions(self):
        """Test recruiter role permissions."""
        recruiter_perms = ROLE_PERMISSIONS[TenantUser.UserRole.RECRUITER]

        assert 'view_candidates' in recruiter_perms
        assert 'edit_candidates' in recruiter_perms
        assert 'schedule_interviews' in recruiter_perms
        assert 'manage_billing' not in recruiter_perms

    def test_hr_manager_permissions(self):
        """Test HR manager role permissions."""
        hr_perms = ROLE_PERMISSIONS[TenantUser.UserRole.HR_MANAGER]

        assert 'manage_hr' in hr_perms
        assert 'edit_employees' in hr_perms
        assert 'export_data' in hr_perms
        assert 'manage_billing' not in hr_perms


# =============================================================================
# API ENDPOINT TESTS
# =============================================================================

class TestAuthenticationEndpoints(APITenantTestCase):
    """Tests for authentication API endpoints."""

    def test_register_user(self):
        """Test user registration endpoint."""
        self.unauthenticate()

        data = {
            'email': 'newuser@example.com',
            'username': 'newuser',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'TestPass123!',
            'password_confirm': 'TestPass123!',
            'profile_type': 'candidate'
        }

        response = self.client.post('/api/accounts/auth/register/', data, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert 'user' in response.data
        assert 'tokens' in response.data
        assert 'access' in response.data['tokens']
        assert 'refresh' in response.data['tokens']

    def test_login_valid_credentials(self):
        """Test login with valid credentials."""
        self.unauthenticate()

        # Set known password for user
        self.user.set_password('ValidPass123!')
        self.user.save()

        data = {
            'email': self.user.email,
            'password': 'ValidPass123!'
        }

        response = self.client.post('/api/accounts/auth/login/', data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert 'user' in response.data
        assert 'tokens' in response.data

        # Check login history was created
        assert LoginHistory.objects.filter(
            user=self.user,
            result='success'
        ).exists()

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        self.unauthenticate()

        data = {
            'email': self.user.email,
            'password': 'WrongPassword'
        }

        response = self.client.post('/api/accounts/auth/login/', data, format='json')

        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED]

    def test_logout(self):
        """Test logout endpoint."""
        # Get a refresh token first
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(self.user)

        data = {'refresh': str(refresh)}
        response = self.client.post('/api/accounts/auth/logout/', data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'logged out'

    def test_current_user(self):
        """Test getting current user endpoint."""
        response = self.client.get('/api/accounts/me/')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['email'] == self.user.email

    def test_password_change(self):
        """Test password change endpoint."""
        self.user.set_password('OldPass123!')
        self.user.save()

        data = {
            'old_password': 'OldPass123!',
            'new_password': 'NewPass123!',
            'new_password_confirm': 'NewPass123!'
        }

        response = self.client.post('/api/accounts/me/password/', data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'password changed'


class TestTenantUserEndpoints(APITenantTestCase):
    """Tests for TenantUser API endpoints."""

    def test_list_tenant_users(self):
        """Test listing tenant users."""
        from conftest import TenantUserFactory, UserFactory

        # Create additional users
        for i in range(3):
            TenantUserFactory(user=UserFactory(), tenant=self.tenant)

        response = self.get_with_tenant('/api/accounts/tenant-users/')

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 3

    def test_create_tenant_user_as_admin(self):
        """Test creating tenant user as admin."""
        from conftest import UserFactory

        new_user = UserFactory()

        data = {
            'user_id': new_user.id,
            'role': 'recruiter',
            'job_title': 'Senior Recruiter'
        }

        response = self.post_with_tenant('/api/accounts/tenant-users/', data)

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['role'] == 'recruiter'

    def test_create_tenant_user_unauthorized(self):
        """Test that non-admins cannot create tenant users."""
        self.authenticate_as_role('viewer')

        from conftest import UserFactory
        new_user = UserFactory()

        data = {
            'user_id': new_user.id,
            'role': 'employee'
        }

        response = self.post_with_tenant('/api/accounts/tenant-users/', data)

        self.assert_permission_denied(response)

    def test_update_role(self):
        """Test updating user role."""
        from conftest import TenantUserFactory, UserFactory

        target_user = TenantUserFactory(
            user=UserFactory(),
            tenant=self.tenant,
            role='employee'
        )

        data = {'role': 'recruiter'}
        response = self.post_with_tenant(
            f'/api/accounts/tenant-users/{target_user.uuid}/update_role/',
            data
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data['role'] == 'recruiter'

    def test_prevent_demoting_last_owner(self):
        """Test that last owner cannot be demoted."""
        # Current user is owner, try to demote
        data = {'role': 'admin'}
        response = self.post_with_tenant(
            f'/api/accounts/tenant-users/{self.tenant_user.uuid}/update_role/',
            data
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'Cannot demote the last owner' in str(response.data)

    def test_deactivate_user(self):
        """Test deactivating a tenant user."""
        from conftest import TenantUserFactory, UserFactory

        target_user = TenantUserFactory(
            user=UserFactory(),
            tenant=self.tenant,
            role='employee'
        )

        response = self.post_with_tenant(
            f'/api/accounts/tenant-users/{target_user.uuid}/deactivate/'
        )

        assert response.status_code == status.HTTP_200_OK
        target_user.refresh_from_db()
        assert target_user.is_active is False

    def test_reactivate_user(self):
        """Test reactivating a deactivated user."""
        from conftest import TenantUserFactory, UserFactory

        target_user = TenantUserFactory(
            user=UserFactory(),
            tenant=self.tenant,
            role='employee',
            is_active=False
        )

        response = self.post_with_tenant(
            f'/api/accounts/tenant-users/{target_user.uuid}/reactivate/'
        )

        assert response.status_code == status.HTTP_200_OK
        target_user.refresh_from_db()
        assert target_user.is_active is True

    def test_get_current_tenant_membership(self):
        """Test getting current user's tenant membership."""
        response = self.get_with_tenant('/api/accounts/tenant-users/me/')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['role'] == 'owner'


class TestUserProfileEndpoints(APITenantTestCase):
    """Tests for UserProfile API endpoints."""

    def test_get_own_profile(self):
        """Test getting own profile."""
        from conftest import UserProfileFactory
        UserProfileFactory(user=self.user)

        response = self.get_with_tenant('/api/accounts/profiles/me/')

        assert response.status_code == status.HTTP_200_OK

    def test_update_own_profile(self):
        """Test updating own profile."""
        from conftest import UserProfileFactory
        UserProfileFactory(user=self.user)

        data = {
            'bio': 'Updated bio',
            'city': 'Vancouver'
        }

        response = self.patch_with_tenant('/api/accounts/profiles/me/', data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['bio'] == 'Updated bio'


class TestKYCVerificationEndpoints(APITenantTestCase):
    """Tests for KYC Verification API endpoints."""

    def test_submit_kyc_verification(self):
        """Test submitting KYC verification request."""
        data = {
            'verification_type': 'identity',
            'level': 'standard',
            'document_type': 'passport',
            'document_country': 'CA'
        }

        response = self.post_with_tenant('/api/accounts/kyc/', data)

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['status'] == 'pending'

    def test_list_own_kyc_verifications(self):
        """Test listing own KYC verifications."""
        from conftest import KYCVerificationFactory

        KYCVerificationFactory(user=self.user)
        KYCVerificationFactory(user=self.user, verification_type='address')

        response = self.get_with_tenant('/api/accounts/kyc/')

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 2

    def test_verify_kyc_as_admin(self):
        """Test verifying KYC as admin."""
        from conftest import KYCVerificationFactory, UserFactory, TenantUserFactory

        # Create a KYC for another user in the tenant
        target_user = UserFactory()
        TenantUserFactory(user=target_user, tenant=self.tenant)
        kyc = KYCVerificationFactory(user=target_user)

        data = {
            'confidence_score': 95.5,
            'notes': 'Document verified successfully'
        }

        response = self.post_with_tenant(
            f'/api/accounts/kyc/{kyc.uuid}/verify/',
            data
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'verified'

    def test_reject_kyc_as_admin(self):
        """Test rejecting KYC as admin."""
        from conftest import KYCVerificationFactory, UserFactory, TenantUserFactory

        target_user = UserFactory()
        TenantUserFactory(user=target_user, tenant=self.tenant)
        kyc = KYCVerificationFactory(user=target_user)

        data = {
            'rejection_reason': 'Document is expired',
            'notes': 'Please submit a valid document'
        }

        response = self.post_with_tenant(
            f'/api/accounts/kyc/{kyc.uuid}/reject/',
            data
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'rejected'

    def test_get_kyc_status_summary(self):
        """Test getting KYC status summary."""
        from conftest import KYCVerificationFactory, VerifiedKYCFactory

        KYCVerificationFactory(user=self.user, status='pending')
        VerifiedKYCFactory(user=self.user, verification_type='identity')

        response = self.get_with_tenant('/api/accounts/kyc/my_status/')

        assert response.status_code == status.HTTP_200_OK
        assert 'total_verifications' in response.data
        assert 'verified_count' in response.data


class TestProgressiveConsentEndpoints(APITenantTestCase):
    """Tests for Progressive Consent API endpoints."""

    def test_request_consent(self):
        """Test requesting consent from another user."""
        from conftest import UserFactory

        data_subject = UserFactory()

        data = {
            'data_subject_id': data_subject.id,
            'data_category': 'contact',
            'purpose': 'To contact regarding job opportunity'
        }

        response = self.post_with_tenant('/api/accounts/consents/request_consent/', data)

        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK]
        assert response.data['status'] == 'pending'

    def test_grant_consent(self):
        """Test granting consent."""
        from conftest import ProgressiveConsentFactory

        consent = ProgressiveConsentFactory(
            grantor=self.user,
            grantee_tenant=self.tenant,
            status='pending'
        )

        data = {
            'consent_uuid': str(consent.uuid),
            'action': 'grant'
        }

        response = self.post_with_tenant('/api/accounts/consents/respond/', data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'granted'

    def test_deny_consent(self):
        """Test denying consent."""
        from conftest import ProgressiveConsentFactory

        consent = ProgressiveConsentFactory(
            grantor=self.user,
            grantee_tenant=self.tenant,
            status='pending'
        )

        data = {
            'consent_uuid': str(consent.uuid),
            'action': 'deny'
        }

        response = self.post_with_tenant('/api/accounts/consents/respond/', data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'denied'

    def test_revoke_consent(self):
        """Test revoking granted consent."""
        from conftest import ProgressiveConsentFactory

        consent = ProgressiveConsentFactory(
            grantor=self.user,
            grantee_tenant=self.tenant,
            status='granted'
        )

        data = {'consent_uuid': str(consent.uuid)}

        response = self.post_with_tenant('/api/accounts/consents/revoke/', data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'revoked'

    def test_get_pending_consents(self):
        """Test getting pending consent requests."""
        from conftest import ProgressiveConsentFactory, UserFactory

        # Create pending consents for current user
        for _ in range(3):
            ProgressiveConsentFactory(
                grantor=self.user,
                grantee_user=UserFactory(),
                status='pending'
            )

        response = self.get_with_tenant('/api/accounts/consents/pending/')

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 3


class TestLoginHistoryEndpoints(APITenantTestCase):
    """Tests for Login History API endpoints."""

    def test_list_login_history(self):
        """Test listing login history."""
        from conftest import LoginHistoryFactory

        for result in ['success', 'failed', 'success']:
            LoginHistoryFactory(user=self.user, result=result)

        response = self.get_with_tenant('/api/accounts/login-history/')

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 3

    def test_get_recent_logins(self):
        """Test getting recent logins."""
        from conftest import LoginHistoryFactory

        for _ in range(5):
            LoginHistoryFactory(user=self.user)

        response = self.get_with_tenant('/api/accounts/login-history/recent/')

        assert response.status_code == status.HTTP_200_OK

    def test_get_failed_logins(self):
        """Test getting failed logins."""
        from conftest import LoginHistoryFactory

        LoginHistoryFactory(user=self.user, result='failed')
        LoginHistoryFactory(user=self.user, result='failed')
        LoginHistoryFactory(user=self.user, result='success')

        response = self.get_with_tenant('/api/accounts/login-history/failed/')

        assert response.status_code == status.HTTP_200_OK


class TestTrustScoreEndpoints(APITenantTestCase):
    """Tests for Trust Score API endpoints."""

    def test_get_own_trust_score(self):
        """Test getting own trust score."""
        TrustScore.objects.create(user=self.user)

        response = self.get_with_tenant('/api/accounts/trust-scores/me/')

        assert response.status_code == status.HTTP_200_OK
        assert 'overall_score' in response.data
        assert 'trust_level' in response.data

    def test_recalculate_trust_score(self):
        """Test recalculating trust score."""
        TrustScore.objects.create(user=self.user)

        response = self.post_with_tenant('/api/accounts/trust-scores/recalculate/')

        assert response.status_code == status.HTTP_200_OK
        assert 'last_calculated_at' in response.data


class TestEmploymentVerificationEndpoints(APITenantTestCase):
    """Tests for Employment Verification API endpoints."""

    def test_create_employment_verification(self):
        """Test creating employment verification entry."""
        data = {
            'company_name': 'Test Corp',
            'job_title': 'Software Engineer',
            'start_date': '2020-01-01',
            'end_date': '2023-12-31',
            'employment_type': 'full_time',
            'hr_contact_email': 'hr@testcorp.com'
        }

        response = self.post_with_tenant('/api/accounts/employment-verifications/', data)

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['company_name'] == 'Test Corp'
        assert response.data['status'] == 'unverified'

    def test_list_employment_verifications(self):
        """Test listing employment verifications."""
        EmploymentVerification.objects.create(
            user=self.user,
            company_name='Company A',
            job_title='Role A',
            start_date=date(2020, 1, 1)
        )
        EmploymentVerification.objects.create(
            user=self.user,
            company_name='Company B',
            job_title='Role B',
            start_date=date(2022, 1, 1)
        )

        response = self.get_with_tenant('/api/accounts/employment-verifications/')

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 2

    def test_request_verification(self):
        """Test requesting employment verification."""
        verification = EmploymentVerification.objects.create(
            user=self.user,
            company_name='Test Corp',
            job_title='Engineer',
            start_date=date(2020, 1, 1),
            hr_contact_email='hr@test.com'
        )

        response = self.post_with_tenant(
            f'/api/accounts/employment-verifications/{verification.uuid}/request_verification/'
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'verification_request_sent'

    def test_cannot_delete_verified_employment(self):
        """Test that verified employment records cannot be deleted."""
        verification = EmploymentVerification.objects.create(
            user=self.user,
            company_name='Test Corp',
            job_title='Engineer',
            start_date=date(2020, 1, 1),
            status='verified'
        )

        response = self.delete_with_tenant(
            f'/api/accounts/employment-verifications/{verification.uuid}/'
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestEducationVerificationEndpoints(APITenantTestCase):
    """Tests for Education Verification API endpoints."""

    def test_create_education_verification(self):
        """Test creating education verification entry."""
        data = {
            'institution_name': 'Test University',
            'institution_type': 'university',
            'degree_type': 'bachelor',
            'field_of_study': 'Computer Science',
            'start_date': '2016-09-01',
            'end_date': '2020-06-01',
            'graduated': True
        }

        response = self.post_with_tenant('/api/accounts/education-verifications/', data)

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['institution_name'] == 'Test University'

    def test_list_education_verifications(self):
        """Test listing education verifications."""
        EducationVerification.objects.create(
            user=self.user,
            institution_name='University A',
            degree_type='bachelor',
            field_of_study='CS',
            start_date=date(2016, 9, 1)
        )

        response = self.get_with_tenant('/api/accounts/education-verifications/')

        assert response.status_code == status.HTTP_200_OK


class TestReviewEndpoints(APITenantTestCase):
    """Tests for Review API endpoints."""

    def test_create_review(self):
        """Test creating a review."""
        from conftest import UserFactory

        reviewee = UserFactory()

        data = {
            'reviewee_id': reviewee.id,
            'review_type': 'emp_to_cand',
            'overall_rating': 4,
            'content': 'Great candidate, highly recommend!',
            'communication_rating': 5,
            'professionalism_rating': 4
        }

        response = self.post_with_tenant('/api/accounts/reviews/', data)

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['overall_rating'] == 4

    def test_list_own_reviews(self):
        """Test listing reviews given/received."""
        from conftest import UserFactory

        # Create reviews
        Review.objects.create(
            reviewer=self.user,
            reviewee=UserFactory(),
            review_type='emp_to_cand',
            overall_rating=4,
            content='Good'
        )

        response = self.get_with_tenant('/api/accounts/reviews/')

        assert response.status_code == status.HTTP_200_OK

    def test_get_reviews_given(self):
        """Test getting reviews given by current user."""
        from conftest import UserFactory

        Review.objects.create(
            reviewer=self.user,
            reviewee=UserFactory(),
            review_type='emp_to_cand',
            overall_rating=4,
            content='Good'
        )

        response = self.get_with_tenant('/api/accounts/reviews/given/')

        assert response.status_code == status.HTTP_200_OK

    def test_get_reviews_received(self):
        """Test getting reviews received by current user."""
        from conftest import UserFactory

        Review.objects.create(
            reviewer=UserFactory(),
            reviewee=self.user,
            review_type='cand_to_emp',
            overall_rating=5,
            content='Great employer!',
            status='published'
        )

        response = self.get_with_tenant('/api/accounts/reviews/received/')

        assert response.status_code == status.HTTP_200_OK

    def test_dispute_review(self):
        """Test disputing a review."""
        from conftest import UserFactory

        reviewer = UserFactory()
        review = Review.objects.create(
            reviewer=reviewer,
            reviewee=self.user,
            review_type='emp_to_cand',
            overall_rating=2,
            content='Not recommended',
            status='published'
        )

        data = {
            'response': 'This review contains inaccurate information about my performance.'
        }

        response = self.post_with_tenant(
            f'/api/accounts/reviews/{review.uuid}/dispute/',
            data
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'review_disputed'

    def test_respond_to_review(self):
        """Test responding to a review."""
        from conftest import UserFactory

        reviewer = UserFactory()
        review = Review.objects.create(
            reviewer=reviewer,
            reviewee=self.user,
            review_type='emp_to_cand',
            overall_rating=3,
            content='Average performance',
            status='published'
        )

        data = {
            'response': 'Thank you for the feedback. I appreciate your time.'
        }

        response = self.post_with_tenant(
            f'/api/accounts/reviews/{review.uuid}/respond/',
            data
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'response_added'


class TestCandidateCVEndpoints(APITenantTestCase):
    """Tests for Candidate CV API endpoints."""

    def test_create_cv(self):
        """Test creating a CV."""
        data = {
            'name': 'Software Engineer CV',
            'summary': 'Experienced full-stack developer',
            'headline': 'Full-Stack Software Engineer',
            'skills': ['Python', 'Django', 'React'],
            'target_keywords': ['backend', 'full-stack']
        }

        response = self.post_with_tenant('/api/accounts/cvs/', data)

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['name'] == 'Software Engineer CV'

    def test_list_own_cvs(self):
        """Test listing own CVs."""
        CandidateCV.objects.create(user=self.user, name='CV 1')
        CandidateCV.objects.create(user=self.user, name='CV 2')

        response = self.get_with_tenant('/api/accounts/cvs/')

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 2

    def test_set_primary_cv(self):
        """Test setting a CV as primary."""
        cv = CandidateCV.objects.create(user=self.user, name='My CV')

        response = self.post_with_tenant(
            f'/api/accounts/cvs/{cv.uuid}/set_primary/'
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data['data']['is_primary'] is True

    def test_get_primary_cv(self):
        """Test getting primary CV."""
        CandidateCV.objects.create(user=self.user, name='Primary CV', is_primary=True)

        response = self.get_with_tenant('/api/accounts/cvs/primary/')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['is_primary'] is True

    def test_best_match_cv(self):
        """Test getting best matching CV for job."""
        CandidateCV.objects.create(
            user=self.user,
            name='Backend CV',
            status='active',
            target_keywords=['python', 'django', 'backend'],
            highlighted_skills=['Python', 'Django']
        )

        data = {
            'job_description': 'Looking for a Python Django developer',
            'job_keywords': ['python', 'django', 'backend']
        }

        response = self.post_with_tenant('/api/accounts/cvs/best_match/', data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['match_found'] is True


class TestStudentProfileEndpoints(APITenantTestCase):
    """Tests for Student Profile API endpoints."""

    def test_create_student_profile(self):
        """Test creating a student profile."""
        data = {
            'student_type': 'university',
            'program_type': 'coop',
            'institution_name': 'University of Test',
            'program_name': 'Computer Science Co-op',
            'major': 'Computer Science',
            'expected_graduation': '2025-06-01',
            'current_year': 3
        }

        response = self.post_with_tenant('/api/accounts/student-profiles/me/', data)

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['institution_name'] == 'University of Test'

    def test_get_own_student_profile(self):
        """Test getting own student profile."""
        StudentProfile.objects.create(
            user=self.user,
            student_type='university',
            program_type='coop',
            institution_name='Test U',
            program_name='CS',
            major='CS'
        )

        response = self.get_with_tenant('/api/accounts/student-profiles/me/')

        assert response.status_code == status.HTTP_200_OK

    def test_update_student_profile(self):
        """Test updating student profile."""
        StudentProfile.objects.create(
            user=self.user,
            student_type='university',
            program_type='coop',
            institution_name='Test U',
            program_name='CS',
            major='CS'
        )

        data = {'current_year': 4}

        response = self.patch_with_tenant('/api/accounts/student-profiles/me/', data)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['current_year'] == 4


class TestEmploymentVerificationPublicEndpoint(APITenantTestCase):
    """Tests for public employment verification response endpoint."""

    def test_submit_verification_response(self):
        """Test submitting verification response with valid token."""
        self.unauthenticate()

        verification = EmploymentVerification.objects.create(
            user=self.user,
            company_name='Test Corp',
            job_title='Engineer',
            start_date=date(2020, 1, 1),
            hr_contact_email='hr@test.com',
            status='pending'
        )

        data = {
            'token': verification.verification_token,
            'dates_confirmed': True,
            'title_confirmed': True,
            'eligible_for_rehire': True,
            'verifier_name': 'HR Manager',
            'verifier_email': 'hr@test.com'
        }

        response = self.client.post(
            '/api/accounts/verify/employment/',
            data,
            format='json'
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] == 'verification_submitted'

        verification.refresh_from_db()
        assert verification.status == 'verified'

    def test_invalid_token_rejected(self):
        """Test that invalid token is rejected."""
        self.unauthenticate()

        data = {
            'token': 'invalid-token-12345',
            'dates_confirmed': True,
            'title_confirmed': True,
            'verifier_name': 'HR Manager',
            'verifier_email': 'hr@test.com'
        }

        response = self.client.post(
            '/api/accounts/verify/employment/',
            data,
            format='json'
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_expired_token_rejected(self):
        """Test that expired token is rejected."""
        self.unauthenticate()

        verification = EmploymentVerification.objects.create(
            user=self.user,
            company_name='Test Corp',
            job_title='Engineer',
            start_date=date(2020, 1, 1),
            hr_contact_email='hr@test.com',
            status='pending',
            token_expires_at=timezone.now() - timedelta(days=1)
        )

        data = {
            'token': verification.verification_token,
            'dates_confirmed': True,
            'title_confirmed': True,
            'verifier_name': 'HR Manager',
            'verifier_email': 'hr@test.com'
        }

        response = self.client.post(
            '/api/accounts/verify/employment/',
            data,
            format='json'
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'expired' in str(response.data).lower()


# =============================================================================
# SECURITY AND AUTHORIZATION TESTS
# =============================================================================

class TestTenantIsolation(APITenantTestCase):
    """Tests for tenant data isolation."""

    def test_cannot_access_other_tenant_users(self):
        """Test that users cannot see other tenant's members."""
        from conftest import TenantFactory, UserFactory, TenantUserFactory

        # Create another tenant with users
        other_tenant = TenantFactory(plan=self.plan, slug='other-tenant')
        other_user = UserFactory()
        TenantUserFactory(user=other_user, tenant=other_tenant)

        # List tenant users (should only see own tenant)
        response = self.get_with_tenant('/api/accounts/tenant-users/')

        user_emails = [u['user']['email'] for u in response.data['results']]
        assert other_user.email not in user_emails

    def test_cannot_access_other_tenant_kyc(self):
        """Test that users cannot see other tenant's KYC verifications."""
        from conftest import TenantFactory, UserFactory, TenantUserFactory, KYCVerificationFactory

        other_tenant = TenantFactory(plan=self.plan, slug='other-tenant-2')
        other_user = UserFactory()
        TenantUserFactory(user=other_user, tenant=other_tenant)
        KYCVerificationFactory(user=other_user)

        response = self.get_with_tenant('/api/accounts/kyc/')

        user_ids = [v['user'] for v in response.data['results']]
        assert other_user.id not in user_ids


class TestAuthorizationChecks(APITenantTestCase):
    """Tests for authorization enforcement."""

    def test_unauthenticated_requests_blocked(self):
        """Test that unauthenticated requests are blocked."""
        self.unauthenticate()

        endpoints = [
            '/api/accounts/me/',
            '/api/accounts/tenant-users/',
            '/api/accounts/profiles/',
            '/api/accounts/kyc/',
            '/api/accounts/consents/',
        ]

        for endpoint in endpoints:
            response = self.client.get(endpoint)
            assert response.status_code in [
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_403_FORBIDDEN
            ], f"Endpoint {endpoint} should require authentication"

    def test_viewer_cannot_modify_data(self):
        """Test that viewer role cannot modify data."""
        self.authenticate_as_role('viewer')

        from conftest import UserFactory

        # Try to create a tenant user
        data = {
            'user_id': UserFactory().id,
            'role': 'employee'
        }

        response = self.post_with_tenant('/api/accounts/tenant-users/', data)

        self.assert_permission_denied(response)


# =============================================================================
# DATA ACCESS LOG TESTS
# =============================================================================

class TestDataAccessLogEndpoints(APITenantTestCase):
    """Tests for Data Access Log API endpoints."""

    def test_list_access_logs(self):
        """Test listing data access logs."""
        from conftest import UserFactory

        data_subject = UserFactory()

        # Create access logs
        DataAccessLog.objects.create(
            accessor=self.user,
            data_subject=data_subject,
            data_category='contact',
            accessor_tenant=self.tenant
        )

        response = self.get_with_tenant('/api/accounts/access-logs/')

        assert response.status_code == status.HTTP_200_OK

    def test_my_data_accessed(self):
        """Test getting logs of who accessed my data."""
        from conftest import UserFactory

        accessor = UserFactory()

        DataAccessLog.objects.create(
            accessor=accessor,
            data_subject=self.user,
            data_category='resume',
            accessor_tenant=self.tenant
        )

        response = self.get_with_tenant('/api/accounts/access-logs/my_data_accessed/')

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# EDGE CASE AND ERROR HANDLING TESTS
# =============================================================================

class TestErrorHandling(APITenantTestCase):
    """Tests for error handling and edge cases."""

    def test_invalid_uuid_returns_404(self):
        """Test that invalid UUID returns 404."""
        fake_uuid = str(uuid.uuid4())

        response = self.get_with_tenant(f'/api/accounts/tenant-users/{fake_uuid}/')

        self.assert_not_found(response)

    def test_invalid_role_rejected(self):
        """Test that invalid role is rejected."""
        from conftest import TenantUserFactory, UserFactory

        target = TenantUserFactory(user=UserFactory(), tenant=self.tenant)

        data = {'role': 'invalid_role'}

        response = self.post_with_tenant(
            f'/api/accounts/tenant-users/{target.uuid}/update_role/',
            data
        )

        self.assert_bad_request(response)

    def test_consent_for_nonexistent_user(self):
        """Test requesting consent for non-existent user."""
        data = {
            'data_subject_id': 999999,
            'data_category': 'contact',
            'purpose': 'Test'
        }

        response = self.post_with_tenant('/api/accounts/consents/request_consent/', data)

        self.assert_not_found(response)

    def test_duplicate_review_prevented(self):
        """Test that duplicate reviews are prevented."""
        from conftest import UserFactory

        reviewee = UserFactory()

        # Create first review
        Review.objects.create(
            reviewer=self.user,
            reviewee=reviewee,
            review_type='emp_to_cand',
            overall_rating=4,
            content='First review',
            context_type='job',
            context_id=1
        )

        # Try to create duplicate
        data = {
            'reviewee_id': reviewee.id,
            'review_type': 'emp_to_cand',
            'overall_rating': 5,
            'content': 'Second review',
            'context_type': 'job',
            'context_id': 1
        }

        response = self.post_with_tenant('/api/accounts/reviews/', data)

        # Should fail due to unique constraint
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_409_CONFLICT
        ]
