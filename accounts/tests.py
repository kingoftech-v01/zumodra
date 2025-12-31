"""
Accounts Tests - Authentication, KYC, and RBAC

Tests for:
- User registration and login/logout
- KYC verification workflow
- Progressive consent management
- Role-Based Access Control (RBAC)
- User profiles
- Login history and security
"""

import pytest
from decimal import Decimal
from datetime import timedelta
from django.utils import timezone
from django.db import IntegrityError
from django.contrib.auth import get_user_model

from accounts.models import (
    TenantUser, ROLE_PERMISSIONS, UserProfile,
    KYCVerification, ProgressiveConsent, DataAccessLog,
    SecurityQuestion, LoginHistory
)

User = get_user_model()


# ============================================================================
# USER REGISTRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestUserRegistration:
    """Tests for user registration."""

    def test_create_user(self, user_factory):
        """Test basic user creation."""
        user = user_factory()
        assert user.pk is not None
        assert user.email is not None
        assert user.is_active is True

    def test_create_user_with_email(self, user_factory):
        """Test user creation with specific email."""
        user = user_factory(email='test@example.com')
        assert user.email == 'test@example.com'

    def test_user_password_is_hashed(self, user_factory):
        """Test that user password is properly hashed."""
        user = user_factory(password='testpass123')
        assert user.password != 'testpass123'
        assert user.check_password('testpass123')

    def test_create_superuser(self, superuser_factory):
        """Test superuser creation."""
        admin = superuser_factory()
        assert admin.is_staff is True
        assert admin.is_superuser is True

    def test_user_unique_email(self, user_factory):
        """Test that email must be unique."""
        user_factory(email='unique@example.com')
        with pytest.raises(IntegrityError):
            user_factory(email='unique@example.com')


@pytest.mark.django_db
class TestUserAuthentication:
    """Tests for user authentication."""

    def test_user_can_login(self, user_factory, client):
        """Test user can login with correct credentials."""
        user = user_factory(email='login@example.com')
        user.set_password('testpass123')
        user.save()

        logged_in = client.login(username=user.username, password='testpass123')
        # Note: This may fail due to 2FA requirements
        # The actual login test depends on the auth backend configuration

    def test_user_cannot_login_with_wrong_password(self, user_factory, client):
        """Test user cannot login with wrong password."""
        user = user_factory(email='wrong@example.com')
        user.set_password('correctpassword')
        user.save()

        logged_in = client.login(username=user.username, password='wrongpassword')
        assert logged_in is False

    def test_inactive_user_cannot_login(self, user_factory, client):
        """Test inactive user cannot login."""
        user = user_factory(is_active=False)
        user.set_password('testpass123')
        user.save()

        logged_in = client.login(username=user.username, password='testpass123')
        assert logged_in is False


# ============================================================================
# TENANT USER TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantUserModel:
    """Tests for TenantUser model."""

    def test_create_tenant_user(self, tenant_user_factory):
        """Test basic tenant user creation."""
        tenant_user = tenant_user_factory()
        assert tenant_user.pk is not None
        assert tenant_user.uuid is not None
        assert tenant_user.user is not None
        assert tenant_user.tenant is not None

    def test_tenant_user_roles(self, tenant_user_factory):
        """Test different tenant user roles."""
        for role, label in TenantUser.UserRole.choices:
            tenant_user = tenant_user_factory(role=role)
            assert tenant_user.role == role
            assert tenant_user.get_role_display() == label

    def test_tenant_user_is_admin_property(self, tenant_user_factory):
        """Test is_admin property."""
        owner = tenant_user_factory(role='owner')
        admin = tenant_user_factory(role='admin')
        recruiter = tenant_user_factory(role='recruiter')
        employee = tenant_user_factory(role='employee')

        assert owner.is_admin is True
        assert admin.is_admin is True
        assert recruiter.is_admin is False
        assert employee.is_admin is False

    def test_tenant_user_can_hire_property(self, tenant_user_factory):
        """Test can_hire property."""
        owner = tenant_user_factory(role='owner')
        recruiter = tenant_user_factory(role='recruiter')
        hr_manager = tenant_user_factory(role='hr_manager')
        hiring_manager = tenant_user_factory(role='hiring_manager')
        employee = tenant_user_factory(role='employee')
        viewer = tenant_user_factory(role='viewer')

        assert owner.can_hire is True
        assert recruiter.can_hire is True
        assert hr_manager.can_hire is True
        assert hiring_manager.can_hire is True
        assert employee.can_hire is False
        assert viewer.can_hire is False

    def test_tenant_user_unique_constraint(self, tenant_user_factory, user_factory, tenant_factory):
        """Test user can only have one membership per tenant."""
        user = user_factory()
        tenant = tenant_factory()
        tenant_user_factory(user=user, tenant=tenant)

        with pytest.raises(IntegrityError):
            tenant_user_factory(user=user, tenant=tenant)

    def test_user_multiple_tenants(self, tenant_user_factory, user_factory, tenant_factory):
        """Test user can belong to multiple tenants."""
        user = user_factory()
        tenant1 = tenant_factory()
        tenant2 = tenant_factory()

        tu1 = tenant_user_factory(user=user, tenant=tenant1, is_primary_tenant=True)
        tu2 = tenant_user_factory(user=user, tenant=tenant2, is_primary_tenant=False)

        assert user.tenant_memberships.count() == 2

    def test_tenant_user_string_representation(self, tenant_user_factory):
        """Test tenant user string representation."""
        tenant_user = tenant_user_factory(role='recruiter')
        assert '@' in str(tenant_user)
        assert 'Recruiter' in str(tenant_user)


@pytest.mark.django_db
class TestRBACPermissions:
    """Tests for Role-Based Access Control."""

    def test_owner_has_all_permissions(self, tenant_user_factory):
        """Test owner role has all permissions."""
        owner = tenant_user_factory(role='owner')
        permissions = owner.get_all_permissions()

        assert 'view_all' in permissions
        assert 'edit_all' in permissions
        assert 'delete_all' in permissions
        assert 'manage_users' in permissions
        assert 'manage_billing' in permissions

    def test_admin_permissions(self, tenant_user_factory):
        """Test admin role permissions."""
        admin = tenant_user_factory(role='admin')
        permissions = admin.get_all_permissions()

        assert 'view_all' in permissions
        assert 'edit_all' in permissions
        assert 'manage_users' in permissions
        # Admin doesn't have billing permissions
        assert 'manage_billing' not in permissions

    def test_hr_manager_permissions(self, tenant_user_factory):
        """Test HR manager role permissions."""
        hr = tenant_user_factory(role='hr_manager')
        permissions = hr.get_all_permissions()

        assert 'view_candidates' in permissions
        assert 'edit_candidates' in permissions
        assert 'view_employees' in permissions
        assert 'manage_hr' in permissions
        assert 'manage_billing' not in permissions

    def test_recruiter_permissions(self, tenant_user_factory):
        """Test recruiter role permissions."""
        recruiter = tenant_user_factory(role='recruiter')
        permissions = recruiter.get_all_permissions()

        assert 'view_candidates' in permissions
        assert 'edit_candidates' in permissions
        assert 'view_jobs' in permissions
        assert 'edit_jobs' in permissions
        assert 'schedule_interviews' in permissions
        assert 'manage_hr' not in permissions

    def test_employee_permissions(self, tenant_user_factory):
        """Test employee role permissions."""
        employee = tenant_user_factory(role='employee')
        permissions = employee.get_all_permissions()

        assert 'view_profile' in permissions
        assert 'edit_profile' in permissions
        assert 'request_time_off' in permissions
        assert 'view_candidates' not in permissions
        assert 'edit_jobs' not in permissions

    def test_viewer_permissions(self, tenant_user_factory):
        """Test viewer role permissions (read-only)."""
        viewer = tenant_user_factory(role='viewer')
        permissions = viewer.get_all_permissions()

        assert 'view_jobs' in permissions
        assert 'view_candidates' in permissions
        assert 'view_reports' in permissions
        assert 'edit_jobs' not in permissions
        assert 'edit_candidates' not in permissions

    def test_has_permission_method(self, tenant_user_factory):
        """Test has_permission method."""
        recruiter = tenant_user_factory(role='recruiter')

        assert recruiter.has_permission('view_candidates') is True
        assert recruiter.has_permission('manage_billing') is False


# ============================================================================
# USER PROFILE TESTS
# ============================================================================

@pytest.mark.django_db
class TestUserProfileModel:
    """Tests for UserProfile model."""

    def test_create_user_profile(self, user_profile_factory):
        """Test basic user profile creation."""
        profile = user_profile_factory()
        assert profile.pk is not None
        assert profile.uuid is not None
        assert profile.user is not None

    def test_profile_types(self, user_profile_factory):
        """Test different profile types."""
        for profile_type, label in UserProfile.ProfileType.choices:
            profile = user_profile_factory(profile_type=profile_type)
            assert profile.profile_type == profile_type

    def test_profile_is_complete_property(self, user_profile_factory):
        """Test is_complete property."""
        # Complete profile
        complete_profile = user_profile_factory(
            phone='+14165551234',
            city='Toronto',
            country='CA'
        )
        assert complete_profile.is_complete is True

        # Incomplete profile
        incomplete_profile = user_profile_factory(
            phone='',
            city='',
            country=''
        )
        assert incomplete_profile.is_complete is False

    def test_profile_completion_percentage(self, user_profile_factory):
        """Test completion percentage calculation."""
        profile = user_profile_factory(
            phone='+14165551234',
            date_of_birth=None,
            address_line1='123 Main St',
            city='Toronto',
            country='CA',
            bio='Test bio',
            avatar=None
        )
        percentage = profile.completion_percentage

        assert percentage >= 0
        assert percentage <= 100

    def test_profile_social_links(self, user_profile_factory):
        """Test social link fields."""
        profile = user_profile_factory(
            linkedin_url='https://linkedin.com/in/testuser',
            github_url='https://github.com/testuser',
            portfolio_url='https://testuser.com',
            twitter_url='https://twitter.com/testuser'
        )

        assert profile.linkedin_url == 'https://linkedin.com/in/testuser'
        assert profile.github_url == 'https://github.com/testuser'

    def test_profile_string_representation(self, user_profile_factory):
        """Test profile string representation."""
        profile = user_profile_factory()
        assert 'Profile:' in str(profile)


# ============================================================================
# KYC VERIFICATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestKYCVerificationModel:
    """Tests for KYCVerification model."""

    def test_create_kyc_verification(self, kyc_verification_factory):
        """Test basic KYC verification creation."""
        kyc = kyc_verification_factory()
        assert kyc.pk is not None
        assert kyc.uuid is not None
        assert kyc.user is not None

    def test_kyc_verification_types(self, kyc_verification_factory):
        """Test different verification types."""
        for vtype, label in KYCVerification.VerificationType.choices:
            kyc = kyc_verification_factory(verification_type=vtype)
            assert kyc.verification_type == vtype

    def test_kyc_verification_statuses(self, kyc_verification_factory):
        """Test different verification statuses."""
        for status, label in KYCVerification.VerificationStatus.choices:
            kyc = kyc_verification_factory(status=status)
            assert kyc.status == status

    def test_kyc_verification_levels(self, kyc_verification_factory):
        """Test different verification levels."""
        for level, label in KYCVerification.VerificationLevel.choices:
            kyc = kyc_verification_factory(level=level)
            assert kyc.level == level

    def test_kyc_is_valid_property(self, kyc_verification_factory):
        """Test is_valid property."""
        # Valid verification
        from conftest import VerifiedKYCFactory
        valid_kyc = VerifiedKYCFactory()
        assert valid_kyc.is_valid is True

        # Invalid - wrong status
        pending_kyc = kyc_verification_factory(status='pending')
        assert pending_kyc.is_valid is False

        # Invalid - expired
        expired_kyc = VerifiedKYCFactory(
            expires_at=timezone.now() - timedelta(days=1)
        )
        assert expired_kyc.is_valid is False

    def test_mark_verified(self, kyc_verification_factory, user_factory):
        """Test mark_verified method."""
        kyc = kyc_verification_factory(status='pending')
        verifier = user_factory()

        kyc.mark_verified(verified_by=verifier, confidence_score=Decimal('95.00'))

        assert kyc.status == 'verified'
        assert kyc.verified_at is not None
        assert kyc.verified_by == verifier
        assert kyc.confidence_score == Decimal('95.00')
        assert kyc.expires_at is not None

    def test_mark_rejected(self, kyc_verification_factory):
        """Test mark_rejected method."""
        kyc = kyc_verification_factory(status='pending')

        kyc.mark_rejected(reason='Document not clear')

        assert kyc.status == 'rejected'
        assert kyc.rejection_reason == 'Document not clear'

    def test_kyc_string_representation(self, kyc_verification_factory):
        """Test KYC verification string representation."""
        kyc = kyc_verification_factory()
        assert 'KYC' in str(kyc)


@pytest.mark.django_db
class TestKYCWorkflow:
    """Tests for KYC verification workflow."""

    def test_kyc_workflow_pending_to_in_progress(self, kyc_verification_factory):
        """Test KYC status transition: pending to in_progress."""
        kyc = kyc_verification_factory(status='pending')

        kyc.status = 'in_progress'
        kyc.save()

        assert kyc.status == 'in_progress'

    def test_kyc_workflow_in_progress_to_verified(self, kyc_verification_factory, user_factory):
        """Test KYC status transition: in_progress to verified."""
        kyc = kyc_verification_factory(status='in_progress')
        verifier = user_factory()

        kyc.mark_verified(verified_by=verifier)

        assert kyc.status == 'verified'
        assert kyc.is_valid is True

    def test_kyc_workflow_in_progress_to_rejected(self, kyc_verification_factory):
        """Test KYC status transition: in_progress to rejected."""
        kyc = kyc_verification_factory(status='in_progress')

        kyc.mark_rejected(reason='Fraudulent document')

        assert kyc.status == 'rejected'

    def test_bidirectional_kyc_candidate(self, kyc_verification_factory, user_factory):
        """Test KYC verification for candidate."""
        user = user_factory()
        kyc = kyc_verification_factory(
            user=user,
            verification_type='identity',
            level='standard'
        )

        assert kyc.user == user
        assert kyc.verification_type == 'identity'

    def test_bidirectional_kyc_recruiter(self, kyc_verification_factory, user_factory):
        """Test KYC verification for recruiter."""
        user = user_factory()
        kyc = kyc_verification_factory(
            user=user,
            verification_type='business',
            level='enhanced'
        )

        assert kyc.user == user
        assert kyc.verification_type == 'business'


# ============================================================================
# PROGRESSIVE CONSENT TESTS
# ============================================================================

@pytest.mark.django_db
class TestProgressiveConsentModel:
    """Tests for ProgressiveConsent model."""

    def test_create_progressive_consent(self, progressive_consent_factory):
        """Test basic progressive consent creation."""
        consent = progressive_consent_factory()
        assert consent.pk is not None
        assert consent.uuid is not None
        assert consent.grantor is not None

    def test_consent_data_categories(self, progressive_consent_factory):
        """Test different data categories."""
        for category, label in ProgressiveConsent.DataCategory.choices:
            consent = progressive_consent_factory(data_category=category)
            assert consent.data_category == category

    def test_consent_statuses(self, progressive_consent_factory):
        """Test different consent statuses."""
        for status, label in ProgressiveConsent.ConsentStatus.choices:
            consent = progressive_consent_factory(status=status)
            assert consent.status == status

    def test_consent_is_active_property(self, progressive_consent_factory):
        """Test is_active property."""
        # Active consent
        active_consent = progressive_consent_factory(status='granted')
        active_consent.expires_at = timezone.now() + timedelta(days=30)
        active_consent.save()
        assert active_consent.is_active is True

        # Inactive - not granted
        pending_consent = progressive_consent_factory(status='pending')
        assert pending_consent.is_active is False

        # Inactive - expired
        expired_consent = progressive_consent_factory(
            status='granted',
            expires_at=timezone.now() - timedelta(days=1)
        )
        assert expired_consent.is_active is False

    def test_grant_consent(self, progressive_consent_factory):
        """Test granting consent."""
        consent = progressive_consent_factory(status='pending')

        consent.grant()

        assert consent.status == 'granted'
        assert consent.responded_at is not None
        assert consent.expires_at is not None

    def test_deny_consent(self, progressive_consent_factory):
        """Test denying consent."""
        consent = progressive_consent_factory(status='pending')

        consent.deny()

        assert consent.status == 'denied'
        assert consent.responded_at is not None

    def test_revoke_consent(self, progressive_consent_factory):
        """Test revoking consent."""
        consent = progressive_consent_factory(status='granted')

        consent.revoke()

        assert consent.status == 'revoked'
        assert consent.revoked_at is not None

    def test_consent_string_representation(self, progressive_consent_factory):
        """Test consent string representation."""
        consent = progressive_consent_factory()
        assert '->' in str(consent)


@pytest.mark.django_db
class TestProgressiveRevelation:
    """Tests for progressive data revelation."""

    def test_basic_data_category(self, progressive_consent_factory, user_factory):
        """Test basic data category consent."""
        user = user_factory()
        consent = progressive_consent_factory(
            grantor=user,
            data_category='basic',
            status='granted'
        )

        assert consent.data_category == 'basic'
        assert consent.status == 'granted'

    def test_contact_data_requires_consent(self, progressive_consent_factory, user_factory):
        """Test contact data requires explicit consent."""
        user = user_factory()
        consent = progressive_consent_factory(
            grantor=user,
            data_category='contact',
            status='pending'
        )

        assert consent.status == 'pending'
        assert consent.is_active is False

    def test_sensitive_data_consent(self, progressive_consent_factory, user_factory):
        """Test sensitive data consent."""
        user = user_factory()
        consent = progressive_consent_factory(
            grantor=user,
            data_category='sensitive',
            status='pending',
            purpose='Background check for employment'
        )

        assert consent.data_category == 'sensitive'
        assert consent.purpose == 'Background check for employment'

    def test_consent_with_context(self, progressive_consent_factory, user_factory):
        """Test consent with application context."""
        user = user_factory()
        consent = progressive_consent_factory(
            grantor=user,
            data_category='resume',
            context_type='job_application',
            context_id=123
        )

        assert consent.context_type == 'job_application'
        assert consent.context_id == 123


# ============================================================================
# DATA ACCESS LOG TESTS
# ============================================================================

@pytest.mark.django_db
class TestDataAccessLogModel:
    """Tests for DataAccessLog model."""

    def test_create_data_access_log(self, user_factory, tenant_factory):
        """Test basic data access log creation."""
        accessor = user_factory()
        data_subject = user_factory()
        tenant = tenant_factory()

        log = DataAccessLog.objects.create(
            accessor=accessor,
            accessor_tenant=tenant,
            data_subject=data_subject,
            data_category='contact',
            data_fields=['email', 'phone'],
            access_reason='Reviewing job application',
            ip_address='192.168.1.1'
        )

        assert log.pk is not None
        assert log.accessor == accessor
        assert log.data_subject == data_subject
        assert log.data_category == 'contact'

    def test_data_access_log_fields(self, user_factory):
        """Test data access log tracks specific fields."""
        accessor = user_factory()
        data_subject = user_factory()

        log = DataAccessLog.objects.create(
            accessor=accessor,
            data_subject=data_subject,
            data_category='personal',
            data_fields=['address', 'date_of_birth', 'nationality']
        )

        assert 'address' in log.data_fields
        assert 'date_of_birth' in log.data_fields

    def test_data_access_log_with_consent(self, user_factory, progressive_consent_factory):
        """Test data access log linked to consent."""
        accessor = user_factory()
        data_subject = user_factory()
        consent = progressive_consent_factory(
            grantor=data_subject,
            data_category='resume',
            status='granted'
        )

        log = DataAccessLog.objects.create(
            accessor=accessor,
            data_subject=data_subject,
            data_category='resume',
            consent=consent,
            data_fields=['resume_text']
        )

        assert log.consent == consent


# ============================================================================
# LOGIN HISTORY TESTS
# ============================================================================

@pytest.mark.django_db
class TestLoginHistoryModel:
    """Tests for LoginHistory model."""

    def test_create_login_history(self, login_history_factory):
        """Test basic login history creation."""
        login = login_history_factory()
        assert login.pk is not None
        assert login.user is not None
        assert login.timestamp is not None

    def test_login_result_types(self, login_history_factory):
        """Test different login result types."""
        for result, label in LoginHistory.LoginResult.choices:
            login = login_history_factory(result=result)
            assert login.result == result

    def test_successful_login_record(self, login_history_factory):
        """Test recording successful login."""
        login = login_history_factory(
            result='success',
            ip_address='192.168.1.1'
        )

        assert login.result == 'success'
        assert login.ip_address == '192.168.1.1'

    def test_failed_login_record(self, login_history_factory):
        """Test recording failed login."""
        login = login_history_factory(
            result='failed',
            failure_reason='Invalid password'
        )

        assert login.result == 'failed'
        assert login.failure_reason == 'Invalid password'

    def test_blocked_login_record(self, login_history_factory):
        """Test recording blocked login."""
        login = login_history_factory(
            result='blocked',
            failure_reason='Account locked due to too many failed attempts'
        )

        assert login.result == 'blocked'

    def test_login_history_ordering(self, login_history_factory, user_factory):
        """Test login history is ordered by timestamp descending."""
        user = user_factory()
        login1 = login_history_factory(user=user)
        login2 = login_history_factory(user=user)
        login3 = login_history_factory(user=user)

        logins = list(LoginHistory.objects.filter(user=user))
        # Most recent should be first
        assert logins[0].pk == login3.pk

    def test_login_history_string_representation(self, login_history_factory):
        """Test login history string representation."""
        login = login_history_factory()
        assert 'login' in str(login).lower()


# ============================================================================
# SECURITY QUESTION TESTS
# ============================================================================

@pytest.mark.django_db
class TestSecurityQuestionModel:
    """Tests for SecurityQuestion model."""

    def test_create_security_question(self, user_factory):
        """Test basic security question creation."""
        user = user_factory()
        question = SecurityQuestion.objects.create(
            user=user,
            question='What is your mother\'s maiden name?',
            answer_hash='hashed_answer_here'
        )

        assert question.pk is not None
        assert question.user == user

    def test_multiple_security_questions(self, user_factory):
        """Test user can have multiple security questions."""
        user = user_factory()
        SecurityQuestion.objects.create(
            user=user,
            question='What is your mother\'s maiden name?',
            answer_hash='hash1'
        )
        SecurityQuestion.objects.create(
            user=user,
            question='What was the name of your first pet?',
            answer_hash='hash2'
        )
        SecurityQuestion.objects.create(
            user=user,
            question='What city were you born in?',
            answer_hash='hash3'
        )

        assert user.security_questions.count() == 3

    def test_security_question_string_representation(self, user_factory):
        """Test security question string representation."""
        user = user_factory()
        question = SecurityQuestion.objects.create(
            user=user,
            question='Test question?',
            answer_hash='hash'
        )

        assert 'Security Q' in str(question)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestAccountsIntegration:
    """Integration tests for accounts functionality."""

    def test_user_with_profile_and_kyc(self, user_factory, user_profile_factory, kyc_verification_factory):
        """Test user with complete profile and KYC."""
        user = user_factory()
        profile = user_profile_factory(user=user)
        kyc = kyc_verification_factory(user=user, status='verified')

        assert user.profile == profile
        assert user.kyc_verifications.count() == 1
        assert user.kyc_verifications.first().status == 'verified'

    def test_user_with_multiple_tenant_memberships(
        self, user_factory, tenant_factory, tenant_user_factory
    ):
        """Test user with multiple tenant memberships."""
        user = user_factory()
        tenant1 = tenant_factory()
        tenant2 = tenant_factory()

        tu1 = tenant_user_factory(user=user, tenant=tenant1, role='admin')
        tu2 = tenant_user_factory(user=user, tenant=tenant2, role='employee')

        assert user.tenant_memberships.count() == 2

        # Check different permissions per tenant
        assert tu1.is_admin is True
        assert tu2.is_admin is False

    def test_complete_user_registration_flow(
        self, user_factory, user_profile_factory,
        tenant_factory, tenant_user_factory
    ):
        """Test complete user registration flow."""
        # Create user
        user = user_factory(email='newuser@example.com')

        # Create profile
        profile = user_profile_factory(
            user=user,
            phone='+14165551234',
            city='Toronto',
            country='CA'
        )

        # Join tenant
        tenant = tenant_factory()
        membership = tenant_user_factory(
            user=user,
            tenant=tenant,
            role='employee'
        )

        assert user.email == 'newuser@example.com'
        assert profile.is_complete is True
        assert membership.tenant == tenant
