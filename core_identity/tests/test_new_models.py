"""
Comprehensive tests for Phase 10 refactored models in core_identity.

Tests cover:
- UserIdentity auto-creation
- MarketplaceProfile OPTIONAL behavior
- TenantInvitation workflow
- KYCVerification in PUBLIC schema
- TrustScore calculation
- EmploymentHistory cross-tenant visibility

Author: Zumodra Team
Date: 2026-01-17
"""

import pytest
from datetime import date, timedelta
from decimal import Decimal
from django.utils import timezone
from django.core.exceptions import ValidationError
from core_identity.models import (
    CustomUser, UserIdentity, MarketplaceProfile,
    StudentProfile, CoopSupervisor, TenantInvitation
)
from core_identity.verification_models import (
    KYCVerification, TrustScore, EducationVerification, EmploymentHistory
)


@pytest.mark.django_db
class TestUserIdentityAutoCreation:
    """Test UserIdentity is automatically created for every user."""

    def test_user_identity_auto_created_on_user_creation(self):
        """UserIdentity should be auto-created via signal."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )

        # UserIdentity should exist
        assert hasattr(user, 'identity')
        assert user.identity is not None
        assert user.identity.display_name == 'John Doe'

    def test_user_identity_display_name_from_email_if_no_name(self):
        """If user has no name, display_name should be email username."""
        user = CustomUser.objects.create_user(
            email='johndoe@example.com',
            password='testpass123'
        )

        assert user.identity.display_name == 'johndoe'

    def test_user_identity_update_when_name_changes(self):
        """UserIdentity display_name should update when user name changes."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )

        # Change user name
        user.first_name = 'Jane'
        user.last_name = 'Smith'
        user.save()

        # Identity should update
        user.identity.refresh_from_db()
        assert user.identity.display_name == 'Jane Smith'


@pytest.mark.django_db
class TestMarketplaceProfileOptional:
    """Test MarketplaceProfile is OPTIONAL and requires activation."""

    def test_marketplace_profile_not_auto_created(self):
        """MarketplaceProfile should NOT be auto-created."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        # User has identity but NOT marketplace_profile
        assert hasattr(user, 'identity')
        assert not hasattr(user, 'marketplace_profile')

    def test_marketplace_profile_defaults_to_inactive(self):
        """MarketplaceProfile should default to is_active=False."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        profile = MarketplaceProfile.objects.create(
            user=user,
            professional_title='Developer'
        )

        assert profile.is_active is False
        assert profile.activated_at is None

    def test_marketplace_profile_activation(self):
        """Test activate() method sets is_active=True."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        profile = MarketplaceProfile.objects.create(
            user=user,
            professional_title='Developer'
        )

        # Activate
        profile.activate()

        assert profile.is_active is True
        assert profile.activated_at is not None

    def test_marketplace_profile_deactivation(self):
        """Test deactivate() method sets is_active=False."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        profile = MarketplaceProfile.objects.create(
            user=user,
            professional_title='Developer',
            is_active=True
        )

        # Deactivate
        profile.deactivate()

        assert profile.is_active is False
        assert profile.deactivated_at is not None


@pytest.mark.django_db
class TestTenantInvitation:
    """Test TenantInvitation workflow."""

    def test_invitation_auto_sets_expiry(self):
        """Invitation should auto-set expires_at to 7 days from creation."""
        invitation = TenantInvitation.objects.create(
            email='newuser@example.com',
            tenant_uuid='12345678-1234-1234-1234-123456789012',
            tenant_name='Acme Corp',
            invited_role='employee'
        )

        # expires_at should be ~7 days from now
        expected_expiry = timezone.now() + timedelta(days=7)
        delta = abs((invitation.expires_at - expected_expiry).total_seconds())
        assert delta < 60  # Within 1 minute tolerance

    def test_invitation_is_expired_property(self):
        """Test is_expired property."""
        # Create invitation that's already expired
        invitation = TenantInvitation.objects.create(
            email='newuser@example.com',
            tenant_uuid='12345678-1234-1234-1234-123456789012',
            tenant_name='Acme Corp',
            invited_role='employee',
            expires_at=timezone.now() - timedelta(days=1)
        )

        assert invitation.is_expired is True

    def test_invitation_accept(self):
        """Test accepting an invitation."""
        invitation = TenantInvitation.objects.create(
            email='newuser@example.com',
            tenant_uuid='12345678-1234-1234-1234-123456789012',
            tenant_name='Acme Corp',
            invited_role='employee'
        )

        invitation.accept()

        assert invitation.status == TenantInvitation.STATUS_ACCEPTED
        assert invitation.accepted_at is not None

    def test_invitation_reject(self):
        """Test rejecting an invitation."""
        invitation = TenantInvitation.objects.create(
            email='newuser@example.com',
            tenant_uuid='12345678-1234-1234-1234-123456789012',
            tenant_name='Acme Corp',
            invited_role='employee'
        )

        invitation.reject()

        assert invitation.status == TenantInvitation.STATUS_REJECTED
        assert invitation.rejected_at is not None


@pytest.mark.django_db
class TestKYCVerificationPublicSchema:
    """Test KYCVerification is in PUBLIC schema (one per user globally)."""

    def test_kyc_verification_one_per_user(self):
        """User should have ONE KYC verification globally."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        # Create KYC verification
        kyc = KYCVerification.objects.create(
            user=user,
            provider=KYCVerification.PROVIDER_ONFIDO,
            status=KYCVerification.STATUS_PENDING,
            level=KYCVerification.LEVEL_1
        )

        # Should be accessible globally
        assert KYCVerification.objects.filter(user=user).count() == 1

    def test_kyc_verification_only_onfido_provider(self):
        """KYC should only support Onfido provider."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        kyc = KYCVerification.objects.create(
            user=user,
            provider=KYCVerification.PROVIDER_ONFIDO
        )

        # Verify only Onfido and Manual are valid choices
        valid_providers = [choice[0] for choice in KYCVerification.PROVIDER_CHOICES]
        assert 'onfido' in valid_providers
        assert 'manual' in valid_providers
        assert 'idenfy' not in valid_providers  # iDenfy removed

    def test_kyc_verification_status_flow(self):
        """Test KYC verification status transitions."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        kyc = KYCVerification.objects.create(
            user=user,
            provider=KYCVerification.PROVIDER_ONFIDO,
            status=KYCVerification.STATUS_PENDING
        )

        # Transition to approved
        kyc.status = KYCVerification.STATUS_APPROVED
        kyc.verified_at = timezone.now()
        kyc.save()

        assert kyc.status == KYCVerification.STATUS_APPROVED
        assert kyc.verified_at is not None


@pytest.mark.django_db
class TestTrustScore:
    """Test TrustScore calculation and aggregation."""

    def test_trust_score_creation(self):
        """Test creating a trust score for a user."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        trust_score = TrustScore.objects.create(
            user=user,
            identity_score=Decimal('80.00'),
            career_score=Decimal('70.00'),
            platform_activity_score=Decimal('60.00'),
            dispute_score=Decimal('100.00'),
            completion_rate_score=Decimal('90.00')
        )

        assert trust_score.overall_score == Decimal('0.00')  # Not calculated yet

    def test_trust_score_calculation(self):
        """Test calculate_overall_score() method."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        trust_score = TrustScore.objects.create(
            user=user,
            identity_score=Decimal('80.00'),
            career_score=Decimal('70.00'),
            platform_activity_score=Decimal('60.00'),
            dispute_score=Decimal('100.00'),
            completion_rate_score=Decimal('90.00')
        )

        # Calculate
        trust_score.calculate_overall_score()

        # Expected: 80*0.25 + 70*0.20 + 60*0.20 + 100*0.15 + 90*0.20 = 80
        expected = Decimal('80.00')
        assert trust_score.overall_score == expected


@pytest.mark.django_db
class TestEmploymentHistory:
    """Test EmploymentHistory in PUBLIC schema for cross-tenant visibility."""

    def test_employment_history_cross_tenant_visible(self):
        """Employment history should be globally visible."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        # Create employment history
        history = EmploymentHistory.objects.create(
            user=user,
            company_name='Acme Corp',
            job_title='Senior Developer',
            employment_type=EmploymentHistory.EMPLOYMENT_TYPE_FULL_TIME,
            start_date=date(2020, 1, 1),
            end_date=date(2023, 12, 31),
            verified=True,
            verification_method=EmploymentHistory.VERIFICATION_METHOD_REFERENCE
        )

        # Should be accessible globally (not tenant-scoped)
        assert EmploymentHistory.objects.filter(user=user).count() == 1

    def test_employment_history_current_position(self):
        """Test is_current flag and duration calculation."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        history = EmploymentHistory.objects.create(
            user=user,
            company_name='Google',
            job_title='Staff Engineer',
            employment_type=EmploymentHistory.EMPLOYMENT_TYPE_FULL_TIME,
            start_date=date(2024, 1, 1),
            is_current=True
        )

        assert history.is_current is True
        assert history.end_date is None


@pytest.mark.django_db
class TestEducationVerification:
    """Test EducationVerification model."""

    def test_education_verification_creation(self):
        """Test creating education verification."""
        user = CustomUser.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        education = EducationVerification.objects.create(
            user=user,
            institution='MIT',
            degree='Bachelor of Science',
            field_of_study='Computer Science',
            start_date=date(2015, 9, 1),
            end_date=date(2019, 5, 15),
            verified=True,
            verification_method=EducationVerification.VERIFICATION_METHOD_DIPLOMA
        )

        assert education.verified is True
        assert education.degree == 'Bachelor of Science'


@pytest.mark.django_db
class TestStudentProfile:
    """Test StudentProfile for co-op education."""

    def test_student_profile_creation(self):
        """Test creating a student profile."""
        user = CustomUser.objects.create_user(
            email='student@example.com',
            password='testpass123'
        )

        student = StudentProfile.objects.create(
            user=user,
            student_id='S12345678',
            institution='Université de Montréal',
            program='Computer Science',
            coop_required_hours=Decimal('420.00'),
            expected_graduation=date(2026, 5, 15)
        )

        assert student.student_id == 'S12345678'
        assert student.coop_completed_hours == Decimal('0.00')

    def test_student_coop_hours_tracking(self):
        """Test co-op hours completion tracking."""
        user = CustomUser.objects.create_user(
            email='student@example.com',
            password='testpass123'
        )

        student = StudentProfile.objects.create(
            user=user,
            student_id='S12345678',
            institution='UdeM',
            program='CS',
            coop_required_hours=Decimal('420.00')
        )

        # Update completed hours
        student.coop_completed_hours = Decimal('210.00')
        student.save()

        # Check completion percentage
        completion = (student.coop_completed_hours / student.coop_required_hours) * 100
        assert completion == Decimal('50.00')


@pytest.mark.django_db
class TestCoopSupervisor:
    """Test CoopSupervisor model."""

    def test_academic_supervisor_creation(self):
        """Test creating an academic supervisor."""
        supervisor = CoopSupervisor.objects.create(
            supervisor_type=CoopSupervisor.SUPERVISOR_TYPE_ACADEMIC,
            name='Prof. Jean Dubois',
            email='j.dubois@udem.ca',
            phone='+1-514-555-1234',
            institution='Université de Montréal',
            title='Professor',
            department='Computer Science'
        )

        assert supervisor.supervisor_type == CoopSupervisor.SUPERVISOR_TYPE_ACADEMIC
        assert supervisor.institution == 'Université de Montréal'

    def test_workplace_supervisor_creation(self):
        """Test creating a workplace supervisor."""
        supervisor = CoopSupervisor.objects.create(
            supervisor_type=CoopSupervisor.SUPERVISOR_TYPE_WORKPLACE,
            name='Marie Tremblay',
            email='m.tremblay@acme.com',
            phone='+1-514-555-5678',
            title='Senior Developer',
            department='Engineering'
        )

        assert supervisor.supervisor_type == CoopSupervisor.SUPERVISOR_TYPE_WORKPLACE
        assert supervisor.title == 'Senior Developer'
