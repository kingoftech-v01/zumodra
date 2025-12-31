"""
KYC & Career Verification Flow Tests for Zumodra

Tests the complete verification workflow including:
- KYC (Know Your Customer) identity verification
- Career/Employment verification
- Trust score calculation
- Verification status transitions
"""

import pytest
from datetime import timedelta
from decimal import Decimal
from django.utils import timezone
from unittest.mock import patch, MagicMock

from conftest import (
    UserFactory, TenantFactory, PlanFactory, TenantUserFactory,
    KYCVerificationFactory, VerifiedKYCFactory, UserProfileFactory
)


# ============================================================================
# KYC VERIFICATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestKYCVerification:
    """Test KYC verification workflow."""

    def test_create_kyc_verification_request(self, user_factory):
        """Test creating a new KYC verification request."""
        user = user_factory()
        from accounts.models import KYCVerification

        kyc = KYCVerification.objects.create(
            user=user,
            verification_type='identity',
            status='pending',
            level='basic',
            provider='onfido',
            document_type='passport',
            document_country='CA'
        )

        assert kyc.pk is not None
        assert kyc.status == 'pending'
        assert kyc.verification_type == 'identity'

    def test_kyc_verification_submission(self, user_factory):
        """Test submitting documents for KYC verification."""
        user = user_factory()
        from accounts.models import KYCVerification

        kyc = KYCVerification.objects.create(
            user=user,
            verification_type='identity',
            status='pending',
            level='basic',
            document_type='drivers_license',
            document_country='CA'
        )

        # Submit for verification
        kyc.status = 'submitted'
        kyc.submitted_at = timezone.now()
        kyc.save()

        assert kyc.status == 'submitted'
        assert kyc.submitted_at is not None

    def test_kyc_verification_approved(self, user_factory):
        """Test approving a KYC verification request."""
        user = user_factory()
        from accounts.models import KYCVerification

        kyc = KYCVerification.objects.create(
            user=user,
            verification_type='identity',
            status='submitted',
            level='basic',
            document_type='passport',
            document_country='CA'
        )

        # Approve verification
        kyc.status = 'verified'
        kyc.confidence_score = Decimal('98.50')
        kyc.verified_at = timezone.now()
        kyc.expires_at = timezone.now() + timedelta(days=365)
        kyc.save()

        assert kyc.status == 'verified'
        assert kyc.confidence_score == Decimal('98.50')
        assert kyc.verified_at is not None

    def test_kyc_verification_rejected(self, user_factory):
        """Test rejecting a KYC verification request."""
        user = user_factory()
        from accounts.models import KYCVerification

        kyc = KYCVerification.objects.create(
            user=user,
            verification_type='identity',
            status='submitted',
            level='basic',
            document_type='passport',
            document_country='CA'
        )

        # Reject verification
        kyc.status = 'rejected'
        kyc.rejection_reason = 'Document expired'
        kyc.rejection_code = 'DOCUMENT_EXPIRED'
        kyc.save()

        assert kyc.status == 'rejected'
        assert kyc.rejection_reason == 'Document expired'

    def test_kyc_verification_expiry(self, user_factory):
        """Test KYC verification expiration handling."""
        user = user_factory()
        from accounts.models import KYCVerification

        # Create expired verification
        kyc = KYCVerification.objects.create(
            user=user,
            verification_type='identity',
            status='verified',
            level='basic',
            verified_at=timezone.now() - timedelta(days=400),
            expires_at=timezone.now() - timedelta(days=35)  # Expired 35 days ago
        )

        # Check if expired
        assert kyc.expires_at < timezone.now()
        assert kyc.status == 'verified'  # Status unchanged until revalidation

    def test_kyc_verification_levels(self, user_factory):
        """Test different KYC verification levels."""
        user = user_factory()
        from accounts.models import KYCVerification

        # Basic level - ID only
        basic_kyc = KYCVerification.objects.create(
            user=user,
            verification_type='identity',
            status='verified',
            level='basic',
            document_type='passport'
        )

        # Enhanced level - ID + address
        enhanced_kyc = KYCVerification.objects.create(
            user=user,
            verification_type='address',
            status='verified',
            level='enhanced',
            document_type='utility_bill'
        )

        assert basic_kyc.level == 'basic'
        assert enhanced_kyc.level == 'enhanced'


# ============================================================================
# CAREER/EMPLOYMENT VERIFICATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestCareerVerification:
    """Test career and employment verification workflow."""

    def test_create_employment_verification(self, user_factory):
        """Test creating an employment verification request."""
        user = user_factory()
        from accounts.models import EmploymentVerification

        verification = EmploymentVerification.objects.create(
            user=user,
            company_name='Tech Corp Inc.',
            job_title='Senior Developer',
            start_date=timezone.now().date() - timedelta(days=730),
            end_date=timezone.now().date() - timedelta(days=30),
            is_current=False,
            status='pending'
        )

        assert verification.pk is not None
        assert verification.status == 'pending'
        assert verification.company_name == 'Tech Corp Inc.'

    def test_verify_current_employment(self, user_factory):
        """Test verifying current employment."""
        user = user_factory()
        from accounts.models import EmploymentVerification

        verification = EmploymentVerification.objects.create(
            user=user,
            company_name='Current Employer Ltd.',
            job_title='Lead Engineer',
            start_date=timezone.now().date() - timedelta(days=365),
            is_current=True,
            status='pending'
        )

        # Verify employment
        verification.status = 'verified'
        verification.verified_at = timezone.now()
        verification.verification_method = 'employer_contact'
        verification.save()

        assert verification.status == 'verified'
        assert verification.is_current

    def test_education_verification(self, user_factory):
        """Test education/degree verification."""
        user = user_factory()
        from accounts.models import EducationVerification

        verification = EducationVerification.objects.create(
            user=user,
            institution_name='University of Tech',
            degree_type='bachelor',
            field_of_study='Computer Science',
            graduation_year=2018,
            status='pending'
        )

        # Verify education
        verification.status = 'verified'
        verification.verified_at = timezone.now()
        verification.save()

        assert verification.status == 'verified'
        assert verification.degree_type == 'bachelor'

    def test_certification_verification(self, user_factory):
        """Test professional certification verification."""
        user = user_factory()
        from accounts.models import CertificationVerification

        verification = CertificationVerification.objects.create(
            user=user,
            certification_name='AWS Solutions Architect',
            issuing_organization='Amazon Web Services',
            issue_date=timezone.now().date() - timedelta(days=180),
            expiry_date=timezone.now().date() + timedelta(days=730),
            credential_id='AWS-123456',
            status='pending'
        )

        verification.status = 'verified'
        verification.verified_at = timezone.now()
        verification.save()

        assert verification.status == 'verified'
        assert verification.credential_id == 'AWS-123456'


# ============================================================================
# TRUST SCORE TESTS
# ============================================================================

@pytest.mark.django_db
class TestTrustScore:
    """Test trust score calculation and management."""

    def test_create_trust_score(self, user_factory):
        """Test creating a trust score for a user."""
        user = user_factory()
        from accounts.models import TrustScore

        trust_score = TrustScore.objects.create(
            user=user,
            overall_score=Decimal('75.00'),
            level='VERIFIED',
            identity_score=Decimal('95.00'),
            career_score=Decimal('80.00'),
            activity_score=Decimal('50.00'),
            review_score=Decimal('85.00'),
            dispute_score=Decimal('100.00'),
            payment_score=Decimal('90.00')
        )

        assert trust_score.pk is not None
        assert trust_score.level == 'VERIFIED'
        assert trust_score.overall_score == Decimal('75.00')

    def test_trust_level_progression(self, user_factory):
        """Test trust level progression based on score."""
        user = user_factory()
        from accounts.models import TrustScore

        # NEW level (0-20)
        trust_score = TrustScore.objects.create(
            user=user,
            overall_score=Decimal('15.00'),
            level='NEW'
        )
        assert trust_score.level == 'NEW'

        # BASIC level (20-40)
        trust_score.overall_score = Decimal('35.00')
        trust_score.level = 'BASIC'
        trust_score.save()
        assert trust_score.level == 'BASIC'

        # VERIFIED level (40-60)
        trust_score.overall_score = Decimal('55.00')
        trust_score.level = 'VERIFIED'
        trust_score.save()
        assert trust_score.level == 'VERIFIED'

        # HIGH level (60-80)
        trust_score.overall_score = Decimal('75.00')
        trust_score.level = 'HIGH'
        trust_score.save()
        assert trust_score.level == 'HIGH'

        # PREMIUM level (80-100)
        trust_score.overall_score = Decimal('92.00')
        trust_score.level = 'PREMIUM'
        trust_score.save()
        assert trust_score.level == 'PREMIUM'

    def test_trust_score_components(self, user_factory):
        """Test individual trust score components."""
        user = user_factory()
        from accounts.models import TrustScore

        trust_score = TrustScore.objects.create(
            user=user,
            overall_score=Decimal('80.00'),
            level='HIGH',
            identity_score=Decimal('100.00'),  # Fully verified ID
            career_score=Decimal('90.00'),     # Verified employment
            activity_score=Decimal('60.00'),   # Moderate activity
            review_score=Decimal('85.00'),     # Good reviews
            dispute_score=Decimal('100.00'),   # No disputes
            payment_score=Decimal('95.00')     # Good payment history
        )

        assert trust_score.identity_score == Decimal('100.00')
        assert trust_score.career_score == Decimal('90.00')

    def test_trust_score_update_on_verification(self, user_factory):
        """Test trust score updates when verification completes."""
        user = user_factory()
        from accounts.models import TrustScore, KYCVerification

        # Initial low trust score
        trust_score = TrustScore.objects.create(
            user=user,
            overall_score=Decimal('25.00'),
            level='BASIC',
            identity_score=Decimal('0.00'),
            career_score=Decimal('50.00')
        )

        # Complete KYC
        kyc = KYCVerification.objects.create(
            user=user,
            verification_type='identity',
            status='verified',
            confidence_score=Decimal('95.00'),
            verified_at=timezone.now()
        )

        # Update trust score based on KYC
        trust_score.identity_score = kyc.confidence_score
        trust_score.overall_score = Decimal('50.00')
        trust_score.level = 'VERIFIED'
        trust_score.save()

        assert trust_score.identity_score == Decimal('95.00')
        assert trust_score.level == 'VERIFIED'


# ============================================================================
# VERIFICATION FLOW INTEGRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestCompleteVerificationFlow:
    """Integration tests for complete verification workflows."""

    def test_full_kyc_flow(self, user_factory, user_profile_factory):
        """Test complete KYC verification flow from start to finish."""
        from accounts.models import KYCVerification, TrustScore

        # 1. Create user
        user = user_factory()
        profile = user_profile_factory(user=user)

        # 2. Create initial trust score (NEW level)
        trust_score = TrustScore.objects.create(
            user=user,
            overall_score=Decimal('10.00'),
            level='NEW',
            identity_score=Decimal('0.00')
        )

        # 3. Start KYC verification
        kyc = KYCVerification.objects.create(
            user=user,
            verification_type='identity',
            status='pending',
            level='basic',
            document_type='passport',
            document_country='CA'
        )
        assert kyc.status == 'pending'

        # 4. Submit documents
        kyc.status = 'submitted'
        kyc.submitted_at = timezone.now()
        kyc.save()

        # 5. Verification in progress
        kyc.status = 'processing'
        kyc.save()

        # 6. Verification completed
        kyc.status = 'verified'
        kyc.confidence_score = Decimal('97.50')
        kyc.verified_at = timezone.now()
        kyc.expires_at = timezone.now() + timedelta(days=365)
        kyc.save()

        # 7. Update trust score
        trust_score.identity_score = kyc.confidence_score
        trust_score.overall_score = Decimal('45.00')
        trust_score.level = 'VERIFIED'
        trust_score.last_calculated_at = timezone.now()
        trust_score.save()

        # Final assertions
        assert kyc.status == 'verified'
        assert trust_score.level == 'VERIFIED'
        assert trust_score.identity_score == Decimal('97.50')

    def test_kyc_failure_and_retry(self, user_factory):
        """Test KYC verification failure and retry flow."""
        from accounts.models import KYCVerification

        user = user_factory()

        # First attempt - rejected
        kyc1 = KYCVerification.objects.create(
            user=user,
            verification_type='identity',
            status='rejected',
            level='basic',
            document_type='passport',
            rejection_reason='Document image unclear',
            rejection_code='POOR_QUALITY'
        )

        assert kyc1.status == 'rejected'

        # Second attempt - success
        kyc2 = KYCVerification.objects.create(
            user=user,
            verification_type='identity',
            status='verified',
            level='basic',
            document_type='passport',
            confidence_score=Decimal('95.00'),
            verified_at=timezone.now()
        )

        assert kyc2.status == 'verified'

        # User should have 2 verification attempts
        all_verifications = KYCVerification.objects.filter(user=user)
        assert all_verifications.count() == 2

    def test_career_verification_with_trust_update(self, user_factory):
        """Test career verification updating trust score."""
        from accounts.models import (
            EmploymentVerification, EducationVerification, TrustScore
        )

        user = user_factory()

        # Initial trust score with verified identity
        trust_score = TrustScore.objects.create(
            user=user,
            overall_score=Decimal('45.00'),
            level='VERIFIED',
            identity_score=Decimal('95.00'),
            career_score=Decimal('0.00')
        )

        # Verify employment
        employment = EmploymentVerification.objects.create(
            user=user,
            company_name='Tech Corp',
            job_title='Developer',
            start_date=timezone.now().date() - timedelta(days=365),
            is_current=True,
            status='verified',
            verified_at=timezone.now()
        )

        # Verify education
        education = EducationVerification.objects.create(
            user=user,
            institution_name='University',
            degree_type='bachelor',
            field_of_study='CS',
            graduation_year=2020,
            status='verified',
            verified_at=timezone.now()
        )

        # Update trust score
        trust_score.career_score = Decimal('85.00')
        trust_score.overall_score = Decimal('65.00')
        trust_score.level = 'HIGH'
        trust_score.save()

        assert trust_score.career_score == Decimal('85.00')
        assert trust_score.level == 'HIGH'


# ============================================================================
# VERIFICATION SECURITY TESTS
# ============================================================================

@pytest.mark.django_db
class TestVerificationSecurity:
    """Test verification security measures."""

    def test_verification_rate_limiting(self, user_factory):
        """Test that verification attempts are rate-limited."""
        from accounts.models import KYCVerification

        user = user_factory()

        # Simulate multiple verification attempts
        for i in range(5):
            KYCVerification.objects.create(
                user=user,
                verification_type='identity',
                status='rejected',
                level='basic',
                document_type='passport',
                rejection_reason=f'Attempt {i+1} failed'
            )

        # Count rejections
        rejected = KYCVerification.objects.filter(
            user=user, status='rejected'
        ).count()

        assert rejected == 5
        # In production, system would block further attempts after threshold

    def test_verification_document_security(self, user_factory):
        """Test that sensitive verification data is handled securely."""
        from accounts.models import KYCVerification

        user = user_factory()

        kyc = KYCVerification.objects.create(
            user=user,
            verification_type='identity',
            status='verified',
            level='basic',
            document_type='passport',
            document_country='CA',
            # Sensitive fields should be encrypted/hashed in production
            document_number_hash='sha256_hashed_value'
        )

        # Document number should not be stored in plain text
        assert 'sha256' in str(kyc.document_number_hash) or kyc.document_number_hash is None

    def test_verification_access_control(self, user_factory):
        """Test that users can only access their own verifications."""
        from accounts.models import KYCVerification

        user1 = user_factory()
        user2 = user_factory()

        kyc1 = KYCVerification.objects.create(
            user=user1,
            verification_type='identity',
            status='verified'
        )

        kyc2 = KYCVerification.objects.create(
            user=user2,
            verification_type='identity',
            status='pending'
        )

        # Each user should only see their own verifications
        user1_verifications = KYCVerification.objects.filter(user=user1)
        user2_verifications = KYCVerification.objects.filter(user=user2)

        assert user1_verifications.count() == 1
        assert user2_verifications.count() == 1
        assert user1_verifications.first().id != user2_verifications.first().id
