"""
Unit tests for FreelancerProfile model.

Tests model methods, properties, validators, and business logic.
"""

import pytest
from decimal import Decimal
from django.core.exceptions import ValidationError
from django.utils import timezone

from tenant_profiles.models import FreelancerProfile

pytestmark = pytest.mark.django_db


class TestFreelancerProfileModel:
    """Test FreelancerProfile model basic functionality."""

    def test_create_freelancer_profile(self, user_factory, service_category_factory):
        """Test creating a basic freelancer profile."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory()

        assert profile.id is not None
        assert profile.uuid is not None
        assert profile.user is not None
        assert profile.professional_title
        assert profile.bio
        assert profile.hourly_rate > 0
        assert profile.created_at is not None
        assert profile.updated_at is not None

    def test_one_to_one_relationship_with_user(self, user_factory):
        """Test that user can only have one freelancer profile."""
        from conftest import FreelancerProfileFactory
        from core_identity.models import CustomUser

        user = user_factory()
        profile1 = FreelancerProfileFactory(user=user)

        # Attempting to create another profile for same user should fail
        with pytest.raises(Exception):  # IntegrityError
            FreelancerProfileFactory(user=user)

        # Accessing via user.freelancer_profile should work
        assert user.freelancer_profile == profile1

    def test_str_representation(self):
        """Test string representation of freelancer profile."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(
            professional_title="Full-Stack Developer"
        )

        assert "Full-Stack Developer" in str(profile)

    def test_default_availability_status(self):
        """Test default availability status is 'available'."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory()

        assert profile.availability_status == 'available'

    def test_default_currency_is_cad(self):
        """Test default hourly rate currency is CAD."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory()

        assert profile.hourly_rate_currency == 'CAD'

    def test_default_stats_are_zero(self):
        """Test default statistics are initialized to zero."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory()

        assert profile.completed_projects == 0
        assert profile.completed_services == 0
        assert profile.total_earnings == Decimal('0.00')
        assert profile.average_rating is None
        assert profile.total_reviews == 0

    def test_skills_as_json_field(self):
        """Test skills are stored as JSON list."""
        from conftest import FreelancerProfileFactory

        skills = ['Python', 'Django', 'React', 'PostgreSQL']
        profile = FreelancerProfileFactory(skills=skills)

        assert profile.skills == skills
        assert isinstance(profile.skills, list)

    def test_verification_fields(self):
        """Test verification-related fields."""
        from conftest import VerifiedFreelancerProfileFactory

        profile = VerifiedFreelancerProfileFactory()

        assert profile.is_verified is True
        assert profile.identity_verified is True
        assert profile.payment_method_verified is True
        assert profile.verification_date is not None


class TestFreelancerProfileProperties:
    """Test computed properties on FreelancerProfile."""

    def test_is_available_for_work_when_available(self):
        """Test is_available_for_work returns True when status is available."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(availability_status='available')

        assert profile.is_available_for_work is True

    def test_is_available_for_work_when_busy(self):
        """Test is_available_for_work returns False when status is busy."""
        from conftest import BusyFreelancerProfileFactory

        profile = BusyFreelancerProfileFactory()

        assert profile.is_available_for_work is False

    def test_is_available_for_work_when_unavailable(self):
        """Test is_available_for_work returns False when status is unavailable."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(availability_status='unavailable')

        assert profile.is_available_for_work is False

    def test_has_portfolio_with_urls(self):
        """Test has_portfolio returns True when portfolio links exist."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(
            portfolio_url="https://example.com",
            github_url="https://github.com/user",
        )

        assert profile.has_portfolio is True

    def test_has_portfolio_without_urls(self):
        """Test has_portfolio returns False when no portfolio links exist."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(
            portfolio_url='',
            github_url='',
            linkedin_url='',
            behance_url='',
            dribbble_url='',
        )

        assert profile.has_portfolio is False

    def test_completion_rate_with_completed_work(self):
        """Test completion_rate calculation."""
        from conftest import VerifiedFreelancerProfileFactory

        profile = VerifiedFreelancerProfileFactory(
            completed_projects=10,
            completed_services=5
        )

        assert profile.completion_rate == 100.0

    def test_completion_rate_with_no_completed_work(self):
        """Test completion_rate is 0 when no work completed."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(
            completed_projects=0,
            completed_services=0
        )

        assert profile.completion_rate == 0.0


class TestFreelancerProfileUpdateStats:
    """Test update_stats method."""

    def test_update_stats_increment_projects(self):
        """Test incrementing completed projects."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(completed_projects=5)
        profile.update_stats(completed_projects=3)

        profile.refresh_from_db()
        assert profile.completed_projects == 8

    def test_update_stats_increment_services(self):
        """Test incrementing completed services."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(completed_services=2)
        profile.update_stats(completed_services=5)

        profile.refresh_from_db()
        assert profile.completed_services == 7

    def test_update_stats_add_earnings(self):
        """Test adding to total earnings."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(total_earnings=Decimal('1000.00'))
        profile.update_stats(earnings=500.50)

        profile.refresh_from_db()
        assert profile.total_earnings == Decimal('1500.50')

    def test_update_stats_first_rating(self):
        """Test adding first rating."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(
            average_rating=None,
            total_reviews=0
        )
        profile.update_stats(rating=4.5)

        profile.refresh_from_db()
        assert profile.average_rating == Decimal('4.50')
        assert profile.total_reviews == 1

    def test_update_stats_multiple_ratings(self):
        """Test calculating average rating across multiple reviews."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(
            average_rating=Decimal('4.00'),
            total_reviews=2
        )
        profile.update_stats(rating=5.0)

        profile.refresh_from_db()
        # (4.0 * 2 + 5.0) / 3 = 13.0 / 3 = 4.33...
        assert abs(float(profile.average_rating) - 4.33) < 0.01
        assert profile.total_reviews == 3

    def test_update_stats_combined_update(self):
        """Test updating multiple stats at once."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory(
            completed_projects=10,
            completed_services=5,
            total_earnings=Decimal('5000.00'),
            average_rating=Decimal('4.00'),
            total_reviews=10
        )

        profile.update_stats(
            completed_projects=2,
            completed_services=1,
            earnings=1500.00,
            rating=5.0
        )

        profile.refresh_from_db()
        assert profile.completed_projects == 12
        assert profile.completed_services == 6
        assert profile.total_earnings == Decimal('6500.00')
        assert profile.total_reviews == 11
        # (4.0 * 10 + 5.0) / 11 = 45.0 / 11 = 4.09...
        assert abs(float(profile.average_rating) - 4.09) < 0.01


class TestFreelancerProfileValidation:
    """Test field validations on FreelancerProfile."""

    def test_hourly_rate_must_be_positive(self):
        """Test hourly rate must be greater than zero."""
        from conftest import FreelancerProfileFactory

        # Should raise validation error on model clean()
        profile = FreelancerProfileFactory.build(hourly_rate=Decimal('0.00'))

        with pytest.raises(ValidationError):
            profile.full_clean()

    def test_negative_hourly_rate_invalid(self):
        """Test negative hourly rate is invalid."""
        from conftest import FreelancerProfileFactory

        profile = FreelancerProfileFactory.build(hourly_rate=Decimal('-50.00'))

        with pytest.raises(ValidationError):
            profile.full_clean()

    def test_availability_hours_within_valid_range(self):
        """Test availability hours must be between 1 and 168."""
        from conftest import FreelancerProfileFactory

        # Valid range
        profile = FreelancerProfileFactory(availability_hours_per_week=40)
        profile.full_clean()  # Should not raise

        # Upper bound
        profile.availability_hours_per_week = 168
        profile.full_clean()  # Should not raise

        # Lower bound
        profile.availability_hours_per_week = 1
        profile.full_clean()  # Should not raise

    def test_availability_hours_out_of_range(self):
        """Test availability hours outside valid range raises error."""
        from conftest import FreelancerProfileFactory

        # Too high
        profile = FreelancerProfileFactory.build(availability_hours_per_week=169)
        with pytest.raises(ValidationError):
            profile.full_clean()

        # Zero
        profile = FreelancerProfileFactory.build(availability_hours_per_week=0)
        with pytest.raises(ValidationError):
            profile.full_clean()

    def test_years_of_experience_valid_range(self):
        """Test years of experience validation."""
        from conftest import FreelancerProfileFactory

        # Valid
        profile = FreelancerProfileFactory(years_of_experience=5)
        profile.full_clean()  # Should not raise

        # Upper bound
        profile.years_of_experience = 50
        profile.full_clean()  # Should not raise

        # Zero is valid (entry level)
        profile.years_of_experience = 0
        profile.full_clean()  # Should not raise

    def test_average_rating_range(self):
        """Test average rating must be between 0 and 5."""
        from conftest import VerifiedFreelancerProfileFactory

        # Valid range
        profile = VerifiedFreelancerProfileFactory(average_rating=Decimal('4.5'))
        profile.full_clean()  # Should not raise

        # Upper bound
        profile.average_rating = Decimal('5.0')
        profile.full_clean()  # Should not raise

        # Lower bound
        profile.average_rating = Decimal('0.0')
        profile.full_clean()  # Should not raise
