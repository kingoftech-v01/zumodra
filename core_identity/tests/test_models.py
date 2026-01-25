"""
Unit tests for custom_account_u models (PublicProfile, ProfileFieldSync).
"""

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from custom_account_u.models import CustomUser, PublicProfile, ProfileFieldSync


@pytest.mark.django_db
class TestPublicProfile:
    """Test PublicProfile model."""

    def test_create_public_profile_minimal(self):
        """Test creating PublicProfile with minimal required fields."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        profile = PublicProfile.objects.create(
            user=user,
            display_name='Test User'
        )

        assert profile.user == user
        assert profile.display_name == 'Test User'
        assert profile.country == 'CA'  # Default
        assert profile.timezone == 'America/Toronto'  # Default
        assert profile.currency == 'CAD'  # Default
        assert profile.profile_visibility == PublicProfile.VISIBILITY_TENANTS_ONLY  # Default
        assert profile.available_for_work is False  # Default

    def test_create_public_profile_full(self):
        """Test creating PublicProfile with all fields."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        profile = PublicProfile.objects.create(
            user=user,
            display_name='John Doe',
            professional_title='Senior Software Engineer',
            bio='Experienced developer with 10+ years',
            public_email='john@example.com',
            phone='+14165551234',
            city='Toronto',
            state='Ontario',
            country='CA',
            linkedin_url='https://linkedin.com/in/johndoe',
            github_url='https://github.com/johndoe',
            portfolio_url='https://johndoe.dev',
            skills=['Python', 'Django', 'PostgreSQL'],
            languages=['English', 'French'],
            certifications=[{'name': 'AWS Certified', 'year': 2023}],
            available_for_work=True,
            hourly_rate_min=100.00,
            hourly_rate_max=150.00,
            currency='CAD',
            profile_visibility=PublicProfile.VISIBILITY_PUBLIC,
        )

        assert profile.display_name == 'John Doe'
        assert profile.professional_title == 'Senior Software Engineer'
        assert len(profile.skills) == 3
        assert len(profile.languages) == 2
        assert profile.hourly_rate_min == 100.00

    def test_one_to_one_constraint(self):
        """Test that each user can only have one PublicProfile."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        PublicProfile.objects.create(user=user, display_name='Profile 1')

        with pytest.raises(IntegrityError):
            PublicProfile.objects.create(user=user, display_name='Profile 2')

    def test_completion_percentage_empty(self):
        """Test completion percentage for empty profile."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        profile = PublicProfile.objects.create(user=user, display_name='Test')

        # Only display_name is filled
        assert profile.completion_percentage == 9  # 1/11 fields = ~9%

    def test_completion_percentage_partial(self):
        """Test completion percentage for partially filled profile."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        profile = PublicProfile.objects.create(
            user=user,
            display_name='John Doe',
            professional_title='Developer',
            bio='Bio text',
            city='Toronto',
            country='CA',
            linkedin_url='https://linkedin.com/in/johndoe',
        )

        # 6 out of 11 fields filled = ~54%
        assert profile.completion_percentage >= 50

    def test_completion_percentage_full(self):
        """Test completion percentage for fully filled profile."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )
        profile = PublicProfile.objects.create(
            user=user,
            display_name='John Doe',
            professional_title='Developer',
            bio='Bio text',
            city='Toronto',
            country='CA',
            linkedin_url='https://linkedin.com/in/johndoe',
            github_url='https://github.com/johndoe',
            skills=['Python', 'Django'],
            languages=['English'],
        )

        # Mock avatar (can't easily test file upload in unit test)
        # Should be high percentage
        assert profile.completion_percentage >= 70

    def test_verification_badges_none(self):
        """Test verification badges when user has no verifications."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        profile = PublicProfile.objects.create(user=user, display_name='Test')

        badges = profile.verification_badges
        assert isinstance(badges, list)
        assert len(badges) == 0

    def test_verification_badges_cv_verified(self):
        """Test verification badges when CV is verified."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        user.cv_verified = True
        user.save()

        profile = PublicProfile.objects.create(user=user, display_name='Test')
        badges = profile.verification_badges

        assert len(badges) == 1
        assert badges[0]['type'] == 'cv'

    def test_verification_badges_both_verified(self):
        """Test verification badges when both CV and KYC are verified."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        user.cv_verified = True
        user.kyc_verified = True
        user.save()

        profile = PublicProfile.objects.create(user=user, display_name='Test')
        badges = profile.verification_badges

        assert len(badges) == 2
        badge_types = [b['type'] for b in badges]
        assert 'cv' in badge_types
        assert 'kyc' in badge_types

    def test_str_representation(self):
        """Test string representation of PublicProfile."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        profile = PublicProfile.objects.create(user=user, display_name='John Doe')

        assert str(profile) == 'PublicProfile: John Doe (test@example.com)'


@pytest.mark.django_db
class TestProfileFieldSync:
    """Test ProfileFieldSync model."""

    def test_create_sync_settings_defaults(self):
        """Test creating ProfileFieldSync with default values."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        import uuid
        tenant_uuid = uuid.uuid4()

        sync_settings = ProfileFieldSync.objects.create(
            user=user,
            tenant_uuid=tenant_uuid
        )

        # Privacy-friendly defaults
        assert sync_settings.sync_display_name is True
        assert sync_settings.sync_avatar is True
        assert sync_settings.sync_bio is True
        assert sync_settings.sync_public_email is False  # Privacy OFF
        assert sync_settings.sync_phone is False  # Privacy OFF
        assert sync_settings.sync_city is True
        assert sync_settings.sync_linkedin is True
        assert sync_settings.auto_sync is False  # Manual only

    def test_unique_together_constraint(self):
        """Test that user + tenant_uuid must be unique."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        import uuid
        tenant_uuid = uuid.uuid4()

        ProfileFieldSync.objects.create(user=user, tenant_uuid=tenant_uuid)

        with pytest.raises(IntegrityError):
            ProfileFieldSync.objects.create(user=user, tenant_uuid=tenant_uuid)

    def test_get_enabled_fields_all_on(self):
        """Test get_enabled_fields when all fields are enabled."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        import uuid
        sync_settings = ProfileFieldSync.objects.create(
            user=user,
            tenant_uuid=uuid.uuid4(),
            sync_display_name=True,
            sync_avatar=True,
            sync_bio=True,
            sync_public_email=True,
            sync_phone=True,
            sync_city=True,
            sync_state=True,
            sync_country=True,
            sync_linkedin=True,
            sync_github=True,
            sync_portfolio=True,
            sync_skills=True,
            sync_languages=True,
        )

        enabled = sync_settings.get_enabled_fields()
        assert len(enabled) == 13
        assert 'display_name' in enabled
        assert 'public_email' in enabled
        assert 'phone' in enabled

    def test_get_enabled_fields_privacy_defaults(self):
        """Test get_enabled_fields with privacy-friendly defaults."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        import uuid
        sync_settings = ProfileFieldSync.objects.create(
            user=user,
            tenant_uuid=uuid.uuid4()
            # Using model defaults
        )

        enabled = sync_settings.get_enabled_fields()

        # Public fields should be enabled
        assert 'display_name' in enabled
        assert 'avatar' in enabled
        assert 'bio' in enabled
        assert 'city' in enabled

        # Sensitive fields should NOT be enabled
        assert 'public_email' not in enabled
        assert 'phone' not in enabled

    def test_get_enabled_fields_none(self):
        """Test get_enabled_fields when all fields are disabled."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        import uuid
        sync_settings = ProfileFieldSync.objects.create(
            user=user,
            tenant_uuid=uuid.uuid4(),
            sync_display_name=False,
            sync_avatar=False,
            sync_bio=False,
            sync_public_email=False,
            sync_phone=False,
            sync_city=False,
            sync_state=False,
            sync_country=False,
            sync_linkedin=False,
            sync_github=False,
            sync_portfolio=False,
            sync_skills=False,
            sync_languages=False,
        )

        enabled = sync_settings.get_enabled_fields()
        assert len(enabled) == 0

    def test_get_or_create_defaults_creates_new(self):
        """Test get_or_create_defaults creates new record with privacy defaults."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        import uuid
        tenant_uuid = uuid.uuid4()

        sync_settings, created = ProfileFieldSync.get_or_create_defaults(
            user=user,
            tenant_uuid=tenant_uuid
        )

        assert created is True
        assert sync_settings.user == user
        assert sync_settings.tenant_uuid == tenant_uuid

        # Check privacy defaults
        assert sync_settings.sync_display_name is True
        assert sync_settings.sync_public_email is False  # Privacy OFF
        assert sync_settings.sync_phone is False  # Privacy OFF
        assert sync_settings.auto_sync is False

    def test_get_or_create_defaults_gets_existing(self):
        """Test get_or_create_defaults retrieves existing record."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        import uuid
        tenant_uuid = uuid.uuid4()

        # Create initial record
        initial = ProfileFieldSync.objects.create(
            user=user,
            tenant_uuid=tenant_uuid,
            sync_phone=True  # Custom setting
        )

        # Get existing
        sync_settings, created = ProfileFieldSync.get_or_create_defaults(
            user=user,
            tenant_uuid=tenant_uuid
        )

        assert created is False
        assert sync_settings.id == initial.id
        assert sync_settings.sync_phone is True  # Preserved custom setting

    def test_str_representation(self):
        """Test string representation of ProfileFieldSync."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        import uuid
        tenant_uuid = uuid.uuid4()
        sync_settings = ProfileFieldSync.objects.create(
            user=user,
            tenant_uuid=tenant_uuid
        )

        assert str(sync_settings) == f'Sync settings: test@example.com → Tenant {tenant_uuid}'
