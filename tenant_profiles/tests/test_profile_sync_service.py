"""
Unit tests for ProfileSyncService in accounts/services.py.
"""

import pytest
from django.utils import timezone
from django_tenants.utils import tenant_context

from custom_account_u.models import CustomUser, PublicProfile, ProfileFieldSync
from tenant_profiles.models import TenantProfile
from tenant_profiles.services import ProfileSyncService
from tenants.models import Tenant


@pytest.mark.django_db
class TestProfileSyncService:
    """Test ProfileSyncService synchronization logic."""

    @pytest.fixture
    def user_with_public_profile(self):
        """Create a user with a complete PublicProfile."""
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
            professional_title='Senior Developer',
            bio='Experienced software engineer',
            public_email='john.public@example.com',
            phone='+14165551234',
            city='Toronto',
            state='Ontario',
            country='CA',
            linkedin_url='https://linkedin.com/in/johndoe',
            github_url='https://github.com/johndoe',
            portfolio_url='https://johndoe.dev',
            skills=['Python', 'Django', 'PostgreSQL'],
            languages=['English', 'French'],
        )
        return user

    @pytest.fixture
    def tenant(self, db):
        """Create a test tenant."""
        tenant = Tenant.objects.create(
            schema_name='test_tenant',
            name='Test Company',
            domain_url='test.localhost',
        )
        return tenant

    def test_sync_on_invitation_acceptance_creates_profile(self, user_with_public_profile, tenant):
        """Test sync on invitation creates TenantProfile and syncs enabled fields."""
        user = user_with_public_profile

        with tenant_context(tenant):
            # Verify TenantProfile doesn't exist yet
            assert not TenantProfile.objects.filter(user=user, tenant=tenant).exists()

            # Trigger sync
            result = ProfileSyncService.sync_on_invitation_acceptance(
                user=user,
                tenant=tenant
            )

            # Verify result
            assert result['success'] is True
            assert result['tenant_profile_created'] is True
            assert len(result['synced_fields']) > 0

            # Verify TenantProfile was created
            tenant_profile = TenantProfile.objects.get(user=user, tenant=tenant)
            assert tenant_profile.job_title == 'Employee'  # Default

            # Verify enabled fields were synced
            assert tenant_profile.full_name == 'John Doe'
            assert tenant_profile.bio == 'Experienced software engineer'
            assert tenant_profile.city == 'Toronto'
            assert tenant_profile.state == 'Ontario'
            assert tenant_profile.country == 'CA'
            assert tenant_profile.linkedin_url == 'https://linkedin.com/in/johndoe'
            assert tenant_profile.skills_json == ['Python', 'Django', 'PostgreSQL']
            assert tenant_profile.languages_json == ['English', 'French']

            # Verify privacy: email and phone should NOT be synced by default
            assert tenant_profile.email == ''
            assert tenant_profile.phone == ''

            # Verify sync metadata
            assert tenant_profile.last_synced_at is not None
            assert 'display_name' in tenant_profile.synced_fields
            assert 'bio' in tenant_profile.synced_fields

    def test_sync_on_invitation_creates_sync_settings(self, user_with_public_profile, tenant):
        """Test that sync creates ProfileFieldSync with privacy defaults."""
        user = user_with_public_profile

        # Verify no sync settings exist
        assert not ProfileFieldSync.objects.filter(
            user=user, tenant_uuid=tenant.uuid
        ).exists()

        with tenant_context(tenant):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant)

        # Verify sync settings were created
        sync_settings = ProfileFieldSync.objects.get(user=user, tenant_uuid=tenant.uuid)
        assert sync_settings.sync_display_name is True
        assert sync_settings.sync_public_email is False  # Privacy OFF
        assert sync_settings.sync_phone is False  # Privacy OFF
        assert sync_settings.auto_sync is False

    def test_sync_on_invitation_no_public_profile(self, tenant):
        """Test sync creates PublicProfile if user doesn't have one."""
        user = CustomUser.objects.create_user(
            username='newuser',
            email='new@example.com',
            password='testpass123'
        )

        # Verify no PublicProfile exists
        assert not hasattr(user, 'public_profile') or not PublicProfile.objects.filter(user=user).exists()

        with tenant_context(tenant):
            result = ProfileSyncService.sync_on_invitation_acceptance(
                user=user,
                tenant=tenant
            )

            assert result['success'] is True

        # Verify PublicProfile was created
        assert PublicProfile.objects.filter(user=user).exists()
        public_profile = PublicProfile.objects.get(user=user)
        assert public_profile.display_name == 'new@example.com'  # Fallback to email

    def test_manual_sync_updates_existing_profile(self, user_with_public_profile, tenant):
        """Test manual sync updates existing TenantProfile."""
        user = user_with_public_profile

        with tenant_context(tenant):
            # Create initial TenantProfile
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant)

            # Update PublicProfile
            user.public_profile.bio = 'Updated bio text'
            user.public_profile.city = 'Vancouver'
            user.public_profile.save()

            # Trigger manual sync
            result = ProfileSyncService.sync_manual_trigger(
                user=user,
                tenant=tenant
            )

            assert result['success'] is True
            assert len(result['synced_fields']) > 0

            # Verify updates
            tenant_profile = TenantProfile.objects.get(user=user, tenant=tenant)
            assert tenant_profile.bio == 'Updated bio text'
            assert tenant_profile.city == 'Vancouver'

    def test_manual_sync_with_field_overrides(self, user_with_public_profile, tenant):
        """Test manual sync with one-time field overrides."""
        user = user_with_public_profile

        with tenant_context(tenant):
            # Initial sync (phone not synced by default)
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant)

            tenant_profile = TenantProfile.objects.get(user=user, tenant=tenant)
            assert tenant_profile.phone == ''  # Not synced

            # Manual sync with override to sync phone
            result = ProfileSyncService.sync_manual_trigger(
                user=user,
                tenant=tenant,
                field_overrides={'sync_phone': True}
            )

            assert result['success'] is True
            assert 'phone' in result['synced_fields']

            # Verify phone was synced
            tenant_profile.refresh_from_db()
            assert tenant_profile.phone == '+14165551234'

    def test_manual_sync_respects_privacy_settings(self, user_with_public_profile, tenant):
        """Test that manual sync respects ProfileFieldSync privacy settings."""
        user = user_with_public_profile

        # Disable bio sync
        sync_settings, _ = ProfileFieldSync.get_or_create_defaults(
            user=user,
            tenant_uuid=tenant.uuid
        )
        sync_settings.sync_bio = False
        sync_settings.save()

        with tenant_context(tenant):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant)

            tenant_profile = TenantProfile.objects.get(user=user, tenant=tenant)

            # Bio should NOT be synced
            assert tenant_profile.bio == ''
            assert 'bio' not in tenant_profile.synced_fields

            # But other enabled fields should be synced
            assert tenant_profile.full_name == 'John Doe'
            assert 'display_name' in tenant_profile.synced_fields

    def test_perform_sync_avatar_conversion(self, user_with_public_profile, tenant):
        """Test that avatar ImageField is converted to URL during sync."""
        # Note: This test is limited without actual file upload
        # In production, avatar.url would return the file URL
        user = user_with_public_profile

        with tenant_context(tenant):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant)

            tenant_profile = TenantProfile.objects.get(user=user, tenant=tenant)

            # Avatar should be empty string (no file uploaded in test)
            # In production with real file, this would be a URL
            assert isinstance(tenant_profile.avatar_url, str)

    def test_sync_handles_empty_json_fields(self, tenant):
        """Test sync handles empty lists for JSON fields."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        PublicProfile.objects.create(
            user=user,
            display_name='Test User',
            skills=[],  # Empty list
            languages=[],  # Empty list
        )

        with tenant_context(tenant):
            result = ProfileSyncService.sync_on_invitation_acceptance(
                user=user,
                tenant=tenant
            )

            assert result['success'] is True

            tenant_profile = TenantProfile.objects.get(user=user, tenant=tenant)
            assert tenant_profile.skills_json == []
            assert tenant_profile.languages_json == []

    def test_sync_handles_none_values(self, tenant):
        """Test sync handles None values gracefully."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        PublicProfile.objects.create(
            user=user,
            display_name='Test User',
            bio='',  # Empty string
            city='',
            linkedin_url='',
        )

        with tenant_context(tenant):
            result = ProfileSyncService.sync_on_invitation_acceptance(
                user=user,
                tenant=tenant
            )

            assert result['success'] is True

            tenant_profile = TenantProfile.objects.get(user=user, tenant=tenant)
            assert tenant_profile.bio == ''
            assert tenant_profile.city == ''
            assert tenant_profile.linkedin_url == ''

    def test_sync_updates_timestamp(self, user_with_public_profile, tenant):
        """Test that sync updates last_synced_at timestamp."""
        user = user_with_public_profile

        with tenant_context(tenant):
            before_sync = timezone.now()

            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant)

            tenant_profile = TenantProfile.objects.get(user=user, tenant=tenant)

            assert tenant_profile.last_synced_at is not None
            assert tenant_profile.last_synced_at >= before_sync

    def test_multiple_tenants_independent_sync(self, user_with_public_profile, db):
        """Test that user can have different sync settings for different tenants."""
        user = user_with_public_profile

        # Create two tenants
        tenant1 = Tenant.objects.create(
            schema_name='tenant1',
            name='Company 1',
            domain_url='tenant1.localhost',
        )
        tenant2 = Tenant.objects.create(
            schema_name='tenant2',
            name='Company 2',
            domain_url='tenant2.localhost',
        )

        # Different sync settings for each tenant
        sync1, _ = ProfileFieldSync.get_or_create_defaults(user=user, tenant_uuid=tenant1.uuid)
        sync1.sync_bio = True
        sync1.sync_phone = False
        sync1.save()

        sync2, _ = ProfileFieldSync.get_or_create_defaults(user=user, tenant_uuid=tenant2.uuid)
        sync2.sync_bio = False
        sync2.sync_phone = True
        sync2.save()

        # Sync to both tenants
        with tenant_context(tenant1):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant1)
            profile1 = TenantProfile.objects.get(user=user, tenant=tenant1)

        with tenant_context(tenant2):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant2)
            profile2 = TenantProfile.objects.get(user=user, tenant=tenant2)

        # Verify different sync results
        assert profile1.bio == 'Experienced software engineer'  # Synced
        assert profile1.phone == ''  # Not synced

        assert profile2.bio == ''  # Not synced
        assert profile2.phone == '+14165551234'  # Synced
