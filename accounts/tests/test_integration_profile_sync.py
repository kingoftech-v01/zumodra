"""
Integration tests for complete profile sync flow.
Tests signals, invitation acceptance, and multi-tenant synchronization.
"""

import pytest
from django.utils import timezone
from django_tenants.utils import tenant_context

from custom_account_u.models import CustomUser, PublicProfile, ProfileFieldSync
from accounts.models import TenantProfile, TenantUser
from tenants.models import Tenant, TenantInvitation
from accounts.services import ProfileSyncService


@pytest.mark.integration
@pytest.mark.django_db
class TestProfileSignals:
    """Test signal-based profile creation."""

    def test_public_profile_created_on_user_creation(self):
        """Test that PublicProfile is auto-created when user is created."""
        user = CustomUser.objects.create_user(
            username='newuser',
            email='new@example.com',
            password='testpass123',
            first_name='New',
            last_name='User'
        )

        # PublicProfile should be auto-created by signal
        assert PublicProfile.objects.filter(user=user).exists()

        profile = PublicProfile.objects.get(user=user)
        assert profile.display_name == 'New User'

    def test_public_profile_display_name_fallback_to_email(self):
        """Test that display_name falls back to email if name is empty."""
        user = CustomUser.objects.create_user(
            username='emailuser',
            email='email@example.com',
            password='testpass123'
            # No first_name or last_name
        )

        profile = PublicProfile.objects.get(user=user)
        assert profile.display_name == 'email@example.com'

    def test_public_profile_updated_on_user_name_change(self):
        """Test that PublicProfile display_name updates when user name changes."""
        user = CustomUser.objects.create_user(
            username='changeuser',
            email='change@example.com',
            password='testpass123',
            first_name='Old',
            last_name='Name'
        )

        profile = user.public_profile
        assert profile.display_name == 'Old Name'

        # Update user name
        user.first_name = 'New'
        user.last_name = 'Name'
        user.save()

        # PublicProfile should update
        profile.refresh_from_db()
        assert profile.display_name == 'New Name'


@pytest.mark.integration
@pytest.mark.django_db
class TestInvitationWithProfileSync:
    """Test invitation acceptance flow with automatic profile sync."""

    @pytest.fixture
    def tenant(self, db):
        """Create test tenant."""
        tenant = Tenant.objects.create(
            schema_name='invitation_test',
            name='Invitation Test Company',
            domain_url='invitation.localhost',
        )
        return tenant

    @pytest.fixture
    def inviter(self, tenant):
        """Create inviter user with admin role."""
        inviter = CustomUser.objects.create_user(
            username='inviter',
            email='inviter@example.com',
            password='testpass123'
        )

        with tenant_context(tenant):
            TenantUser.objects.create(
                user=inviter,
                tenant=tenant,
                role=TenantUser.UserRole.ADMIN,
            )

        return inviter

    @pytest.fixture
    def invitee_with_profile(self):
        """Create invitee user with complete PublicProfile."""
        invitee = CustomUser.objects.create_user(
            username='invitee',
            email='invitee@example.com',
            password='testpass123',
            first_name='Jane',
            last_name='Smith'
        )

        # Update PublicProfile with detailed info
        profile = invitee.public_profile
        profile.professional_title = 'Senior Developer'
        profile.bio = 'Experienced full-stack developer'
        profile.city = 'Montreal'
        profile.state = 'Quebec'
        profile.country = 'CA'
        profile.linkedin_url = 'https://linkedin.com/in/janesmith'
        profile.github_url = 'https://github.com/janesmith'
        profile.skills = ['Python', 'JavaScript', 'React', 'Node.js']
        profile.languages = ['English', 'French']
        profile.save()

        return invitee

    def test_invitation_acceptance_triggers_profile_sync(
        self, tenant, inviter, invitee_with_profile
    ):
        """Test that accepting invitation triggers automatic profile sync."""
        invitee = invitee_with_profile

        # Create invitation
        with tenant_context(tenant):
            invitation = TenantInvitation.objects.create(
                tenant=tenant,
                email=invitee.email,
                invited_by=inviter,
                role=TenantUser.UserRole.EMPLOYEE,
            )

            # Accept invitation (this should trigger profile sync)
            from tenants.services import InvitationService

            result = InvitationService.accept_invitation(
                invitation_uuid=invitation.uuid,
                user=invitee
            )

            # Verify invitation accepted
            assert result['success'] is True

            # Verify TenantProfile created and synced
            assert TenantProfile.objects.filter(user=invitee, tenant=tenant).exists()

            tenant_profile = TenantProfile.objects.get(user=invitee, tenant=tenant)

            # Verify synced fields
            assert tenant_profile.full_name == 'Jane Smith'
            assert tenant_profile.bio == 'Experienced full-stack developer'
            assert tenant_profile.city == 'Montreal'
            assert tenant_profile.state == 'Quebec'
            assert tenant_profile.linkedin_url == 'https://linkedin.com/in/janesmith'
            assert tenant_profile.github_url == 'https://github.com/janesmith'
            assert tenant_profile.skills_json == ['Python', 'JavaScript', 'React', 'Node.js']
            assert tenant_profile.languages_json == ['English', 'French']

            # Verify privacy: email and phone NOT synced
            assert tenant_profile.email == ''
            assert tenant_profile.phone == ''

            # Verify sync metadata
            assert tenant_profile.last_synced_at is not None
            assert len(tenant_profile.synced_fields) > 0

    def test_invitation_acceptance_creates_sync_settings(
        self, tenant, inviter, invitee_with_profile
    ):
        """Test that invitation acceptance creates ProfileFieldSync settings."""
        invitee = invitee_with_profile

        # Verify no sync settings exist before
        assert not ProfileFieldSync.objects.filter(
            user=invitee,
            tenant_uuid=tenant.uuid
        ).exists()

        with tenant_context(tenant):
            invitation = TenantInvitation.objects.create(
                tenant=tenant,
                email=invitee.email,
                invited_by=inviter,
                role=TenantUser.UserRole.EMPLOYEE,
            )

            from tenants.services import InvitationService
            InvitationService.accept_invitation(
                invitation_uuid=invitation.uuid,
                user=invitee
            )

        # Verify sync settings created with privacy defaults
        sync_settings = ProfileFieldSync.objects.get(
            user=invitee,
            tenant_uuid=tenant.uuid
        )

        assert sync_settings.sync_display_name is True
        assert sync_settings.sync_avatar is True
        assert sync_settings.sync_bio is True
        assert sync_settings.sync_public_email is False  # Privacy OFF
        assert sync_settings.sync_phone is False  # Privacy OFF
        assert sync_settings.auto_sync is False  # Manual only


@pytest.mark.integration
@pytest.mark.django_db
class TestMultiTenantProfileSync:
    """Test profile synchronization across multiple tenants."""

    @pytest.fixture
    def user_with_profile(self):
        """Create user with PublicProfile."""
        user = CustomUser.objects.create_user(
            username='multiuser',
            email='multi@example.com',
            password='testpass123',
            first_name='Multi',
            last_name='Tenant'
        )

        profile = user.public_profile
        profile.bio = 'Multi-tenant professional'
        profile.city = 'Toronto'
        profile.skills = ['Python', 'Django', 'PostgreSQL']
        profile.save()

        return user

    @pytest.fixture
    def tenants(self, db):
        """Create multiple test tenants."""
        tenant1 = Tenant.objects.create(
            schema_name='company_a',
            name='Company A',
            domain_url='company-a.localhost',
        )
        tenant2 = Tenant.objects.create(
            schema_name='company_b',
            name='Company B',
            domain_url='company-b.localhost',
        )
        return {'tenant1': tenant1, 'tenant2': tenant2}

    def test_user_joins_multiple_tenants_with_different_sync_settings(
        self, user_with_profile, tenants
    ):
        """Test user can join multiple tenants with independent sync settings."""
        user = user_with_profile
        tenant1 = tenants['tenant1']
        tenant2 = tenants['tenant2']

        # Configure different sync settings for each tenant
        sync1, _ = ProfileFieldSync.get_or_create_defaults(
            user=user,
            tenant_uuid=tenant1.uuid
        )
        sync1.sync_bio = True
        sync1.sync_phone = False
        sync1.save()

        sync2, _ = ProfileFieldSync.get_or_create_defaults(
            user=user,
            tenant_uuid=tenant2.uuid
        )
        sync2.sync_bio = False  # Different setting
        sync2.sync_phone = True  # Different setting
        sync2.save()

        # Add phone to PublicProfile
        user.public_profile.phone = '+14165551234'
        user.public_profile.save()

        # Sync to tenant1
        with tenant_context(tenant1):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant1)
            profile1 = TenantProfile.objects.get(user=user, tenant=tenant1)

        # Sync to tenant2
        with tenant_context(tenant2):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant2)
            profile2 = TenantProfile.objects.get(user=user, tenant=tenant2)

        # Verify different sync results
        assert profile1.bio == 'Multi-tenant professional'  # Synced
        assert profile1.phone == ''  # Not synced

        assert profile2.bio == ''  # Not synced
        assert profile2.phone == '+14165551234'  # Synced

    def test_public_profile_update_does_not_auto_sync_to_tenants(
        self, user_with_profile, tenants
    ):
        """Test that updating PublicProfile does NOT auto-sync (manual only)."""
        user = user_with_profile
        tenant1 = tenants['tenant1']

        # Initial sync
        with tenant_context(tenant1):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant1)
            profile1 = TenantProfile.objects.get(user=user, tenant=tenant1)
            original_bio = profile1.bio
            sync_time = profile1.last_synced_at

        # Update PublicProfile
        user.public_profile.bio = 'Updated bio - should NOT auto-sync'
        user.public_profile.save()

        # Wait a moment
        import time
        time.sleep(0.1)

        # Verify TenantProfile NOT updated (no auto-sync)
        with tenant_context(tenant1):
            profile1.refresh_from_db()
            assert profile1.bio == original_bio  # Unchanged
            assert profile1.last_synced_at == sync_time  # Not re-synced

    def test_manual_sync_updates_out_of_sync_profile(
        self, user_with_profile, tenants
    ):
        """Test manual sync updates profile that is out of sync."""
        user = user_with_profile
        tenant1 = tenants['tenant1']

        # Initial sync
        with tenant_context(tenant1):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant1)
            profile1 = TenantProfile.objects.get(user=user, tenant=tenant1)

            # Verify sync_status
            assert profile1.sync_status == 'synced'

        # Update PublicProfile
        user.public_profile.bio = 'Manual sync test'
        user.public_profile.city = 'Vancouver'
        user.public_profile.save()

        # Verify out_of_sync status
        with tenant_context(tenant1):
            profile1.refresh_from_db()
            assert profile1.sync_status == 'out_of_sync'

            # Trigger manual sync
            result = ProfileSyncService.sync_manual_trigger(
                user=user,
                tenant=tenant1
            )

            assert result['success'] is True

            # Verify updated
            profile1.refresh_from_db()
            assert profile1.bio == 'Manual sync test'
            assert profile1.city == 'Vancouver'
            assert profile1.sync_status == 'synced'


@pytest.mark.integration
@pytest.mark.django_db
class TestProfilePrivacyControls:
    """Test privacy controls and field-level sync permissions."""

    @pytest.fixture
    def tenant(self, db):
        """Create test tenant."""
        tenant = Tenant.objects.create(
            schema_name='privacy_test',
            name='Privacy Test Company',
            domain_url='privacy.localhost',
        )
        return tenant

    @pytest.fixture
    def user_with_sensitive_data(self):
        """Create user with sensitive personal data."""
        user = CustomUser.objects.create_user(
            username='sensitive',
            email='sensitive@example.com',
            password='testpass123'
        )

        profile = user.public_profile
        profile.display_name = 'Sensitive User'
        profile.public_email = 'sensitive.public@example.com'
        profile.phone = '+14165551234'
        profile.bio = 'Public bio'
        profile.save()

        return user

    def test_sensitive_fields_not_synced_by_default(
        self, user_with_sensitive_data, tenant
    ):
        """Test that email and phone are NOT synced by default (privacy)."""
        user = user_with_sensitive_data

        with tenant_context(tenant):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant)

            profile = TenantProfile.objects.get(user=user, tenant=tenant)

            # Public fields synced
            assert profile.full_name == 'Sensitive User'
            assert profile.bio == 'Public bio'

            # Sensitive fields NOT synced
            assert profile.email == ''
            assert profile.phone == ''

    def test_user_can_enable_sensitive_field_sync(
        self, user_with_sensitive_data, tenant
    ):
        """Test user can enable sync for sensitive fields."""
        user = user_with_sensitive_data

        # Enable phone sync
        sync_settings, _ = ProfileFieldSync.get_or_create_defaults(
            user=user,
            tenant_uuid=tenant.uuid
        )
        sync_settings.sync_phone = True
        sync_settings.sync_public_email = True
        sync_settings.save()

        with tenant_context(tenant):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant)

            profile = TenantProfile.objects.get(user=user, tenant=tenant)

            # Now sensitive fields ARE synced
            assert profile.email == 'sensitive.public@example.com'
            assert profile.phone == '+14165551234'

    def test_user_can_disable_any_field_sync(
        self, user_with_sensitive_data, tenant
    ):
        """Test user can disable sync for any field, even public ones."""
        user = user_with_sensitive_data

        # Disable bio sync (normally ON by default)
        sync_settings, _ = ProfileFieldSync.get_or_create_defaults(
            user=user,
            tenant_uuid=tenant.uuid
        )
        sync_settings.sync_bio = False
        sync_settings.save()

        with tenant_context(tenant):
            ProfileSyncService.sync_on_invitation_acceptance(user=user, tenant=tenant)

            profile = TenantProfile.objects.get(user=user, tenant=tenant)

            # Bio NOT synced
            assert profile.bio == ''

            # But display_name still synced
            assert profile.full_name == 'Sensitive User'
