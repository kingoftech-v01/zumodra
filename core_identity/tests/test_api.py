"""
API tests for PublicProfile and ProfileFieldSync endpoints.
"""

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from core_identity.models import CustomUser, PublicProfile, ProfileFieldSync


@pytest.mark.django_db
class TestPublicProfileAPI:
    """Test PublicProfile API endpoints."""

    @pytest.fixture
    def api_client(self):
        """Create API client."""
        return APIClient()

    @pytest.fixture
    def user_with_profile(self):
        """Create user with PublicProfile."""
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
            professional_title='Software Engineer',
            bio='Experienced developer',
            city='Toronto',
            country='CA',
            profile_visibility=PublicProfile.VISIBILITY_PUBLIC,
        )
        return user

    def test_get_own_profile_authenticated(self, api_client, user_with_profile):
        """Test GET /api/profile/public/me/ returns own profile."""
        api_client.force_authenticate(user=user_with_profile)

        url = '/api/profile/public/me/'
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['display_name'] == 'John Doe'
        assert response.data['professional_title'] == 'Software Engineer'
        assert response.data['user_email'] == 'test@example.com'
        assert 'completion_percentage' in response.data
        assert 'verification_badges' in response.data

    def test_get_own_profile_unauthenticated(self, api_client):
        """Test GET /api/profile/public/me/ requires authentication."""
        url = '/api/profile/public/me/'
        response = api_client.get(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_own_profile_patch(self, api_client, user_with_profile):
        """Test PATCH /api/profile/public/me/ updates own profile."""
        api_client.force_authenticate(user=user_with_profile)

        url = '/api/profile/public/me/'
        data = {
            'bio': 'Updated bio text',
            'city': 'Vancouver',
            'available_for_work': True,
        }
        response = api_client.patch(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['bio'] == 'Updated bio text'
        assert response.data['city'] == 'Vancouver'
        assert response.data['available_for_work'] is True

        # Verify database update
        profile = PublicProfile.objects.get(user=user_with_profile)
        assert profile.bio == 'Updated bio text'

    def test_update_profile_skills_languages(self, api_client, user_with_profile):
        """Test updating JSON fields (skills, languages)."""
        api_client.force_authenticate(user=user_with_profile)

        url = '/api/profile/public/me/'
        data = {
            'skills': ['Python', 'Django', 'PostgreSQL', 'React'],
            'languages': ['English', 'French', 'Spanish'],
        }
        response = api_client.patch(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['skills']) == 4
        assert len(response.data['languages']) == 3

    def test_update_profile_hourly_rates_validation(self, api_client, user_with_profile):
        """Test hourly rate validation (min cannot be > max)."""
        api_client.force_authenticate(user=user_with_profile)

        url = '/api/profile/public/me/'
        data = {
            'hourly_rate_min': 150.00,
            'hourly_rate_max': 100.00,  # Invalid: max < min
        }
        response = api_client.patch(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'hourly_rate_min' in response.data

    def test_update_profile_valid_hourly_rates(self, api_client, user_with_profile):
        """Test valid hourly rate update."""
        api_client.force_authenticate(user=user_with_profile)

        url = '/api/profile/public/me/'
        data = {
            'hourly_rate_min': 100.00,
            'hourly_rate_max': 150.00,
            'currency': 'CAD',
        }
        response = api_client.patch(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert float(response.data['hourly_rate_min']) == 100.00
        assert float(response.data['hourly_rate_max']) == 150.00

    def test_retrieve_public_profile_by_uuid(self, api_client, user_with_profile):
        """Test GET /api/profile/public/{uuid}/ retrieves public profile."""
        # Create another user to view the profile
        viewer = CustomUser.objects.create_user(
            username='viewer',
            email='viewer@example.com',
            password='testpass123'
        )
        api_client.force_authenticate(user=viewer)

        profile = user_with_profile.public_profile
        url = f'/api/profile/public/{profile.uuid}/'
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['display_name'] == 'John Doe'

    def test_retrieve_private_profile_forbidden(self, api_client):
        """Test retrieving private profile returns 403."""
        # Create user with private profile
        private_user = CustomUser.objects.create_user(
            username='private',
            email='private@example.com',
            password='testpass123'
        )
        profile = PublicProfile.objects.create(
            user=private_user,
            display_name='Private User',
            profile_visibility=PublicProfile.VISIBILITY_PRIVATE,
        )

        # Another user tries to view
        viewer = CustomUser.objects.create_user(
            username='viewer',
            email='viewer@example.com',
            password='testpass123'
        )
        api_client.force_authenticate(user=viewer)

        url = f'/api/profile/public/{profile.uuid}/'
        response = api_client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_update_other_user_profile_forbidden(self, api_client, user_with_profile):
        """Test that users cannot update other users' profiles."""
        # Create another user
        other_user = CustomUser.objects.create_user(
            username='other',
            email='other@example.com',
            password='testpass123'
        )
        api_client.force_authenticate(user=other_user)

        profile = user_with_profile.public_profile
        url = f'/api/profile/public/{profile.uuid}/'
        data = {'bio': 'Hacked!'}
        response = api_client.patch(url, data, format='json')

        # Should fail (update not allowed on detail endpoint)
        assert response.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_405_METHOD_NOT_ALLOWED]


@pytest.mark.django_db
class TestProfileFieldSyncAPI:
    """Test ProfileFieldSync API endpoints."""

    @pytest.fixture
    def api_client(self):
        """Create API client."""
        return APIClient()

    @pytest.fixture
    def user(self):
        """Create user."""
        return CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_get_sync_settings_for_tenant(self, api_client, user):
        """Test GET /api/profile/sync-settings/tenant/{uuid}/ returns sync settings."""
        import uuid
        tenant_uuid = uuid.uuid4()

        api_client.force_authenticate(user=user)

        url = f'/api/profile/sync-settings/tenant/{tenant_uuid}/'
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['tenant_uuid'] == str(tenant_uuid)
        assert response.data['user_email'] == 'test@example.com'

        # Verify privacy defaults
        assert response.data['sync_display_name'] is True
        assert response.data['sync_public_email'] is False  # Privacy OFF
        assert response.data['sync_phone'] is False  # Privacy OFF
        assert response.data['auto_sync'] is False

    def test_update_sync_settings_for_tenant(self, api_client, user):
        """Test PATCH /api/profile/sync-settings/tenant/{uuid}/ updates settings."""
        import uuid
        tenant_uuid = uuid.uuid4()

        # Create initial settings
        ProfileFieldSync.get_or_create_defaults(user=user, tenant_uuid=tenant_uuid)

        api_client.force_authenticate(user=user)

        url = f'/api/profile/sync-settings/tenant/{tenant_uuid}/'
        data = {
            'sync_phone': True,  # Enable phone sync
            'sync_bio': False,  # Disable bio sync
        }
        response = api_client.patch(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert response.data['sync_phone'] is True
        assert response.data['sync_bio'] is False

        # Verify database update
        sync_settings = ProfileFieldSync.objects.get(user=user, tenant_uuid=tenant_uuid)
        assert sync_settings.sync_phone is True
        assert sync_settings.sync_bio is False

    def test_list_all_sync_settings(self, api_client, user):
        """Test GET /api/profile/sync-settings/ lists all user's sync settings."""
        import uuid

        # Create sync settings for multiple tenants
        tenant1_uuid = uuid.uuid4()
        tenant2_uuid = uuid.uuid4()
        ProfileFieldSync.get_or_create_defaults(user=user, tenant_uuid=tenant1_uuid)
        ProfileFieldSync.get_or_create_defaults(user=user, tenant_uuid=tenant2_uuid)

        api_client.force_authenticate(user=user)

        url = '/api/profile/sync-settings/'
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 2

        # Verify both tenants present
        tenant_uuids = [item['tenant_uuid'] for item in response.data]
        assert str(tenant1_uuid) in tenant_uuids
        assert str(tenant2_uuid) in tenant_uuids

    def test_sync_settings_unauthenticated(self, api_client):
        """Test sync settings endpoints require authentication."""
        import uuid
        url = f'/api/profile/sync-settings/tenant/{uuid.uuid4()}/'
        response = api_client.get(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_enabled_fields_in_response(self, api_client, user):
        """Test that enabled_fields is included in response."""
        import uuid
        tenant_uuid = uuid.uuid4()

        # Create settings with specific fields enabled
        sync_settings, _ = ProfileFieldSync.get_or_create_defaults(
            user=user, tenant_uuid=tenant_uuid
        )
        sync_settings.sync_bio = True
        sync_settings.sync_phone = True
        sync_settings.save()

        api_client.force_authenticate(user=user)

        url = f'/api/profile/sync-settings/tenant/{tenant_uuid}/'
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'enabled_fields' in response.data
        assert 'bio' in response.data['enabled_fields']
        assert 'phone' in response.data['enabled_fields']

    def test_cannot_update_other_user_sync_settings(self, api_client):
        """Test users cannot update other users' sync settings."""
        import uuid

        # User 1 creates sync settings
        user1 = CustomUser.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='testpass123'
        )
        tenant_uuid = uuid.uuid4()
        ProfileFieldSync.get_or_create_defaults(user=user1, tenant_uuid=tenant_uuid)

        # User 2 tries to update user1's settings
        user2 = CustomUser.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='testpass123'
        )
        api_client.force_authenticate(user=user2)

        url = f'/api/profile/sync-settings/tenant/{tenant_uuid}/'
        data = {'sync_phone': True}
        response = api_client.patch(url, data, format='json')

        # Should create new settings for user2, not update user1's
        assert response.status_code == status.HTTP_200_OK

        # Verify user1's settings unchanged
        user1_settings = ProfileFieldSync.objects.get(user=user1, tenant_uuid=tenant_uuid)
        assert user1_settings.sync_phone is False  # Still default

        # Verify user2 has own settings
        user2_settings = ProfileFieldSync.objects.get(user=user2, tenant_uuid=tenant_uuid)
        assert user2_settings.sync_phone is True
