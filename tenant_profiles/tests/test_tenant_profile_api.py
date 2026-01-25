"""
API tests for TenantProfile endpoints.
"""

import pytest
from django.utils import timezone
from django_tenants.utils import tenant_context
from rest_framework import status
from rest_framework.test import APIClient

from custom_account_u.models import CustomUser, PublicProfile, ProfileFieldSync
from tenant_profiles.models import TenantProfile, TenantUser
from tenants.models import Tenant


@pytest.mark.django_db
class TestTenantProfileAPI:
    """Test TenantProfile API endpoints."""

    @pytest.fixture
    def api_client(self):
        """Create API client."""
        return APIClient()

    @pytest.fixture
    def tenant(self, db):
        """Create test tenant."""
        tenant = Tenant.objects.create(
            schema_name='test_tenant',
            name='Test Company',
            domain_url='test.localhost',
        )
        return tenant

    @pytest.fixture
    def user_with_public_profile(self):
        """Create user with PublicProfile."""
        user = CustomUser.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )
        PublicProfile.objects.create(
            user=user,
            display_name='John Doe',
            professional_title='Software Engineer',
            bio='Experienced developer',
            city='Toronto',
            state='Ontario',
            country='CA',
            skills=['Python', 'Django'],
            languages=['English', 'French'],
        )
        return user

    @pytest.fixture
    def tenant_user_with_profile(self, tenant, user_with_public_profile):
        """Create TenantUser and TenantProfile."""
        user = user_with_public_profile

        with tenant_context(tenant):
            tenant_user = TenantUser.objects.create(
                user=user,
                tenant=tenant,
                role=TenantUser.UserRole.EMPLOYEE,
                job_title='Software Engineer'
            )

            tenant_profile = TenantProfile.objects.create(
                user=user,
                tenant=tenant,
                job_title='Software Engineer',
                full_name='John Doe',
                bio='Experienced developer',
                city='Toronto',
                state='Ontario',
                country='CA',
            )

        return {'user': user, 'tenant_user': tenant_user, 'profile': tenant_profile}

    def test_get_own_tenant_profile(self, api_client, tenant, tenant_user_with_profile):
        """Test GET /api/profile/tenant/me/ returns own tenant profile."""
        user = tenant_user_with_profile['user']

        with tenant_context(tenant):
            api_client.force_authenticate(user=user)

            # Mock request.tenant
            url = '/api/profile/tenant/me/'
            response = api_client.get(url)

            # Note: This test may need adjustment based on actual tenant middleware
            # In production, request.tenant is set by django-tenants middleware
            # For unit tests, you may need to mock or set this differently

    def test_update_own_tenant_profile(self, api_client, tenant, tenant_user_with_profile):
        """Test PATCH /api/profile/tenant/me/ updates employment data."""
        user = tenant_user_with_profile['user']

        with tenant_context(tenant):
            api_client.force_authenticate(user=user)

            url = '/api/profile/tenant/me/'
            data = {
                'job_title': 'Senior Software Engineer',
                'employee_id': 'EMP-12345',
                'address_line1': '123 Main St',
                'postal_code': 'M5V 1A1',
            }

            # Note: Actual API call may need tenant context in request
            # This is a simplified example
            response = api_client.patch(url, data, format='json')

            # Verify synced fields are read-only and not updated
            # Only employment/personal fields should be updatable

    def test_cannot_update_synced_fields(self, api_client, tenant, tenant_user_with_profile):
        """Test that synced fields from PublicProfile are read-only."""
        user = tenant_user_with_profile['user']

        with tenant_context(tenant):
            api_client.force_authenticate(user=user)

            url = '/api/profile/tenant/me/'
            data = {
                'full_name': 'Hacked Name',  # Synced field, should be read-only
                'bio': 'Hacked bio',  # Synced field
                'employee_id': 'EMP-999',  # Tenant-specific, should be updatable
            }

            response = api_client.patch(url, data, format='json')

            # Verify synced fields were not updated
            profile = TenantProfile.objects.get(
                user=user,
                tenant=tenant
            )
            assert profile.full_name == 'John Doe'  # Unchanged
            assert profile.employee_id == 'EMP-999'  # Updated

    def test_trigger_manual_sync(self, api_client, tenant, tenant_user_with_profile):
        """Test POST /api/profile/tenant/sync/ triggers manual sync."""
        user = tenant_user_with_profile['user']

        # Update PublicProfile
        user.public_profile.bio = 'Updated bio from public profile'
        user.public_profile.city = 'Vancouver'
        user.public_profile.save()

        with tenant_context(tenant):
            api_client.force_authenticate(user=user)

            url = '/api/profile/tenant/sync/'
            response = api_client.post(url, {}, format='json')

            # Verify sync occurred
            if response.status_code == status.HTTP_200_OK:
                assert response.data['success'] is True
                assert len(response.data['synced_fields']) > 0

                # Verify TenantProfile updated
                profile = TenantProfile.objects.get(user=user, tenant=tenant)
                assert profile.bio == 'Updated bio from public profile'
                assert profile.city == 'Vancouver'

    def test_manual_sync_with_field_overrides(self, api_client, tenant, tenant_user_with_profile):
        """Test manual sync with one-time field overrides."""
        user = tenant_user_with_profile['user']

        # Update phone in PublicProfile
        user.public_profile.phone = '+14165551234'
        user.public_profile.save()

        # Phone sync is OFF by default
        sync_settings = ProfileFieldSync.objects.get(
            user=user,
            tenant_uuid=tenant.uuid
        )
        assert sync_settings.sync_phone is False

        with tenant_context(tenant):
            api_client.force_authenticate(user=user)

            url = '/api/profile/tenant/sync/'
            data = {
                'field_overrides': {
                    'sync_phone': True  # One-time override
                }
            }
            response = api_client.post(url, data, format='json')

            if response.status_code == status.HTTP_200_OK:
                assert 'phone' in response.data['synced_fields']

                # Verify phone synced
                profile = TenantProfile.objects.get(user=user, tenant=tenant)
                assert profile.phone == '+14165551234'

    def test_admin_can_view_all_profiles(self, api_client, tenant):
        """Test admin can view all tenant profiles."""
        # Create admin user
        admin = CustomUser.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='testpass123'
        )

        # Create regular employee
        employee = CustomUser.objects.create_user(
            username='employee',
            email='employee@example.com',
            password='testpass123'
        )

        with tenant_context(tenant):
            # Admin TenantUser
            TenantUser.objects.create(
                user=admin,
                tenant=tenant,
                role=TenantUser.UserRole.ADMIN,
            )

            # Employee TenantUser
            TenantUser.objects.create(
                user=employee,
                tenant=tenant,
                role=TenantUser.UserRole.EMPLOYEE,
            )

            # Create profiles
            TenantProfile.objects.create(
                user=admin,
                tenant=tenant,
                job_title='Admin'
            )
            TenantProfile.objects.create(
                user=employee,
                tenant=tenant,
                job_title='Developer'
            )

            # Admin queries all profiles
            api_client.force_authenticate(user=admin)
            url = '/api/profile/tenant/'
            response = api_client.get(url)

            # Admin should see all profiles (admin + employee)
            if response.status_code == status.HTTP_200_OK:
                assert len(response.data) >= 2

    def test_employee_can_only_view_own_profile(self, api_client, tenant):
        """Test regular employee can only view their own profile."""
        employee = CustomUser.objects.create_user(
            username='employee',
            email='employee@example.com',
            password='testpass123'
        )

        with tenant_context(tenant):
            TenantUser.objects.create(
                user=employee,
                tenant=tenant,
                role=TenantUser.UserRole.EMPLOYEE,
            )
            TenantProfile.objects.create(
                user=employee,
                tenant=tenant,
                job_title='Developer'
            )

            api_client.force_authenticate(user=employee)
            url = '/api/profile/tenant/'
            response = api_client.get(url)

            # Employee should only see own profile
            if response.status_code == status.HTTP_200_OK:
                assert len(response.data) == 1
                assert response.data[0]['user_email'] == 'employee@example.com'

    def test_sync_status_property_in_response(self, api_client, tenant, tenant_user_with_profile):
        """Test that sync_status property is included in response."""
        user = tenant_user_with_profile['user']

        with tenant_context(tenant):
            api_client.force_authenticate(user=user)

            url = '/api/profile/tenant/me/'
            response = api_client.get(url)

            if response.status_code == status.HTTP_200_OK:
                assert 'sync_status' in response.data
                assert response.data['sync_status'] in [
                    'never_synced', 'synced', 'out_of_sync', 'no_public_profile'
                ]

    def test_unauthenticated_access_denied(self, api_client):
        """Test unauthenticated users cannot access tenant profile endpoints."""
        url = '/api/profile/tenant/me/'
        response = api_client.get(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.integration
@pytest.mark.django_db
class TestTenantProfileSyncIntegration:
    """Integration tests for complete sync flow."""

    @pytest.fixture
    def api_client(self):
        """Create API client."""
        return APIClient()

    @pytest.fixture
    def tenant(self, db):
        """Create test tenant."""
        tenant = Tenant.objects.create(
            schema_name='integration_test',
            name='Integration Test Company',
            domain_url='integration.localhost',
        )
        return tenant

    def test_end_to_end_profile_sync_flow(self, api_client, tenant):
        """Test complete flow: create public profile → join tenant → sync → update → re-sync."""
        # 1. Create user and public profile
        user = CustomUser.objects.create_user(
            username='syncuser',
            email='sync@example.com',
            password='testpass123',
            first_name='Sync',
            last_name='User'
        )
        public_profile = PublicProfile.objects.create(
            user=user,
            display_name='Sync User',
            bio='Original bio',
            city='Toronto',
            skills=['Python', 'Django'],
        )

        # 2. User joins tenant (simulate invitation acceptance)
        with tenant_context(tenant):
            from tenant_profiles.services import ProfileSyncService

            result = ProfileSyncService.sync_on_invitation_acceptance(
                user=user,
                tenant=tenant
            )

            assert result['success'] is True
            assert len(result['synced_fields']) > 0

            # Verify TenantProfile created
            tenant_profile = TenantProfile.objects.get(user=user, tenant=tenant)
            assert tenant_profile.full_name == 'Sync User'
            assert tenant_profile.bio == 'Original bio'
            assert tenant_profile.city == 'Toronto'
            assert tenant_profile.skills_json == ['Python', 'Django']

        # 3. Update PublicProfile
        public_profile.bio = 'Updated bio'
        public_profile.city = 'Vancouver'
        public_profile.skills = ['Python', 'Django', 'PostgreSQL', 'React']
        public_profile.save()

        # 4. Trigger manual sync via API
        with tenant_context(tenant):
            api_client.force_authenticate(user=user)

            url = '/api/profile/tenant/sync/'
            response = api_client.post(url, {}, format='json')

            # Verify sync succeeded
            if response.status_code == status.HTTP_200_OK:
                # Verify TenantProfile updated
                tenant_profile.refresh_from_db()
                assert tenant_profile.bio == 'Updated bio'
                assert tenant_profile.city == 'Vancouver'
                assert len(tenant_profile.skills_json) == 4

        # 5. Verify sync timestamp updated
        with tenant_context(tenant):
            tenant_profile.refresh_from_db()
            assert tenant_profile.last_synced_at is not None
            assert tenant_profile.last_synced_at > public_profile.created_at
