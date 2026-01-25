"""
API tests for FreelancerProfile ViewSet.

Tests REST API endpoints, permissions, filtering, and custom actions.
"""

import pytest
from decimal import Decimal
from rest_framework.test import APIClient
from django.urls import reverse

pytestmark = pytest.mark.django_db


@pytest.fixture
def api_client():
    """Return an API client instance."""
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, user_factory):
    """Return an authenticated API client."""
    user = user_factory()
    api_client.force_authenticate(user=user)
    return api_client, user


class TestFreelancerProfileListAPI:
    """Test listing freelancer profiles (public endpoint)."""

    def test_list_freelancer_profiles_public_access(self, api_client):
        """Test anyone can list freelancer profiles (no auth required)."""
        from conftest import VerifiedFreelancerProfileFactory

        # Create some verified profiles
        VerifiedFreelancerProfileFactory.create_batch(5)

        url = reverse('tenant_profiles:freelancer-profile-list')
        response = api_client.get(url)

        assert response.status_code == 200
        assert len(response.data['results']) == 5

    def test_list_only_shows_verified_profiles(self, api_client):
        """Test list endpoint only shows verified freelancers."""
        from conftest import FreelancerProfileFactory, VerifiedFreelancerProfileFactory

        # Create unverified profiles
        FreelancerProfileFactory.create_batch(3, is_verified=False)

        # Create verified profiles
        VerifiedFreelancerProfileFactory.create_batch(7)

        url = reverse('tenant_profiles:freelancer-profile-list')
        response = api_client.get(url)

        assert response.status_code == 200
        assert len(response.data['results']) == 7  # Only verified

    def test_filter_by_availability_status(self, api_client):
        """Test filtering by availability status."""
        from conftest import (
            VerifiedFreelancerProfileFactory,
            BusyFreelancerProfileFactory
        )

        # Create available
        VerifiedFreelancerProfileFactory.create_batch(5, availability_status='available')

        # Create busy
        BusyFreelancerProfileFactory.create_batch(3)

        url = reverse('tenant_profiles:freelancer-profile-list')
        response = api_client.get(url, {'availability_status': 'available'})

        assert response.status_code == 200
        assert len(response.data['results']) == 5

    def test_filter_by_remote_only(self, api_client):
        """Test filtering by remote_only flag."""
        from conftest import (
            RemoteOnlyFreelancerProfileFactory,
            WillingToRelocateFreelancerProfileFactory
        )

        # Create remote-only
        RemoteOnlyFreelancerProfileFactory.create_batch(4)

        # Create willing to relocate (not remote-only)
        WillingToRelocateFreelancerProfileFactory.create_batch(6, remote_only=False)

        url = reverse('tenant_profiles:freelancer-profile-list')
        response = api_client.get(url, {'remote_only': 'true'})

        assert response.status_code == 200
        assert len(response.data['results']) == 4

    def test_search_by_professional_title(self, api_client):
        """Test searching freelancers by professional title."""
        from conftest import VerifiedFreelancerProfileFactory

        # Create profiles with specific titles
        VerifiedFreelancerProfileFactory(professional_title="Full-Stack Developer")
        VerifiedFreelancerProfileFactory(professional_title="Frontend Developer")
        VerifiedFreelancerProfileFactory(professional_title="Backend Developer")
        VerifiedFreelancerProfileFactory(professional_title="UI/UX Designer")

        url = reverse('tenant_profiles:freelancer-profile-list')
        response = api_client.get(url, {'search': 'Developer'})

        assert response.status_code == 200
        assert len(response.data['results']) == 3  # 3 developers

    def test_search_by_skills(self, api_client):
        """Test searching freelancers by skills."""
        from conftest import VerifiedFreelancerProfileFactory

        VerifiedFreelancerProfileFactory(skills=['Python', 'Django', 'React'])
        VerifiedFreelancerProfileFactory(skills=['JavaScript', 'Node.js', 'React'])
        VerifiedFreelancerProfileFactory(skills=['Java', 'Spring', 'MySQL'])

        url = reverse('tenant_profiles:freelancer-profile-list')
        response = api_client.get(url, {'search': 'React'})

        assert response.status_code == 200
        assert len(response.data['results']) == 2  # 2 with React

    def test_order_by_hourly_rate(self, api_client):
        """Test ordering by hourly rate."""
        from conftest import VerifiedFreelancerProfileFactory

        VerifiedFreelancerProfileFactory(hourly_rate=Decimal('50.00'))
        VerifiedFreelancerProfileFactory(hourly_rate=Decimal('100.00'))
        VerifiedFreelancerProfileFactory(hourly_rate=Decimal('75.00'))

        url = reverse('tenant_profiles:freelancer-profile-list')
        response = api_client.get(url, {'ordering': 'hourly_rate'})

        assert response.status_code == 200
        rates = [Decimal(item['hourly_rate']) for item in response.data['results']]
        assert rates == sorted(rates)  # Ascending order

    def test_order_by_average_rating_desc(self, api_client):
        """Test ordering by average rating (descending)."""
        from conftest import VerifiedFreelancerProfileFactory

        VerifiedFreelancerProfileFactory(average_rating=Decimal('4.2'))
        VerifiedFreelancerProfileFactory(average_rating=Decimal('4.8'))
        VerifiedFreelancerProfileFactory(average_rating=Decimal('3.9'))

        url = reverse('tenant_profiles:freelancer-profile-list')
        response = api_client.get(url, {'ordering': '-average_rating'})

        assert response.status_code == 200
        ratings = [item['average_rating'] for item in response.data['results'] if item['average_rating']]
        assert ratings == sorted(ratings, reverse=True)  # Descending


class TestFreelancerProfileRetrieveAPI:
    """Test retrieving individual freelancer profiles."""

    def test_retrieve_freelancer_profile_public(self, api_client):
        """Test anyone can retrieve a freelancer profile."""
        from conftest import VerifiedFreelancerProfileFactory

        profile = VerifiedFreelancerProfileFactory(
            professional_title="Senior Python Developer"
        )

        url = reverse('tenant_profiles:freelancer-profile-detail', args=[profile.uuid])
        response = api_client.get(url)

        assert response.status_code == 200
        assert response.data['professional_title'] == "Senior Python Developer"
        assert response.data['uuid'] == str(profile.uuid)

    def test_retrieve_includes_user_info(self, api_client):
        """Test retrieve includes nested user information."""
        from conftest import VerifiedFreelancerProfileFactory

        profile = VerifiedFreelancerProfileFactory()

        url = reverse('tenant_profiles:freelancer-profile-detail', args=[profile.uuid])
        response = api_client.get(url)

        assert response.status_code == 200
        assert 'user' in response.data
        assert response.data['user']['email'] == profile.user.email

    def test_retrieve_nonexistent_profile_404(self, api_client):
        """Test retrieving non-existent profile returns 404."""
        import uuid

        url = reverse('tenant_profiles:freelancer-profile-detail', args=[uuid.uuid4()])
        response = api_client.get(url)

        assert response.status_code == 404


class TestFreelancerProfileCreateAPI:
    """Test creating freelancer profiles."""

    def test_create_freelancer_profile_requires_auth(self, api_client):
        """Test creating profile requires authentication."""
        url = reverse('tenant_profiles:freelancer-profile-list')
        data = {
            'professional_title': 'Web Developer',
            'bio': 'I build websites',
            'hourly_rate': '75.00',
            'hourly_rate_currency': 'CAD',
            'skills': ['Python', 'Django'],
        }

        response = api_client.post(url, data, format='json')

        assert response.status_code == 401  # Unauthorized

    def test_create_freelancer_profile_authenticated(self, authenticated_client):
        """Test authenticated user can create freelancer profile."""
        client, user = authenticated_client

        url = reverse('tenant_profiles:freelancer-profile-list')
        data = {
            'professional_title': 'Full-Stack Developer',
            'bio': 'Experienced full-stack developer',
            'years_of_experience': 5,
            'hourly_rate': '85.00',
            'hourly_rate_currency': 'USD',
            'availability_hours_per_week': 40,
            'skills': ['Python', 'JavaScript', 'React'],
            'city': 'Toronto',
            'country': 'Canada',
            'remote_only': True,
        }

        response = client.post(url, data, format='json')

        assert response.status_code == 201
        assert response.data['professional_title'] == 'Full-Stack Developer'
        assert response.data['hourly_rate'] == '85.00'

        # Verify profile is linked to user
        from tenant_profiles.models import FreelancerProfile
        profile = FreelancerProfile.objects.get(uuid=response.data['uuid'])
        assert profile.user == user

    def test_create_duplicate_profile_fails(self, authenticated_client):
        """Test user cannot create multiple freelancer profiles."""
        from conftest import FreelancerProfileFactory

        client, user = authenticated_client

        # User already has a profile
        FreelancerProfileFactory(user=user)

        url = reverse('tenant_profiles:freelancer-profile-list')
        data = {
            'professional_title': 'Developer',
            'bio': 'Bio',
            'hourly_rate': '50.00',
        }

        response = client.post(url, data, format='json')

        assert response.status_code == 400
        assert 'already have' in str(response.data).lower()

    def test_create_validates_hourly_rate_positive(self, authenticated_client):
        """Test hourly rate must be positive."""
        client, user = authenticated_client

        url = reverse('tenant_profiles:freelancer-profile-list')
        data = {
            'professional_title': 'Developer',
            'bio': 'Bio',
            'hourly_rate': '0.00',  # Invalid
        }

        response = client.post(url, data, format='json')

        assert response.status_code == 400
        assert 'hourly_rate' in response.data

    def test_create_validates_availability_hours(self, authenticated_client):
        """Test availability hours must be in valid range."""
        client, user = authenticated_client

        url = reverse('tenant_profiles:freelancer-profile-list')
        data = {
            'professional_title': 'Developer',
            'bio': 'Bio',
            'hourly_rate': '50.00',
            'availability_hours_per_week': 200,  # Invalid (> 168)
        }

        response = client.post(url, data, format='json')

        assert response.status_code == 400


class TestFreelancerProfileUpdateAPI:
    """Test updating freelancer profiles."""

    def test_update_own_profile(self, authenticated_client):
        """Test user can update their own profile."""
        from conftest import FreelancerProfileFactory

        client, user = authenticated_client
        profile = FreelancerProfileFactory(user=user, hourly_rate=Decimal('50.00'))

        url = reverse('tenant_profiles:freelancer-profile-detail', args=[profile.uuid])
        data = {
            'hourly_rate': '100.00',
            'bio': 'Updated bio',
        }

        response = client.patch(url, data, format='json')

        assert response.status_code == 200
        profile.refresh_from_db()
        assert profile.hourly_rate == Decimal('100.00')
        assert profile.bio == 'Updated bio'

    def test_cannot_update_other_users_profile(self, authenticated_client):
        """Test user cannot update another user's profile."""
        from conftest import FreelancerProfileFactory, UserFactory

        client, user = authenticated_client
        other_user = UserFactory()
        other_profile = FreelancerProfileFactory(user=other_user)

        url = reverse('tenant_profiles:freelancer-profile-detail', args=[other_profile.uuid])
        data = {'hourly_rate': '999.00'}

        response = client.patch(url, data, format='json')

        assert response.status_code == 403  # Forbidden

    def test_cannot_update_read_only_fields(self, authenticated_client):
        """Test cannot update read-only fields like stats."""
        from conftest import FreelancerProfileFactory

        client, user = authenticated_client
        profile = FreelancerProfileFactory(user=user, completed_projects=5)

        url = reverse('tenant_profiles:freelancer-profile-detail', args=[profile.uuid])
        data = {
            'completed_projects': 999,  # Read-only field
            'is_verified': True,  # Read-only field
        }

        response = client.patch(url, data, format='json')

        # Should succeed but ignore read-only fields
        profile.refresh_from_db()
        assert profile.completed_projects == 5  # Unchanged
        assert profile.is_verified is False  # Unchanged


class TestFreelancerProfileMeAction:
    """Test /me custom action."""

    def test_me_get_own_profile(self, authenticated_client):
        """Test GET /me returns current user's profile."""
        from conftest import FreelancerProfileFactory

        client, user = authenticated_client
        profile = FreelancerProfileFactory(user=user)

        url = reverse('tenant_profiles:freelancer-profile-me')
        response = client.get(url)

        assert response.status_code == 200
        assert response.data['uuid'] == str(profile.uuid)

    def test_me_get_no_profile_returns_404(self, authenticated_client):
        """Test GET /me returns 404 if user has no profile."""
        client, user = authenticated_client

        url = reverse('tenant_profiles:freelancer-profile-me')
        response = client.get(url)

        assert response.status_code == 404

    def test_me_post_creates_profile(self, authenticated_client):
        """Test POST /me creates profile for current user."""
        client, user = authenticated_client

        url = reverse('tenant_profiles:freelancer-profile-me')
        data = {
            'professional_title': 'Backend Developer',
            'bio': 'I love databases',
            'hourly_rate': '60.00',
            'skills': ['Python', 'PostgreSQL'],
        }

        response = client.post(url, data, format='json')

        assert response.status_code == 201
        assert response.data['professional_title'] == 'Backend Developer'

        # Verify profile is linked to user
        from tenant_profiles.models import FreelancerProfile
        assert FreelancerProfile.objects.filter(user=user).exists()

    def test_me_post_duplicate_fails(self, authenticated_client):
        """Test POST /me fails if user already has profile."""
        from conftest import FreelancerProfileFactory

        client, user = authenticated_client
        FreelancerProfileFactory(user=user)

        url = reverse('tenant_profiles:freelancer-profile-me')
        data = {
            'professional_title': 'Developer',
            'bio': 'Bio',
            'hourly_rate': '50.00',
        }

        response = client.post(url, data, format='json')

        assert response.status_code == 400

    def test_me_patch_updates_own_profile(self, authenticated_client):
        """Test PATCH /me updates current user's profile."""
        from conftest import FreelancerProfileFactory

        client, user = authenticated_client
        profile = FreelancerProfileFactory(user=user, bio='Old bio')

        url = reverse('tenant_profiles:freelancer-profile-me')
        data = {'bio': 'New bio'}

        response = client.patch(url, data, format='json')

        assert response.status_code == 200
        profile.refresh_from_db()
        assert profile.bio == 'New bio'


class TestFreelancerProfileCustomActions:
    """Test custom viewset actions."""

    def test_available_action_filters_available_freelancers(self, api_client):
        """Test /available/ action returns only available freelancers."""
        from conftest import (
            VerifiedFreelancerProfileFactory,
            BusyFreelancerProfileFactory
        )

        # Create available
        VerifiedFreelancerProfileFactory.create_batch(6, availability_status='available')

        # Create busy
        BusyFreelancerProfileFactory.create_batch(4)

        # Create unavailable
        VerifiedFreelancerProfileFactory.create_batch(2, availability_status='unavailable')

        url = reverse('tenant_profiles:freelancer-profile-available')
        response = api_client.get(url)

        assert response.status_code == 200
        assert len(response.data['results']) == 6  # Only available

    def test_verified_action_filters_verified_freelancers(self, api_client):
        """Test /verified/ action returns only verified freelancers."""
        from conftest import FreelancerProfileFactory, VerifiedFreelancerProfileFactory

        # Create unverified
        FreelancerProfileFactory.create_batch(5, is_verified=False)

        # Create verified
        VerifiedFreelancerProfileFactory.create_batch(8)

        url = reverse('tenant_profiles:freelancer-profile-verified')
        response = api_client.get(url)

        assert response.status_code == 200
        assert len(response.data['results']) == 8  # Only verified
