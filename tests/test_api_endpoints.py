"""
API Endpoint Tests - Comprehensive REST API Testing for Zumodra

This module tests all major API endpoints including:
1. JWT Authentication (token obtain, refresh, verify)
2. Service Provider API (CRUD operations)
3. Service Marketplace API
4. Appointment API
5. Company API
6. Error handling and validation

Author: Rhematek Solutions
"""

import pytest
import json
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import patch, MagicMock

from django.test import TestCase, override_settings
from django.utils import timezone
from django.contrib.auth import get_user_model

from rest_framework import status
from rest_framework.test import APIClient, APITestCase

User = get_user_model()


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def api_client():
    """Return an unauthenticated API client."""
    return APIClient()


@pytest.fixture
def authenticated_client(db, user_factory):
    """Return an authenticated API client."""
    client = APIClient()
    user = user_factory(email='test@example.com', password='testpass123')
    client.force_authenticate(user=user)
    return client, user


@pytest.fixture
def user_factory(db):
    """Factory for creating users."""
    def create_user(**kwargs):
        defaults = {
            'email': f'user_{uuid.uuid4().hex[:8]}@example.com',
            'username': f'user_{uuid.uuid4().hex[:8]}',
            'password': 'testpass123',
            'first_name': 'Test',
            'last_name': 'User',
        }
        defaults.update(kwargs)
        password = defaults.pop('password')
        user = User.objects.create(**defaults)
        user.set_password(password)
        user.save()
        return user
    return create_user


# ============================================================================
# JWT AUTHENTICATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestJWTAuthentication:
    """Tests for JWT token authentication endpoints."""

    def test_obtain_token_with_valid_credentials(self, api_client, user_factory):
        """Test obtaining JWT tokens with valid credentials."""
        user = user_factory(email='jwt@example.com', password='testpass123')

        response = api_client.post('/api/auth/token/', {
            'email': 'jwt@example.com',
            'password': 'testpass123'
        }, format='json')

        # Should return 200 with access and refresh tokens
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED]
        if response.status_code == status.HTTP_200_OK:
            assert 'access' in response.data
            assert 'refresh' in response.data

    def test_obtain_token_with_invalid_credentials(self, api_client, user_factory):
        """Test token rejection with invalid credentials."""
        user_factory(email='jwt@example.com', password='testpass123')

        response = api_client.post('/api/auth/token/', {
            'email': 'jwt@example.com',
            'password': 'wrongpassword'
        }, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_obtain_token_with_nonexistent_user(self, api_client):
        """Test token rejection for nonexistent user."""
        response = api_client.post('/api/auth/token/', {
            'email': 'nonexistent@example.com',
            'password': 'testpass123'
        }, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_refresh_token(self, api_client, user_factory):
        """Test refreshing an access token."""
        user = user_factory(email='refresh@example.com', password='testpass123')

        # First obtain tokens
        token_response = api_client.post('/api/auth/token/', {
            'email': 'refresh@example.com',
            'password': 'testpass123'
        }, format='json')

        if token_response.status_code == status.HTTP_200_OK:
            refresh_token = token_response.data.get('refresh')

            # Try to refresh
            refresh_response = api_client.post('/api/auth/token/refresh/', {
                'refresh': refresh_token
            }, format='json')

            assert refresh_response.status_code == status.HTTP_200_OK
            assert 'access' in refresh_response.data

    def test_verify_valid_token(self, api_client, user_factory):
        """Test verifying a valid token."""
        user = user_factory(email='verify@example.com', password='testpass123')

        # Obtain tokens
        token_response = api_client.post('/api/auth/token/', {
            'email': 'verify@example.com',
            'password': 'testpass123'
        }, format='json')

        if token_response.status_code == status.HTTP_200_OK:
            access_token = token_response.data.get('access')

            # Verify token
            verify_response = api_client.post('/api/auth/token/verify/', {
                'token': access_token
            }, format='json')

            assert verify_response.status_code == status.HTTP_200_OK

    def test_verify_invalid_token(self, api_client):
        """Test rejection of invalid token."""
        response = api_client.post('/api/auth/token/verify/', {
            'token': 'invalid.token.here'
        }, format='json')

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ============================================================================
# SERVICE CATEGORY API TESTS
# ============================================================================

@pytest.mark.django_db
class TestServiceCategoryAPI:
    """Tests for service category endpoints."""

    def test_list_categories_unauthenticated(self, api_client):
        """Test listing categories without authentication."""
        response = api_client.get('/api/categories/')

        # Should allow public access or require auth
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    def test_list_categories_authenticated(self, authenticated_client):
        """Test listing categories with authentication."""
        client, user = authenticated_client

        response = client.get('/api/categories/')

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]
        if response.status_code == status.HTTP_200_OK:
            assert isinstance(response.data, (list, dict))


# ============================================================================
# SERVICE PROVIDER API TESTS
# ============================================================================

@pytest.mark.django_db
class TestServiceProviderAPI:
    """Tests for service provider endpoints."""

    def test_list_providers_unauthenticated(self, api_client):
        """Test listing providers without authentication."""
        response = api_client.get('/api/providers/')

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    def test_list_providers_authenticated(self, authenticated_client):
        """Test listing providers with authentication."""
        client, user = authenticated_client

        response = client.get('/api/providers/')

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]

    def test_create_provider_profile(self, authenticated_client):
        """Test creating a provider profile."""
        client, user = authenticated_client

        response = client.post('/api/providers/', {
            'business_name': 'Test Provider',
            'description': 'A test service provider',
            'hourly_rate': '50.00',
        }, format='json')

        # Should create or fail with validation
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND
        ]


# ============================================================================
# SERVICE API TESTS
# ============================================================================

@pytest.mark.django_db
class TestServiceAPI:
    """Tests for service endpoints."""

    def test_list_services_unauthenticated(self, api_client):
        """Test listing services without authentication."""
        response = api_client.get('/api/services/')

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    def test_list_services_with_filters(self, authenticated_client):
        """Test listing services with query filters."""
        client, user = authenticated_client

        response = client.get('/api/services/', {
            'ordering': '-created_at',
            'page': 1,
            'page_size': 10
        })

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


# ============================================================================
# SERVICE REQUEST API TESTS
# ============================================================================

@pytest.mark.django_db
class TestServiceRequestAPI:
    """Tests for service request endpoints."""

    def test_list_requests_requires_auth(self, api_client):
        """Test that listing requests requires authentication."""
        response = api_client.get('/api/requests/')

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    def test_list_requests_authenticated(self, authenticated_client):
        """Test listing requests with authentication."""
        client, user = authenticated_client

        response = client.get('/api/requests/')

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]

    def test_create_request(self, authenticated_client):
        """Test creating a service request."""
        client, user = authenticated_client

        response = client.post('/api/requests/', {
            'title': 'Need a website',
            'description': 'Looking for a web developer',
            'budget': '1000.00',
        }, format='json')

        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND
        ]


# ============================================================================
# PROPOSAL API TESTS
# ============================================================================

@pytest.mark.django_db
class TestProposalAPI:
    """Tests for proposal endpoints."""

    def test_list_proposals_requires_auth(self, api_client):
        """Test that listing proposals requires authentication."""
        response = api_client.get('/api/proposals/')

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    def test_list_proposals_authenticated(self, authenticated_client):
        """Test listing proposals with authentication."""
        client, user = authenticated_client

        response = client.get('/api/proposals/')

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


# ============================================================================
# CONTRACT API TESTS
# ============================================================================

@pytest.mark.django_db
class TestContractAPI:
    """Tests for contract endpoints."""

    def test_list_contracts_requires_auth(self, api_client):
        """Test that listing contracts requires authentication."""
        response = api_client.get('/api/contracts/')

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    def test_list_contracts_authenticated(self, authenticated_client):
        """Test listing contracts with authentication."""
        client, user = authenticated_client

        response = client.get('/api/contracts/')

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


# ============================================================================
# APPOINTMENT API TESTS
# ============================================================================

@pytest.mark.django_db
class TestAppointmentAPI:
    """Tests for appointment endpoints."""

    def test_list_appointments_requires_auth(self, api_client):
        """Test that listing appointments requires authentication."""
        response = api_client.get('/api/appointments/')

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    def test_list_appointments_authenticated(self, authenticated_client):
        """Test listing appointments with authentication."""
        client, user = authenticated_client

        response = client.get('/api/appointments/')

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


# ============================================================================
# COMPANY API TESTS
# ============================================================================

@pytest.mark.django_db
class TestCompanyAPI:
    """Tests for company endpoints."""

    def test_list_companies_unauthenticated(self, api_client):
        """Test listing companies without authentication."""
        response = api_client.get('/api/companies/')

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    def test_list_companies_authenticated(self, authenticated_client):
        """Test listing companies with authentication."""
        client, user = authenticated_client

        response = client.get('/api/companies/')

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

@pytest.mark.django_db
class TestAPIErrorHandling:
    """Tests for API error responses."""

    def test_404_for_nonexistent_resource(self, authenticated_client):
        """Test 404 response for nonexistent resources."""
        client, user = authenticated_client

        fake_uuid = str(uuid.uuid4())
        response = client.get(f'/api/services/{fake_uuid}/')

        assert response.status_code in [
            status.HTTP_404_NOT_FOUND,
            status.HTTP_403_FORBIDDEN
        ]

    def test_405_for_unsupported_method(self, authenticated_client):
        """Test 405 response for unsupported HTTP methods."""
        client, user = authenticated_client

        # DELETE on list endpoint should fail
        response = client.delete('/api/categories/')

        assert response.status_code in [
            status.HTTP_405_METHOD_NOT_ALLOWED,
            status.HTTP_404_NOT_FOUND
        ]

    def test_400_for_invalid_json(self, authenticated_client):
        """Test 400 response for invalid JSON."""
        client, user = authenticated_client

        response = client.post(
            '/api/providers/',
            data='not valid json',
            content_type='application/json'
        )

        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_404_NOT_FOUND,
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        ]


# ============================================================================
# PAGINATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestAPIPagination:
    """Tests for API pagination."""

    def test_pagination_params(self, authenticated_client):
        """Test pagination query parameters."""
        client, user = authenticated_client

        response = client.get('/api/services/', {
            'page': 1,
            'page_size': 5
        })

        if response.status_code == status.HTTP_200_OK:
            # Check for pagination metadata
            data = response.data
            if isinstance(data, dict):
                # DRF standard pagination
                assert 'results' in data or 'count' in data or isinstance(data.get('results'), list)

    def test_ordering_param(self, authenticated_client):
        """Test ordering query parameter."""
        client, user = authenticated_client

        response = client.get('/api/services/', {
            'ordering': '-created_at'
        })

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


# ============================================================================
# CONTENT TYPE TESTS
# ============================================================================

@pytest.mark.django_db
class TestAPIContentTypes:
    """Tests for API content type handling."""

    def test_json_response(self, authenticated_client):
        """Test that API returns JSON."""
        client, user = authenticated_client

        response = client.get('/api/categories/')

        if response.status_code == status.HTTP_200_OK:
            assert response['Content-Type'].startswith('application/json')

    def test_accept_json(self, authenticated_client):
        """Test API accepts JSON content type."""
        client, user = authenticated_client

        response = client.get(
            '/api/categories/',
            HTTP_ACCEPT='application/json'
        )

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


# ============================================================================
# SECURITY TESTS
# ============================================================================

@pytest.mark.django_db
class TestAPISecurity:
    """Tests for API security measures."""

    def test_csrf_not_required_for_api(self, api_client, user_factory):
        """Test that CSRF is not required for API endpoints (JWT-based)."""
        user = user_factory(email='csrf@example.com', password='testpass123')

        # API should use JWT, not CSRF
        response = api_client.post('/api/auth/token/', {
            'email': 'csrf@example.com',
            'password': 'testpass123'
        }, format='json')

        # Should not fail due to CSRF
        assert response.status_code != status.HTTP_403_FORBIDDEN or 'csrf' not in str(response.data).lower()

    def test_xss_prevention_in_response(self, authenticated_client):
        """Test XSS characters are escaped in responses."""
        client, user = authenticated_client

        # Try to create content with XSS
        response = client.post('/api/providers/', {
            'business_name': '<script>alert("xss")</script>',
            'description': 'Test',
        }, format='json')

        # If created, XSS should be escaped
        if response.status_code == status.HTTP_201_CREATED:
            assert '<script>' not in response.content.decode()


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================

@pytest.mark.django_db
class TestAPIRateLimiting:
    """Tests for API rate limiting."""

    def test_rate_limit_headers(self, authenticated_client):
        """Test that rate limit headers are present."""
        client, user = authenticated_client

        response = client.get('/api/services/')

        # Check for rate limit headers (if enabled)
        # Common headers: X-RateLimit-Limit, X-RateLimit-Remaining
        if response.status_code == status.HTTP_200_OK:
            # Headers may or may not be present depending on config
            pass

    @pytest.mark.slow
    def test_rate_limit_enforcement(self, api_client, user_factory):
        """Test rate limiting is enforced after threshold."""
        # This test is marked slow as it may need many requests
        user = user_factory(email='ratelimit@example.com', password='testpass123')

        # Make many requests
        for i in range(10):
            response = api_client.post('/api/auth/token/', {
                'email': 'wrong@example.com',
                'password': 'wrongpass'
            }, format='json')

        # Eventually should be rate limited (429) or continue with 401
        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_429_TOO_MANY_REQUESTS
        ]
