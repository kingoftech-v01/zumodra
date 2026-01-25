"""
Tests for Services Marketplace API.

This module tests the services API endpoints including:
- Categories and tags
- Service providers
- Services CRUD
- Client requests
- Proposals
- Contracts
- Reviews
"""

import pytest
from decimal import Decimal
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from services.models import (
    ServiceCategory, ServiceTag, ServiceProvider, Service,
    ClientRequest, ServiceProposal, ServiceContract, ServiceReview
)


@pytest.fixture
def api_client():
    """Return API client."""
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, user_factory):
    """Return authenticated API client."""
    user = user_factory()
    api_client.force_authenticate(user=user)
    return api_client, user


@pytest.fixture
def service_category(db):
    """Create test service category."""
    return ServiceCategory.objects.create(
        name='Test Category',
        slug='test-category',
        description='Test category description'
    )


@pytest.fixture
def service_tag(db):
    """Create test service tag."""
    return ServiceTag.objects.create(
        name='Test Tag',
        slug='test-tag'
    )


@pytest.fixture
def service_provider(db, user_factory, tenant_factory):
    """Create test service provider."""
    user = user_factory()
    tenant = tenant_factory()
    return ServiceProvider.objects.create(
        user=user,
        tenant=tenant,
        business_name='Test Provider',
        description='Test provider description',
        hourly_rate=Decimal('50.00'),
        is_verified=True,
        is_active=True
    )


@pytest.fixture
def service(db, service_category, service_provider):
    """Create test service."""
    return Service.objects.create(
        provider=service_provider,
        category=service_category,
        title='Test Service',
        description='Test service description',
        price=Decimal('100.00'),
        price_type='fixed',
        status='active'
    )


class TestServiceCategoryViewSet:
    """Tests for ServiceCategoryViewSet."""

    @pytest.mark.django_db
    def test_list_categories(self, api_client, service_category):
        """Test listing service categories."""
        url = reverse('services-api:category-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 1

    @pytest.mark.django_db
    def test_retrieve_category(self, api_client, service_category):
        """Test retrieving single category."""
        url = reverse('services-api:category-detail', args=[service_category.id])
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['name'] == service_category.name


class TestServiceTagViewSet:
    """Tests for ServiceTagViewSet."""

    @pytest.mark.django_db
    def test_list_tags(self, api_client, service_tag):
        """Test listing service tags."""
        url = reverse('services-api:tag-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestServiceProviderViewSet:
    """Tests for ServiceProviderViewSet."""

    @pytest.mark.django_db
    def test_list_providers(self, api_client, service_provider):
        """Test listing service providers."""
        url = reverse('services-api:provider-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_retrieve_provider(self, api_client, service_provider):
        """Test retrieving single provider."""
        url = reverse('services-api:provider-detail', args=[service_provider.id])
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['business_name'] == service_provider.business_name

    @pytest.mark.django_db
    def test_provider_stats_action(self, authenticated_client, service_provider):
        """Test provider stats endpoint."""
        client, user = authenticated_client
        # Set provider to the authenticated user
        service_provider.user = user
        service_provider.save()

        url = reverse('services-api:provider-stats', args=[service_provider.id])
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestServiceViewSet:
    """Tests for ServiceViewSet."""

    @pytest.mark.django_db
    def test_list_services(self, api_client, service):
        """Test listing services."""
        url = reverse('services-api:service-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_retrieve_service(self, api_client, service):
        """Test retrieving single service."""
        url = reverse('services-api:service-detail', args=[service.id])
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['title'] == service.title

    @pytest.mark.django_db
    def test_filter_services_by_category(self, api_client, service):
        """Test filtering services by category."""
        url = reverse('services-api:service-list')
        response = api_client.get(url, {'category': service.category.id})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_search_services(self, api_client, service):
        """Test searching services."""
        url = reverse('services-api:service-list')
        response = api_client.get(url, {'search': 'Test'})

        assert response.status_code == status.HTTP_200_OK


class TestClientRequestViewSet:
    """Tests for ClientRequestViewSet."""

    @pytest.mark.django_db
    def test_list_requests_authenticated(self, authenticated_client):
        """Test listing client requests requires authentication."""
        client, user = authenticated_client
        url = reverse('services-api:request-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_list_requests_unauthenticated(self, api_client):
        """Test listing client requests fails without authentication."""
        url = reverse('services-api:request-list')
        response = api_client.get(url)

        # Should require authentication
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]


class TestServiceProposalViewSet:
    """Tests for ServiceProposalViewSet."""

    @pytest.mark.django_db
    def test_list_proposals_authenticated(self, authenticated_client):
        """Test listing proposals requires authentication."""
        client, user = authenticated_client
        url = reverse('services-api:proposal-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestServiceContractViewSet:
    """Tests for ServiceContractViewSet."""

    @pytest.mark.django_db
    def test_list_contracts_authenticated(self, authenticated_client):
        """Test listing contracts requires authentication."""
        client, user = authenticated_client
        url = reverse('services-api:contract-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestServiceReviewViewSet:
    """Tests for ServiceReviewViewSet."""

    @pytest.mark.django_db
    def test_list_reviews(self, api_client):
        """Test listing reviews is public."""
        url = reverse('services-api:review-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestMarketplaceAnalyticsView:
    """Tests for MarketplaceAnalyticsView."""

    @pytest.mark.django_db
    def test_analytics_requires_auth(self, api_client):
        """Test analytics requires admin authentication."""
        url = reverse('services-api:analytics')
        response = api_client.get(url)

        # Should require authentication
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]
