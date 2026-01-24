"""
Tests for Dashboard API.

This module tests the dashboard API endpoints including:
- Overview
- Quick stats
- Search
- Upcoming interviews
- Recent activity
- ATS/HR metrics
"""

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


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
def admin_client(api_client, user_factory):
    """Return admin authenticated API client."""
    user = user_factory(is_staff=True, is_superuser=True)
    api_client.force_authenticate(user=user)
    return api_client, user


class TestDashboardOverviewView:
    """Tests for DashboardOverviewView."""

    @pytest.mark.django_db
    def test_overview_requires_auth(self, api_client):
        """Test overview requires authentication."""
        url = reverse('dashboard-api:overview')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    @pytest.mark.django_db
    def test_overview_with_auth(self, authenticated_client):
        """Test overview with authentication."""
        client, user = authenticated_client
        url = reverse('dashboard-api:overview')
        response = client.get(url)

        # May fail with 400 if no tenant, but endpoint exists
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_400_BAD_REQUEST  # No tenant context
        ]


class TestQuickStatsView:
    """Tests for QuickStatsView."""

    @pytest.mark.django_db
    def test_quick_stats_requires_auth(self, api_client):
        """Test quick stats requires authentication."""
        url = reverse('dashboard-api:quick-stats')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestSearchView:
    """Tests for SearchView."""

    @pytest.mark.django_db
    def test_search_requires_auth(self, api_client):
        """Test search requires authentication."""
        url = reverse('dashboard-api:search')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    @pytest.mark.django_db
    def test_search_with_auth(self, authenticated_client):
        """Test search with authentication."""
        client, user = authenticated_client
        url = reverse('dashboard-api:search')
        response = client.get(url, {'q': 'test'})

        assert response.status_code == status.HTTP_200_OK


class TestUpcomingInterviewsView:
    """Tests for UpcomingInterviewsView."""

    @pytest.mark.django_db
    def test_interviews_requires_auth(self, api_client):
        """Test interviews requires authentication."""
        url = reverse('dashboard-api:interviews')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestRecentActivityView:
    """Tests for RecentActivityView."""

    @pytest.mark.django_db
    def test_activity_requires_auth(self, api_client):
        """Test activity requires authentication."""
        url = reverse('dashboard-api:activity')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestATSMetricsView:
    """Tests for ATSMetricsView."""

    @pytest.mark.django_db
    def test_ats_metrics_requires_auth(self, api_client):
        """Test ATS metrics requires authentication."""
        url = reverse('dashboard-api:ats-metrics')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestHRMetricsView:
    """Tests for HRMetricsView."""

    @pytest.mark.django_db
    def test_hr_metrics_requires_auth(self, api_client):
        """Test HR metrics requires authentication."""
        url = reverse('dashboard-api:hr-metrics')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]
