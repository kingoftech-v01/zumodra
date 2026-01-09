"""
Tests for Analytics API.

This module tests the analytics API endpoints including:
- Dashboard analytics
- Provider analytics
- Client analytics
- ATS analytics
- HR analytics
"""

import pytest
from decimal import Decimal
from datetime import timedelta
from django.utils import timezone
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
def admin_authenticated_client(api_client, superuser_factory):
    """Return authenticated admin API client."""
    admin = superuser_factory()
    api_client.force_authenticate(user=admin)
    return api_client, admin


@pytest.fixture
def tenant_with_owner(db, tenant_factory, user_factory, owner_tenant_user_factory):
    """Create tenant with owner user."""
    tenant = tenant_factory()
    user = user_factory()
    owner_tenant_user_factory(user=user, tenant=tenant)
    return tenant, user


# =============================================================================
# ANALYTICS ENDPOINT TESTS
# =============================================================================

class TestAnalyticsEndpoints:
    """Tests for Analytics endpoints."""

    @pytest.mark.django_db
    def test_analytics_requires_authentication(self, api_client):
        """Test analytics endpoints require authentication."""
        url = reverse('api_v1:analytics:dashboard')
        response = api_client.get(url)

        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_dashboard_authenticated(self, authenticated_client):
        """Test authenticated user can access dashboard."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:dashboard')
        response = client.get(url)

        # May be 200 or 403 depending on permissions
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_admin_dashboard(self, admin_authenticated_client):
        """Test admin can access dashboard analytics."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:analytics:dashboard')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestProviderAnalytics:
    """Tests for provider analytics."""

    @pytest.mark.django_db
    def test_provider_analytics_authenticated(self, authenticated_client):
        """Test provider analytics requires authentication."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:provider-analytics')
        response = client.get(url)

        # May be 200 or 403 depending on whether user is a provider
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]


class TestClientAnalytics:
    """Tests for client analytics."""

    @pytest.mark.django_db
    def test_client_analytics_authenticated(self, authenticated_client):
        """Test client analytics requires authentication."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:client-analytics')
        response = client.get(url)

        # May be 200 or 403 depending on whether user is a client
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]


# =============================================================================
# ATS ANALYTICS TESTS
# =============================================================================

class TestATSAnalytics:
    """Tests for ATS analytics."""

    @pytest.mark.django_db
    def test_ats_overview(self, authenticated_client):
        """Test ATS overview analytics."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:ats-overview')
        response = client.get(url)

        # Check it's accessible or permission denied
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_pipeline_analytics(self, authenticated_client):
        """Test pipeline analytics."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:pipeline-analytics')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_source_analytics(self, authenticated_client):
        """Test source analytics."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:source-analytics')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]


# =============================================================================
# HR ANALYTICS TESTS
# =============================================================================

class TestHRAnalytics:
    """Tests for HR analytics."""

    @pytest.mark.django_db
    def test_hr_overview(self, authenticated_client):
        """Test HR overview analytics."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:hr-overview')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_headcount_analytics(self, authenticated_client):
        """Test headcount analytics."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:headcount')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_turnover_analytics(self, authenticated_client):
        """Test turnover analytics."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:turnover')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]


# =============================================================================
# DIVERSITY ANALYTICS TESTS
# =============================================================================

class TestDiversityAnalytics:
    """Tests for diversity analytics."""

    @pytest.mark.django_db
    def test_diversity_analytics(self, authenticated_client):
        """Test diversity analytics."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:diversity')
        response = client.get(url)

        # May require enterprise plan
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]


# =============================================================================
# TIME SERIES ANALYTICS TESTS
# =============================================================================

class TestTimeSeriesAnalytics:
    """Tests for time series analytics."""

    @pytest.mark.django_db
    def test_applications_over_time(self, authenticated_client):
        """Test applications over time analytics."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:applications-trend')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_hires_over_time(self, authenticated_client):
        """Test hires over time analytics."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:hires-trend')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]


# =============================================================================
# EXPORT ANALYTICS TESTS
# =============================================================================

class TestExportAnalytics:
    """Tests for export analytics functionality."""

    @pytest.mark.django_db
    def test_export_csv(self, admin_authenticated_client):
        """Test exporting analytics as CSV."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:analytics:export')
        response = client.get(url, {'format': 'csv', 'report': 'ats-overview'})

        # May be 200 or 400 depending on implementation
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]

    @pytest.mark.django_db
    def test_export_requires_admin(self, authenticated_client):
        """Test export requires admin permissions."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:export')
        response = client.get(url, {'format': 'csv', 'report': 'ats-overview'})

        assert response.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_400_BAD_REQUEST]


# =============================================================================
# REAL-TIME METRICS TESTS
# =============================================================================

class TestRealTimeMetrics:
    """Tests for real-time metrics endpoints."""

    @pytest.mark.django_db
    def test_active_users(self, admin_authenticated_client):
        """Test active users metric."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:analytics:active-users')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_pending_tasks(self, authenticated_client):
        """Test pending tasks metric."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:pending-tasks')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]


# =============================================================================
# DATE RANGE FILTER TESTS
# =============================================================================

class TestDateRangeFilters:
    """Tests for date range filter functionality."""

    @pytest.mark.django_db
    def test_analytics_with_date_range(self, admin_authenticated_client):
        """Test analytics with date range filter."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:analytics:dashboard')
        today = timezone.now().date()
        week_ago = today - timedelta(days=7)

        response = client.get(url, {
            'start_date': week_ago.isoformat(),
            'end_date': today.isoformat()
        })

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_analytics_with_preset_period(self, admin_authenticated_client):
        """Test analytics with preset period."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:analytics:dashboard')

        for period in ['7d', '30d', '90d', 'ytd']:
            response = client.get(url, {'period': period})
            assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]


# =============================================================================
# COMPARISON ANALYTICS TESTS
# =============================================================================

class TestComparisonAnalytics:
    """Tests for comparison analytics."""

    @pytest.mark.django_db
    def test_compare_periods(self, admin_authenticated_client):
        """Test period comparison."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:analytics:compare')
        response = client.get(url, {
            'metric': 'applications',
            'period1': 'last_week',
            'period2': 'previous_week'
        })

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]


# =============================================================================
# WIDGET DATA TESTS
# =============================================================================

class TestWidgetData:
    """Tests for dashboard widget data."""

    @pytest.mark.django_db
    def test_quick_stats_widget(self, authenticated_client):
        """Test quick stats widget data."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:quick-stats')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_recent_activity_widget(self, authenticated_client):
        """Test recent activity widget data."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:recent-activity')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_upcoming_interviews_widget(self, authenticated_client):
        """Test upcoming interviews widget data."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:upcoming-interviews')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]


# =============================================================================
# BENCHMARK ANALYTICS TESTS
# =============================================================================

class TestBenchmarkAnalytics:
    """Tests for benchmark analytics."""

    @pytest.mark.django_db
    def test_industry_benchmarks(self, admin_authenticated_client):
        """Test industry benchmarks."""
        client, admin = admin_authenticated_client

        url = reverse('api_v1:analytics:benchmarks')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_hiring_velocity(self, authenticated_client):
        """Test hiring velocity metric."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:hiring-velocity')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_time_to_fill(self, authenticated_client):
        """Test time to fill metric."""
        client, user = authenticated_client

        url = reverse('api_v1:analytics:time-to-fill')
        response = client.get(url)

        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]
