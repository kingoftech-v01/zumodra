"""
Tests for Appointment API.

This module tests the appointment API endpoints including:
- Services
- Staff members
- Appointments
- Working hours
- Days off
- Config
"""

import pytest
from datetime import date, time, timedelta
from decimal import Decimal
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


class TestServiceViewSet:
    """Tests for Appointment ServiceViewSet."""

    @pytest.mark.django_db
    def test_list_services_public(self, api_client):
        """Test listing services is public."""
        url = reverse('interviews-api:service-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_create_service_requires_admin(self, api_client):
        """Test creating service requires admin."""
        url = reverse('interviews-api:service-list')
        data = {
            'name': 'Test Service',
            'duration': '00:30:00',
            'price': '50.00'
        }
        response = api_client.post(url, data)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestStaffMemberViewSet:
    """Tests for StaffMemberViewSet."""

    @pytest.mark.django_db
    def test_list_staff_public(self, api_client):
        """Test listing staff is public."""
        url = reverse('interviews-api:staff-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_create_staff_requires_admin(self, api_client):
        """Test creating staff requires admin."""
        url = reverse('interviews-api:staff-list')
        data = {'user': 1}
        response = api_client.post(url, data)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestWorkingHoursViewSet:
    """Tests for WorkingHoursViewSet."""

    @pytest.mark.django_db
    def test_list_working_hours_requires_admin(self, api_client):
        """Test listing working hours requires admin."""
        url = reverse('interviews-api:working-hours-list')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    @pytest.mark.django_db
    def test_list_working_hours_with_admin(self, admin_client):
        """Test listing working hours with admin."""
        client, user = admin_client
        url = reverse('interviews-api:working-hours-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestDayOffViewSet:
    """Tests for DayOffViewSet."""

    @pytest.mark.django_db
    def test_list_days_off_requires_admin(self, api_client):
        """Test listing days off requires admin."""
        url = reverse('interviews-api:days-off-list')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestAppointmentViewSet:
    """Tests for AppointmentViewSet."""

    @pytest.mark.django_db
    def test_list_appointments_requires_auth(self, api_client):
        """Test listing appointments requires authentication."""
        url = reverse('interviews-api:appointment-list')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    @pytest.mark.django_db
    def test_list_appointments_with_auth(self, authenticated_client):
        """Test listing appointments with authentication."""
        client, user = authenticated_client
        url = reverse('interviews-api:appointment-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_my_appointments(self, authenticated_client):
        """Test my appointments endpoint."""
        client, user = authenticated_client
        url = reverse('interviews-api:appointment-my-appointments')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK


class TestConfigViewSet:
    """Tests for ConfigViewSet."""

    @pytest.mark.django_db
    def test_config_requires_admin(self, api_client):
        """Test config requires admin."""
        url = reverse('interviews-api:config-list')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]


class TestBookingView:
    """Tests for BookingView."""

    @pytest.mark.django_db
    def test_booking_endpoint_exists(self, api_client):
        """Test booking endpoint exists."""
        url = reverse('interviews-api:book')
        response = api_client.post(url, {})

        # Will fail validation but endpoint should exist
        assert response.status_code == status.HTTP_400_BAD_REQUEST


class TestAppointmentStatsView:
    """Tests for AppointmentStatsView."""

    @pytest.mark.django_db
    def test_stats_requires_admin(self, api_client):
        """Test stats requires admin."""
        url = reverse('interviews-api:stats')
        response = api_client.get(url)

        assert response.status_code in [
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN
        ]

    @pytest.mark.django_db
    def test_stats_with_admin(self, admin_client):
        """Test stats with admin."""
        client, user = admin_client
        url = reverse('interviews-api:stats')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK
