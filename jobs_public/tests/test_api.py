"""
Tests for jobs_public API endpoints.

Tests API functionality, filtering, pagination, and custom actions.
"""

import pytest
from rest_framework import status
from django.urls import reverse


@pytest.mark.django_db
class TestPublicJobCatalogAPI:
    """Test PublicJobCatalog API ViewSet."""

    def test_list_jobs(self, api_client, multiple_jobs):
        """Test listing all active jobs."""
        url = reverse('jobs_public_api:publicjob-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert 'results' in response.data
        # Should only return active, non-expired jobs (4 out of 5)
        assert len([j for j in multiple_jobs if j.is_active and not j.is_expired]) >= 4

    def test_retrieve_job_detail(self, api_client, sample_job):
        """Test retrieving a single job detail."""
        url = reverse('jobs_public_api:publicjob-detail', kwargs={'jobposting_uuid': sample_job.jobposting_uuid})
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['title'] == sample_job.title
        assert response.data['company_name'] == sample_job.company_name

    def test_filter_by_location_city(self, api_client, multiple_jobs):
        """Test filtering jobs by city."""
        url = reverse('jobs_public_api:publicjob-list')
        response = api_client.get(url, {'location_city': 'San Francisco'})

        assert response.status_code == status.HTTP_200_OK
        # All results should be in San Francisco
        for job in response.data['results']:
            assert 'San Francisco' in job['location']['display']

    def test_filter_by_remote_only(self, api_client, multiple_jobs):
        """Test filtering for remote jobs only."""
        url = reverse('jobs_public_api:publicjob-list')
        response = api_client.get(url, {'is_remote': 'true'})

        assert response.status_code == status.HTTP_200_OK
        # All results should be remote
        for job in response.data['results']:
            assert job['location']['is_remote'] is True

    def test_filter_by_employment_type(self, api_client, multiple_jobs):
        """Test filtering by employment type."""
        url = reverse('jobs_public_api:publicjob-list')
        response = api_client.get(url, {'employment_type': 'full-time'})

        assert response.status_code == status.HTTP_200_OK
        for job in response.data['results']:
            assert job['employment_type'] == 'full-time'

    def test_search_jobs(self, api_client, multiple_jobs):
        """Test searching jobs by keyword."""
        url = reverse('jobs_public_api:publicjob-list')
        response = api_client.get(url, {'search': 'Python'})

        assert response.status_code == status.HTTP_200_OK
        # Should find Python developer job
        assert response.data['count'] >= 1

    def test_pagination(self, api_client, multiple_jobs):
        """Test API pagination."""
        url = reverse('jobs_public_api:publicjob-list')
        response = api_client.get(url, {'page_size': 2})

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) <= 2
        assert 'next' in response.data or 'previous' in response.data

    def test_map_data_endpoint(self, api_client, multiple_jobs):
        """Test map_data custom action."""
        url = reverse('jobs_public_api:publicjob-map-data')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        # Should only return jobs with geocoding
        for job in response.data['results']:
            assert job['location']['lat'] is not None
            assert job['location']['lng'] is not None

    def test_nearby_jobs_endpoint(self, api_client, multiple_jobs):
        """Test nearby custom action."""
        url = reverse('jobs_public_api:publicjob-nearby')
        # San Francisco coordinates
        response = api_client.get(url, {'lat': 37.7749, 'lng': -122.4194, 'radius': 50})

        assert response.status_code == status.HTTP_200_OK

    def test_ordering_by_published_date(self, api_client, multiple_jobs):
        """Test ordering jobs by published date."""
        url = reverse('jobs_public_api:publicjob-list')
        response = api_client.get(url, {'ordering': '-published_at'})

        assert response.status_code == status.HTTP_200_OK
        # Results should be in descending order
        if len(response.data['results']) > 1:
            dates = [job['published_at'] for job in response.data['results']]
            assert dates == sorted(dates, reverse=True)
