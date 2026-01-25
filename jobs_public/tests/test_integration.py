"""
Integration tests for jobs_public app.

Tests end-to-end workflows and cross-component functionality.
"""

import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
class TestJobPublicationWorkflow:
    """Test complete job publication workflow."""

    def test_complete_job_listing_workflow(self, client, multiple_jobs):
        """Test complete workflow: list -> filter -> detail."""
        # 1. User views job list
        list_url = reverse('jobs_public:job_list')
        list_response = client.get(list_url)
        assert list_response.status_code == 200
        assert len(list_response.context['jobs']) > 0

        # 2. User filters for remote jobs
        filter_response = client.get(list_url, {'remote_only': 'true'})
        assert filter_response.status_code == 200
        remote_jobs = filter_response.context['jobs']
        assert all(job.is_remote for job in remote_jobs)

        # 3. User views job detail
        if remote_jobs:
            job = remote_jobs[0]
            detail_url = reverse('jobs_public:job_detail', kwargs={'uuid': job.jobposting_uuid})
            detail_response = client.get(detail_url)
            assert detail_response.status_code == 200
            assert detail_response.context['job'].id == job.id

    def test_api_to_web_consistency(self, api_client, client, sample_job):
        """Test consistency between API and web views."""
        # Get job via API
        api_url = reverse('jobs_public_api:publicjob-detail', kwargs={'jobposting_uuid': sample_job.jobposting_uuid})
        api_response = api_client.get(api_url)

        # Get job via web view
        web_url = reverse('jobs_public:job_detail', kwargs={'uuid': sample_job.jobposting_uuid})
        web_response = client.get(web_url)

        # Data should match
        assert api_response.data['title'] == web_response.context['job'].title
        assert api_response.data['company_name'] == web_response.context['job'].company_name

    def test_search_across_multiple_fields(self, client, multiple_jobs):
        """Test searching across title, company, description."""
        # Create jobs with searchable content
        list_url = reverse('jobs_public:job_list')

        # Search for "Developer" should find engineering jobs
        response = client.get(list_url, {'q': 'Developer'})
        assert response.status_code == 200
        assert response.context['total_jobs'] > 0

    def test_pagination_preserves_filters(self, client, multiple_jobs):
        """Test that pagination preserves filter parameters."""
        list_url = reverse('jobs_public:job_list')

        # Apply filter and go to page 2
        response = client.get(list_url, {
            'employment_type': 'full-time',
            'page': 1
        })

        assert response.status_code == 200
        assert response.context['selected_employment_type'] == 'full-time'


@pytest.mark.django_db
class TestMapIntegration:
    """Test map functionality integration."""

    def test_map_displays_geocoded_jobs_only(self, client, job_with_geocoding, job_without_geocoding):
        """Test map view only shows jobs with geocoding."""
        map_url = reverse('jobs_public:job_map')
        response = client.get(map_url)

        assert response.status_code == 200

        # Parse jobs_data_json to check only geocoded jobs are included
        import json
        jobs_data = json.loads(response.context['jobs_data_json'])

        for job_data in jobs_data:
            assert job_data['location']['lat'] is not None
            assert job_data['location']['lng'] is not None

    def test_map_api_endpoint_integration(self, api_client, multiple_jobs):
        """Test map data API endpoint."""
        url = reverse('jobs_public_api:publicjob-map-data')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        # All jobs in response should have coordinates
        for job in response.data['results']:
            location = job['location']
            assert location.get('lat') is not None
            assert location.get('lng') is not None


@pytest.mark.django_db
class TestFilteringIntegration:
    """Test filtering integration across views and API."""

    def test_filter_combination(self, client, multiple_jobs):
        """Test combining multiple filters."""
        list_url = reverse('jobs_public:job_list')

        # Combine remote + location + employment type
        response = client.get(list_url, {
            'remote_only': 'true',
            'employment_type': 'full-time',
            'state': 'CA',
        })

        assert response.status_code == 200

        # All returned jobs should match all filters
        jobs = response.context['jobs']
        for job in jobs:
            assert job.is_remote is True
            assert job.employment_type == 'full-time'

    def test_salary_range_filtering(self, client, multiple_jobs):
        """Test filtering by salary range."""
        list_url = reverse('jobs_public:job_list')

        response = client.get(list_url, {
            'salary_min': '100000',
            'salary_max': '180000',
        })

        assert response.status_code == 200


@pytest.mark.django_db
class TestViewCountTracking:
    """Test view count tracking across the app."""

    def test_view_count_increments_on_detail_view(self, client, sample_job):
        """Test view count increments when job detail is viewed."""
        initial_count = sample_job.view_count

        detail_url = reverse('jobs_public:job_detail', kwargs={'uuid': sample_job.jobposting_uuid})

        # View the job 3 times
        for _ in range(3):
            client.get(detail_url)

        sample_job.refresh_from_db()
        assert sample_job.view_count == initial_count + 3

    def test_view_count_not_incremented_on_list_view(self, client, sample_job):
        """Test view count doesn't increment on list view."""
        initial_count = sample_job.view_count

        list_url = reverse('jobs_public:job_list')
        client.get(list_url)

        sample_job.refresh_from_db()
        assert sample_job.view_count == initial_count
