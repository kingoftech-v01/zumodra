"""
Tests for jobs_public views.

Tests view rendering, context data, filtering, and pagination.
"""

import pytest
from django.urls import reverse


@pytest.mark.django_db
class TestJobListViews:
    """Test job list views."""

    def test_job_list_default_view(self, client, multiple_jobs):
        """Test default job list view."""
        url = reverse('jobs_public:job_list')
        response = client.get(url)

        assert response.status_code == 200
        assert 'jobs' in response.context
        assert 'total_jobs' in response.context
        assert response.context['total_jobs'] >= 4

    def test_job_list_grid_view(self, client, multiple_jobs):
        """Test grid view."""
        url = reverse('jobs_public:job_list_grid')
        response = client.get(url)

        assert response.status_code == 200
        assert 'jobs' in response.context

    def test_job_list_list_view(self, client, multiple_jobs):
        """Test list view."""
        url = reverse('jobs_public:job_list_list')
        response = client.get(url)

        assert response.status_code == 200
        assert 'jobs' in response.context

    def test_filter_by_search_query(self, client, multiple_jobs):
        """Test filtering jobs by search query."""
        url = reverse('jobs_public:job_list')
        response = client.get(url, {'q': 'Python'})

        assert response.status_code == 200
        # Should find Python developer job
        assert response.context['search_query'] == 'Python'

    def test_filter_by_location(self, client, multiple_jobs):
        """Test filtering by location."""
        url = reverse('jobs_public:job_list')
        response = client.get(url, {'city': 'New York'})

        assert response.status_code == 200
        assert response.context['selected_city'] == 'New York'

    def test_filter_by_remote_only(self, client, multiple_jobs):
        """Test filtering for remote jobs."""
        url = reverse('jobs_public:job_list')
        response = client.get(url, {'remote_only': 'true'})

        assert response.status_code == 200
        assert response.context['remote_only'] is True

    def test_pagination_works(self, client, multiple_jobs):
        """Test pagination."""
        url = reverse('jobs_public:job_list')
        response = client.get(url, {'page': 1})

        assert response.status_code == 200
        assert 'page_obj' in response.context
        assert 'paginator' in response.context

    def test_sort_by_newest(self, client, multiple_jobs):
        """Test sorting by newest first."""
        url = reverse('jobs_public:job_list')
        response = client.get(url, {'sort': 'newest'})

        assert response.status_code == 200
        assert response.context['sort_by'] == 'newest'


@pytest.mark.django_db
class TestJobDetailViews:
    """Test job detail views."""

    def test_job_detail_v1_view(self, client, sample_job):
        """Test job detail view v1."""
        url = reverse('jobs_public:job_detail', kwargs={'uuid': sample_job.jobposting_uuid})
        response = client.get(url)

        assert response.status_code == 200
        assert 'job' in response.context
        assert response.context['job'].id == sample_job.id

    def test_job_detail_v2_view(self, client, sample_job):
        """Test job detail view v2."""
        url = reverse('jobs_public:job_detail_v2', kwargs={'uuid': sample_job.jobposting_uuid})
        response = client.get(url)

        assert response.status_code == 200
        assert 'job' in response.context

    def test_job_detail_increments_view_count(self, client, sample_job):
        """Test that viewing job detail increments view count."""
        initial_count = sample_job.view_count
        url = reverse('jobs_public:job_detail', kwargs={'uuid': sample_job.jobposting_uuid})
        client.get(url)

        sample_job.refresh_from_db()
        assert sample_job.view_count == initial_count + 1

    def test_job_detail_shows_related_jobs(self, client, multiple_jobs):
        """Test that related jobs are shown on detail page."""
        job = multiple_jobs[0]
        url = reverse('jobs_public:job_detail', kwargs={'uuid': job.jobposting_uuid})
        response = client.get(url)

        assert response.status_code == 200
        assert 'related_jobs' in response.context

    def test_job_detail_404_for_invalid_uuid(self, client):
        """Test 404 for invalid job UUID."""
        url = reverse('jobs_public:job_detail', kwargs={'uuid': '00000000-0000-0000-0000-000000000000'})
        response = client.get(url)

        assert response.status_code == 404


@pytest.mark.django_db
class TestJobMapViews:
    """Test job map views."""

    def test_job_map_v1_view(self, client, multiple_jobs):
        """Test job map view v1."""
        url = reverse('jobs_public:job_map')
        response = client.get(url)

        assert response.status_code == 200
        assert 'jobs' in response.context
        assert 'jobs_data_json' in response.context
        assert 'map_center_lat' in response.context
        assert 'map_center_lng' in response.context

    def test_job_map_v2_view(self, client, multiple_jobs):
        """Test job map view v2."""
        url = reverse('jobs_public:job_map_v2')
        response = client.get(url)

        assert response.status_code == 200
        assert 'jobs_data_json' in response.context
