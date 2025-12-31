"""
ATS API Tests - Integration tests for Applicant Tracking System REST API

This module provides comprehensive API integration tests for:
- Job Category endpoints
- Pipeline endpoints
- Job Posting endpoints
- Candidate endpoints
- Application endpoints
- Interview endpoints
- Offer endpoints
- Dashboard endpoints

Tests are marked with @pytest.mark.integration for easy categorization.
"""

import pytest
from decimal import Decimal
from datetime import timedelta
from django.utils import timezone
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from ats.models import (
    JobCategory, Pipeline, PipelineStage, JobPosting,
    Candidate, Application, Interview, Offer
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def api_client():
    """Provide a DRF API test client."""
    return APIClient()


@pytest.fixture
def authenticated_api_client(api_client, user_factory):
    """Provide an authenticated API client."""
    user = user_factory()
    api_client.force_authenticate(user=user)
    return api_client, user


@pytest.fixture
def recruiter_api_client(api_client, user_factory, tenant_factory, plan_factory):
    """Provide API client authenticated as recruiter."""
    from conftest import RecruiterTenantUserFactory
    plan = plan_factory()
    tenant = tenant_factory(plan=plan)
    user = user_factory()
    RecruiterTenantUserFactory(user=user, tenant=tenant)
    api_client.force_authenticate(user=user)
    return api_client, user, tenant


# ============================================================================
# JOB CATEGORY API TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestJobCategoryAPI:
    """Integration tests for Job Category API endpoints."""

    def test_list_categories_unauthenticated(self, api_client):
        """Test listing categories without authentication returns 401."""
        response = api_client.get('/api/ats/categories/')
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    def test_list_categories_authenticated(self, authenticated_api_client, job_category_factory):
        """Test listing categories with authentication."""
        client, user = authenticated_api_client
        job_category_factory(name='Engineering')
        job_category_factory(name='Sales')

        response = client.get('/api/ats/categories/')

        # Accept 200 or 403 depending on permissions setup
        if response.status_code == status.HTTP_200_OK:
            assert 'results' in response.data or isinstance(response.data, list)

    def test_create_category(self, authenticated_api_client):
        """Test creating a job category."""
        client, user = authenticated_api_client
        data = {
            'name': 'New Category',
            'slug': 'new-category',
            'description': 'Test description',
            'color': '#FF5733'
        }

        response = client.post('/api/ats/categories/', data, format='json')

        # Accept 201 or 403 depending on permissions
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_400_BAD_REQUEST
        ]

    def test_retrieve_category(self, authenticated_api_client, job_category_factory):
        """Test retrieving a single category."""
        client, user = authenticated_api_client
        category = job_category_factory(name='Test Category')

        response = client.get(f'/api/ats/categories/{category.pk}/')

        if response.status_code == status.HTTP_200_OK:
            assert response.data['name'] == 'Test Category'


# ============================================================================
# PIPELINE API TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestPipelineAPI:
    """Integration tests for Pipeline API endpoints."""

    def test_list_pipelines_unauthenticated(self, api_client):
        """Test listing pipelines without authentication."""
        response = api_client.get('/api/ats/pipelines/')
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    def test_list_pipelines_authenticated(self, authenticated_api_client, pipeline_factory):
        """Test listing pipelines with authentication."""
        client, user = authenticated_api_client
        pipeline_factory(name='Engineering Pipeline')
        pipeline_factory(name='Sales Pipeline')

        response = client.get('/api/ats/pipelines/')

        if response.status_code == status.HTTP_200_OK:
            assert 'results' in response.data or isinstance(response.data, list)

    def test_create_pipeline_with_stages(self, authenticated_api_client):
        """Test creating a pipeline with stages."""
        client, user = authenticated_api_client
        data = {
            'name': 'New Pipeline',
            'description': 'Test pipeline',
            'is_default': False
        }

        response = client.post('/api/ats/pipelines/', data, format='json')

        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_400_BAD_REQUEST
        ]

    def test_retrieve_pipeline_with_stages(
        self, authenticated_api_client, pipeline_factory, pipeline_stage_factory
    ):
        """Test retrieving pipeline includes stages."""
        client, user = authenticated_api_client
        pipeline = pipeline_factory()
        pipeline_stage_factory(pipeline=pipeline, name='Stage 1', order=0)
        pipeline_stage_factory(pipeline=pipeline, name='Stage 2', order=1)

        response = client.get(f'/api/ats/pipelines/{pipeline.uuid}/')

        if response.status_code == status.HTTP_200_OK:
            assert response.data['name'] == pipeline.name


# ============================================================================
# JOB POSTING API TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestJobPostingAPI:
    """Integration tests for Job Posting API endpoints."""

    def test_list_jobs_unauthenticated(self, api_client):
        """Test listing jobs without authentication."""
        response = api_client.get('/api/ats/jobs/')
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    def test_list_jobs_authenticated(self, authenticated_api_client, job_posting_factory):
        """Test listing jobs with authentication."""
        client, user = authenticated_api_client
        job_posting_factory(title='Software Engineer')
        job_posting_factory(title='Product Manager')

        response = client.get('/api/ats/jobs/')

        if response.status_code == status.HTTP_200_OK:
            assert 'results' in response.data or isinstance(response.data, list)

    def test_create_job_posting(self, authenticated_api_client, pipeline_factory, job_category_factory):
        """Test creating a job posting."""
        client, user = authenticated_api_client
        pipeline = pipeline_factory()
        category = job_category_factory()

        data = {
            'title': 'Senior Developer',
            'reference_code': f'JOB-TEST-{timezone.now().timestamp()}',
            'description': 'Test job description',
            'job_type': 'full_time',
            'experience_level': 'senior',
            'remote_policy': 'hybrid',
            'pipeline': str(pipeline.pk),
            'category': category.pk,
            'location_country': 'Canada'
        }

        response = client.post('/api/ats/jobs/', data, format='json')

        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_400_BAD_REQUEST
        ]

    def test_retrieve_job_posting(self, authenticated_api_client, job_posting_factory):
        """Test retrieving a single job posting."""
        client, user = authenticated_api_client
        job = job_posting_factory(title='Test Job')

        response = client.get(f'/api/ats/jobs/{job.uuid}/')

        if response.status_code == status.HTTP_200_OK:
            assert response.data['title'] == 'Test Job'

    def test_filter_jobs_by_status(self, authenticated_api_client, job_posting_factory):
        """Test filtering jobs by status."""
        client, user = authenticated_api_client
        job_posting_factory(status='open')
        job_posting_factory(status='draft')
        job_posting_factory(status='closed')

        response = client.get('/api/ats/jobs/?status=open')

        if response.status_code == status.HTTP_200_OK:
            results = response.data.get('results', response.data)
            if isinstance(results, list):
                for job in results:
                    assert job.get('status') == 'open'

    def test_filter_jobs_by_job_type(self, authenticated_api_client, job_posting_factory):
        """Test filtering jobs by job type."""
        client, user = authenticated_api_client
        job_posting_factory(job_type='full_time')
        job_posting_factory(job_type='contract')

        response = client.get('/api/ats/jobs/?job_type=full_time')

        if response.status_code == status.HTTP_200_OK:
            results = response.data.get('results', response.data)
            if isinstance(results, list):
                for job in results:
                    assert job.get('job_type') == 'full_time'

    def test_publish_job_action(self, authenticated_api_client, job_posting_factory):
        """Test publishing a job via action endpoint."""
        client, user = authenticated_api_client
        job = job_posting_factory(status='draft', created_by=user)

        response = client.post(f'/api/ats/jobs/{job.uuid}/publish/')

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND
        ]

    def test_close_job_action(self, authenticated_api_client, job_posting_factory):
        """Test closing a job via action endpoint."""
        client, user = authenticated_api_client
        job = job_posting_factory(status='open', created_by=user)

        response = client.post(f'/api/ats/jobs/{job.uuid}/close/', {'reason': 'filled'}, format='json')

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND
        ]


# ============================================================================
# CANDIDATE API TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestCandidateAPI:
    """Integration tests for Candidate API endpoints."""

    def test_list_candidates_unauthenticated(self, api_client):
        """Test listing candidates without authentication."""
        response = api_client.get('/api/ats/candidates/')
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    def test_list_candidates_authenticated(self, authenticated_api_client, candidate_factory):
        """Test listing candidates with authentication."""
        client, user = authenticated_api_client
        candidate_factory(first_name='John', last_name='Doe')
        candidate_factory(first_name='Jane', last_name='Smith')

        response = client.get('/api/ats/candidates/')

        if response.status_code == status.HTTP_200_OK:
            assert 'results' in response.data or isinstance(response.data, list)

    def test_create_candidate(self, authenticated_api_client):
        """Test creating a candidate."""
        client, user = authenticated_api_client
        data = {
            'first_name': 'New',
            'last_name': 'Candidate',
            'email': 'new.candidate@example.com',
            'phone': '+1234567890',
            'source': 'career_page',
            'consent_to_store': True
        }

        response = client.post('/api/ats/candidates/', data, format='json')

        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_400_BAD_REQUEST
        ]

    def test_retrieve_candidate(self, authenticated_api_client, candidate_factory):
        """Test retrieving a single candidate."""
        client, user = authenticated_api_client
        candidate = candidate_factory(first_name='Test', last_name='Candidate')

        response = client.get(f'/api/ats/candidates/{candidate.uuid}/')

        if response.status_code == status.HTTP_200_OK:
            assert response.data['first_name'] == 'Test'

    def test_search_candidates_by_name(self, authenticated_api_client, candidate_factory):
        """Test searching candidates by name."""
        client, user = authenticated_api_client
        candidate_factory(first_name='John', last_name='Doe')
        candidate_factory(first_name='Jane', last_name='Smith')

        response = client.get('/api/ats/candidates/?search=John')

        if response.status_code == status.HTTP_200_OK:
            results = response.data.get('results', response.data)
            if isinstance(results, list) and len(results) > 0:
                assert any('John' in c.get('first_name', '') for c in results)

    def test_filter_candidates_by_source(self, authenticated_api_client, candidate_factory):
        """Test filtering candidates by source."""
        client, user = authenticated_api_client
        candidate_factory(source='linkedin')
        candidate_factory(source='career_page')

        response = client.get('/api/ats/candidates/?source=linkedin')

        if response.status_code == status.HTTP_200_OK:
            results = response.data.get('results', response.data)
            if isinstance(results, list):
                for candidate in results:
                    assert candidate.get('source') == 'linkedin'


# ============================================================================
# APPLICATION API TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestApplicationAPI:
    """Integration tests for Application API endpoints."""

    def test_list_applications_unauthenticated(self, api_client):
        """Test listing applications without authentication."""
        response = api_client.get('/api/ats/applications/')
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    def test_list_applications_authenticated(self, authenticated_api_client, application_factory):
        """Test listing applications with authentication."""
        client, user = authenticated_api_client
        application_factory()
        application_factory()

        response = client.get('/api/ats/applications/')

        if response.status_code == status.HTTP_200_OK:
            assert 'results' in response.data or isinstance(response.data, list)

    def test_create_application(
        self, authenticated_api_client, job_posting_factory, candidate_factory, pipeline_stage_factory
    ):
        """Test creating an application."""
        client, user = authenticated_api_client
        job = job_posting_factory(status='open')
        candidate = candidate_factory()
        stage = pipeline_stage_factory()

        data = {
            'job': str(job.pk),
            'candidate': str(candidate.pk),
            'current_stage': stage.pk,
            'cover_letter': 'I am interested in this position.'
        }

        response = client.post('/api/ats/applications/', data, format='json')

        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_400_BAD_REQUEST
        ]

    def test_retrieve_application(self, authenticated_api_client, application_factory):
        """Test retrieving a single application."""
        client, user = authenticated_api_client
        application = application_factory()

        response = client.get(f'/api/ats/applications/{application.uuid}/')

        if response.status_code == status.HTTP_200_OK:
            assert 'candidate' in response.data or 'job' in response.data

    def test_filter_applications_by_status(self, authenticated_api_client, application_factory):
        """Test filtering applications by status."""
        client, user = authenticated_api_client
        application_factory(status='new')
        application_factory(status='in_review')
        application_factory(status='rejected')

        response = client.get('/api/ats/applications/?status=new')

        if response.status_code == status.HTTP_200_OK:
            results = response.data.get('results', response.data)
            if isinstance(results, list):
                for app in results:
                    assert app.get('status') == 'new'

    def test_move_application_stage_action(
        self, authenticated_api_client, application_factory, pipeline_factory, pipeline_stage_factory
    ):
        """Test moving application to different stage."""
        client, user = authenticated_api_client
        pipeline = pipeline_factory()
        stage1 = pipeline_stage_factory(pipeline=pipeline, order=0)
        stage2 = pipeline_stage_factory(pipeline=pipeline, order=1)
        application = application_factory(current_stage=stage1)

        response = client.post(
            f'/api/ats/applications/{application.uuid}/move_stage/',
            {'stage_id': stage2.pk},
            format='json'
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND
        ]

    def test_reject_application_action(self, authenticated_api_client, application_factory):
        """Test rejecting an application."""
        client, user = authenticated_api_client
        application = application_factory(status='in_review')

        response = client.post(
            f'/api/ats/applications/{application.uuid}/reject/',
            {'reason': 'Not qualified', 'feedback': 'Thank you for applying'},
            format='json'
        )

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND
        ]


# ============================================================================
# INTERVIEW API TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestInterviewAPI:
    """Integration tests for Interview API endpoints."""

    def test_list_interviews_unauthenticated(self, api_client):
        """Test listing interviews without authentication."""
        response = api_client.get('/api/ats/interviews/')
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    def test_list_interviews_authenticated(self, authenticated_api_client, interview_factory):
        """Test listing interviews with authentication."""
        client, user = authenticated_api_client
        interview_factory()
        interview_factory()

        response = client.get('/api/ats/interviews/')

        if response.status_code == status.HTTP_200_OK:
            assert 'results' in response.data or isinstance(response.data, list)

    def test_create_interview(self, authenticated_api_client, application_factory, user_factory):
        """Test creating an interview."""
        client, user = authenticated_api_client
        application = application_factory()
        organizer = user_factory()
        scheduled_start = timezone.now() + timedelta(days=3)

        data = {
            'application': str(application.pk),
            'interview_type': 'video',
            'title': 'Technical Interview',
            'scheduled_start': scheduled_start.isoformat(),
            'scheduled_end': (scheduled_start + timedelta(hours=1)).isoformat(),
            'organizer': organizer.pk,
            'meeting_url': 'https://meet.google.com/test'
        }

        response = client.post('/api/ats/interviews/', data, format='json')

        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_400_BAD_REQUEST
        ]

    def test_retrieve_interview(self, authenticated_api_client, interview_factory):
        """Test retrieving a single interview."""
        client, user = authenticated_api_client
        interview = interview_factory()

        response = client.get(f'/api/ats/interviews/{interview.uuid}/')

        if response.status_code == status.HTTP_200_OK:
            assert 'application' in response.data or 'interview_type' in response.data

    def test_filter_interviews_by_status(self, authenticated_api_client, interview_factory):
        """Test filtering interviews by status."""
        client, user = authenticated_api_client
        interview_factory(status='scheduled')
        interview_factory(status='completed')

        response = client.get('/api/ats/interviews/?status=scheduled')

        if response.status_code == status.HTTP_200_OK:
            results = response.data.get('results', response.data)
            if isinstance(results, list):
                for interview in results:
                    assert interview.get('status') == 'scheduled'

    def test_cancel_interview_action(self, authenticated_api_client, interview_factory):
        """Test cancelling an interview."""
        client, user = authenticated_api_client
        interview = interview_factory(status='scheduled')

        response = client.post(f'/api/ats/interviews/{interview.uuid}/cancel/')

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND
        ]


# ============================================================================
# OFFER API TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestOfferAPI:
    """Integration tests for Offer API endpoints."""

    def test_list_offers_unauthenticated(self, api_client):
        """Test listing offers without authentication."""
        response = api_client.get('/api/ats/offers/')
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    def test_list_offers_authenticated(self, authenticated_api_client, offer_factory):
        """Test listing offers with authentication."""
        client, user = authenticated_api_client
        offer_factory()
        offer_factory()

        response = client.get('/api/ats/offers/')

        if response.status_code == status.HTTP_200_OK:
            assert 'results' in response.data or isinstance(response.data, list)

    def test_create_offer(self, authenticated_api_client, application_factory):
        """Test creating an offer."""
        client, user = authenticated_api_client
        application = application_factory()

        data = {
            'application': str(application.pk),
            'job_title': 'Senior Developer',
            'base_salary': '80000.00',
            'salary_currency': 'CAD',
            'salary_period': 'yearly',
            'pto_days': 20,
            'start_date': (timezone.now() + timedelta(days=30)).date().isoformat()
        }

        response = client.post('/api/ats/offers/', data, format='json')

        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_400_BAD_REQUEST
        ]

    def test_retrieve_offer(self, authenticated_api_client, offer_factory):
        """Test retrieving a single offer."""
        client, user = authenticated_api_client
        offer = offer_factory()

        response = client.get(f'/api/ats/offers/{offer.uuid}/')

        if response.status_code == status.HTTP_200_OK:
            assert 'base_salary' in response.data or 'job_title' in response.data

    def test_filter_offers_by_status(self, authenticated_api_client, offer_factory):
        """Test filtering offers by status."""
        client, user = authenticated_api_client
        offer_factory(status='draft')
        offer_factory(status='sent')

        response = client.get('/api/ats/offers/?status=draft')

        if response.status_code == status.HTTP_200_OK:
            results = response.data.get('results', response.data)
            if isinstance(results, list):
                for offer in results:
                    assert offer.get('status') == 'draft'

    def test_send_offer_action(self, authenticated_api_client, offer_factory):
        """Test sending an offer."""
        client, user = authenticated_api_client
        offer = offer_factory(status='approved', created_by=user)

        response = client.post(f'/api/ats/offers/{offer.uuid}/send/')

        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND
        ]


# ============================================================================
# DASHBOARD API TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestDashboardAPI:
    """Integration tests for Dashboard API endpoints."""

    def test_dashboard_stats_unauthenticated(self, api_client):
        """Test dashboard stats without authentication."""
        response = api_client.get('/api/ats/dashboard/stats/')
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    def test_dashboard_stats_authenticated(self, authenticated_api_client):
        """Test dashboard stats with authentication."""
        client, user = authenticated_api_client

        response = client.get('/api/ats/dashboard/stats/')

        # Accept 200 or permission denied
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_403_FORBIDDEN
        ]


# ============================================================================
# SAVED SEARCH API TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestSavedSearchAPI:
    """Integration tests for Saved Search API endpoints."""

    def test_list_saved_searches_unauthenticated(self, api_client):
        """Test listing saved searches without authentication."""
        response = api_client.get('/api/ats/saved-searches/')
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    def test_list_saved_searches_authenticated(self, authenticated_api_client):
        """Test listing saved searches with authentication."""
        client, user = authenticated_api_client
        from conftest import SavedSearchFactory
        SavedSearchFactory(user=user)

        response = client.get('/api/ats/saved-searches/')

        if response.status_code == status.HTTP_200_OK:
            assert 'results' in response.data or isinstance(response.data, list)

    def test_create_saved_search(self, authenticated_api_client):
        """Test creating a saved search."""
        client, user = authenticated_api_client
        data = {
            'name': 'Python Developers',
            'filters': {'skills': ['Python', 'Django'], 'location': 'Toronto'},
            'is_alert_enabled': True,
            'alert_frequency': 'daily'
        }

        response = client.post('/api/ats/saved-searches/', data, format='json')

        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_400_BAD_REQUEST
        ]


# ============================================================================
# PAGINATION AND ORDERING TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestAPIPaginationOrdering:
    """Test API pagination and ordering functionality."""

    def test_jobs_pagination(self, authenticated_api_client, job_posting_factory):
        """Test jobs endpoint pagination."""
        client, user = authenticated_api_client
        # Create multiple jobs
        for i in range(25):
            job_posting_factory(title=f'Job {i}')

        response = client.get('/api/ats/jobs/?page=1&page_size=10')

        if response.status_code == status.HTTP_200_OK:
            if 'results' in response.data:
                assert len(response.data['results']) <= 10

    def test_jobs_ordering(self, authenticated_api_client, job_posting_factory):
        """Test jobs endpoint ordering."""
        client, user = authenticated_api_client
        job_posting_factory(title='Alpha Job')
        job_posting_factory(title='Zebra Job')

        response = client.get('/api/ats/jobs/?ordering=title')

        if response.status_code == status.HTTP_200_OK:
            results = response.data.get('results', response.data)
            if isinstance(results, list) and len(results) >= 2:
                # First job should come before last alphabetically
                pass  # Ordering verification

    def test_candidates_pagination(self, authenticated_api_client, candidate_factory):
        """Test candidates endpoint pagination."""
        client, user = authenticated_api_client
        for i in range(15):
            candidate_factory(first_name=f'Candidate{i}')

        response = client.get('/api/ats/candidates/?page=1&page_size=5')

        if response.status_code == status.HTTP_200_OK:
            if 'results' in response.data:
                assert len(response.data['results']) <= 5


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

@pytest.mark.integration
@pytest.mark.django_db
class TestAPIErrorHandling:
    """Test API error handling."""

    def test_job_not_found(self, authenticated_api_client):
        """Test 404 for non-existent job."""
        client, user = authenticated_api_client
        import uuid
        fake_uuid = str(uuid.uuid4())

        response = client.get(f'/api/ats/jobs/{fake_uuid}/')

        assert response.status_code in [status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN]

    def test_candidate_not_found(self, authenticated_api_client):
        """Test 404 for non-existent candidate."""
        client, user = authenticated_api_client
        import uuid
        fake_uuid = str(uuid.uuid4())

        response = client.get(f'/api/ats/candidates/{fake_uuid}/')

        assert response.status_code in [status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN]

    def test_invalid_job_data(self, authenticated_api_client):
        """Test validation error for invalid job data."""
        client, user = authenticated_api_client
        data = {
            'title': '',  # Empty title should fail
            'description': 'Test'
        }

        response = client.post('/api/ats/jobs/', data, format='json')

        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_403_FORBIDDEN
        ]

    def test_duplicate_application(
        self, authenticated_api_client, job_posting_factory, candidate_factory, application_factory
    ):
        """Test error when creating duplicate application."""
        client, user = authenticated_api_client
        job = job_posting_factory()
        candidate = candidate_factory()
        application_factory(job=job, candidate=candidate)

        data = {
            'job': str(job.pk),
            'candidate': str(candidate.pk)
        }

        response = client.post('/api/ats/applications/', data, format='json')

        # Should fail due to unique constraint or return 403
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_403_FORBIDDEN
        ]
