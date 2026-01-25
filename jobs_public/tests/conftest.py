"""
Test fixtures and factories for jobs_public app tests.

Provides reusable pytest fixtures for creating test data.
"""

import pytest
from decimal import Decimal
from django.utils import timezone
from datetime import timedelta
import uuid

from jobs_public.models import PublicJobCatalog


@pytest.fixture
def sample_job_data():
    """Sample job data dictionary for creating test jobs."""
    return {
        'jobposting_uuid': uuid.uuid4(),
        'tenant_schema_name': 'test_company',
        'title': 'Senior Python Developer',
        'description_html': '<p>We are seeking an experienced Python developer...</p>',
        'company_name': 'Test Tech Corp',
        'company_logo_url': 'https://example.com/logo.png',
        'location_city': 'San Francisco',
        'location_state': 'CA',
        'location_country': 'USA',
        'location_display': 'San Francisco, CA, USA',
        'is_remote': False,
        'employment_type': 'full-time',
        'experience_level': 'senior',
        'salary_min': Decimal('120000.00'),
        'salary_max': Decimal('180000.00'),
        'salary_currency': 'USD',
        'salary_period': 'yearly',
        'show_salary': True,
        'required_skills': ['Python', 'Django', 'PostgreSQL'],
        'category_names': ['Engineering', 'Software Development'],
        'category_slugs': ['engineering', 'software-development'],
        'is_featured': False,
        'is_active': True,
        'is_expired': False,
        'published_at': timezone.now(),
        'latitude': 37.7749,
        'longitude': -122.4194,
    }


@pytest.fixture
def create_job(db):
    """Factory fixture for creating PublicJobCatalog instances."""
    def _create_job(**kwargs):
        defaults = {
            'jobposting_uuid': uuid.uuid4(),
            'tenant_schema_name': 'test_company',
            'title': 'Test Job',
            'company_name': 'Test Company',
            'location_display': 'Test City, USA',
            'employment_type': 'full-time',
            'is_active': True,
            'is_expired': False,
            'published_at': timezone.now(),
        }
        defaults.update(kwargs)
        return PublicJobCatalog.objects.create(**defaults)
    return _create_job


@pytest.fixture
def sample_job(create_job, sample_job_data):
    """Create a single sample job for testing."""
    return create_job(**sample_job_data)


@pytest.fixture
def multiple_jobs(create_job):
    """Create multiple jobs for testing list views and filtering."""
    jobs = []

    # Job 1: Remote Python job in SF
    jobs.append(create_job(
        title='Remote Python Developer',
        company_name='Tech Startup Inc',
        location_city='San Francisco',
        location_state='CA',
        location_country='USA',
        location_display='San Francisco, CA, USA',
        is_remote=True,
        employment_type='full-time',
        salary_min=Decimal('100000'),
        salary_max=Decimal('150000'),
        show_salary=True,
        latitude=37.7749,
        longitude=-122.4194,
        category_slugs=['engineering'],
        published_at=timezone.now() - timedelta(days=1),
    ))

    # Job 2: On-site Designer in NYC
    jobs.append(create_job(
        title='Senior UX Designer',
        company_name='Design Co',
        location_city='New York',
        location_state='NY',
        location_country='USA',
        location_display='New York, NY, USA',
        is_remote=False,
        employment_type='full-time',
        salary_min=Decimal('90000'),
        salary_max=Decimal('130000'),
        show_salary=True,
        latitude=40.7128,
        longitude=-74.0060,
        category_slugs=['design'],
        published_at=timezone.now() - timedelta(days=2),
    ))

    # Job 3: Part-time Marketing in LA
    jobs.append(create_job(
        title='Marketing Manager',
        company_name='Marketing Agency',
        location_city='Los Angeles',
        location_state='CA',
        location_country='USA',
        location_display='Los Angeles, CA, USA',
        is_remote=False,
        employment_type='part-time',
        salary_min=Decimal('60000'),
        salary_max=Decimal('80000'),
        show_salary=False,
        latitude=34.0522,
        longitude=-118.2437,
        category_slugs=['marketing'],
        published_at=timezone.now() - timedelta(days=3),
    ))

    # Job 4: Featured job
    jobs.append(create_job(
        title='Lead Software Engineer',
        company_name='Big Tech Company',
        location_city='Seattle',
        location_state='WA',
        location_country='USA',
        location_display='Seattle, WA, USA',
        is_remote=True,
        employment_type='full-time',
        salary_min=Decimal('150000'),
        salary_max=Decimal('220000'),
        show_salary=True,
        is_featured=True,
        latitude=47.6062,
        longitude=-122.3321,
        category_slugs=['engineering', 'leadership'],
        published_at=timezone.now(),
    ))

    # Job 5: Expired job
    jobs.append(create_job(
        title='Expired Position',
        company_name='Old Company',
        location_display='Somewhere, USA',
        is_expired=True,
        is_active=False,
        published_at=timezone.now() - timedelta(days=30),
    ))

    return jobs


@pytest.fixture
def api_client():
    """Django REST Framework API client."""
    from rest_framework.test import APIClient
    return APIClient()


@pytest.fixture
def authenticated_user(db, django_user_model):
    """Create and return an authenticated user."""
    user = django_user_model.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123'
    )
    return user
