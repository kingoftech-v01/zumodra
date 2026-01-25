"""
Tests for PublicJobCatalog model.

Tests model creation, properties, methods, and business logic.
"""

import pytest
from decimal import Decimal
from django.utils import timezone
from datetime import timedelta

from jobs_public.models import PublicJobCatalog


@pytest.mark.django_db
class TestPublicJobCatalogModel:
    """Test PublicJobCatalog model functionality."""

    def test_create_job(self, sample_job_data):
        """Test creating a PublicJobCatalog instance."""
        job = PublicJobCatalog.objects.create(**sample_job_data)

        assert job.id is not None
        assert job.title == sample_job_data['title']
        assert job.company_name == sample_job_data['company_name']
        assert job.is_active is True
        assert job.is_expired is False

    def test_str_representation(self, sample_job):
        """Test string representation of job."""
        expected = f"{sample_job.title} at {sample_job.company_name}"
        assert str(sample_job) == expected

    def test_salary_display_property_with_range(self, create_job):
        """Test salary_display property with min and max salary."""
        job = create_job(
            salary_min=Decimal('100000'),
            salary_max=Decimal('150000'),
            salary_currency='USD',
            show_salary=True,
        )

        assert job.salary_display == '$100,000 - $150,000'

    def test_salary_display_property_min_only(self, create_job):
        """Test salary_display with only minimum salary."""
        job = create_job(
            salary_min=Decimal('80000'),
            salary_max=None,
            salary_currency='USD',
            show_salary=True,
        )

        assert job.salary_display == '$80,000+'

    def test_salary_display_property_max_only(self, create_job):
        """Test salary_display with only maximum salary."""
        job = create_job(
            salary_min=None,
            salary_max=Decimal('120000'),
            salary_currency='USD',
            show_salary=True,
        )

        assert job.salary_display == 'Up to $120,000'

    def test_salary_display_hidden(self, create_job):
        """Test salary_display when show_salary is False."""
        job = create_job(
            salary_min=Decimal('100000'),
            salary_max=Decimal('150000'),
            show_salary=False,
        )

        assert job.salary_display is None

    def test_salary_display_no_salary_data(self, create_job):
        """Test salary_display when no salary data exists."""
        job = create_job(
            salary_min=None,
            salary_max=None,
            show_salary=True,
        )

        assert job.salary_display is None

    def test_increment_view_count(self, sample_job):
        """Test incrementing job view count."""
        initial_count = sample_job.view_count
        sample_job.increment_view_count()

        # Refresh from database
        sample_job.refresh_from_db()
        assert sample_job.view_count == initial_count + 1

    def test_increment_view_count_multiple_times(self, sample_job):
        """Test incrementing view count multiple times."""
        initial_count = sample_job.view_count

        for i in range(5):
            sample_job.increment_view_count()

        sample_job.refresh_from_db()
        assert sample_job.view_count == initial_count + 5

    def test_is_expired_computed_property(self, create_job):
        """Test is_expired_computed property for expired jobs."""
        # Job expired 1 day ago
        expired_job = create_job(
            expiration_date=timezone.now() - timedelta(days=1)
        )

        assert expired_job.is_expired_computed is True

    def test_is_not_expired_computed_property(self, create_job):
        """Test is_expired_computed for active jobs."""
        # Job expires in 7 days
        active_job = create_job(
            expiration_date=timezone.now() + timedelta(days=7)
        )

        assert active_job.is_expired_computed is False

    def test_no_expiration_date(self, create_job):
        """Test jobs without expiration date."""
        job = create_job(expiration_date=None)

        assert job.is_expired_computed is False

    def test_has_salary_info_property(self, create_job):
        """Test has_salary_info property."""
        job_with_salary = create_job(
            salary_min=Decimal('50000'),
            salary_max=Decimal('80000'),
        )
        job_without_salary = create_job(
            salary_min=None,
            salary_max=None,
        )

        assert job_with_salary.has_salary_info is True
        assert job_without_salary.has_salary_info is False

    def test_ordering(self, create_job):
        """Test default ordering of jobs."""
        job1 = create_job(
            title='Job 1',
            published_at=timezone.now() - timedelta(days=3),
            is_featured=False,
        )
        job2 = create_job(
            title='Job 2',
            published_at=timezone.now() - timedelta(days=1),
            is_featured=True,
        )
        job3 = create_job(
            title='Job 3',
            published_at=timezone.now(),
            is_featured=False,
        )

        jobs = list(PublicJobCatalog.objects.all())

        # Featured jobs should come first, then ordered by published_at desc
        assert jobs[0] == job2  # Featured
        assert jobs[1] == job3  # Newest non-featured
        assert jobs[2] == job1  # Oldest non-featured

    def test_geocoding_data(self, create_job):
        """Test jobs with geocoding data."""
        job = create_job(
            latitude=37.7749,
            longitude=-122.4194,
        )

        assert job.latitude == 37.7749
        assert job.longitude == -122.4194

    def test_rich_content_lists(self, create_job):
        """Test rich content JSON fields."""
        job = create_job(
            responsibilities_list=['Task 1', 'Task 2'],
            requirements_list=['Requirement 1', 'Requirement 2'],
            benefits_list=['Benefit 1', 'Benefit 2'],
        )

        assert len(job.responsibilities_list) == 2
        assert len(job.requirements_list) == 2
        assert len(job.benefits_list) == 2
        assert 'Task 1' in job.responsibilities_list

    def test_image_gallery(self, create_job):
        """Test image gallery JSON field."""
        job = create_job(
            image_gallery=[
                'https://example.com/image1.jpg',
                'https://example.com/image2.jpg',
            ]
        )

        assert len(job.image_gallery) == 2
        assert job.image_gallery[0] == 'https://example.com/image1.jpg'
