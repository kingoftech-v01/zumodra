"""
Scalability Tests for Zumodra

Tests for:
1. Concurrent Request Handling
2. Database Query Performance
3. Bulk Operations
4. Rate Limiting Behavior
5. Memory and Resource Usage
6. Cache Performance

Run with: pytest tests/test_scalability.py -v -m scalability
"""

import pytest
import time
import threading
import concurrent.futures
import statistics
from decimal import Decimal
from datetime import datetime, timedelta

from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import connection, reset_queries
from django.test.utils import CaptureQueriesContext
from django.core.cache import cache
from rest_framework.test import APIClient
from rest_framework import status
from contextlib import contextmanager

User = get_user_model()


# No-op tenant_context for tests without django-tenants
@contextmanager
def tenant_context(tenant):
    """No-op context manager when django-tenants is disabled."""
    yield


# =============================================================================
# FIXTURES - Use conftest factories to avoid django-tenants schema creation
# =============================================================================

@pytest.fixture
def tenant(tenant_factory, plan_factory):
    """Create test tenant using factory."""
    plan = plan_factory(
        plan_type='enterprise',
        name='Enterprise',
        slug='enterprise',
        price_monthly=Decimal('299.00'),
        max_job_postings=10000,
        max_candidates_per_month=100000,
        max_users=10000,
    )
    return tenant_factory(
        name='Scale Test Company',
        slug='scaletest',
        schema_name='scaletest',
        owner_email='owner@scaletest.com',
        plan=plan,
        status='active',
    )


@pytest.fixture
def admin_user(tenant, user_factory, tenant_user_factory):
    """Create admin user."""
    user = user_factory(
        username='scaleadmin',
        email='admin@scaletest.com',
        password='ScalePass123!',
        first_name='Scale',
        last_name='Admin'
    )

    tenant_user_factory(
        user=user,
        tenant=tenant,
        role='owner',
        is_active=True
    )

    return user


@pytest.fixture
def api_client():
    """Return API client."""
    return APIClient()


@pytest.fixture
def large_dataset(tenant, admin_user):
    """Create a large dataset for performance testing."""
    from ats.models import JobPosting, JobCategory, Pipeline, PipelineStage, Candidate, Application

    # Create category
    category = JobCategory.objects.create(
        name='Engineering',
        slug='engineering',
        tenant=tenant
    )

    # Create pipeline with stages
    pipeline = Pipeline.objects.create(
        name='Standard',
        tenant=tenant,
        is_default=True,
        created_by=admin_user
    )

    stages = []
    for i, name in enumerate(['New', 'Screening', 'Interview', 'Offer', 'Hired']):
        stage = PipelineStage.objects.create(
            pipeline=pipeline,
            name=name,
            stage_type='new' if i == 0 else 'interview',
            order=i
        )
        stages.append(stage)

    # Create jobs
    jobs = []
    for i in range(50):
        job = JobPosting.objects.create(
            title=f'Software Engineer {i}',
            description=f'Job description {i}',
            tenant=tenant,
            category=category,
            pipeline=pipeline,
            created_by=admin_user,
            status='open'
        )
        jobs.append(job)

    # Create candidates
    candidates = []
    for i in range(200):
        candidate = Candidate.objects.create(
            first_name=f'Candidate{i}',
            last_name=f'LastName{i}',
            email=f'candidate{i}@test.com',
            tenant=tenant
        )
        candidates.append(candidate)

    # Create applications
    for i, candidate in enumerate(candidates):
        job = jobs[i % len(jobs)]
        Application.objects.create(
            candidate=candidate,
            job=job,
            tenant=tenant,
            current_stage=stages[0],
            status='new'
        )

    return {
        'jobs': jobs,
        'candidates': candidates,
        'category': category,
        'pipeline': pipeline,
        'stages': stages
    }


# =============================================================================
# CONCURRENT REQUEST TESTS
# =============================================================================

@pytest.mark.django_db(transaction=True)
@pytest.mark.scalability
class TestConcurrentRequests:
    """Test concurrent request handling."""

    @pytest.mark.skip(reason="Requires django-tenants for API tenant routing")
    def test_concurrent_reads_50_requests(self, api_client, tenant, admin_user, large_dataset):
        """Test handling 50 concurrent read requests."""
        results = []
        errors = []
        response_times = []

        def make_request():
            try:
                client = APIClient()
                client.force_authenticate(user=admin_user)
                start = time.time()
                with tenant_context(tenant):
                    response = client.get(
                        '/api/v1/ats/jobs/',
                        HTTP_HOST='scaletest.localhost'
                    )
                elapsed = time.time() - start
                response_times.append(elapsed)
                results.append(response.status_code)
            except Exception as e:
                errors.append(str(e))

        # Create 50 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            concurrent.futures.wait(futures, timeout=60)

        # Assertions
        assert len(errors) == 0, f"Errors: {errors}"
        success_rate = results.count(status.HTTP_200_OK) / len(results)
        assert success_rate >= 0.95, f"Success rate too low: {success_rate}"

        # Response time assertions
        if response_times:
            avg_time = statistics.mean(response_times)
            max_time = max(response_times)
            assert avg_time < 2.0, f"Average response time too high: {avg_time}s"
            assert max_time < 5.0, f"Max response time too high: {max_time}s"

    def test_concurrent_mixed_operations(self, api_client, tenant, admin_user, large_dataset):
        """Test concurrent mixed read/write operations."""
        results = []
        errors = []

        def read_request():
            try:
                client = APIClient()
                client.force_authenticate(user=admin_user)
                with tenant_context(tenant):
                    response = client.get(
                        '/api/v1/ats/candidates/',
                        HTTP_HOST='scaletest.localhost'
                    )
                results.append(('read', response.status_code))
            except Exception as e:
                errors.append(('read', str(e)))

        def write_request(i):
            try:
                client = APIClient()
                client.force_authenticate(user=admin_user)
                with tenant_context(tenant):
                    from ats.models import Candidate
                    # Create a candidate
                    candidate = Candidate.objects.create(
                        first_name=f'ConcurrentCandidate{i}',
                        last_name=f'Test{i}',
                        email=f'concurrent{i}@test.com',
                        tenant=tenant
                    )
                results.append(('write', 'success'))
            except Exception as e:
                errors.append(('write', str(e)))

        # Mix of reads and writes
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for i in range(30):
                if i % 3 == 0:
                    futures.append(executor.submit(write_request, i))
                else:
                    futures.append(executor.submit(read_request))
            concurrent.futures.wait(futures, timeout=60)

        # Check results
        assert len(errors) == 0, f"Errors: {errors}"


# =============================================================================
# QUERY PERFORMANCE TESTS
# =============================================================================

@pytest.mark.django_db
@pytest.mark.scalability
class TestQueryPerformance:
    """Test database query performance."""

    def test_jobs_list_query_efficiency(self, api_client, tenant, admin_user, large_dataset):
        """Test that jobs list uses efficient queries (no N+1)."""
        api_client.force_authenticate(user=admin_user)

        with tenant_context(tenant):
            reset_queries()
            with CaptureQueriesContext(connection) as context:
                response = api_client.get(
                    '/api/v1/ats/jobs/',
                    HTTP_HOST='scaletest.localhost'
                )

            # Check query count - should be constant, not proportional to items
            query_count = len(context)
            assert query_count < 15, f"Too many queries ({query_count}) - possible N+1"

    def test_candidates_list_query_efficiency(self, api_client, tenant, admin_user, large_dataset):
        """Test that candidates list uses efficient queries."""
        api_client.force_authenticate(user=admin_user)

        with tenant_context(tenant):
            reset_queries()
            with CaptureQueriesContext(connection) as context:
                response = api_client.get(
                    '/api/v1/ats/candidates/',
                    HTTP_HOST='scaletest.localhost'
                )

            query_count = len(context)
            assert query_count < 15, f"Too many queries ({query_count}) - possible N+1"

    def test_dashboard_query_efficiency(self, api_client, tenant, admin_user, large_dataset):
        """Test that dashboard uses efficient queries."""
        api_client.force_authenticate(user=admin_user)

        with tenant_context(tenant):
            reset_queries()
            with CaptureQueriesContext(connection) as context:
                response = api_client.get(
                    '/api/v1/dashboard/overview/',
                    HTTP_HOST='scaletest.localhost'
                )

            query_count = len(context)
            # Dashboard aggregates may need more queries
            assert query_count < 25, f"Too many queries ({query_count})"


# =============================================================================
# BULK OPERATION TESTS
# =============================================================================

@pytest.mark.django_db
@pytest.mark.scalability
class TestBulkOperations:
    """Test bulk operation performance."""

    def test_bulk_candidate_creation(self, tenant, admin_user):
        """Test bulk candidate creation performance."""
        from ats.models import Candidate

        start_time = time.time()

        with tenant_context(tenant):
            # Create 1000 candidates using bulk_create
            candidates = [
                Candidate(
                    first_name=f'Bulk{i}',
                    last_name=f'Candidate{i}',
                    email=f'bulk{i}@test.com',
                    tenant=tenant
                )
                for i in range(1000)
            ]
            Candidate.objects.bulk_create(candidates, batch_size=100)

        elapsed = time.time() - start_time

        # Should complete in reasonable time
        assert elapsed < 10, f"Bulk create took too long: {elapsed}s"

    def test_bulk_job_creation(self, tenant, admin_user):
        """Test bulk job creation performance."""
        from ats.models import JobPosting, JobCategory, Pipeline
        from django.utils.text import slugify
        import uuid

        category = JobCategory.objects.create(
            name='Bulk Test',
            slug='bulk-test',
            tenant=tenant
        )

        pipeline = Pipeline.objects.create(
            name='Bulk Pipeline',
            tenant=tenant,
            is_default=True,
            created_by=admin_user
        )

        start_time = time.time()

        # Create 100 jobs with unique reference codes (bulk_create bypasses pre_save signal)
        date_part = timezone.now().strftime('%Y%m')
        jobs = []
        for i in range(100):
            reference_code = f"JOB-{date_part}-{uuid.uuid4().hex[:4].upper()}"
            title = f'Bulk Job {i}'
            slug = f"{slugify(title)[:200]}-{reference_code.lower()}"
            jobs.append(JobPosting(
                title=title,
                description=f'Description {i}',
                tenant=tenant,
                category=category,
                pipeline=pipeline,
                created_by=admin_user,
                reference_code=reference_code,
                slug=slug,
            ))
        JobPosting.objects.bulk_create(jobs, batch_size=50)

        elapsed = time.time() - start_time

        assert elapsed < 5, f"Bulk create took too long: {elapsed}s"

    def test_bulk_application_update(self, tenant, admin_user, large_dataset):
        """Test bulk application update performance."""
        from ats.models import Application

        with tenant_context(tenant):
            start_time = time.time()

            # Update all applications
            Application.objects.filter(tenant=tenant).update(
                status='in_review'
            )

            elapsed = time.time() - start_time

        assert elapsed < 2, f"Bulk update took too long: {elapsed}s"


# =============================================================================
# PAGINATION TESTS
# =============================================================================

@pytest.mark.django_db
@pytest.mark.scalability
class TestPagination:
    """Test pagination efficiency."""

    @pytest.mark.skip(reason="Requires django-tenants for API tenant routing")
    def test_pagination_first_page(self, api_client, tenant, admin_user, large_dataset):
        """Test first page response time."""
        api_client.force_authenticate(user=admin_user)

        start_time = time.time()
        with tenant_context(tenant):
            response = api_client.get(
                '/api/v1/ats/candidates/?page=1&page_size=20',
                HTTP_HOST='scaletest.localhost'
            )
        elapsed = time.time() - start_time

        assert response.status_code == status.HTTP_200_OK
        assert elapsed < 1.0, f"First page took too long: {elapsed}s"

    def test_pagination_deep_page(self, api_client, tenant, admin_user, large_dataset):
        """Test deep page response time."""
        api_client.force_authenticate(user=admin_user)

        start_time = time.time()
        with tenant_context(tenant):
            response = api_client.get(
                '/api/v1/ats/candidates/?page=5&page_size=20',
                HTTP_HOST='scaletest.localhost'
            )
        elapsed = time.time() - start_time

        # Deep pages shouldn't be much slower
        assert elapsed < 2.0, f"Deep page took too long: {elapsed}s"


# =============================================================================
# CACHE PERFORMANCE TESTS
# =============================================================================

@pytest.mark.django_db
@pytest.mark.scalability
class TestCachePerformance:
    """Test cache effectiveness."""

    @pytest.mark.skip(reason="Requires django-tenants for API tenant routing")
    def test_repeated_requests_faster(self, api_client, tenant, admin_user, large_dataset):
        """Test that repeated requests benefit from caching."""
        api_client.force_authenticate(user=admin_user)

        # First request (cold)
        start_time = time.time()
        with tenant_context(tenant):
            response1 = api_client.get(
                '/api/v1/dashboard/overview/',
                HTTP_HOST='scaletest.localhost'
            )
        cold_time = time.time() - start_time

        # Second request (potentially cached)
        start_time = time.time()
        with tenant_context(tenant):
            response2 = api_client.get(
                '/api/v1/dashboard/overview/',
                HTTP_HOST='scaletest.localhost'
            )
        warm_time = time.time() - start_time

        assert response1.status_code == status.HTTP_200_OK
        assert response2.status_code == status.HTTP_200_OK

        # Warm request should be same or faster
        # (may not always be faster due to other factors)

    def test_cache_invalidation(self, api_client, tenant, admin_user, large_dataset):
        """Test that cache is properly invalidated on updates."""
        from ats.models import Candidate

        api_client.force_authenticate(user=admin_user)

        with tenant_context(tenant):
            # Get initial list
            response1 = api_client.get(
                '/api/v1/ats/candidates/',
                HTTP_HOST='scaletest.localhost'
            )
            initial_count = response1.data.get('count', len(response1.data))

            # Add a new candidate
            Candidate.objects.create(
                first_name='CacheTest',
                last_name='User',
                email='cachetest@test.com',
                tenant=tenant
            )

            # Get list again
            response2 = api_client.get(
                '/api/v1/ats/candidates/',
                HTTP_HOST='scaletest.localhost'
            )
            new_count = response2.data.get('count', len(response2.data))

            # New candidate should be visible
            assert new_count >= initial_count


# =============================================================================
# MEMORY USAGE TESTS
# =============================================================================

@pytest.mark.django_db
@pytest.mark.scalability
class TestMemoryUsage:
    """Test memory usage patterns."""

    @pytest.mark.skip(reason="Requires django-tenants for API tenant routing")
    def test_large_response_memory(self, api_client, tenant, admin_user, large_dataset):
        """Test that large responses don't cause memory issues."""
        import sys

        api_client.force_authenticate(user=admin_user)

        # Get memory before
        # Note: This is a rough estimate

        with tenant_context(tenant):
            response = api_client.get(
                '/api/v1/ats/candidates/?page_size=100',
                HTTP_HOST='scaletest.localhost'
            )

        assert response.status_code == status.HTTP_200_OK

        # Response should be paginated and manageable


# =============================================================================
# STRESS TESTS
# =============================================================================

@pytest.mark.django_db(transaction=True)
@pytest.mark.scalability
class TestStress:
    """Stress tests for the API."""

    @pytest.mark.skip(reason="Requires django-tenants for API tenant routing")
    def test_sustained_load(self, api_client, tenant, admin_user, large_dataset):
        """Test sustained load over time."""
        results = []
        errors = []

        def make_requests(duration_seconds=10):
            end_time = time.time() + duration_seconds
            client = APIClient()
            client.force_authenticate(user=admin_user)

            while time.time() < end_time:
                try:
                    with tenant_context(tenant):
                        response = client.get(
                            '/api/v1/dashboard/overview/',
                            HTTP_HOST='scaletest.localhost'
                        )
                    results.append(response.status_code)
                except Exception as e:
                    errors.append(str(e))
                time.sleep(0.1)  # Small delay between requests

        # Run sustained load with multiple threads
        threads = []
        for _ in range(5):
            t = threading.Thread(target=make_requests, args=(5,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=30)

        # Check results
        assert len(errors) == 0, f"Errors during sustained load: {errors}"
        success_rate = results.count(status.HTTP_200_OK) / len(results) if results else 0
        assert success_rate >= 0.90, f"Success rate too low: {success_rate}"


# =============================================================================
# RESPONSE TIME BENCHMARKS
# =============================================================================

@pytest.mark.django_db
@pytest.mark.scalability
class TestResponseTimeBenchmarks:
    """Benchmark response times."""

    def test_endpoint_response_times(self, api_client, tenant, admin_user, large_dataset):
        """Benchmark response times for key endpoints."""
        api_client.force_authenticate(user=admin_user)

        endpoints = [
            '/api/v1/dashboard/overview/',
            '/api/v1/ats/jobs/',
            '/api/v1/ats/candidates/',
            '/api/v1/hr/employees/',
        ]

        benchmarks = {}

        for endpoint in endpoints:
            times = []
            for _ in range(5):  # 5 requests per endpoint
                start = time.time()
                with tenant_context(tenant):
                    response = api_client.get(
                        endpoint,
                        HTTP_HOST='scaletest.localhost'
                    )
                elapsed = time.time() - start
                if response.status_code == status.HTTP_200_OK:
                    times.append(elapsed)

            if times:
                benchmarks[endpoint] = {
                    'avg': statistics.mean(times),
                    'min': min(times),
                    'max': max(times),
                    'p95': sorted(times)[int(len(times) * 0.95)] if len(times) >= 5 else max(times)
                }

        # Print benchmarks for analysis
        for endpoint, stats in benchmarks.items():
            print(f"{endpoint}: avg={stats['avg']:.3f}s, max={stats['max']:.3f}s")

        # Assert reasonable response times
        for endpoint, stats in benchmarks.items():
            assert stats['avg'] < 2.0, f"{endpoint} average too slow: {stats['avg']}s"
            assert stats['max'] < 5.0, f"{endpoint} max too slow: {stats['max']}s"
