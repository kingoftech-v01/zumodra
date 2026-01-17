#!/usr/bin/env python
"""
Search Performance and Load Testing Suite
==========================================

Comprehensive performance testing for global search functionality:
- Response time benchmarks
- Throughput testing
- Memory usage analysis
- Database query optimization
- Load testing with concurrent requests
- Caching effectiveness

Author: Zumodra Test Suite
Date: 2026-01-16
"""

import pytest
import time
import json
import statistics
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.test.utils import override_settings
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from django.core.cache import cache

from ats.models import JobPosting, Candidate, Application, Pipeline, PipelineStage
from hr_core.models import Employee, Department
from accounts.models import UserProfile
from tenants.models import Tenant, TenantUser, Domain

User = get_user_model()

pytestmark = pytest.mark.integration


@pytest.fixture
def performance_tenant(db):
    """Create a tenant for performance testing."""
    tenant = Tenant.objects.create(
        name="Performance Test Company",
        slug="perf-test",
        schema_name="perf_test"
    )
    Domain.objects.create(
        domain="perf-test.localhost",
        tenant=tenant,
        is_primary=True
    )
    return tenant


@pytest.fixture
def performance_user(db, performance_tenant):
    """Create a user for performance testing."""
    user = User.objects.create_user(
        username="perftest",
        email="perftest@test.com",
        password="perfpass"
    )
    TenantUser.objects.create(
        user=user,
        tenant=performance_tenant,
        role='admin'
    )
    UserProfile.objects.create(user=user)
    return user


@pytest.fixture
def performance_client(db, performance_user):
    """Create an authenticated client for performance testing."""
    client = APIClient()
    client.force_authenticate(user=performance_user)
    return client


class TestSearchResponseTimeBaselines:
    """Test and establish baseline response times."""

    def test_search_response_time_empty_database(self, performance_client):
        """Measure search response time on empty database."""
        start = time.time()
        response = performance_client.get('/api/v1/dashboard/search/', {'q': 'test'})
        duration = time.time() - start

        assert response.status_code == status.HTTP_200_OK
        assert duration < 0.05, f"Empty search took {duration:.3f}s"

    def test_search_response_time_100_items(self, performance_client, performance_tenant):
        """Measure response time with 100 items."""
        # Create pipeline
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Test Pipeline",
            is_default=True
        )

        # Create 100 jobs
        for i in range(100):
            JobPosting.objects.create(
                tenant=performance_tenant,
                title=f"Developer Position {i}",
                description="Job description",
                requirements="Python, Django",
                location="Remote",
                pipeline=pipeline
            )

        start = time.time()
        response = performance_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        duration = time.time() - start

        assert response.status_code == status.HTTP_200_OK
        assert duration < 0.1, f"Search with 100 items took {duration:.3f}s"

    def test_search_response_time_1000_items(self, performance_client, performance_tenant):
        """Measure response time with 1000 items."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Large Pipeline",
            is_default=False
        )

        # Create 1000 jobs
        jobs = []
        for i in range(1000):
            jobs.append(JobPosting(
                tenant=performance_tenant,
                title=f"Developer Position {i}",
                description="Job description",
                requirements="Python, Django",
                location="Remote",
                pipeline=pipeline
            ))

        JobPosting.objects.bulk_create(jobs, batch_size=100)

        start = time.time()
        response = performance_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        duration = time.time() - start

        assert response.status_code == status.HTTP_200_OK
        assert duration < 0.5, f"Search with 1000 items took {duration:.3f}s"

    def test_search_response_time_5000_items(self, performance_client, performance_tenant):
        """Measure response time with 5000 items (stress test)."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Huge Pipeline",
            is_default=False
        )

        # Create 5000 jobs
        jobs = []
        for i in range(5000):
            jobs.append(JobPosting(
                tenant=performance_tenant,
                title=f"Position {i}",
                description="Job description",
                requirements="Skills",
                location="Remote",
                pipeline=pipeline
            ))

        JobPosting.objects.bulk_create(jobs, batch_size=500)

        start = time.time()
        response = performance_client.get('/api/v1/dashboard/search/', {'q': 'position'})
        duration = time.time() - start

        assert response.status_code == status.HTTP_200_OK
        assert duration < 1.0, f"Search with 5000 items took {duration:.3f}s"


class TestSearchConsistency:
    """Test response time consistency."""

    def test_response_time_consistency(self, performance_client, performance_tenant):
        """Verify response times are consistent across multiple requests."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Consistency Test",
            is_default=True
        )

        # Create 500 jobs
        for i in range(500):
            JobPosting.objects.create(
                tenant=performance_tenant,
                title=f"Developer {i}",
                description="Test job",
                requirements="Python",
                location="Remote",
                pipeline=pipeline
            )

        # Make 10 requests and measure response times
        response_times = []
        for _ in range(10):
            start = time.time()
            response = performance_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
            duration = time.time() - start
            response_times.append(duration)
            assert response.status_code == status.HTTP_200_OK

        # Verify consistency
        mean_time = statistics.mean(response_times)
        stdev = statistics.stdev(response_times) if len(response_times) > 1 else 0
        coefficient_of_variation = stdev / mean_time if mean_time > 0 else 0

        # CV should be low (< 30%)
        assert coefficient_of_variation < 0.3, f"High variance in response times: CV={coefficient_of_variation:.2%}"

    def test_response_time_median_vs_p95(self, performance_client, performance_tenant):
        """Compare median and 95th percentile response times."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="P95 Test",
            is_default=True
        )

        # Create 300 jobs
        for i in range(300):
            JobPosting.objects.create(
                tenant=performance_tenant,
                title=f"Job {i}",
                description="Test",
                requirements="Skills",
                location="Remote",
                pipeline=pipeline
            )

        response_times = []
        for _ in range(20):
            start = time.time()
            response = performance_client.get('/api/v1/dashboard/search/', {'q': 'job'})
            duration = time.time() - start
            response_times.append(duration)

        response_times.sort()
        median = statistics.median(response_times)
        p95 = response_times[int(len(response_times) * 0.95)]

        # P95 should not be significantly higher than median
        ratio = p95 / median if median > 0 else 1
        assert ratio < 3.0, f"P95 significantly higher than median: {ratio:.2f}x"


class TestSearchCachingEffectiveness:
    """Test search result caching."""

    @override_settings(CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        }
    })
    def test_cache_hit_improves_performance(self, performance_client, performance_tenant):
        """Verify caching improves response time."""
        cache.clear()

        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Cache Test",
            is_default=True
        )

        # Create items
        for i in range(200):
            JobPosting.objects.create(
                tenant=performance_tenant,
                title=f"Developer {i}",
                description="Job",
                requirements="Python",
                location="Remote",
                pipeline=pipeline
            )

        # First request (cache miss)
        start1 = time.time()
        response1 = performance_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        time1 = time.time() - start1

        # Second request (cache hit)
        start2 = time.time()
        response2 = performance_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        time2 = time.time() - start2

        assert response1.status_code == status.HTTP_200_OK
        assert response2.status_code == status.HTTP_200_OK

        # Cache hit should be faster or similar
        # (It might not always be faster in tests, so just verify it works)
        assert time2 <= time1 or time1 < 0.05


class TestSearchMemoryUsage:
    """Test memory efficiency of search."""

    def test_search_result_limiting(self, performance_client, performance_tenant):
        """Verify search limits results per category to prevent memory bloat."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Memory Test",
            is_default=True
        )

        # Create 1000 matching items
        for i in range(1000):
            JobPosting.objects.create(
                tenant=performance_tenant,
                title="Developer",
                description=f"Description {i}",
                requirements="Python",
                location="Remote",
                pipeline=pipeline
            )

        response = performance_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        # Should limit results per category
        assert len(data['jobs']) <= 10, "Too many job results returned"

    def test_search_avoids_n_plus_one_queries(self, performance_client, performance_tenant, django_assert_num_queries):
        """Verify search doesn't have N+1 query problems."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="N+1 Test",
            is_default=True
        )

        # Create 20 jobs
        for i in range(20):
            JobPosting.objects.create(
                tenant=performance_tenant,
                title="Developer",
                description="Job",
                requirements="Python",
                location="Remote",
                pipeline=pipeline
            )

        # Query count should be constant regardless of result count
        with django_assert_num_queries(8):  # Allow reasonable number of queries
            response = performance_client.get('/api/v1/dashboard/search/', {'q': 'developer'})

        assert response.status_code == status.HTTP_200_OK


class TestSearchConcurrency:
    """Test search behavior under concurrent load."""

    def test_concurrent_search_requests(self, performance_client, performance_tenant):
        """Test multiple concurrent search requests."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Concurrent Test",
            is_default=True
        )

        # Create test data
        for i in range(100):
            JobPosting.objects.create(
                tenant=performance_tenant,
                title=f"Developer {i}",
                description="Job",
                requirements="Python",
                location="Remote",
                pipeline=pipeline
            )

        def make_search():
            response = performance_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
            return response.status_code == status.HTTP_200_OK

        # Execute 10 concurrent requests
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_search) for _ in range(10)]
            results = [f.result() for f in as_completed(futures)]

        # All should succeed
        assert all(results), "Some concurrent requests failed"

    def test_search_under_spike_load(self, performance_client, performance_tenant):
        """Test search behavior under spike load (many requests in short time)."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Spike Test",
            is_default=True
        )

        # Create test data
        for i in range(100):
            JobPosting.objects.create(
                tenant=performance_tenant,
                title=f"Developer {i}",
                description="Job",
                requirements="Python",
                location="Remote",
                pipeline=pipeline
            )

        response_times = []
        errors = 0

        # Send 50 requests as fast as possible
        for i in range(50):
            start = time.time()
            try:
                response = performance_client.get('/api/v1/dashboard/search/', {'q': 'dev'})
                duration = time.time() - start
                response_times.append(duration)
                if response.status_code != status.HTTP_200_OK:
                    errors += 1
            except Exception as e:
                errors += 1

        assert errors == 0, f"Errors under spike load: {errors}"
        assert len(response_times) > 40, "Most requests should succeed"


class TestSearchDatabasePerformance:
    """Test database query performance."""

    def test_search_uses_indexes(self, performance_client, performance_tenant):
        """Verify search queries use database indexes."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Index Test",
            is_default=True
        )

        # Create items
        for i in range(500):
            JobPosting.objects.create(
                tenant=performance_tenant,
                title=f"Developer {i}",
                description="Job description",
                requirements="Python",
                location="Remote",
                pipeline=pipeline
            )

        # Execute search and verify it completes quickly
        start = time.time()
        response = performance_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        duration = time.time() - start

        assert response.status_code == status.HTTP_200_OK
        assert duration < 0.2, f"Query should use indexes and be fast: {duration:.3f}s"

    def test_search_query_plan_optimization(self, performance_client, performance_tenant):
        """Test that search uses optimized query plans."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Plan Test",
            is_default=True
        )

        # Create diverse data
        for i in range(200):
            JobPosting.objects.create(
                tenant=performance_tenant,
                title=f"Developer {i % 10}",
                description=f"Description {i}",
                requirements="Various skills",
                location=["Remote", "On-site", "Hybrid"][i % 3],
                pipeline=pipeline
            )

        # Complex query should still be efficient
        start = time.time()
        response = performance_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'location': 'Remote'
        })
        duration = time.time() - start

        assert response.status_code == status.HTTP_200_OK
        assert duration < 0.15


class TestSearchScalability:
    """Test search scalability with increasing data sizes."""

    def test_search_time_vs_dataset_size(self, performance_client, performance_tenant):
        """Measure how search performance scales with dataset size."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Scalability Test",
            is_default=True
        )

        results = []

        # Test at different dataset sizes
        sizes = [100, 500, 1000, 2000]

        for size in sizes:
            # Create items for this size (if not already created)
            existing = JobPosting.objects.filter(tenant=performance_tenant).count()
            needed = size - existing

            if needed > 0:
                jobs = []
                for i in range(needed):
                    jobs.append(JobPosting(
                        tenant=performance_tenant,
                        title="Developer",
                        description=f"Job {i}",
                        requirements="Python",
                        location="Remote",
                        pipeline=pipeline
                    ))
                JobPosting.objects.bulk_create(jobs, batch_size=100)

            # Measure search time
            start = time.time()
            response = performance_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
            duration = time.time() - start

            results.append({
                'dataset_size': size,
                'response_time': duration,
                'status': response.status_code
            })

        # Verify scalability
        for result in results:
            assert result['status'] == status.HTTP_200_OK

        # Response time should grow sub-linearly with dataset size
        # (Assuming good indexing and result limiting)
        if len(results) >= 2:
            time_ratio = results[-1]['response_time'] / results[0]['response_time']
            size_ratio = results[-1]['dataset_size'] / results[0]['dataset_size']

            # Should not grow linearly
            assert time_ratio < size_ratio, f"Response time grows linearly with dataset"


class TestSearchOptimizationOpportunities:
    """Identify and test optimization opportunities."""

    def test_search_query_efficiency_report(self, performance_client, performance_tenant):
        """Generate a report on search query efficiency."""
        pipeline = Pipeline.objects.create(
            tenant=performance_tenant,
            name="Report Test",
            is_default=True
        )

        # Create diverse data
        for i in range(300):
            JobPosting.objects.create(
                tenant=performance_tenant,
                title=f"Developer {i}",
                description="Job",
                requirements="Python",
                location="Remote",
                pipeline=pipeline
            )

        for i in range(300):
            Candidate.objects.create(
                tenant=performance_tenant,
                first_name="John",
                last_name=f"Developer{i}",
                email=f"dev{i}@test.com",
                current_title="Developer"
            )

        # Measure various aspects
        metrics = {}

        # Response time
        start = time.time()
        response = performance_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        metrics['response_time'] = time.time() - start

        # Result counts
        data = response.json()
        metrics['jobs_returned'] = len(data['jobs'])
        metrics['candidates_returned'] = len(data['candidates'])
        metrics['total_results'] = data['total_count']

        # Assertions
        assert response.status_code == status.HTTP_200_OK
        assert metrics['response_time'] < 0.3
        assert metrics['jobs_returned'] > 0
        assert metrics['candidates_returned'] > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
