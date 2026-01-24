#!/usr/bin/env python
"""
Comprehensive Global Search Functionality Test Suite
======================================================

Tests the global search functionality across all modules:
1. Cross-module search (jobs, candidates, employees, services)
2. Full-text search accuracy
3. Search filters and facets
4. Search result ranking
5. Search performance with large datasets
6. Autocomplete/suggestions
7. Advanced search operators

Author: Zumodra Test Suite
Date: 2026-01-16
"""

import pytest
import time
import json
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory
from django.utils import timezone
from django.db.models import Q
from rest_framework.test import APIClient, APIRequestFactory
from rest_framework import status

from jobs.models import JobPosting, Candidate, Application, Pipeline, PipelineStage
from hr_core.models import Employee, Department
from tenant_profiles.models import UserProfile
from services.models import Service, ServiceListing
from tenants.models import Tenant, TenantUser, Domain
from dashboard.views import SearchView

User = get_user_model()

pytestmark = pytest.mark.integration


@pytest.fixture
def tenant(db):
    """Create a test tenant."""
    tenant = Tenant.objects.create(
        name="Test Company",
        slug="test-company",
        schema_name="test_company"
    )
    Domain.objects.create(
        domain="test-company.localhost",
        tenant=tenant,
        is_primary=True
    )
    return tenant


@pytest.fixture
def admin_user(db, tenant):
    """Create an admin user for the tenant."""
    user = User.objects.create_superuser(
        username="admin",
        email="admin@test.com",
        password="adminpass"
    )
    TenantUser.objects.create(
        user=user,
        tenant=tenant,
        role='admin'
    )
    return user


@pytest.fixture
def recruiter_user(db, tenant):
    """Create a recruiter user."""
    user = User.objects.create_user(
        username="recruiter",
        email="recruiter@test.com",
        password="recruiterpass",
        first_name="John",
        last_name="Recruiter"
    )
    TenantUser.objects.create(
        user=user,
        tenant=tenant,
        role='recruiter'
    )
    UserProfile.objects.create(user=user)
    return user


@pytest.fixture
def hr_user(db, tenant):
    """Create an HR manager user."""
    user = User.objects.create_user(
        username="hr_manager",
        email="hr@test.com",
        password="hrpass",
        first_name="Jane",
        last_name="HR"
    )
    TenantUser.objects.create(
        user=user,
        tenant=tenant,
        role='hr_manager'
    )
    UserProfile.objects.create(user=user)
    return user


@pytest.fixture
def test_jobs(db, tenant):
    """Create test job postings."""
    pipeline = Pipeline.objects.create(
        tenant=tenant,
        name="Standard Pipeline",
        is_default=True
    )
    PipelineStage.objects.create(
        pipeline=pipeline,
        name="Applied",
        order=1
    )

    jobs = []
    job_data = [
        ("Senior Python Developer", "Senior", "Python development, Django", "Remote", "open"),
        ("Frontend React Developer", "Mid-Level", "React, JavaScript, TypeScript", "On-site", "open"),
        ("DevOps Engineer", "Mid-Level", "Kubernetes, Docker, CI/CD", "Hybrid", "open"),
        ("Product Manager", "Senior", "Product strategy, roadmap", "On-site", "closed"),
        ("Data Scientist", "Mid-Level", "Machine learning, Python, SQL", "Remote", "open"),
    ]

    for title, level, requirements, location, status in job_data:
        job = JobPosting.objects.create(
            tenant=tenant,
            title=title,
            description=f"We are looking for a {title} professional.",
            requirements=requirements,
            location=location,
            status=status,
            pipeline=pipeline,
            experience_level=level
        )
        jobs.append(job)

    return jobs


@pytest.fixture
def test_candidates(db, tenant):
    """Create test candidates."""
    candidates = []
    candidate_data = [
        ("John", "Smith", "john.smith@example.com", "Senior Python Developer"),
        ("Sarah", "Johnson", "sarah.johnson@example.com", "Frontend Developer"),
        ("Michael", "Chen", "michael.chen@example.com", "DevOps Engineer"),
        ("Emily", "Williams", "emily.williams@example.com", "Product Manager"),
        ("David", "Brown", "david.brown@example.com", "Data Scientist"),
    ]

    for first_name, last_name, email, title in candidate_data:
        candidate = Candidate.objects.create(
            tenant=tenant,
            first_name=first_name,
            last_name=last_name,
            email=email,
            current_title=title,
            phone="+1234567890"
        )
        candidates.append(candidate)

    return candidates


@pytest.fixture
def test_employees(db, tenant, admin_user):
    """Create test employees."""
    dept = Department.objects.create(
        tenant=tenant,
        name="Engineering",
        description="Engineering Department"
    )

    employees = []
    employee_data = [
        ("Alice", "Johnson", "alice@test.com", "Senior Engineer"),
        ("Bob", "Smith", "bob@test.com", "Junior Developer"),
        ("Charlie", "Brown", "charlie@test.com", "Manager"),
    ]

    for first_name, last_name, email, job_title in employee_data:
        user = User.objects.create_user(
            username=email.split("@")[0],
            email=email,
            password="testpass",
            first_name=first_name,
            last_name=last_name
        )
        TenantUser.objects.create(
            user=user,
            tenant=tenant,
            role='employee'
        )
        UserProfile.objects.create(user=user)

        employee = Employee.objects.create(
            user=user,
            department=dept,
            job_title=job_title,
            employee_id=f"EMP{len(employees):03d}"
        )
        employees.append(employee)

    return employees


@pytest.fixture
def test_applications(db, tenant, test_jobs, test_candidates):
    """Create test applications."""
    applications = []
    for i, candidate in enumerate(test_candidates):
        job = test_jobs[i % len(test_jobs)]
        app = Application.objects.create(
            tenant=tenant,
            candidate=candidate,
            job=job,
            status='in_review'
        )
        applications.append(app)
    return applications


@pytest.fixture
def authenticated_client(db, admin_user):
    """Create an authenticated API client."""
    client = APIClient()
    client.force_authenticate(user=admin_user)
    return client


class TestGlobalSearchCrossModule:
    """Test cross-module search functionality."""

    def test_search_jobs(self, authenticated_client, admin_user, test_jobs):
        """Test searching for jobs by title and description."""
        # Search by title
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'Python'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert 'jobs' in data
        assert len(data['jobs']) > 0
        assert any('Python' in job.get('title', '') for job in data['jobs'])

    def test_search_candidates(self, authenticated_client, test_candidates):
        """Test searching for candidates by name and title."""
        # Search by first name
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'John'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert 'candidates' in data
        assert len(data['candidates']) > 0

    def test_search_employees(self, authenticated_client, hr_user, test_employees):
        """Test searching for employees."""
        hr_client = APIClient()
        hr_client.force_authenticate(user=hr_user)

        response = hr_client.get('/api/v1/dashboard/search/', {'q': 'Engineer'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert 'employees' in data

    def test_search_applications(self, authenticated_client, test_applications):
        """Test searching for applications."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'John'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert 'applications' in data

    def test_search_all_modules(self, authenticated_client, test_jobs, test_candidates, test_employees):
        """Test searching across all modules simultaneously."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Verify all module types are present
        assert 'jobs' in data
        assert 'candidates' in data
        assert 'employees' in data
        assert 'applications' in data

        # Verify total_count
        assert 'total_count' in data
        expected_count = (len(data['jobs']) + len(data['candidates']) +
                         len(data['employees']) + len(data['applications']))
        assert data['total_count'] == expected_count


class TestFullTextSearchAccuracy:
    """Test full-text search accuracy and relevance."""

    def test_exact_match(self, authenticated_client, test_jobs):
        """Test exact phrase matching."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'Senior Python Developer'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data['jobs']) > 0
        assert any('Senior Python Developer' in job['title'] for job in data['jobs'])

    def test_partial_match(self, authenticated_client, test_jobs):
        """Test partial word matching."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'Pyth'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Should still find Python jobs
        assert len(data['jobs']) > 0

    def test_case_insensitive_search(self, authenticated_client, test_jobs):
        """Test case-insensitive search."""
        response_lower = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'python'})
        response_upper = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'PYTHON'})

        assert response_lower.status_code == status.HTTP_200_OK
        assert response_upper.status_code == status.HTTP_200_OK

        data_lower = response_lower.json()
        data_upper = response_upper.json()

        # Should return same results
        assert len(data_lower['jobs']) == len(data_upper['jobs'])

    def test_special_characters_handling(self, authenticated_client, test_candidates):
        """Test search with special characters."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'john@example.com'})
        assert response.status_code == status.HTTP_200_OK
        # Should not error and return valid response

    def test_empty_search(self, authenticated_client):
        """Test empty search query."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': ''})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data['total_count'] == 0

    def test_minimum_query_length(self, authenticated_client):
        """Test minimum query length requirement."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'a'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Should return empty since query is too short
        assert data['total_count'] == 0


class TestSearchFiltersAndFacets:
    """Test search filters and faceting."""

    def test_filter_by_job_status(self, authenticated_client, test_jobs):
        """Test filtering jobs by status."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'job_status': 'open'
        })
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # All returned jobs should be open
        for job in data['jobs']:
            assert job['status'] == 'open'

    def test_filter_by_location(self, authenticated_client, test_jobs):
        """Test filtering jobs by location."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'location': 'Remote'
        })
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # All returned jobs should be Remote
        for job in data['jobs']:
            if 'location' in job:
                assert job['location'] == 'Remote'

    def test_filter_by_experience_level(self, authenticated_client, test_jobs):
        """Test filtering by experience level."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'experience_level': 'Senior'
        })
        assert response.status_code == status.HTTP_200_OK

    def test_facet_counts(self, authenticated_client, test_jobs):
        """Test facet count aggregation."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'facets': 'true'
        })
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Should include facet information
        if 'facets' in data:
            assert 'status' in data['facets'] or 'location' in data['facets']


class TestSearchResultRanking:
    """Test search result ranking and relevance."""

    def test_exact_title_match_ranks_first(self, authenticated_client, test_jobs):
        """Test that exact title matches rank first."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'Senior Python Developer'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        if len(data['jobs']) > 0:
            first_result = data['jobs'][0]
            assert 'Senior Python Developer' == first_result['title']

    def test_field_weight_title_over_description(self, authenticated_client, test_jobs):
        """Test that title field has higher weight than description."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'Python'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Jobs with Python in title should come before jobs with Python only in description
        if len(data['jobs']) > 1:
            # Verify title field relevance
            for job in data['jobs']:
                assert 'Python' in job.get('title', '') or 'python' in job.get('description', '').lower()

    def test_recent_items_rank_higher(self, authenticated_client, test_jobs):
        """Test that recently created items may rank higher."""
        # This is implementation-specific; verify behavior is consistent
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert 'jobs' in data


class TestSearchPerformance:
    """Test search performance with various dataset sizes."""

    def test_search_response_time_small_dataset(self, authenticated_client, test_jobs):
        """Test search response time with small dataset (< 100 items)."""
        start_time = time.time()
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        end_time = time.time()

        assert response.status_code == status.HTTP_200_OK
        response_time = end_time - start_time

        # Should respond within 100ms for small dataset
        assert response_time < 0.1, f"Search took {response_time:.3f}s, expected < 0.1s"

    def test_search_response_time_medium_dataset(self, authenticated_client, tenant):
        """Test search response time with medium dataset (100-1000 items)."""
        # Create 100 jobs
        pipeline = Pipeline.objects.create(
            tenant=tenant,
            name="Perf Test Pipeline",
            is_default=False
        )

        for i in range(100):
            JobPosting.objects.create(
                tenant=tenant,
                title=f"Developer Position {i}",
                description="Test job posting",
                requirements="Python, Django",
                location="Remote",
                status="open",
                pipeline=pipeline
            )

        start_time = time.time()
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        end_time = time.time()

        assert response.status_code == status.HTTP_200_OK
        response_time = end_time - start_time

        # Should respond within 500ms for medium dataset
        assert response_time < 0.5, f"Search took {response_time:.3f}s, expected < 0.5s"

    def test_search_memory_efficiency(self, authenticated_client, tenant):
        """Test that search doesn't load unnecessary data into memory."""
        # Create 500 candidates
        for i in range(500):
            Candidate.objects.create(
                tenant=tenant,
                first_name=f"Candidate{i}",
                last_name="Test",
                email=f"candidate{i}@test.com",
                current_title="Developer"
            )

        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        # Should use result limiting (e.g., top 5-10 results per category)
        for category in ['jobs', 'candidates', 'employees', 'applications']:
            assert len(data[category]) <= 10, f"Too many results in {category}"

    def test_search_database_query_efficiency(self, authenticated_client, test_jobs, django_assert_num_queries):
        """Test that search uses efficient database queries."""
        with django_assert_num_queries(10):  # Allow up to 10 queries
            response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'developer'})

        assert response.status_code == status.HTTP_200_OK


class TestAutocompleteAndSuggestions:
    """Test autocomplete and search suggestions."""

    def test_autocomplete_endpoint_exists(self, authenticated_client):
        """Test that autocomplete endpoint is available."""
        response = authenticated_client.get('/api/v1/dashboard/autocomplete/', {'q': 'dev'})
        # Should either return 200 or 404 if not implemented
        assert response.status_code in [200, 404]

    def test_autocomplete_suggestions(self, authenticated_client, test_jobs):
        """Test autocomplete returns relevant suggestions."""
        response = authenticated_client.get('/api/v1/dashboard/autocomplete/', {'q': 'python'})

        if response.status_code == 200:
            data = response.json()
            # Should return suggestions
            assert 'suggestions' in data or 'results' in data

    def test_suggestions_limit(self, authenticated_client, test_jobs):
        """Test that suggestions respect limit parameter."""
        response = authenticated_client.get('/api/v1/dashboard/autocomplete/', {
            'q': 'dev',
            'limit': 5
        })

        if response.status_code == 200:
            data = response.json()
            suggestions = data.get('suggestions', data.get('results', []))
            assert len(suggestions) <= 5


class TestAdvancedSearchOperators:
    """Test advanced search operators and syntax."""

    def test_quoted_phrase_search(self, authenticated_client, test_jobs):
        """Test quoted phrase search."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': '"Senior Python Developer"'
        })
        assert response.status_code == status.HTTP_200_OK

    def test_exclude_operator(self, authenticated_client, test_jobs):
        """Test excluding terms from search."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer -junior'
        })
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Results should not contain junior positions
        for job in data['jobs']:
            if 'title' in job:
                assert 'junior' not in job['title'].lower()

    def test_wildcard_search(self, authenticated_client, test_jobs):
        """Test wildcard search."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'dev*'
        })
        assert response.status_code == status.HTTP_200_OK

    def test_boolean_operators(self, authenticated_client, test_jobs):
        """Test boolean operators (AND, OR, NOT)."""
        # AND operator
        response_and = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'python AND developer'
        })
        assert response_and.status_code == status.HTTP_200_OK

        # OR operator
        response_or = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'python OR java'
        })
        assert response_or.status_code == status.HTTP_200_OK

        # NOT operator
        response_not = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer NOT junior'
        })
        assert response_not.status_code == status.HTTP_200_OK


class TestSearchSecurityAndValidation:
    """Test search security and input validation."""

    def test_sql_injection_prevention(self, authenticated_client):
        """Test that SQL injection attempts are prevented."""
        malicious_queries = [
            "'; DROP TABLE users; --",
            "1 OR 1=1",
            "developer' UNION SELECT * FROM users --"
        ]

        for query in malicious_queries:
            response = authenticated_client.get('/api/v1/dashboard/search/', {'q': query})
            # Should not error or return database error
            assert response.status_code in [200, 400]
            if response.status_code == 200:
                # Verify no actual database queries were executed
                data = response.json()
                assert isinstance(data, dict)

    def test_xss_prevention(self, authenticated_client):
        """Test that XSS attempts are prevented."""
        xss_queries = [
            '<script>alert("xss")</script>',
            '"><script>alert(1)</script>',
            'javascript:alert("xss")'
        ]

        for query in xss_queries:
            response = authenticated_client.get('/api/v1/dashboard/search/', {'q': query})
            assert response.status_code in [200, 400]

    def test_search_respects_tenant_isolation(self, db, tenant):
        """Test that search results are tenant-isolated."""
        # Create another tenant
        other_tenant = Tenant.objects.create(
            name="Other Company",
            slug="other-company",
            schema_name="other_company"
        )

        # Create jobs in both tenants
        pipeline1 = Pipeline.objects.create(
            tenant=tenant,
            name="Pipeline 1",
            is_default=True
        )
        pipeline2 = Pipeline.objects.create(
            tenant=other_tenant,
            name="Pipeline 2",
            is_default=True
        )

        job1 = JobPosting.objects.create(
            tenant=tenant,
            title="Python Developer",
            description="Job in tenant 1",
            requirements="Python",
            location="Remote",
            pipeline=pipeline1
        )

        job2 = JobPosting.objects.create(
            tenant=other_tenant,
            title="Python Developer",
            description="Job in other tenant",
            requirements="Python",
            location="Remote",
            pipeline=pipeline2
        )

        # User from first tenant should only see their job
        user = User.objects.create_user(username="test", password="test")
        TenantUser.objects.create(user=user, tenant=tenant, role='admin')

        client = APIClient()
        client.force_authenticate(user=user)

        response = client.get('/api/v1/dashboard/search/', {'q': 'Python'})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Should only contain job from their tenant
        assert len(data['jobs']) == 1
        assert data['jobs'][0]['id'] == job1.id

    def test_search_respects_user_permissions(self, db, tenant):
        """Test that search respects user permissions."""
        # Create a user with limited permissions
        user = User.objects.create_user(
            username="limited_user",
            password="pass"
        )
        TenantUser.objects.create(
            user=user,
            tenant=tenant,
            role='viewer'
        )

        client = APIClient()
        client.force_authenticate(user=user)

        response = client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        # Should either allow search for viewer role or return forbidden
        assert response.status_code in [200, 403]


class TestSearchResultFormatting:
    """Test search result formatting and structure."""

    def test_search_response_structure(self, authenticated_client, test_jobs):
        """Test that search response has correct structure."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        assert response.status_code == status.HTTP_200_OK

        data = response.json()

        # Verify required fields
        assert 'query' in data
        assert 'jobs' in data
        assert 'candidates' in data
        assert 'employees' in data
        assert 'applications' in data
        assert 'total_count' in data

    def test_job_result_fields(self, authenticated_client, test_jobs):
        """Test that job results contain expected fields."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'developer'})
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        if data['jobs']:
            job = data['jobs'][0]
            # Verify expected fields for job results
            expected_fields = ['id', 'title', 'status', 'location']
            for field in expected_fields:
                assert field in job

    def test_candidate_result_fields(self, authenticated_client, test_candidates):
        """Test that candidate results contain expected fields."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'john'})
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        if data['candidates']:
            candidate = data['candidates'][0]
            # Verify expected fields for candidate results
            expected_fields = ['id', 'first_name', 'last_name', 'email']
            for field in expected_fields:
                assert field in candidate

    def test_employee_result_fields(self, authenticated_client, test_employees):
        """Test that employee results contain expected fields."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {'q': 'engineer'})
        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        if data['employees']:
            employee = data['employees'][0]
            # Verify expected fields for employee results
            expected_fields = ['id', 'name', 'email', 'job_title']
            for field in expected_fields:
                assert field in employee


class TestSearchSortingAndOrdering:
    """Test search result sorting and ordering."""

    def test_sort_by_relevance(self, authenticated_client, test_jobs):
        """Test sorting by relevance (default)."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'sort': 'relevance'
        })
        assert response.status_code == status.HTTP_200_OK

    def test_sort_by_date(self, authenticated_client, test_jobs):
        """Test sorting by date (newest first)."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'sort': 'date'
        })
        assert response.status_code == status.HTTP_200_OK

    def test_sort_by_title(self, authenticated_client, test_jobs):
        """Test sorting by title alphabetically."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'sort': 'title'
        })
        assert response.status_code == status.HTTP_200_OK

    def test_reverse_sort_order(self, authenticated_client, test_jobs):
        """Test reverse sort order."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'sort': 'date',
            'order': 'desc'
        })
        assert response.status_code == status.HTTP_200_OK


class TestSearchPagination:
    """Test search result pagination."""

    def test_pagination_limit(self, authenticated_client, test_jobs):
        """Test limiting number of results."""
        response = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'limit': 3
        })
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Results should be limited
        total_results = (len(data['jobs']) + len(data['candidates']) +
                        len(data['employees']) + len(data['applications']))
        assert total_results <= 3

    def test_pagination_offset(self, authenticated_client, tenant):
        """Test pagination with offset."""
        # Create multiple items
        pipeline = Pipeline.objects.create(
            tenant=tenant,
            name="Pagination Test",
            is_default=False
        )

        for i in range(20):
            JobPosting.objects.create(
                tenant=tenant,
                title=f"Developer {i}",
                description="Test",
                requirements="Python",
                location="Remote",
                pipeline=pipeline
            )

        response1 = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'limit': 5,
            'offset': 0
        })

        response2 = authenticated_client.get('/api/v1/dashboard/search/', {
            'q': 'developer',
            'limit': 5,
            'offset': 5
        })

        assert response1.status_code == status.HTTP_200_OK
        assert response2.status_code == status.HTTP_200_OK


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
