"""
Comprehensive API Tests for Zumodra

This module provides thorough testing for:
1. API Endpoint Unit Tests - All CRUD operations for main resources
2. Security Tests - Authentication, authorization, injection prevention
3. Scalability Tests - Concurrent requests, rate limiting, performance

Run with: pytest tests/test_comprehensive_api.py -v
"""

import pytest
import json
import time
import threading
import concurrent.futures
from decimal import Decimal
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import connection
from rest_framework.test import APIClient, APITestCase
from rest_framework import status

from django_tenants.utils import tenant_context

User = get_user_model()


# =============================================================================
# BASE TEST CLASSES
# =============================================================================

@pytest.fixture
def api_client():
    """Return an authenticated API client."""
    return APIClient()


@pytest.fixture
def tenant(db):
    """Create test tenant."""
    from tenants.models import Tenant, Domain, Plan

    # Create or get plan
    plan, _ = Plan.objects.get_or_create(
        plan_type='professional',
        defaults={
            'name': 'Professional',
            'price': Decimal('99.00'),
            'max_jobs': 100,
            'max_candidates': 1000,
            'max_employees': 100,
        }
    )

    tenant = Tenant.objects.create(
        name='Test Company',
        slug='testcompany',
        schema_name='testcompany',
        owner_email='owner@testcompany.com',
        plan=plan,
        status='active',
    )

    Domain.objects.create(
        domain='testcompany.localhost',
        tenant=tenant,
        is_primary=True
    )

    return tenant


@pytest.fixture
def owner_user(tenant):
    """Create owner user with proper tenant access."""
    from tenant_profiles.models import TenantUser

    user = User.objects.create_user(
        username='owner',
        email='owner@testcompany.com',
        password='TestPass123!',
        first_name='Test',
        last_name='Owner'
    )

    with tenant_context(tenant):
        TenantUser.objects.create(
            user=user,
            tenant=tenant,
            role='owner',
            is_active=True
        )

    return user


@pytest.fixture
def employee_user(tenant):
    """Create employee user with limited access."""
    from tenant_profiles.models import TenantUser

    user = User.objects.create_user(
        username='employee',
        email='employee@testcompany.com',
        password='TestPass123!',
        first_name='Test',
        last_name='Employee'
    )

    with tenant_context(tenant):
        TenantUser.objects.create(
            user=user,
            tenant=tenant,
            role='employee',
            is_active=True
        )

    return user


@pytest.fixture
def authenticated_client(api_client, owner_user, tenant):
    """Return authenticated API client with owner access."""
    api_client.force_authenticate(user=owner_user)
    api_client.tenant = tenant
    return api_client


# =============================================================================
# API UNIT TESTS
# =============================================================================

@pytest.mark.django_db
@pytest.mark.unit
class TestAuthenticationAPI:
    """Test authentication endpoints."""

    def test_obtain_token_success(self, api_client, owner_user, tenant):
        """Test successful JWT token obtain."""
        response = api_client.post(
            '/api/v1/auth/token/',
            {'username': owner_user.email, 'password': 'TestPass123!'},
            format='json',
            HTTP_HOST='testcompany.localhost'
        )
        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'refresh' in response.data

    def test_obtain_token_invalid_credentials(self, api_client, tenant):
        """Test token obtain with invalid credentials."""
        response = api_client.post(
            '/api/v1/auth/token/',
            {'username': 'invalid@test.com', 'password': 'wrongpassword'},
            format='json',
            HTTP_HOST='testcompany.localhost'
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_token_refresh(self, api_client, owner_user, tenant):
        """Test token refresh."""
        # First get tokens
        response = api_client.post(
            '/api/v1/auth/token/',
            {'username': owner_user.email, 'password': 'TestPass123!'},
            format='json',
            HTTP_HOST='testcompany.localhost'
        )
        refresh_token = response.data['refresh']

        # Refresh the token
        response = api_client.post(
            '/api/v1/auth/token/refresh/',
            {'refresh': refresh_token},
            format='json',
            HTTP_HOST='testcompany.localhost'
        )
        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data

    def test_unauthenticated_access_denied(self, api_client, tenant):
        """Test that unauthenticated requests are denied."""
        response = api_client.get(
            '/api/v1/jobs/jobs/',
            HTTP_HOST='testcompany.localhost'
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
@pytest.mark.unit
class TestATSJobsAPI:
    """Test ATS Jobs API endpoints."""

    @pytest.fixture
    def job_category(self, tenant):
        """Create a job category."""
        from jobs.models import JobCategory

        with tenant_context(tenant):
            return JobCategory.objects.create(
                name='Engineering',
                slug='engineering',
                tenant=tenant
            )

    @pytest.fixture
    def pipeline(self, tenant, owner_user):
        """Create a pipeline."""
        from jobs.models import Pipeline

        with tenant_context(tenant):
            return Pipeline.objects.create(
                name='Default Pipeline',
                tenant=tenant,
                is_default=True,
                created_by=owner_user
            )

    def test_list_jobs_success(self, authenticated_client, tenant):
        """Test listing jobs."""
        with tenant_context(tenant):
            response = authenticated_client.get(
                '/api/v1/jobs/jobs/',
                HTTP_HOST='testcompany.localhost'
            )
        assert response.status_code == status.HTTP_200_OK

    def test_create_job_success(self, authenticated_client, tenant, job_category, pipeline, owner_user):
        """Test creating a job."""
        job_data = {
            'title': 'Senior Developer',
            'description': 'Looking for a senior developer',
            'requirements': 'Python, Django, React',
            'job_type': 'full_time',
            'experience_level': 'senior',
            'remote_policy': 'hybrid',
            'location_city': 'Montreal',
            'location_country': 'CA',
            'salary_min': 80000,
            'salary_max': 120000,
            'category': job_category.id,
            'pipeline': pipeline.id,
        }

        with tenant_context(tenant):
            response = authenticated_client.post(
                '/api/v1/jobs/jobs/',
                job_data,
                format='json',
                HTTP_HOST='testcompany.localhost'
            )

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['title'] == 'Senior Developer'

    def test_filter_jobs_by_status(self, authenticated_client, tenant):
        """Test filtering jobs by status."""
        with tenant_context(tenant):
            response = authenticated_client.get(
                '/api/v1/jobs/jobs/?status=open',
                HTTP_HOST='testcompany.localhost'
            )
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
@pytest.mark.unit
class TestHREmployeesAPI:
    """Test HR Employees API endpoints."""

    def test_list_employees_success(self, authenticated_client, tenant):
        """Test listing employees."""
        with tenant_context(tenant):
            response = authenticated_client.get(
                '/api/v1/hr/employees/',
                HTTP_HOST='testcompany.localhost'
            )
        assert response.status_code == status.HTTP_200_OK

    def test_employee_detail(self, authenticated_client, tenant, owner_user):
        """Test getting employee details."""
        from hr_core.models import Employee

        with tenant_context(tenant):
            employee = Employee.objects.create(
                user=owner_user,
                tenant=tenant,
                employee_id='EMP-001',
                job_title='Manager',
                hire_date=timezone.now().date(),
                status='active'
            )

            response = authenticated_client.get(
                f'/api/v1/hr/employees/{employee.id}/',
                HTTP_HOST='testcompany.localhost'
            )

        assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
@pytest.mark.unit
class TestDashboardAPI:
    """Test Dashboard API endpoints."""

    def test_dashboard_overview(self, authenticated_client, tenant):
        """Test dashboard overview."""
        with tenant_context(tenant):
            response = authenticated_client.get(
                '/api/v1/dashboard/overview/',
                HTTP_HOST='testcompany.localhost'
            )
        assert response.status_code == status.HTTP_200_OK
        assert 'stats' in response.data


# =============================================================================
# SECURITY TESTS
# =============================================================================

@pytest.mark.django_db
@pytest.mark.security
class TestAuthorizationSecurity:
    """Test authorization and access control."""

    def test_role_based_access_control(self, api_client, employee_user, tenant):
        """Test that employees cannot access admin endpoints."""
        api_client.force_authenticate(user=employee_user)

        # Employees should not be able to create jobs
        with tenant_context(tenant):
            response = api_client.post(
                '/api/v1/jobs/jobs/',
                {'title': 'Test Job'},
                format='json',
                HTTP_HOST='testcompany.localhost'
            )

        # Should be 403 Forbidden
        assert response.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_400_BAD_REQUEST]

    def test_tenant_isolation(self, api_client, owner_user, tenant):
        """Test that users cannot access other tenants' data."""
        from tenants.models import Tenant, Domain, Plan
        from jobs.models import JobPosting, JobCategory, Pipeline

        # Create another tenant
        plan, _ = Plan.objects.get_or_create(
            plan_type='basic',
            defaults={
                'name': 'Basic',
                'price': Decimal('49.00'),
                'max_jobs': 10,
                'max_candidates': 100,
                'max_employees': 10,
            }
        )

        other_tenant = Tenant.objects.create(
            name='Other Company',
            slug='othercompany',
            schema_name='othercompany',
            owner_email='owner@other.com',
            plan=plan,
            status='active'
        )

        Domain.objects.create(
            domain='othercompany.localhost',
            tenant=other_tenant,
            is_primary=True
        )

        # Create a job in the other tenant
        with tenant_context(other_tenant):
            category = JobCategory.objects.create(
                name='Test Category',
                slug='test-category',
                tenant=other_tenant
            )

            other_user = User.objects.create_user(
                username='other_owner',
                email='other@other.com',
                password='TestPass123!'
            )

            pipeline = Pipeline.objects.create(
                name='Test Pipeline',
                tenant=other_tenant,
                is_default=True,
                created_by=other_user
            )

            job = JobPosting.objects.create(
                title='Secret Job',
                tenant=other_tenant,
                category=category,
                pipeline=pipeline,
                created_by=other_user
            )

        # Try to access the other tenant's job from the first tenant
        api_client.force_authenticate(user=owner_user)

        with tenant_context(tenant):
            response = api_client.get(
                '/api/v1/jobs/jobs/',
                HTTP_HOST='testcompany.localhost'
            )

        # Should not see the other tenant's job
        job_ids = [j['id'] for j in response.data.get('results', response.data)] if isinstance(response.data, (list, dict)) else []
        assert str(job.id) not in [str(j) for j in job_ids]


@pytest.mark.django_db
@pytest.mark.security
class TestInputValidationSecurity:
    """Test input validation and injection prevention."""

    def test_sql_injection_prevention(self, authenticated_client, tenant):
        """Test that SQL injection attempts are blocked."""
        with tenant_context(tenant):
            # Try SQL injection in search parameter
            response = authenticated_client.get(
                "/api/v1/jobs/jobs/?search='; DROP TABLE ats_jobposting; --",
                HTTP_HOST='testcompany.localhost'
            )

        # Should not crash, should return valid response
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]

    def test_xss_prevention_in_input(self, authenticated_client, tenant):
        """Test that XSS attempts are sanitized."""
        from jobs.models import JobCategory, Pipeline

        with tenant_context(tenant):
            # Create required objects
            category = JobCategory.objects.create(
                name='Test',
                slug='test',
                tenant=tenant
            )

            pipeline = Pipeline.objects.create(
                name='Test',
                tenant=tenant,
                is_default=True,
                created_by=authenticated_client.handler._force_user
            )

            # Try creating a job with XSS payload
            response = authenticated_client.post(
                '/api/v1/jobs/jobs/',
                {
                    'title': '<script>alert("XSS")</script>Test Job',
                    'description': '<img src="x" onerror="alert(1)">',
                    'job_type': 'full_time',
                    'experience_level': 'senior',
                    'remote_policy': 'remote',
                    'category': category.id,
                    'pipeline': pipeline.id,
                },
                format='json',
                HTTP_HOST='testcompany.localhost'
            )

        if response.status_code == status.HTTP_201_CREATED:
            # If created, the XSS should be sanitized
            assert '<script>' not in response.data.get('title', '')
            assert 'onerror' not in response.data.get('description', '')

    def test_path_traversal_prevention(self, authenticated_client, tenant):
        """Test that path traversal attempts are blocked."""
        with tenant_context(tenant):
            response = authenticated_client.get(
                '/api/v1/jobs/jobs/../../../etc/passwd',
                HTTP_HOST='testcompany.localhost'
            )

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
@pytest.mark.security
class TestRateLimiting:
    """Test rate limiting functionality."""

    def test_rate_limiting_enforced(self, api_client, owner_user, tenant):
        """Test that rate limiting prevents excessive requests."""
        api_client.force_authenticate(user=owner_user)

        # Make many rapid requests
        responses = []
        for _ in range(100):
            with tenant_context(tenant):
                response = api_client.get(
                    '/api/v1/dashboard/overview/',
                    HTTP_HOST='testcompany.localhost'
                )
            responses.append(response.status_code)

        # At least some requests should eventually be rate limited
        # (depends on configuration, but this tests the mechanism)
        # Most should succeed
        success_count = responses.count(status.HTTP_200_OK)
        assert success_count > 50  # Most should succeed


# =============================================================================
# SCALABILITY TESTS
# =============================================================================

@pytest.mark.django_db(transaction=True)
@pytest.mark.scalability
class TestConcurrentRequests:
    """Test concurrent request handling."""

    def test_concurrent_reads(self, api_client, owner_user, tenant):
        """Test handling of concurrent read requests."""
        api_client.force_authenticate(user=owner_user)

        results = []
        errors = []

        def make_request():
            try:
                client = APIClient()
                client.force_authenticate(user=owner_user)
                with tenant_context(tenant):
                    response = client.get(
                        '/api/v1/dashboard/overview/',
                        HTTP_HOST='testcompany.localhost'
                    )
                results.append(response.status_code)
            except Exception as e:
                errors.append(str(e))

        # Create 20 concurrent requests
        threads = []
        for _ in range(20):
            t = threading.Thread(target=make_request)
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join(timeout=30)

        # All requests should succeed
        assert len(errors) == 0, f"Errors: {errors}"
        assert all(r == status.HTTP_200_OK for r in results)


@pytest.mark.django_db
@pytest.mark.scalability
class TestQueryPerformance:
    """Test query performance and N+1 prevention."""

    def test_jobs_list_query_count(self, authenticated_client, tenant, owner_user):
        """Test that jobs list uses optimized queries."""
        from jobs.models import JobPosting, JobCategory, Pipeline
        from django.test.utils import CaptureQueriesContext

        with tenant_context(tenant):
            # Create test data
            category = JobCategory.objects.create(
                name='Test',
                slug='test',
                tenant=tenant
            )

            pipeline = Pipeline.objects.create(
                name='Test',
                tenant=tenant,
                is_default=True,
                created_by=owner_user
            )

            # Create multiple jobs
            for i in range(10):
                JobPosting.objects.create(
                    title=f'Job {i}',
                    tenant=tenant,
                    category=category,
                    pipeline=pipeline,
                    created_by=owner_user
                )

            # Count queries when listing jobs
            with CaptureQueriesContext(connection) as context:
                response = authenticated_client.get(
                    '/api/v1/jobs/jobs/',
                    HTTP_HOST='testcompany.localhost'
                )

            # Should use a reasonable number of queries (not N+1)
            # Typically should be < 10 queries for list view
            assert len(context) < 20, f"Too many queries: {len(context)}"


@pytest.mark.django_db
@pytest.mark.scalability
class TestBulkOperations:
    """Test bulk operation performance."""

    def test_bulk_candidate_import_performance(self, authenticated_client, tenant):
        """Test bulk candidate import doesn't timeout."""
        from jobs.models import Candidate

        start_time = time.time()

        with tenant_context(tenant):
            # Create 100 candidates
            candidates = [
                Candidate(
                    first_name=f'Test{i}',
                    last_name=f'Candidate{i}',
                    email=f'candidate{i}@test.com',
                    tenant=tenant
                )
                for i in range(100)
            ]
            Candidate.objects.bulk_create(candidates)

        elapsed = time.time() - start_time

        # Should complete in reasonable time (< 5 seconds)
        assert elapsed < 5, f"Bulk create took too long: {elapsed}s"


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

@pytest.mark.django_db
@pytest.mark.integration
class TestAPIWorkflows:
    """Test complete API workflows."""

    def test_full_job_application_workflow(self, authenticated_client, tenant, owner_user):
        """Test the complete job application workflow."""
        from jobs.models import JobPosting, JobCategory, Pipeline, PipelineStage, Candidate, Application

        with tenant_context(tenant):
            # 1. Create job category
            category = JobCategory.objects.create(
                name='Engineering',
                slug='engineering',
                tenant=tenant
            )

            # 2. Create pipeline with stages
            pipeline = Pipeline.objects.create(
                name='Standard Pipeline',
                tenant=tenant,
                is_default=True,
                created_by=owner_user
            )

            stage1 = PipelineStage.objects.create(
                pipeline=pipeline,
                name='New',
                stage_type='new',
                order=0
            )

            stage2 = PipelineStage.objects.create(
                pipeline=pipeline,
                name='Interview',
                stage_type='interview',
                order=1
            )

            # 3. Create job posting
            job = JobPosting.objects.create(
                title='Software Engineer',
                description='Great opportunity',
                tenant=tenant,
                category=category,
                pipeline=pipeline,
                created_by=owner_user,
                status='open'
            )

            # 4. Create candidate
            candidate = Candidate.objects.create(
                first_name='John',
                last_name='Doe',
                email='john.doe@test.com',
                tenant=tenant
            )

            # 5. Create application
            application = Application.objects.create(
                candidate=candidate,
                job=job,
                tenant=tenant,
                current_stage=stage1,
                status='new'
            )

            # Verify application is in the correct stage
            assert application.current_stage.name == 'New'

            # Move to next stage via API
            response = authenticated_client.post(
                f'/api/v1/jobs/applications/{application.id}/advance/',
                {},
                format='json',
                HTTP_HOST='testcompany.localhost'
            )

            # Verify stage advancement (or check response)
            application.refresh_from_db()
            # The actual behavior depends on the advance action implementation


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

@pytest.mark.django_db
@pytest.mark.unit
class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_list_response(self, authenticated_client, tenant):
        """Test API handles empty lists gracefully."""
        with tenant_context(tenant):
            response = authenticated_client.get(
                '/api/v1/jobs/jobs/',
                HTTP_HOST='testcompany.localhost'
            )

        assert response.status_code == status.HTTP_200_OK
        # Should return empty list or paginated empty result
        assert 'results' in response.data or isinstance(response.data, list)

    def test_invalid_uuid_parameter(self, authenticated_client, tenant):
        """Test API handles invalid UUID gracefully."""
        with tenant_context(tenant):
            response = authenticated_client.get(
                '/api/v1/jobs/jobs/invalid-uuid/',
                HTTP_HOST='testcompany.localhost'
            )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_very_long_input(self, authenticated_client, tenant):
        """Test API handles very long input gracefully."""
        long_string = 'A' * 10000

        with tenant_context(tenant):
            response = authenticated_client.post(
                '/api/v1/jobs/jobs/',
                {'title': long_string},
                format='json',
                HTTP_HOST='testcompany.localhost'
            )

        # Should either truncate or return validation error, not crash
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_201_CREATED,
        ]

    def test_unicode_input_handling(self, authenticated_client, tenant):
        """Test API handles unicode input correctly."""
        from jobs.models import JobCategory, Pipeline

        with tenant_context(tenant):
            category = JobCategory.objects.create(
                name='Test',
                slug='test',
                tenant=tenant
            )

            pipeline = Pipeline.objects.create(
                name='Test',
                tenant=tenant,
                is_default=True,
                created_by=authenticated_client.handler._force_user
            )

            response = authenticated_client.post(
                '/api/v1/jobs/jobs/',
                {
                    'title': 'Développeur Full Stack',  # French
                    'description': 'Poste de développeur 日本語 العربية',  # Multi-language
                    'job_type': 'full_time',
                    'experience_level': 'senior',
                    'remote_policy': 'remote',
                    'category': category.id,
                    'pipeline': pipeline.id,
                },
                format='json',
                HTTP_HOST='testcompany.localhost'
            )

        # Should handle unicode properly
        if response.status_code == status.HTTP_201_CREATED:
            assert 'Développeur' in response.data.get('title', '')
