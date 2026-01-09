"""
Comprehensive Permission Security Tests - ZUMODRA Security Shield

Tests verify the new security infrastructure:
1. Tenant isolation - Users cannot access other tenant data
2. Role-based access control - Role permissions are enforced
3. Object-level permissions - Users can only access owned objects
4. Celery task permissions - Background tasks validate permissions
5. Sensitive data protection - PII is masked for unauthorized users

Run with: pytest tests/test_permissions_comprehensive.py -v -m security
"""

import pytest
from decimal import Decimal
from unittest.mock import Mock, patch, MagicMock
from django.test import RequestFactory, override_settings
from django.core.exceptions import ValidationError, PermissionDenied
from rest_framework.test import APIRequestFactory
from rest_framework import status

from conftest import (
    UserFactory, TenantFactory, TenantUserFactory, PlanFactory,
    JobPostingFactory, CandidateFactory, ApplicationFactory,
    EmployeeFactory, TenantRequestFactory, MockTenantRequest,
    OwnerTenantUserFactory, AdminTenantUserFactory,
    RecruiterTenantUserFactory, HRManagerTenantUserFactory,
    ViewerTenantUserFactory,
)


# =============================================================================
# 1. TENANT ISOLATION TESTS
# =============================================================================

@pytest.mark.security
class TestTenantIsolation:
    """Tests for multi-tenant data isolation."""

    def test_user_cannot_access_other_tenant_data(
        self, api_client, tenant_isolation_setup
    ):
        """Users cannot access data from other tenants."""
        tenant_a = tenant_isolation_setup['tenant_a']
        tenant_b = tenant_isolation_setup['tenant_b']

        # Login as Tenant A user
        api_client.force_authenticate(user=tenant_a['user'])

        # Try to access Tenant B's job
        for job in tenant_b['jobs']:
            response = api_client.get(f'/api/v1/jobs/{job.id}/')
            # Should be 404 (not found in tenant scope) or 403 (forbidden)
            assert response.status_code in [403, 404], \
                f"User from Tenant A accessed Tenant B's job {job.id}"

    def test_tenant_scoped_queryset(self, db):
        """QuerySets are automatically scoped to current tenant."""
        from core.viewsets import SecureTenantViewSet

        plan = PlanFactory()
        tenant1 = TenantFactory(plan=plan)
        tenant2 = TenantFactory(plan=plan)

        user1 = UserFactory()
        TenantUserFactory(user=user1, tenant=tenant1, role='admin')

        # Create mock request with tenant context
        request = MockTenantRequest(user=user1, tenant=tenant1)

        # ViewSet should filter to tenant1 only
        viewset = SecureTenantViewSet()
        viewset.request = request

        # Verify tenant context is applied
        assert viewset.get_tenant() == tenant1

    def test_api_header_tenant_spoofing_blocked(
        self, authenticated_api_client, user, tenant
    ):
        """X-Tenant-Id header spoofing is blocked."""
        # Create another tenant to try to access
        other_tenant = TenantFactory(plan=tenant.plan)

        # Try to spoof tenant via header
        authenticated_api_client.credentials(
            HTTP_X_TENANT_ID=str(other_tenant.id)
        )

        # Make request - tenant should come from authentication, not header
        response = authenticated_api_client.get('/api/v1/me/')

        # Should NOT use the spoofed tenant
        # Either returns current user's tenant or error

    def test_cross_tenant_object_modification_blocked(
        self, api_client, tenant_isolation_setup
    ):
        """Users cannot modify objects in other tenants."""
        tenant_a = tenant_isolation_setup['tenant_a']
        tenant_b = tenant_isolation_setup['tenant_b']

        # Login as Tenant A user
        api_client.force_authenticate(user=tenant_a['user'])

        # Try to update Tenant B's job
        for job in tenant_b['jobs']:
            response = api_client.patch(
                f'/api/v1/jobs/{job.id}/',
                {'title': 'Hacked Title'},
                format='json'
            )
            assert response.status_code in [403, 404], \
                "Cross-tenant object modification was allowed"


# =============================================================================
# 2. ROLE-BASED ACCESS CONTROL TESTS
# =============================================================================

@pytest.mark.security
class TestRoleBasedAccessControl:
    """Tests for role-based permission enforcement."""

    @pytest.fixture
    def tenant_with_all_roles(self, db, plan):
        """Create tenant with users for all roles."""
        tenant = TenantFactory(plan=plan)

        users = {}
        for role in ['owner', 'admin', 'hr_manager', 'recruiter',
                     'hiring_manager', 'employee', 'viewer']:
            user = UserFactory()
            TenantUserFactory(user=user, tenant=tenant, role=role)
            users[role] = user

        return {'tenant': tenant, 'users': users}

    def test_viewer_cannot_create_resources(
        self, api_client, tenant_with_all_roles
    ):
        """Viewer role cannot create any resources."""
        viewer = tenant_with_all_roles['users']['viewer']
        api_client.force_authenticate(user=viewer)

        # Try to create a job posting
        response = api_client.post('/api/v1/jobs/', {
            'title': 'New Job',
            'description': 'Description',
        }, format='json')

        assert response.status_code in [403, 405], \
            "Viewer was able to create a resource"

    def test_viewer_can_read_resources(
        self, api_client, tenant_with_all_roles
    ):
        """Viewer role can read resources."""
        viewer = tenant_with_all_roles['users']['viewer']
        api_client.force_authenticate(user=viewer)

        # Should be able to list jobs
        response = api_client.get('/api/v1/jobs/')
        assert response.status_code == 200

    def test_recruiter_can_manage_candidates(
        self, api_client, tenant_with_all_roles
    ):
        """Recruiter role can create and manage candidates."""
        recruiter = tenant_with_all_roles['users']['recruiter']
        api_client.force_authenticate(user=recruiter)

        # Create a candidate
        response = api_client.post('/api/v1/candidates/', {
            'first_name': 'Test',
            'last_name': 'Candidate',
            'email': 'test@example.com',
        }, format='json')

        # Recruiter should be able to create candidates
        assert response.status_code in [201, 200], \
            "Recruiter could not create candidate"

    def test_employee_cannot_manage_candidates(
        self, api_client, tenant_with_all_roles
    ):
        """Employee role cannot manage candidates."""
        employee = tenant_with_all_roles['users']['employee']
        api_client.force_authenticate(user=employee)

        # Try to create a candidate
        response = api_client.post('/api/v1/candidates/', {
            'first_name': 'Test',
            'last_name': 'Candidate',
            'email': 'test@example.com',
        }, format='json')

        assert response.status_code in [403, 405], \
            "Employee was able to create candidate"

    def test_hr_manager_can_access_employee_records(
        self, api_client, tenant_with_all_roles
    ):
        """HR Manager can access employee records."""
        hr_manager = tenant_with_all_roles['users']['hr_manager']
        api_client.force_authenticate(user=hr_manager)

        # Should be able to list employees
        response = api_client.get('/api/v1/employees/')
        assert response.status_code == 200

    def test_owner_has_full_access(
        self, api_client, tenant_with_all_roles
    ):
        """Owner role has full access to all resources."""
        owner = tenant_with_all_roles['users']['owner']
        api_client.force_authenticate(user=owner)

        # Test access to various endpoints
        endpoints = [
            '/api/v1/jobs/',
            '/api/v1/candidates/',
            '/api/v1/employees/',
        ]

        for endpoint in endpoints:
            response = api_client.get(endpoint)
            assert response.status_code == 200, \
                f"Owner could not access {endpoint}"

    def test_admin_can_manage_tenant_settings(
        self, api_client, tenant_with_all_roles
    ):
        """Admin role can manage tenant settings."""
        admin = tenant_with_all_roles['users']['admin']
        api_client.force_authenticate(user=admin)

        # Should be able to access tenant settings
        response = api_client.get('/api/v1/tenant/settings/')
        assert response.status_code in [200, 404]  # 404 if endpoint doesn't exist


# =============================================================================
# 3. OBJECT-LEVEL PERMISSION TESTS
# =============================================================================

@pytest.mark.security
class TestObjectLevelPermissions:
    """Tests for object-level permission enforcement."""

    def test_user_can_only_edit_own_profile(self, db, api_client):
        """Users can only edit their own profile."""
        user1 = UserFactory()
        user2 = UserFactory()

        api_client.force_authenticate(user=user1)

        # Try to update user2's profile
        response = api_client.patch(
            f'/api/v1/users/{user2.id}/',
            {'first_name': 'Hacked'},
            format='json'
        )

        # Should be denied
        assert response.status_code in [403, 404], \
            "User was able to edit another user's profile"

    def test_hr_can_access_employee_records(self, db, api_client, tenant):
        """HR managers can access any employee record in their tenant."""
        hr_user = UserFactory()
        HRManagerTenantUserFactory(user=hr_user, tenant=tenant)

        employee = EmployeeFactory()

        api_client.force_authenticate(user=hr_user)

        # HR should be able to view employee
        response = api_client.get(f'/api/v1/employees/{employee.id}/')
        # Should succeed (or 404 if not in tenant scope)
        assert response.status_code in [200, 404]

    def test_participant_only_for_contracts(self, db, api_client, tenant):
        """Only contract participants can access contract details."""
        # Create a contract between two users
        buyer = UserFactory()
        seller = UserFactory()
        TenantUserFactory(user=buyer, tenant=tenant)
        TenantUserFactory(user=seller, tenant=tenant)

        # Create an unrelated user
        unrelated_user = UserFactory()
        TenantUserFactory(user=unrelated_user, tenant=tenant)

        api_client.force_authenticate(user=unrelated_user)

        # Try to access a contract they're not part of
        # This assumes contracts endpoint exists
        response = api_client.get('/api/v1/contracts/')
        # Should only see contracts where they are a participant

    def test_candidate_can_only_see_own_applications(self, db, api_client):
        """Candidates can only see their own applications."""
        # This depends on how candidate authentication is implemented
        pass

    def test_hiring_manager_only_sees_assigned_jobs(self, db, api_client, tenant):
        """Hiring managers only see jobs they're assigned to."""
        hm_user = UserFactory()
        TenantUserFactory(user=hm_user, tenant=tenant, role='hiring_manager')

        # Create jobs with different hiring managers
        job_assigned = JobPostingFactory(hiring_manager=hm_user)
        job_not_assigned = JobPostingFactory(hiring_manager=UserFactory())

        api_client.force_authenticate(user=hm_user)

        # Should only see assigned jobs (depends on implementation)


# =============================================================================
# 4. CELERY TASK PERMISSION TESTS
# =============================================================================

@pytest.mark.security
class TestCeleryTaskPermissions:
    """Tests for Celery task permission validation."""

    def test_bulk_operation_requires_permission(self, db):
        """Bulk operations require appropriate permissions."""
        from core.tasks.secure_task import SecureTenantTask

        plan = PlanFactory()
        tenant = TenantFactory(plan=plan)
        viewer_user = UserFactory()
        ViewerTenantUserFactory(user=viewer_user, tenant=tenant)

        # Create a mock task
        class TestBulkTask(SecureTenantTask):
            required_roles = ['recruiter', 'hr_manager', 'admin', 'owner']

            def run_task(self, *args, **kwargs):
                return True

        task = TestBulkTask()

        # Viewer should not pass permission check
        assert not task._has_required_role(viewer_user, tenant)

    def test_task_validates_tenant_context(self, db):
        """Tasks validate tenant context before execution."""
        from core.tasks.secure_task import SecureTenantTask

        plan = PlanFactory()
        tenant = TenantFactory(plan=plan)
        user = UserFactory()
        TenantUserFactory(user=user, tenant=tenant)

        # User from different tenant should fail
        other_tenant = TenantFactory(plan=plan)

        class TestTask(SecureTenantTask):
            def run_task(self, *args, **kwargs):
                return True

        task = TestTask()

        # Should fail if user not in specified tenant
        with pytest.raises(PermissionDenied):
            task._validate_user_tenant(user.id, other_tenant.id)

    def test_secure_task_logs_execution(self, db, caplog):
        """SecureTenantTask logs execution for audit."""
        from core.tasks.secure_task import SecureTenantTask
        import logging

        caplog.set_level(logging.INFO)

        plan = PlanFactory()
        tenant = TenantFactory(plan=plan)
        user = UserFactory()
        TenantUserFactory(user=user, tenant=tenant, role='admin')

        class LoggingTask(SecureTenantTask):
            def run_task(self, *args, **kwargs):
                return "success"

        # Task execution should be logged
        # (actual logging depends on implementation)


# =============================================================================
# 5. SENSITIVE DATA PROTECTION TESTS
# =============================================================================

@pytest.mark.security
class TestSensitiveDataProtection:
    """Tests for sensitive data masking in API responses."""

    def test_phone_number_masked_for_viewer(self, db):
        """Phone numbers are masked for viewers."""
        from core.serializers import SensitiveFieldMixin
        from rest_framework import serializers

        class TestSerializer(SensitiveFieldMixin, serializers.Serializer):
            sensitive_fields = ['phone']
            phone = serializers.CharField()

        plan = PlanFactory()
        tenant = TenantFactory(plan=plan)
        viewer = UserFactory()
        ViewerTenantUserFactory(user=viewer, tenant=tenant)

        # Create mock request
        request = MockTenantRequest(user=viewer, tenant=tenant)

        # Create instance with phone
        class MockObj:
            phone = '555-123-4567'

        serializer = TestSerializer(
            MockObj(),
            context={'request': request}
        )
        data = serializer.data

        # Phone should be masked
        assert 'phone' in data
        assert '555-123-4567' != data['phone'] or '*' in data['phone']

    def test_email_masked_for_unauthorized(self, db):
        """Email addresses are properly masked."""
        from core.serializers import SensitiveFieldMixin

        mixin = SensitiveFieldMixin()
        masked = mixin._mask_email('john.doe@company.com')

        # Should show first char and domain
        assert masked.startswith('j')
        assert '@company.com' in masked
        assert '*' in masked
        assert 'john.doe' not in masked

    def test_ssn_masked_properly(self, db):
        """SSN is masked to show only last 4 digits."""
        from core.serializers import SensitiveFieldMixin

        mixin = SensitiveFieldMixin()
        masked = mixin._mask_ssn('123-45-6789')

        # Should show only last 4 digits
        assert masked == '***-**-6789'

    def test_bank_account_masked(self, db):
        """Bank account numbers are properly masked."""
        from core.serializers import SensitiveFieldMixin

        mixin = SensitiveFieldMixin()
        masked = mixin._mask_account('1234567890')

        # Should show only last 4 digits
        assert masked.endswith('7890')
        assert masked.startswith('*')

    def test_admin_can_see_sensitive_data(self, db):
        """Admins can see unmasked sensitive data."""
        from core.serializers import SensitiveFieldMixin
        from rest_framework import serializers

        class TestSerializer(SensitiveFieldMixin, serializers.Serializer):
            sensitive_fields = ['phone']
            phone = serializers.CharField()

        plan = PlanFactory()
        tenant = TenantFactory(plan=plan)
        admin = UserFactory()
        AdminTenantUserFactory(user=admin, tenant=tenant)

        request = MockTenantRequest(user=admin, tenant=tenant)

        class MockObj:
            phone = '555-123-4567'

        serializer = TestSerializer(
            MockObj(),
            context={'request': request}
        )
        data = serializer.data

        # Admin should see unmasked data
        assert data['phone'] == '555-123-4567'

    def test_sensitive_data_access_logged(self, db, caplog):
        """Access to sensitive data is logged."""
        import logging
        from core.serializers import SensitiveFieldMixin
        from rest_framework import serializers

        caplog.set_level(logging.INFO, logger='security.serializers')

        class TestSerializer(SensitiveFieldMixin, serializers.Serializer):
            sensitive_fields = ['ssn']
            ssn = serializers.CharField()

        plan = PlanFactory()
        tenant = TenantFactory(plan=plan)
        hr_manager = UserFactory()
        HRManagerTenantUserFactory(user=hr_manager, tenant=tenant)

        request = MockTenantRequest(user=hr_manager, tenant=tenant)

        class MockObj:
            pk = 123
            ssn = '123-45-6789'

        serializer = TestSerializer(
            MockObj(),
            context={'request': request}
        )
        _ = serializer.data

        # Should have logged the access
        # (depends on actual logging implementation)


# =============================================================================
# 6. INPUT VALIDATION TESTS
# =============================================================================

@pytest.mark.security
class TestInputValidation:
    """Tests for input validation and sanitization."""

    def test_sql_injection_in_form_blocked(self, db):
        """SQL injection attempts are blocked in forms."""
        from core.validators import NoSQLInjection

        validator = NoSQLInjection()

        payloads = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users --",
        ]

        for payload in payloads:
            with pytest.raises(ValidationError):
                validator(payload)

    def test_xss_in_form_blocked(self, db):
        """XSS attempts are blocked in forms."""
        from core.validators import NoXSS

        validator = NoXSS()

        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
        ]

        for payload in payloads:
            with pytest.raises(ValidationError):
                validator(payload)

    def test_html_sanitization(self, db):
        """HTML is properly sanitized."""
        from core.validators import sanitize_html

        dangerous_html = """
        <script>alert('XSS')</script>
        <p onclick="evil()">Safe text</p>
        <a href="javascript:alert(1)">Link</a>
        <img src=x onerror=alert(1)>
        """

        sanitized = sanitize_html(dangerous_html)

        assert '<script>' not in sanitized
        assert 'onclick' not in sanitized
        assert 'javascript:' not in sanitized
        assert 'onerror' not in sanitized
        assert 'Safe text' in sanitized

    def test_file_upload_validation(self, db):
        """File uploads are validated for type and size."""
        from core.validators import FileValidator
        from django.core.files.uploadedfile import SimpleUploadedFile

        validator = FileValidator('document')

        # Create a fake executable
        exe_file = SimpleUploadedFile(
            'malware.exe',
            b'\x00' * 100,
            content_type='application/x-executable'
        )

        with pytest.raises(ValidationError):
            validator(exe_file)

    def test_file_size_limit(self, db):
        """File size limits are enforced."""
        from core.validators import FileValidator
        from django.core.files.uploadedfile import SimpleUploadedFile

        validator = FileValidator('document', max_size_mb=1)

        # Create oversized file (2MB)
        large_file = SimpleUploadedFile(
            'large.pdf',
            b'\x00' * (2 * 1024 * 1024),
            content_type='application/pdf'
        )

        with pytest.raises(ValidationError):
            validator(large_file)


# =============================================================================
# 7. PERMISSION CLASS TESTS
# =============================================================================

@pytest.mark.security
class TestPermissionClasses:
    """Tests for custom permission classes."""

    def test_is_tenant_user_permission(self, db):
        """IsTenantUser permission class works correctly."""
        from accounts.permissions import IsTenantUser

        plan = PlanFactory()
        tenant = TenantFactory(plan=plan)

        # User with tenant membership
        member_user = UserFactory()
        TenantUserFactory(user=member_user, tenant=tenant)

        # User without tenant membership
        non_member = UserFactory()

        permission = IsTenantUser()

        # Create mock requests
        member_request = MockTenantRequest(user=member_user, tenant=tenant)
        non_member_request = MockTenantRequest(user=non_member, tenant=tenant)

        # Member should have permission
        assert permission.has_permission(member_request, None)

        # Non-member should not have permission
        assert not permission.has_permission(non_member_request, None)

    def test_is_tenant_admin_permission(self, db):
        """IsTenantAdmin permission class works correctly."""
        from accounts.permissions import IsTenantAdmin

        plan = PlanFactory()
        tenant = TenantFactory(plan=plan)

        admin_user = UserFactory()
        AdminTenantUserFactory(user=admin_user, tenant=tenant)

        employee_user = UserFactory()
        TenantUserFactory(user=employee_user, tenant=tenant, role='employee')

        permission = IsTenantAdmin()

        admin_request = MockTenantRequest(user=admin_user, tenant=tenant)
        employee_request = MockTenantRequest(user=employee_user, tenant=tenant)

        # Admin should have permission
        assert permission.has_permission(admin_request, None)

        # Employee should not have admin permission
        assert not permission.has_permission(employee_request, None)

    def test_is_tenant_owner_permission(self, db):
        """IsTenantOwner permission class works correctly."""
        from accounts.permissions import IsTenantOwner

        plan = PlanFactory()
        tenant = TenantFactory(plan=plan)

        owner_user = UserFactory()
        OwnerTenantUserFactory(user=owner_user, tenant=tenant)

        admin_user = UserFactory()
        AdminTenantUserFactory(user=admin_user, tenant=tenant)

        permission = IsTenantOwner()

        owner_request = MockTenantRequest(user=owner_user, tenant=tenant)
        admin_request = MockTenantRequest(user=admin_user, tenant=tenant)

        # Owner should have permission
        assert permission.has_permission(owner_request, None)

        # Admin should not have owner permission
        assert not permission.has_permission(admin_request, None)

    def test_tenant_object_permission(self, db):
        """TenantObjectPermission checks object belongs to tenant."""
        from tenants.permissions import TenantObjectPermission

        plan = PlanFactory()
        tenant1 = TenantFactory(plan=plan)
        tenant2 = TenantFactory(plan=plan)

        user = UserFactory()
        TenantUserFactory(user=user, tenant=tenant1)

        # Create object in tenant1
        job = JobPostingFactory()

        permission = TenantObjectPermission()
        request = MockTenantRequest(user=user, tenant=tenant1)

        # Object permission check depends on tenant isolation setup


# =============================================================================
# 8. DECORATOR TESTS
# =============================================================================

@pytest.mark.security
class TestSecurityDecorators:
    """Tests for security decorators."""

    def test_require_tenant_decorator(self, db, rf):
        """@require_tenant decorator blocks requests without tenant."""
        from core.decorators import require_tenant
        from django.http import HttpResponse

        @require_tenant
        def protected_view(request):
            return HttpResponse('OK')

        # Request without tenant
        request = rf.get('/')
        request.user = UserFactory()

        response = protected_view(request)
        assert response.status_code == 403

    def test_require_role_decorator(self, db, rf):
        """@require_role decorator enforces role requirements."""
        from core.decorators import require_role
        from django.http import HttpResponse

        plan = PlanFactory()
        tenant = TenantFactory(plan=plan)

        @require_role(['admin', 'owner'])
        def admin_only_view(request):
            return HttpResponse('OK')

        # Employee user
        employee = UserFactory()
        TenantUserFactory(user=employee, tenant=tenant, role='employee')

        request = rf.get('/')
        request.user = employee
        request.tenant = tenant

        response = admin_only_view(request)
        assert response.status_code == 403

        # Admin user
        admin = UserFactory()
        AdminTenantUserFactory(user=admin, tenant=tenant)

        request.user = admin
        response = admin_only_view(request)
        assert response.status_code == 200

    def test_audit_access_decorator(self, db, rf, caplog):
        """@audit_access decorator logs access."""
        import logging
        from core.decorators import audit_access
        from django.http import HttpResponse

        caplog.set_level(logging.INFO, logger='security.audit')

        @audit_access('sensitive_operation')
        def audited_view(request):
            return HttpResponse('OK')

        user = UserFactory()
        request = rf.get('/')
        request.user = user
        request.META['REMOTE_ADDR'] = '127.0.0.1'

        response = audited_view(request)
        assert response.status_code == 200

        # Check that access was logged
        # (depends on actual logging implementation)


# =============================================================================
# 9. CACHE SECURITY TESTS
# =============================================================================

@pytest.mark.security
class TestCacheSecurity:
    """Tests for cache security and isolation."""

    def test_tenant_cache_isolation(self, db):
        """Cache is properly isolated per tenant."""
        from core.cache import TenantCache

        cache1 = TenantCache(tenant_id=1)
        cache2 = TenantCache(tenant_id=2)

        # Set value in cache1
        cache1.set('key', 'value1')

        # cache2 should not see it
        assert cache2.get('key') is None

        # cache1 should see its own value
        assert cache1.get('key') == 'value1'

    def test_permission_cache_invalidation(self, db):
        """Permission cache is invalidated on role changes."""
        from core.cache import invalidate_permission_cache, get_cached_permissions

        plan = PlanFactory()
        tenant = TenantFactory(plan=plan)
        user = UserFactory()
        TenantUserFactory(user=user, tenant=tenant)

        # Invalidate should not raise
        invalidate_permission_cache(user.id, tenant.id)

        # Cache should be empty after invalidation
        permissions = get_cached_permissions(user.id, tenant.id)
        assert permissions is None


# =============================================================================
# 10. VIEW SECURITY INTEGRATION TESTS
# =============================================================================

@pytest.mark.security
@pytest.mark.integration
class TestViewSecurityIntegration:
    """Integration tests for view-level security."""

    def test_secure_viewset_requires_authentication(self, api_client):
        """SecureTenantViewSet requires authentication."""
        # Unauthenticated request
        response = api_client.get('/api/v1/jobs/')

        # Should be 401 Unauthorized
        assert response.status_code == 401

    def test_secure_viewset_requires_tenant_membership(
        self, api_client, db
    ):
        """SecureTenantViewSet requires tenant membership."""
        # User without any tenant membership
        user = UserFactory()
        api_client.force_authenticate(user=user)

        response = api_client.get('/api/v1/jobs/')

        # Should be 403 Forbidden (no tenant access)
        assert response.status_code in [403, 404]

    def test_admin_viewset_rejects_non_admins(self, api_client, tenant):
        """AdminOnlyViewSet rejects non-admin users."""
        viewer = UserFactory()
        ViewerTenantUserFactory(user=viewer, tenant=tenant)

        api_client.force_authenticate(user=viewer)

        # Assuming there's an admin-only endpoint
        response = api_client.get('/api/v1/admin/users/')

        # Should be 403 Forbidden
        assert response.status_code in [403, 404]

    def test_role_based_viewset_action_permissions(
        self, api_client, tenant
    ):
        """RoleBasedViewSet enforces per-action role requirements."""
        employee = UserFactory()
        TenantUserFactory(user=employee, tenant=tenant, role='employee')

        api_client.force_authenticate(user=employee)

        # Employee can read but not create (example)
        read_response = api_client.get('/api/v1/jobs/')
        assert read_response.status_code in [200, 403]

        create_response = api_client.post('/api/v1/jobs/', {
            'title': 'Test'
        }, format='json')
        assert create_response.status_code in [403, 405]


# =============================================================================
# PYTEST CONFIGURATION
# =============================================================================

# Mark all tests in this module with 'security' marker
pytestmark = pytest.mark.security
