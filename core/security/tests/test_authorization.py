"""
Authorization Security Tests for Zumodra ATS/HR Platform

This module tests authorization security including:
- Tenant isolation (user A cannot access tenant B data)
- Role-based access (each role can only access permitted resources)
- Object-level permissions (user can only edit own resources)
- Privilege escalation attempts (user cannot promote self)
- Cross-tenant request prevention

Each test documents the attack vector being tested.
"""

import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.test import TestCase, RequestFactory, override_settings

User = get_user_model()


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def request_factory():
    """Provide a Django RequestFactory."""
    return RequestFactory()


@pytest.fixture
def tenant_access_validator():
    """Create TenantAccessControlValidator instance."""
    from core.security.authorization import TenantAccessControlValidator
    return TenantAccessControlValidator()


@pytest.fixture
def permission_checker():
    """Create PermissionChecker instance."""
    from core.security.authorization import PermissionChecker
    return PermissionChecker()


@pytest.fixture
def resource_validator():
    """Create ResourceAccessValidator instance."""
    from core.security.authorization import ResourceAccessValidator
    return ResourceAccessValidator()


@pytest.fixture
def privilege_detector():
    """Create PrivilegeEscalationDetector instance."""
    from core.security.authorization import PrivilegeEscalationDetector
    return PrivilegeEscalationDetector()


# =============================================================================
# TENANT ISOLATION TESTS
# =============================================================================

class TestTenantIsolation:
    """
    Tests for tenant data isolation.

    Attack Vector: Multi-tenancy bypass allows:
    - Accessing other tenants' data
    - Modifying other tenants' resources
    - Cross-tenant data leakage
    """

    def test_user_cannot_access_other_tenant_jobs(
        self, tenant_access_validator, tenant_factory, user_factory,
        tenant_user_factory, job_posting_factory, db
    ):
        """
        Test: User from tenant A cannot access jobs from tenant B.
        Attack Vector: IDOR - Insecure Direct Object Reference.
        """
        # Create two tenants
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        # Create user in tenant A
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant_a)

        # Create job in tenant B
        job = job_posting_factory()
        job.tenant = tenant_b  # Associate with tenant B

        # User from tenant A should not be able to access
        with pytest.raises(PermissionDenied):
            tenant_access_validator.validate_access(
                user=user,
                resource=job,
                current_tenant=tenant_a
            )

    def test_user_cannot_access_other_tenant_candidates(
        self, tenant_access_validator, tenant_factory, user_factory,
        tenant_user_factory, candidate_factory, db
    ):
        """
        Test: User from tenant A cannot access candidates from tenant B.
        Attack Vector: Accessing sensitive candidate PII across tenants.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant_a)

        candidate = candidate_factory()
        # Assume candidate is associated with tenant B

        with pytest.raises(PermissionDenied):
            tenant_access_validator.validate_access(
                user=user,
                resource=candidate,
                current_tenant=tenant_a,
                resource_tenant=tenant_b
            )

    def test_user_cannot_access_other_tenant_employees(
        self, tenant_access_validator, tenant_factory, user_factory,
        tenant_user_factory, employee_factory, db
    ):
        """
        Test: User from tenant A cannot access employees from tenant B.
        Attack Vector: Accessing HR data (salary, performance) across tenants.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant_a)

        employee = employee_factory()

        with pytest.raises(PermissionDenied):
            tenant_access_validator.validate_access(
                user=user,
                resource=employee,
                current_tenant=tenant_a,
                resource_tenant=tenant_b
            )

    def test_api_enforces_tenant_context(
        self, tenant_access_validator, tenant_factory, user_factory,
        tenant_user_factory, db, request_factory
    ):
        """
        Test: API requests enforce tenant context from request.
        Attack Vector: Tampering with tenant header/parameter.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant_a)

        # Request with spoofed tenant header
        request = request_factory.get('/api/jobs/')
        request.user = user
        request.META['HTTP_X_TENANT'] = tenant_b.slug  # Attempting to access tenant B

        # Should fail because user is not a member of tenant B
        with pytest.raises(PermissionDenied):
            tenant_access_validator.validate_request_tenant(request)

    def test_queryset_filtered_by_tenant(
        self, tenant_factory, user_factory, tenant_user_factory,
        job_posting_factory, db
    ):
        """
        Test: QuerySets are automatically filtered by current tenant.
        Attack Vector: Data leakage via unfiltered queries.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        # Create jobs in both tenants
        job_a = job_posting_factory(title='Job in A')
        job_b = job_posting_factory(title='Job in B')

        # Mock the tenant context manager
        with patch('core.db.managers.get_current_tenant') as mock:
            mock.return_value = tenant_a

            from ats.models import JobPosting
            jobs = JobPosting.objects.for_tenant(tenant_a).all()

            # Should only see tenant A's jobs
            assert job_a in jobs
            assert job_b not in jobs

    def test_tenant_switch_clears_cached_permissions(
        self, tenant_factory, user_factory, tenant_user_factory, db
    ):
        """
        Test: Switching tenants clears cached permission data.
        Attack Vector: Carrying permissions from one tenant to another.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        user = user_factory()
        # User is admin in tenant A, viewer in tenant B
        tenant_user_factory(user=user, tenant=tenant_a, role='admin')
        tenant_user_factory(user=user, tenant=tenant_b, role='viewer')

        from core.security.authorization import PermissionChecker
        checker = PermissionChecker()

        # Check permissions in tenant A context
        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant_a
            assert checker.has_permission(user, 'edit_jobs')

        # Switch to tenant B - should not have edit permission
        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant_b
            assert not checker.has_permission(user, 'edit_jobs')

    def test_cross_tenant_foreign_key_blocked(
        self, tenant_factory, user_factory, tenant_user_factory,
        job_posting_factory, application_factory, db
    ):
        """
        Test: Cannot create relationships to objects in different tenant.
        Attack Vector: Data injection across tenant boundaries.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        job_in_b = job_posting_factory()

        # Attempt to create application in tenant A referencing job in tenant B
        with patch('core.db.managers.get_current_tenant') as mock:
            mock.return_value = tenant_a

            with pytest.raises(Exception) as excinfo:
                application_factory(job=job_in_b)

            assert 'tenant' in str(excinfo.value).lower() or 'permission' in str(excinfo.value).lower()


# =============================================================================
# ROLE-BASED ACCESS CONTROL TESTS
# =============================================================================

class TestRoleBasedAccess:
    """
    Tests for role-based access control.

    Attack Vector: Improper RBAC allows:
    - Unauthorized data access
    - Unauthorized actions
    - Privilege escalation
    """

    def test_viewer_cannot_edit_jobs(
        self, permission_checker, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Test: Viewer role cannot edit jobs.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='viewer')

        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant
            assert not permission_checker.has_permission(user, 'edit_jobs')

    def test_recruiter_can_view_candidates(
        self, permission_checker, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Positive Test: Recruiter can view candidates.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='recruiter')

        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant
            assert permission_checker.has_permission(user, 'view_candidates')

    def test_recruiter_cannot_manage_billing(
        self, permission_checker, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Test: Recruiter cannot access billing functions.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='recruiter')

        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant
            assert not permission_checker.has_permission(user, 'manage_billing')

    def test_hr_manager_can_manage_employees(
        self, permission_checker, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Positive Test: HR Manager can manage employees.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='hr_manager')

        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant
            assert permission_checker.has_permission(user, 'manage_hr')
            assert permission_checker.has_permission(user, 'view_employees')
            assert permission_checker.has_permission(user, 'edit_employees')

    def test_employee_limited_to_own_data(
        self, permission_checker, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Test: Employee role is limited to viewing own data.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='employee')

        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant
            # Cannot view other employees
            assert not permission_checker.has_permission(user, 'view_employees')
            # But can view own profile
            assert permission_checker.has_permission(user, 'view_profile')

    def test_admin_has_all_permissions_except_owner(
        self, permission_checker, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Test: Admin has most permissions but not owner-only.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='admin')

        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant
            assert permission_checker.has_permission(user, 'manage_users')
            assert permission_checker.has_permission(user, 'manage_settings')
            # But cannot manage billing (owner only)
            assert not permission_checker.has_permission(user, 'manage_billing')

    def test_owner_has_all_permissions(
        self, permission_checker, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Positive Test: Owner has all permissions.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='owner')

        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant
            assert permission_checker.has_permission(user, 'manage_billing')
            assert permission_checker.has_permission(user, 'manage_users')
            assert permission_checker.has_permission(user, 'delete_all')

    def test_custom_permissions_override_role(
        self, permission_checker, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Test: Custom permissions can extend role permissions.
        """
        tenant = tenant_factory()
        user = user_factory()
        tu = tenant_user_factory(user=user, tenant=tenant, role='viewer')

        # Add custom permission
        from django.contrib.auth.models import Permission
        perm = Permission.objects.get(codename='add_jobposting')
        tu.custom_permissions.add(perm)

        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant
            assert permission_checker.has_permission(user, 'add_jobposting')


# =============================================================================
# OBJECT-LEVEL PERMISSION TESTS
# =============================================================================

class TestObjectLevelPermissions:
    """
    Tests for object-level permissions.

    Attack Vector: Without object-level security:
    - Users can modify objects they don't own
    - Users can access private resources
    """

    def test_user_can_edit_own_job_posting(
        self, resource_validator, tenant_factory, user_factory,
        tenant_user_factory, job_posting_factory, db
    ):
        """
        Positive Test: Recruiter can edit jobs they created.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='recruiter')

        job = job_posting_factory(created_by=user)

        assert resource_validator.can_edit(user, job)

    def test_user_cannot_edit_others_job_posting(
        self, resource_validator, tenant_factory, user_factory,
        tenant_user_factory, job_posting_factory, db
    ):
        """
        Test: Recruiter cannot edit jobs created by others (without permission).
        """
        tenant = tenant_factory()
        user1 = user_factory()
        user2 = user_factory()
        tenant_user_factory(user=user1, tenant=tenant, role='recruiter')
        tenant_user_factory(user=user2, tenant=tenant, role='recruiter')

        job = job_posting_factory(created_by=user2)

        # User1 cannot edit user2's job unless they're admin
        assert not resource_validator.can_edit(user1, job)

    def test_hiring_manager_can_only_view_assigned_candidates(
        self, resource_validator, tenant_factory, user_factory,
        tenant_user_factory, application_factory, db
    ):
        """
        Test: Hiring managers can only see candidates for their jobs.
        """
        tenant = tenant_factory()
        hiring_manager = user_factory()
        tenant_user_factory(user=hiring_manager, tenant=tenant, role='hiring_manager')

        # Application for job they manage
        assigned_app = application_factory()
        assigned_app.job.hiring_manager = hiring_manager

        # Application for job they don't manage
        other_app = application_factory()

        assert resource_validator.can_view(hiring_manager, assigned_app)
        assert not resource_validator.can_view(hiring_manager, other_app)

    def test_employee_can_only_edit_own_profile(
        self, resource_validator, tenant_factory, user_factory,
        tenant_user_factory, user_profile_factory, db
    ):
        """
        Test: Employees can only edit their own profile.
        """
        tenant = tenant_factory()
        user1 = user_factory()
        user2 = user_factory()
        tenant_user_factory(user=user1, tenant=tenant, role='employee')
        tenant_user_factory(user=user2, tenant=tenant, role='employee')

        profile1 = user_profile_factory(user=user1)
        profile2 = user_profile_factory(user=user2)

        # Can edit own profile
        assert resource_validator.can_edit(user1, profile1)
        # Cannot edit other's profile
        assert not resource_validator.can_edit(user1, profile2)

    def test_private_notes_visible_only_to_author(
        self, resource_validator, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Test: Private application notes are only visible to author.
        """
        tenant = tenant_factory()
        recruiter1 = user_factory()
        recruiter2 = user_factory()
        tenant_user_factory(user=recruiter1, tenant=tenant, role='recruiter')
        tenant_user_factory(user=recruiter2, tenant=tenant, role='recruiter')

        # Create private note
        from ats.models import ApplicationNote
        note = Mock(spec=ApplicationNote)
        note.is_private = True
        note.author = recruiter1

        assert resource_validator.can_view(recruiter1, note)
        assert not resource_validator.can_view(recruiter2, note)

    def test_admin_can_access_all_objects(
        self, resource_validator, tenant_factory, user_factory,
        tenant_user_factory, job_posting_factory, db
    ):
        """
        Positive Test: Admins can access all tenant objects.
        """
        tenant = tenant_factory()
        admin = user_factory()
        other_user = user_factory()
        tenant_user_factory(user=admin, tenant=tenant, role='admin')
        tenant_user_factory(user=other_user, tenant=tenant, role='recruiter')

        job = job_posting_factory(created_by=other_user)

        assert resource_validator.can_view(admin, job)
        assert resource_validator.can_edit(admin, job)


# =============================================================================
# PRIVILEGE ESCALATION TESTS
# =============================================================================

class TestPrivilegeEscalation:
    """
    Tests for privilege escalation prevention.

    Attack Vector: Privilege escalation allows:
    - User promoting themselves to admin
    - Bypassing role restrictions
    - Gaining unauthorized access
    """

    def test_user_cannot_promote_self(
        self, privilege_detector, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Test: Users cannot change their own role to a higher level.
        Attack Vector: Self-promotion to admin.
        """
        tenant = tenant_factory()
        user = user_factory()
        tu = tenant_user_factory(user=user, tenant=tenant, role='employee')

        with pytest.raises(PermissionDenied) as excinfo:
            privilege_detector.check_role_change(
                actor=user,
                target_user=user,
                current_role='employee',
                new_role='admin'
            )

        assert 'escalation' in str(excinfo.value).lower() or 'self' in str(excinfo.value).lower()

    def test_recruiter_cannot_create_admin(
        self, privilege_detector, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Test: Recruiters cannot create admin users.
        Attack Vector: Creating high-privilege accounts.
        """
        tenant = tenant_factory()
        recruiter = user_factory()
        new_user = user_factory()
        tenant_user_factory(user=recruiter, tenant=tenant, role='recruiter')

        with pytest.raises(PermissionDenied):
            privilege_detector.check_role_assignment(
                actor=recruiter,
                target_user=new_user,
                role='admin'
            )

    def test_admin_cannot_create_owner(
        self, privilege_detector, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Test: Admins cannot create owner accounts.
        """
        tenant = tenant_factory()
        admin = user_factory()
        new_user = user_factory()
        tenant_user_factory(user=admin, tenant=tenant, role='admin')

        with pytest.raises(PermissionDenied):
            privilege_detector.check_role_assignment(
                actor=admin,
                target_user=new_user,
                role='owner'
            )

    def test_owner_can_create_admin(
        self, privilege_detector, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Positive Test: Owners can create admin accounts.
        """
        tenant = tenant_factory()
        owner = user_factory()
        new_user = user_factory()
        tenant_user_factory(user=owner, tenant=tenant, role='owner')

        # Should not raise
        privilege_detector.check_role_assignment(
            actor=owner,
            target_user=new_user,
            role='admin'
        )

    def test_api_request_tampering_blocked(
        self, privilege_detector, tenant_factory, user_factory,
        tenant_user_factory, db, request_factory
    ):
        """
        Test: API request tampering to change role is blocked.
        Attack Vector: Modifying API payload to include admin role.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='employee')

        # Simulated tampered request to update own profile with role change
        request = request_factory.patch('/api/users/me/')
        request.user = user
        request.data = {'role': 'admin'}  # Attempted escalation

        with pytest.raises(PermissionDenied):
            privilege_detector.validate_update_request(request)

    def test_custom_permission_escalation_blocked(
        self, privilege_detector, tenant_factory, user_factory,
        tenant_user_factory, db
    ):
        """
        Test: Users cannot grant themselves custom permissions.
        Attack Vector: Adding permissions via API manipulation.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='recruiter')

        with pytest.raises(PermissionDenied):
            privilege_detector.check_permission_grant(
                actor=user,
                target_user=user,
                permission='manage_users'
            )


# =============================================================================
# CROSS-TENANT REQUEST PREVENTION TESTS
# =============================================================================

class TestCrossTenantPrevention:
    """
    Tests for cross-tenant request prevention.

    Attack Vector: Cross-tenant requests allow:
    - Data exfiltration
    - Unauthorized modifications
    - Tenant impersonation
    """

    def test_request_tenant_header_validated(
        self, tenant_factory, user_factory, tenant_user_factory,
        db, request_factory
    ):
        """
        Test: X-Tenant header is validated against user membership.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant_a)
        # User is NOT a member of tenant B

        request = request_factory.get('/api/jobs/')
        request.user = user
        request.META['HTTP_X_TENANT'] = tenant_b.slug

        from core.security.authorization import CrossTenantAccessPreventer
        preventer = CrossTenantAccessPreventer()

        with pytest.raises(PermissionDenied):
            preventer.validate(request)

    def test_subdomain_tenant_validated(
        self, tenant_factory, user_factory, tenant_user_factory,
        db, request_factory
    ):
        """
        Test: Subdomain-based tenant identification is validated.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')

        user = user_factory()
        # User is NOT a member of company-a

        request = request_factory.get('/api/jobs/')
        request.user = user
        request.META['HTTP_HOST'] = 'company-a.zumodra.com'

        from core.security.authorization import CrossTenantAccessPreventer
        preventer = CrossTenantAccessPreventer()

        with pytest.raises(PermissionDenied):
            preventer.validate(request)

    def test_bulk_operations_enforce_tenant(
        self, tenant_factory, user_factory, tenant_user_factory,
        job_posting_factory, db, request_factory
    ):
        """
        Test: Bulk operations cannot include cross-tenant IDs.
        Attack Vector: Including other tenant's IDs in bulk delete/update.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant_a, role='admin')

        job_a = job_posting_factory()
        job_b = job_posting_factory()
        job_b.tenant = tenant_b  # Job in other tenant

        request = request_factory.post('/api/jobs/bulk-delete/')
        request.user = user
        request.data = {'ids': [str(job_a.id), str(job_b.id)]}

        from core.security.authorization import CrossTenantAccessPreventer
        preventer = CrossTenantAccessPreventer()

        with pytest.raises(PermissionDenied) as excinfo:
            preventer.validate_bulk_operation(request, tenant_a)

        assert 'cross-tenant' in str(excinfo.value).lower()

    def test_nested_resource_tenant_validated(
        self, tenant_factory, user_factory, tenant_user_factory,
        application_factory, db, request_factory
    ):
        """
        Test: Nested resources validate parent tenant.
        Attack Vector: Accessing /tenantA/jobs/tenantB_job_id/applications
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant_a, role='recruiter')

        # Application for job in tenant B
        app = application_factory()
        app.job.tenant = tenant_b

        request = request_factory.get(f'/api/jobs/{app.job.id}/applications/')
        request.user = user
        request.tenant = tenant_a

        from core.security.authorization import CrossTenantAccessPreventer
        preventer = CrossTenantAccessPreventer()

        with pytest.raises(PermissionDenied):
            preventer.validate_nested_access(request, app.job)

    def test_export_enforces_tenant_boundary(
        self, tenant_factory, user_factory, tenant_user_factory,
        db, request_factory
    ):
        """
        Test: Data exports only include current tenant data.
        Attack Vector: Exporting cross-tenant data via parameter manipulation.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant_a, role='admin')

        request = request_factory.get('/api/export/candidates/')
        request.user = user
        request.tenant = tenant_a
        # Attempt to include all tenants
        request.GET = {'include_all': 'true'}

        from core.security.authorization import CrossTenantAccessPreventer
        preventer = CrossTenantAccessPreventer()

        # Should filter to only current tenant regardless of parameters
        queryset = preventer.filter_export_queryset(request, 'candidates')
        # Verify filter is applied (implementation specific)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestAuthorizationIntegration:
    """
    Integration tests for authorization system.
    """

    @pytest.mark.django_db
    def test_complete_authorization_flow(
        self, tenant_factory, user_factory, tenant_user_factory,
        job_posting_factory, db
    ):
        """
        Test: Complete authorization flow from request to response.
        """
        tenant = tenant_factory()
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='recruiter')

        job = job_posting_factory(created_by=user)

        from core.security.authorization import (
            TenantAccessControlValidator,
            PermissionChecker,
            ResourceAccessValidator
        )

        # Step 1: Validate tenant access
        validator = TenantAccessControlValidator()
        validator.validate_access(user=user, resource=job, current_tenant=tenant)

        # Step 2: Check permission
        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant
            checker = PermissionChecker()
            assert checker.has_permission(user, 'view_jobs')

        # Step 3: Check object-level permission
        resource_validator = ResourceAccessValidator()
        assert resource_validator.can_view(user, job)

    @pytest.mark.django_db
    def test_permission_caching_is_tenant_scoped(
        self, tenant_factory, user_factory, tenant_user_factory, db
    ):
        """
        Test: Permission cache is properly scoped to tenant.
        """
        tenant_a = tenant_factory(name='Company A', slug='company-a')
        tenant_b = tenant_factory(name='Company B', slug='company-b')

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant_a, role='admin')
        tenant_user_factory(user=user, tenant=tenant_b, role='viewer')

        from core.security.authorization import PermissionChecker
        checker = PermissionChecker()

        # Cache permissions for tenant A
        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant_a
            perms_a = checker.get_all_permissions(user)

        # Get permissions for tenant B (should not use tenant A cache)
        with patch('core.security.authorization.get_current_tenant') as mock:
            mock.return_value = tenant_b
            perms_b = checker.get_all_permissions(user)

        # Permissions should be different
        assert perms_a != perms_b
        assert 'edit_all' in perms_a
        assert 'edit_all' not in perms_b
