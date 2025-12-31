"""
Permissions Tests

Tests for Role-Based Access Control (RBAC) including:
- RBAC permissions for each role
- Object-level permissions
- Feature flag permissions
- Cross-tenant permission denial
- Progressive consent permissions
"""

import pytest
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from accounts.models import (
    TenantUser, UserProfile, KYCVerification,
    ProgressiveConsent, ROLE_PERMISSIONS
)
from accounts.permissions import (
    IsTenantUser, IsTenantAdmin, IsTenantOwner,
    HasKYCVerification, CanAccessUserData, CanManageUsers,
    IsOwnerOrReadOnly, HasTenantPermission, IsVerifiedRecruiter
)

User = get_user_model()


# ============================================================================
# RBAC PERMISSIONS TESTS - BY ROLE
# ============================================================================

@pytest.mark.django_db
class TestRolePermissionMappings:
    """Tests for role-to-permission mappings."""

    def test_owner_has_all_permissions(self):
        """Test that owner role has all critical permissions."""
        owner_perms = ROLE_PERMISSIONS[TenantUser.UserRole.OWNER]

        assert 'view_all' in owner_perms
        assert 'edit_all' in owner_perms
        assert 'delete_all' in owner_perms
        assert 'manage_users' in owner_perms
        assert 'manage_billing' in owner_perms
        assert 'manage_settings' in owner_perms

    def test_admin_has_management_permissions(self):
        """Test that admin role has management permissions."""
        admin_perms = ROLE_PERMISSIONS[TenantUser.UserRole.ADMIN]

        assert 'view_all' in admin_perms
        assert 'edit_all' in admin_perms
        assert 'manage_users' in admin_perms
        assert 'manage_settings' in admin_perms
        # Admin should NOT have billing permission
        assert 'manage_billing' not in admin_perms

    def test_hr_manager_has_hr_permissions(self):
        """Test that HR manager has HR-specific permissions."""
        hr_perms = ROLE_PERMISSIONS[TenantUser.UserRole.HR_MANAGER]

        assert 'view_candidates' in hr_perms
        assert 'edit_candidates' in hr_perms
        assert 'view_employees' in hr_perms
        assert 'edit_employees' in hr_perms
        assert 'manage_hr' in hr_perms
        # HR should NOT have billing or settings permissions
        assert 'manage_billing' not in hr_perms

    def test_recruiter_has_hiring_permissions(self):
        """Test that recruiter has hiring-related permissions."""
        recruiter_perms = ROLE_PERMISSIONS[TenantUser.UserRole.RECRUITER]

        assert 'view_candidates' in recruiter_perms
        assert 'edit_candidates' in recruiter_perms
        assert 'view_jobs' in recruiter_perms
        assert 'edit_jobs' in recruiter_perms
        assert 'schedule_interviews' in recruiter_perms
        assert 'send_messages' in recruiter_perms

    def test_hiring_manager_has_limited_permissions(self):
        """Test that hiring manager has limited hiring permissions."""
        hm_perms = ROLE_PERMISSIONS[TenantUser.UserRole.HIRING_MANAGER]

        assert 'view_candidates' in hm_perms
        assert 'view_jobs' in hm_perms
        assert 'leave_feedback' in hm_perms
        assert 'approve_offers' in hm_perms
        # Should NOT have edit permissions for candidates/jobs
        assert 'edit_candidates' not in hm_perms
        assert 'edit_jobs' not in hm_perms

    def test_employee_has_self_service_permissions(self):
        """Test that employee has self-service permissions only."""
        emp_perms = ROLE_PERMISSIONS[TenantUser.UserRole.EMPLOYEE]

        assert 'view_profile' in emp_perms
        assert 'edit_profile' in emp_perms
        assert 'view_directory' in emp_perms
        assert 'request_time_off' in emp_perms
        # Employee should NOT have candidate/job access
        assert 'view_candidates' not in emp_perms
        assert 'view_jobs' not in emp_perms

    def test_viewer_has_readonly_permissions(self):
        """Test that viewer has read-only permissions."""
        viewer_perms = ROLE_PERMISSIONS[TenantUser.UserRole.VIEWER]

        assert 'view_jobs' in viewer_perms
        assert 'view_candidates' in viewer_perms
        assert 'view_reports' in viewer_perms
        # Viewer should have NO edit permissions
        assert 'edit_jobs' not in viewer_perms
        assert 'edit_candidates' not in viewer_perms
        assert 'edit_employees' not in viewer_perms


@pytest.mark.django_db
class TestTenantUserPermissionMethods:
    """Tests for TenantUser permission methods."""

    def test_get_all_permissions_for_role(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test getting all permissions for a tenant user."""
        user = user_factory()
        tenant_user = tenant_user_factory(
            user=user, tenant=tenant, role='recruiter'
        )

        perms = tenant_user.get_all_permissions()

        assert isinstance(perms, set)
        assert 'view_candidates' in perms
        assert 'edit_candidates' in perms

    def test_has_permission_positive(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test has_permission returns True for valid permission."""
        user = user_factory()
        tenant_user = tenant_user_factory(
            user=user, tenant=tenant, role='admin'
        )

        assert tenant_user.has_permission('manage_users') is True
        assert tenant_user.has_permission('view_all') is True

    def test_has_permission_negative(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test has_permission returns False for missing permission."""
        user = user_factory()
        tenant_user = tenant_user_factory(
            user=user, tenant=tenant, role='viewer'
        )

        assert tenant_user.has_permission('edit_candidates') is False
        assert tenant_user.has_permission('manage_users') is False

    def test_is_admin_property(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test is_admin property."""
        user1 = user_factory()
        user2 = user_factory()
        user3 = user_factory()

        admin = tenant_user_factory(user=user1, tenant=tenant, role='admin')
        owner = tenant_user_factory(user=user2, tenant=tenant, role='owner')
        employee = tenant_user_factory(user=user3, tenant=tenant, role='employee')

        assert admin.is_admin is True
        assert owner.is_admin is True
        assert employee.is_admin is False

    def test_can_hire_property(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test can_hire property for different roles."""
        users = [user_factory() for _ in range(5)]

        owner = tenant_user_factory(user=users[0], tenant=tenant, role='owner')
        recruiter = tenant_user_factory(user=users[1], tenant=tenant, role='recruiter')
        hr_manager = tenant_user_factory(user=users[2], tenant=tenant, role='hr_manager')
        employee = tenant_user_factory(user=users[3], tenant=tenant, role='employee')
        viewer = tenant_user_factory(user=users[4], tenant=tenant, role='viewer')

        assert owner.can_hire is True
        assert recruiter.can_hire is True
        assert hr_manager.can_hire is True
        assert employee.can_hire is False
        assert viewer.can_hire is False


# ============================================================================
# PERMISSION CLASS TESTS
# ============================================================================

@pytest.mark.django_db
class TestIsTenantUserPermission:
    """Tests for IsTenantUser permission class."""

    def test_authenticated_tenant_member_allowed(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test authenticated tenant member is allowed."""
        from conftest import MockTenantRequest

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, is_active=True)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsTenantUser()

        assert permission.has_permission(request, None) is True

    def test_authenticated_non_member_denied(
        self, tenant, user_factory
    ):
        """Test authenticated non-member is denied."""
        from conftest import MockTenantRequest

        user = user_factory()
        # User has no membership in tenant

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsTenantUser()

        assert permission.has_permission(request, None) is False

    def test_unauthenticated_user_denied(self, tenant):
        """Test unauthenticated user is denied."""
        from conftest import MockTenantRequest

        mock_user = MagicMock()
        mock_user.is_authenticated = False

        request = MockTenantRequest(user=mock_user, tenant=tenant)
        permission = IsTenantUser()

        assert permission.has_permission(request, None) is False

    def test_no_tenant_context_denied(self, user_factory):
        """Test request without tenant context is denied."""
        from conftest import MockTenantRequest

        user = user_factory()
        request = MockTenantRequest(user=user, tenant=None)
        permission = IsTenantUser()

        assert permission.has_permission(request, None) is False

    def test_inactive_membership_denied(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test inactive tenant membership is denied."""
        from conftest import MockTenantRequest

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, is_active=False)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsTenantUser()

        assert permission.has_permission(request, None) is False


@pytest.mark.django_db
class TestIsTenantAdminPermission:
    """Tests for IsTenantAdmin permission class."""

    def test_admin_role_allowed(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test admin role is allowed."""
        from conftest import MockTenantRequest

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='admin', is_active=True)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsTenantAdmin()

        assert permission.has_permission(request, None) is True

    def test_owner_role_allowed(
        self, tenant, user_factory
    ):
        """Test owner role is allowed."""
        from conftest import MockTenantRequest, OwnerTenantUserFactory

        user = user_factory()
        OwnerTenantUserFactory(user=user, tenant=tenant)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsTenantAdmin()

        assert permission.has_permission(request, None) is True

    def test_non_admin_role_denied(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test non-admin roles are denied."""
        from conftest import MockTenantRequest

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='employee', is_active=True)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsTenantAdmin()

        assert permission.has_permission(request, None) is False


@pytest.mark.django_db
class TestIsTenantOwnerPermission:
    """Tests for IsTenantOwner permission class."""

    def test_owner_allowed(
        self, tenant, user_factory
    ):
        """Test owner role is allowed."""
        from conftest import MockTenantRequest, OwnerTenantUserFactory

        user = user_factory()
        OwnerTenantUserFactory(user=user, tenant=tenant)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsTenantOwner()

        assert permission.has_permission(request, None) is True

    def test_admin_denied(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test admin role is denied (owner-only permission)."""
        from conftest import MockTenantRequest

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='admin', is_active=True)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsTenantOwner()

        assert permission.has_permission(request, None) is False


# ============================================================================
# OBJECT-LEVEL PERMISSION TESTS
# ============================================================================

@pytest.mark.django_db
class TestObjectLevelPermissions:
    """Tests for object-level permission checking."""

    def test_object_permission_checks_tenant(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test object permission verifies tenant matching."""
        from conftest import MockTenantRequest

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, is_active=True)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsTenantUser()

        # Mock object with tenant attribute
        mock_obj = MagicMock()
        mock_obj.tenant = tenant

        assert permission.has_object_permission(request, None, mock_obj) is True

    def test_object_permission_denies_different_tenant(
        self, two_tenants, user_factory, tenant_user_factory
    ):
        """Test object permission denies access to different tenant's object."""
        from conftest import MockTenantRequest

        tenant1, tenant2 = two_tenants
        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant1, is_active=True)

        request = MockTenantRequest(user=user, tenant=tenant1)
        permission = IsTenantUser()

        # Object belongs to different tenant
        mock_obj = MagicMock()
        mock_obj.tenant = tenant2

        assert permission.has_object_permission(request, None, mock_obj) is False

    def test_is_owner_or_readonly_allows_read(
        self, user_factory
    ):
        """Test IsOwnerOrReadOnly allows read operations."""
        user = user_factory()

        request = MagicMock()
        request.method = 'GET'
        request.user = user

        permission = IsOwnerOrReadOnly()

        mock_obj = MagicMock()
        mock_obj.user = user_factory()  # Different user

        # Read should be allowed
        assert permission.has_object_permission(request, None, mock_obj) is True

    def test_is_owner_or_readonly_denies_write(
        self, user_factory
    ):
        """Test IsOwnerOrReadOnly denies write to non-owner."""
        user1 = user_factory()
        user2 = user_factory()

        request = MagicMock()
        request.method = 'PUT'
        request.user = user1

        permission = IsOwnerOrReadOnly()

        mock_obj = MagicMock()
        mock_obj.user = user2  # Different user owns object

        assert permission.has_object_permission(request, None, mock_obj) is False

    def test_is_owner_or_readonly_allows_owner_write(
        self, user_factory
    ):
        """Test IsOwnerOrReadOnly allows owner to write."""
        user = user_factory()

        request = MagicMock()
        request.method = 'PUT'
        request.user = user

        permission = IsOwnerOrReadOnly()

        mock_obj = MagicMock()
        mock_obj.user = user  # Same user

        assert permission.has_object_permission(request, None, mock_obj) is True


# ============================================================================
# FEATURE FLAG PERMISSION TESTS
# ============================================================================

@pytest.mark.django_db
class TestFeatureFlagPermissions:
    """Tests for feature-based permissions."""

    def test_plan_feature_flags(self, plan_factory, enterprise_plan_factory):
        """Test plan feature flags determine access."""
        free_plan = plan_factory(
            plan_type='free',
            feature_ai_matching=False,
            feature_video_interviews=False
        )
        enterprise_plan = enterprise_plan_factory()

        assert free_plan.feature_ai_matching is False
        assert enterprise_plan.feature_ai_matching is True
        assert enterprise_plan.feature_video_interviews is True

    def test_tenant_has_feature_via_plan(
        self, tenant_factory, enterprise_plan_factory
    ):
        """Test tenant feature access via plan."""
        plan = enterprise_plan_factory()
        tenant = tenant_factory(plan=plan)

        assert tenant.plan.feature_sso is True
        assert tenant.plan.feature_custom_branding is True

    def test_tenant_without_feature(
        self, tenant_factory, free_plan_factory
    ):
        """Test tenant without feature access."""
        plan = free_plan_factory()
        tenant = tenant_factory(plan=plan)

        assert tenant.plan.feature_analytics is False
        assert tenant.plan.feature_hr_core is False


# ============================================================================
# CROSS-TENANT PERMISSION DENIAL TESTS
# ============================================================================

@pytest.mark.django_db
class TestCrossTenantPermissionDenial:
    """Tests for cross-tenant permission denial."""

    def test_user_cannot_access_other_tenant_as_admin(
        self, two_tenants, user_factory, tenant_user_factory
    ):
        """Test admin of one tenant cannot access another tenant."""
        from conftest import MockTenantRequest

        tenant1, tenant2 = two_tenants
        user = user_factory()

        # User is admin in tenant1 only
        tenant_user_factory(user=user, tenant=tenant1, role='admin', is_active=True)

        # Try to access tenant2
        request = MockTenantRequest(user=user, tenant=tenant2)
        permission = IsTenantAdmin()

        assert permission.has_permission(request, None) is False

    def test_owner_of_one_tenant_not_owner_of_another(
        self, two_tenants, user_factory
    ):
        """Test owner of one tenant is not owner of another."""
        from conftest import MockTenantRequest, OwnerTenantUserFactory

        tenant1, tenant2 = two_tenants
        user = user_factory()

        # User is owner of tenant1 only
        OwnerTenantUserFactory(user=user, tenant=tenant1)

        # Try to access tenant2 as owner
        request = MockTenantRequest(user=user, tenant=tenant2)
        permission = IsTenantOwner()

        assert permission.has_permission(request, None) is False

    def test_user_with_role_in_both_tenants(
        self, two_tenants, user_factory, tenant_user_factory
    ):
        """Test user with roles in both tenants has correct permissions."""
        from conftest import MockTenantRequest

        tenant1, tenant2 = two_tenants
        user = user_factory()

        # Admin in tenant1, employee in tenant2
        tenant_user_factory(user=user, tenant=tenant1, role='admin', is_active=True)
        tenant_user_factory(user=user, tenant=tenant2, role='employee', is_active=True)

        admin_perm = IsTenantAdmin()

        # Should be admin in tenant1
        request1 = MockTenantRequest(user=user, tenant=tenant1)
        assert admin_perm.has_permission(request1, None) is True

        # Should NOT be admin in tenant2
        request2 = MockTenantRequest(user=user, tenant=tenant2)
        assert admin_perm.has_permission(request2, None) is False


# ============================================================================
# KYC VERIFICATION PERMISSION TESTS
# ============================================================================

@pytest.mark.django_db
class TestKYCVerificationPermission:
    """Tests for KYC-based permissions."""

    def test_verified_user_allowed(self, user_factory, verified_kyc_user):
        """Test user with verified KYC is allowed."""
        request = MagicMock()
        request.user = verified_kyc_user
        request.user.is_authenticated = True

        permission = HasKYCVerification()

        assert permission.has_permission(request, None) is True

    def test_unverified_user_denied(self, user_factory):
        """Test user without KYC is denied."""
        user = user_factory()

        request = MagicMock()
        request.user = user
        request.user.is_authenticated = True

        permission = HasKYCVerification()

        assert permission.has_permission(request, None) is False

    def test_expired_kyc_denied(self, user_factory, kyc_verification_factory):
        """Test user with expired KYC is denied."""
        user = user_factory()
        kyc_verification_factory(
            user=user,
            status='verified',
            verified_at=timezone.now() - timedelta(days=400),
            expires_at=timezone.now() - timedelta(days=35)
        )

        request = MagicMock()
        request.user = user
        request.user.is_authenticated = True

        permission = HasKYCVerification()

        assert permission.has_permission(request, None) is False


# ============================================================================
# PROGRESSIVE CONSENT PERMISSION TESTS
# ============================================================================

@pytest.mark.django_db
class TestProgressiveConsentPermission:
    """Tests for consent-based data access permissions."""

    def test_user_can_access_own_data(self, user_factory):
        """Test user can always access their own data."""
        user = user_factory()

        request = MagicMock()
        request.method = 'GET'
        request.user = user
        request.user.is_authenticated = True

        mock_view = MagicMock()
        mock_view.data_category = None

        mock_obj = MagicMock()
        mock_obj.user = user

        permission = CanAccessUserData()

        assert permission.has_object_permission(request, mock_view, mock_obj) is True

    def test_user_with_consent_can_access_data(
        self, consent_setup
    ):
        """Test user with granted consent can access data."""
        from conftest import MockTenantRequest

        grantor = consent_setup['grantor']
        grantee = consent_setup['grantee']
        tenant = consent_setup['tenant']

        # Mark consent as granted and not expired
        consent = consent_setup['consents']['granted']
        consent.status = 'granted'
        consent.expires_at = timezone.now() + timedelta(days=30)
        consent.save()

        request = MockTenantRequest(user=grantee, tenant=tenant)
        request.method = 'GET'

        mock_view = MagicMock()
        mock_view.data_category = 'basic'

        mock_obj = MagicMock()
        mock_obj.user = grantor

        permission = CanAccessUserData()

        # With proper consent, access should be allowed
        assert permission.has_object_permission(request, mock_view, mock_obj) is True


# ============================================================================
# MANAGE USERS PERMISSION TESTS
# ============================================================================

@pytest.mark.django_db
class TestCanManageUsersPermission:
    """Tests for user management permissions."""

    def test_owner_can_manage_users(
        self, tenant, user_factory
    ):
        """Test owner can manage users."""
        from conftest import MockTenantRequest, OwnerTenantUserFactory

        user = user_factory()
        OwnerTenantUserFactory(user=user, tenant=tenant)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = CanManageUsers()

        assert permission.has_permission(request, None) is True

    def test_hr_manager_can_manage_users(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test HR manager can manage users."""
        from conftest import MockTenantRequest

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='hr_manager', is_active=True)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = CanManageUsers()

        assert permission.has_permission(request, None) is True

    def test_employee_cannot_manage_users(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test employee cannot manage users."""
        from conftest import MockTenantRequest

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='employee', is_active=True)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = CanManageUsers()

        assert permission.has_permission(request, None) is False


# ============================================================================
# VERIFIED RECRUITER PERMISSION TESTS
# ============================================================================

@pytest.mark.django_db
class TestIsVerifiedRecruiterPermission:
    """Tests for verified recruiter permission (combines role + KYC)."""

    def test_verified_recruiter_allowed(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test verified recruiter is allowed."""
        from conftest import MockTenantRequest, VerifiedKYCFactory

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='recruiter', is_active=True)
        VerifiedKYCFactory(user=user)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsVerifiedRecruiter()

        assert permission.has_permission(request, None) is True

    def test_unverified_recruiter_denied(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test recruiter without KYC is denied."""
        from conftest import MockTenantRequest

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='recruiter', is_active=True)
        # No KYC verification

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsVerifiedRecruiter()

        assert permission.has_permission(request, None) is False

    def test_verified_non_recruiter_denied(
        self, tenant, user_factory, tenant_user_factory
    ):
        """Test verified employee (non-recruiter) is denied."""
        from conftest import MockTenantRequest, VerifiedKYCFactory

        user = user_factory()
        tenant_user_factory(user=user, tenant=tenant, role='employee', is_active=True)
        VerifiedKYCFactory(user=user)

        request = MockTenantRequest(user=user, tenant=tenant)
        permission = IsVerifiedRecruiter()

        assert permission.has_permission(request, None) is False
