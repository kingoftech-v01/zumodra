"""
Tenant Isolation Tests

Tests for multi-tenant data isolation, schema switching, and concurrent access.
These tests verify that tenant data is properly isolated and cannot leak across tenants.
"""

import pytest
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.db import connection
from django.test import RequestFactory
from django.utils import timezone

from tenants.models import Tenant, Domain, TenantInvitation, AuditLog
from tenant_profiles.models import TenantUser


# ============================================================================
# CROSS-TENANT DATA ISOLATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestCrossTenantDataIsolation:
    """Tests to verify data cannot leak across tenants."""

    def test_tenant_users_isolated_by_tenant(self, two_tenants, user_factory, tenant_user_factory):
        """Test that tenant users are properly scoped to their tenant."""
        tenant1, tenant2 = two_tenants

        # Create users in each tenant
        user1 = user_factory()
        user2 = user_factory()

        tu1 = tenant_user_factory(user=user1, tenant=tenant1, role='employee')
        tu2 = tenant_user_factory(user=user2, tenant=tenant2, role='employee')

        # Query for tenant1 users
        tenant1_users = TenantUser.objects.filter(tenant=tenant1)
        tenant2_users = TenantUser.objects.filter(tenant=tenant2)

        assert tenant1_users.count() == 1
        assert tenant2_users.count() == 1
        assert tu1 in tenant1_users
        assert tu1 not in tenant2_users
        assert tu2 in tenant2_users
        assert tu2 not in tenant1_users

    def test_audit_logs_isolated_by_tenant(self, two_tenants, user_factory):
        """Test that audit logs are scoped to tenant."""
        from conftest import AuditLogFactory

        tenant1, tenant2 = two_tenants
        user = user_factory()

        # Create audit logs in each tenant
        log1 = AuditLogFactory(tenant=tenant1, user=user, action='create', resource_type='Job')
        log2 = AuditLogFactory(tenant=tenant2, user=user, action='update', resource_type='Candidate')

        # Query audit logs
        tenant1_logs = AuditLog.objects.filter(tenant=tenant1)
        tenant2_logs = AuditLog.objects.filter(tenant=tenant2)

        assert tenant1_logs.count() == 1
        assert tenant2_logs.count() == 1
        assert log1.action == 'create'
        assert log2.action == 'update'

    def test_invitations_isolated_by_tenant(self, two_tenants, tenant_invitation_factory):
        """Test that invitations are scoped to tenant."""
        tenant1, tenant2 = two_tenants

        inv1 = tenant_invitation_factory(tenant=tenant1, email='invite1@example.com')
        inv2 = tenant_invitation_factory(tenant=tenant2, email='invite2@example.com')

        tenant1_invitations = TenantInvitation.objects.filter(tenant=tenant1)
        tenant2_invitations = TenantInvitation.objects.filter(tenant=tenant2)

        assert tenant1_invitations.count() == 1
        assert tenant2_invitations.count() == 1
        assert inv1 in tenant1_invitations
        assert inv2 not in tenant1_invitations

    def test_cannot_access_other_tenant_data_via_relation(self, two_tenants, user_factory, tenant_user_factory):
        """Test that following relations doesn't leak data."""
        tenant1, tenant2 = two_tenants
        user = user_factory()

        # User belongs to both tenants
        tu1 = tenant_user_factory(user=user, tenant=tenant1, role='admin')
        tu2 = tenant_user_factory(user=user, tenant=tenant2, role='employee')

        # Get user's memberships
        memberships = user.tenant_memberships.all()

        # User should see both memberships through their own relation
        assert memberships.count() == 2

        # But tenant-scoped queries should only return their tenant's data
        tenant1_members = TenantUser.objects.filter(tenant=tenant1)
        assert tenant1_members.count() == 1

    def test_tenant_domains_isolated(self, two_tenants, domain_factory):
        """Test that domains are scoped to their tenant."""
        tenant1, tenant2 = two_tenants

        domain1 = domain_factory(tenant=tenant1, domain='alpha.test.com')
        domain2 = domain_factory(tenant=tenant2, domain='beta.test.com')

        assert Domain.objects.filter(tenant=tenant1).count() == 1
        assert Domain.objects.filter(tenant=tenant2).count() == 1
        assert domain1.tenant == tenant1
        assert domain2.tenant == tenant2


# ============================================================================
# SCHEMA SWITCHING TESTS
# ============================================================================

@pytest.mark.django_db
class TestSchemaSwitching:
    """Tests for tenant schema switching behavior."""

    def test_tenants_have_unique_schema_names(self, two_tenants):
        """Test that each tenant has a unique schema name."""
        tenant1, tenant2 = two_tenants

        assert tenant1.schema_name != tenant2.schema_name
        assert tenant1.schema_name == 'company_alpha'
        assert tenant2.schema_name == 'company_beta'

    def test_schema_name_derived_from_slug(self, tenant_factory, plan):
        """Test that schema name is properly derived from slug."""
        tenant = tenant_factory(slug='my-company-name', plan=plan)

        # Schema name should convert hyphens to underscores
        assert tenant.schema_name == 'my_company_name'

    def test_tenant_context_manager(self, tenant_factory, plan):
        """Test the tenant_context context manager."""
        from conftest import tenant_context

        tenant = tenant_factory(plan=plan)

        # This test primarily verifies the context manager doesn't error
        # In a full integration test, we'd verify actual schema switching
        with tenant_context(tenant):
            # Operations happen in tenant schema
            assert tenant.schema_name is not None

    def test_public_schema_context(self):
        """Test context manager with None tenant uses public schema."""
        from conftest import tenant_context

        with tenant_context(None):
            # Should not raise an error
            pass


# ============================================================================
# CONCURRENT TENANT ACCESS TESTS
# ============================================================================

@pytest.mark.django_db
@pytest.mark.slow
class TestConcurrentTenantAccess:
    """Tests for concurrent multi-tenant operations."""

    def test_concurrent_tenant_creation(self, plan_factory):
        """Test creating multiple tenants concurrently."""
        from conftest import TenantFactory

        plan = plan_factory()
        tenants_created = []
        errors = []

        def create_tenant(index):
            try:
                tenant = TenantFactory(
                    name=f'Concurrent Company {index}',
                    slug=f'concurrent-{index}',
                    plan=plan
                )
                tenants_created.append(tenant)
            except Exception as e:
                errors.append(str(e))

        # Create tenants concurrently
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(create_tenant, i) for i in range(5)]
            for future in as_completed(futures):
                future.result()  # Wait for completion

        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(tenants_created) == 5

        # Verify all have unique slugs
        slugs = [t.slug for t in tenants_created]
        assert len(set(slugs)) == 5

    def test_concurrent_audit_log_creation(self, tenant_factory, user_factory, plan):
        """Test creating audit logs concurrently within a tenant."""
        from conftest import AuditLogFactory

        tenant = tenant_factory(plan=plan)
        user = user_factory()
        logs_created = []
        errors = []

        def create_log(index):
            try:
                log = AuditLogFactory(
                    tenant=tenant,
                    user=user,
                    action='create',
                    resource_type=f'Resource{index}'
                )
                logs_created.append(log)
            except Exception as e:
                errors.append(str(e))

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(create_log, i) for i in range(10)]
            for future in as_completed(futures):
                future.result()

        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(logs_created) == 10
        assert AuditLog.objects.filter(tenant=tenant).count() == 10

    def test_concurrent_tenant_user_operations(self, two_tenants, user_factory, tenant_user_factory):
        """Test concurrent user operations across tenants don't interfere."""
        tenant1, tenant2 = two_tenants
        operations_completed = []
        errors = []

        def add_user_to_tenant(tenant, index):
            try:
                user = user_factory()
                tu = tenant_user_factory(
                    user=user,
                    tenant=tenant,
                    role='employee'
                )
                operations_completed.append((tenant.slug, tu.user.email))
            except Exception as e:
                errors.append(str(e))

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = []
            # Add 3 users to each tenant concurrently
            for i in range(3):
                futures.append(executor.submit(add_user_to_tenant, tenant1, i))
                futures.append(executor.submit(add_user_to_tenant, tenant2, i))

            for future in as_completed(futures):
                future.result()

        assert len(errors) == 0, f"Errors occurred: {errors}"

        # Each tenant should have exactly 3 users
        assert TenantUser.objects.filter(tenant=tenant1).count() == 3
        assert TenantUser.objects.filter(tenant=tenant2).count() == 3


# ============================================================================
# TENANT CONTEXT PROPAGATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantContextPropagation:
    """Tests for tenant context in requests and middleware."""

    def test_request_has_tenant_attribute(self, tenant_factory, plan):
        """Test that tenant can be attached to request."""
        from conftest import TenantRequestFactory

        tenant = tenant_factory(plan=plan)
        factory = TenantRequestFactory(tenant=tenant)

        request = factory.get('/api/test/')

        assert hasattr(request, 'tenant')
        assert request.tenant == tenant
        assert request.tenant_plan == tenant.plan

    def test_request_without_tenant(self):
        """Test request factory without tenant context."""
        from conftest import TenantRequestFactory

        factory = TenantRequestFactory()
        request = factory.get('/api/test/')

        # Tenant attribute is None when not set
        assert request.tenant is None

    def test_request_with_user_context(self, tenant_factory, user_factory, plan):
        """Test request factory with both tenant and user context."""
        from conftest import TenantRequestFactory

        tenant = tenant_factory(plan=plan)
        user = user_factory()
        factory = TenantRequestFactory(tenant=tenant, user=user)

        request = factory.get('/api/test/')

        assert request.tenant == tenant
        assert request.user == user

    def test_mock_tenant_request(self, tenant_factory, user_factory, plan):
        """Test MockTenantRequest for permission testing."""
        from conftest import MockTenantRequest

        tenant = tenant_factory(plan=plan)
        user = user_factory()

        mock_request = MockTenantRequest(user=user, tenant=tenant, method='POST')

        assert mock_request.user == user
        assert mock_request.tenant == tenant
        assert mock_request.method == 'POST'
        assert 'REMOTE_ADDR' in mock_request.META

    def test_tenant_settings_propagation(self, tenant_with_settings):
        """Test that tenant settings are accessible via tenant."""
        tenant = tenant_with_settings

        assert hasattr(tenant, 'settings')
        assert tenant.settings is not None
        assert tenant.settings.primary_color == '#3B82F6'


# ============================================================================
# TENANT ISOLATION PERMISSION TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantIsolationPermissions:
    """Tests for permission-based isolation."""

    def test_user_cannot_access_other_tenant_membership(
        self, two_tenants, user_factory, tenant_user_factory
    ):
        """Test that user cannot access membership from another tenant."""
        tenant1, tenant2 = two_tenants
        user1 = user_factory()
        user2 = user_factory()

        # Each user belongs to different tenant
        tu1 = tenant_user_factory(user=user1, tenant=tenant1)
        tu2 = tenant_user_factory(user=user2, tenant=tenant2)

        # User1's memberships don't include tenant2
        user1_memberships = TenantUser.objects.filter(user=user1)
        assert tenant1 in [m.tenant for m in user1_memberships]
        assert tenant2 not in [m.tenant for m in user1_memberships]

    def test_admin_limited_to_own_tenant(
        self, two_tenants, user_factory, tenant_user_factory
    ):
        """Test that admin role is scoped to specific tenant."""
        tenant1, tenant2 = two_tenants
        admin_user = user_factory()

        # User is admin in tenant1, not in tenant2
        tu1 = tenant_user_factory(user=admin_user, tenant=tenant1, role='admin')

        # Check admin status per tenant
        tenant1_membership = TenantUser.objects.filter(
            user=admin_user, tenant=tenant1
        ).first()
        tenant2_membership = TenantUser.objects.filter(
            user=admin_user, tenant=tenant2
        ).first()

        assert tenant1_membership is not None
        assert tenant1_membership.is_admin is True
        assert tenant2_membership is None  # Not a member of tenant2

    def test_owner_role_highest_in_tenant_only(
        self, two_tenants, user_factory, tenant_user_factory
    ):
        """Test owner role is highest but only within their tenant."""
        from conftest import OwnerTenantUserFactory

        tenant1, tenant2 = two_tenants
        owner = user_factory()

        # Owner of tenant1
        OwnerTenantUserFactory(user=owner, tenant=tenant1)

        owner_in_t1 = TenantUser.objects.filter(user=owner, tenant=tenant1).first()
        owner_in_t2 = TenantUser.objects.filter(user=owner, tenant=tenant2).first()

        assert owner_in_t1.role == 'owner'
        assert owner_in_t2 is None


# ============================================================================
# TENANT DATA INTEGRITY TESTS
# ============================================================================

@pytest.mark.django_db
class TestTenantDataIntegrity:
    """Tests for data integrity within tenants."""

    def test_tenant_usage_tracking_isolated(self, two_tenants):
        """Test that usage tracking is per-tenant."""
        from conftest import TenantUsageFactory

        tenant1, tenant2 = two_tenants

        usage1 = TenantUsageFactory(
            tenant=tenant1,
            user_count=10,
            active_job_count=5
        )
        usage2 = TenantUsageFactory(
            tenant=tenant2,
            user_count=25,
            active_job_count=15
        )

        # Verify isolation
        assert tenant1.usage.user_count == 10
        assert tenant2.usage.user_count == 25
        assert tenant1.usage.active_job_count == 5
        assert tenant2.usage.active_job_count == 15

    def test_tenant_cascade_on_delete(self, tenant_factory, plan, domain_factory):
        """Test that related objects are handled properly on tenant deletion."""
        tenant = tenant_factory(plan=plan)
        domain = domain_factory(tenant=tenant)

        tenant_id = tenant.id
        domain_tenant_id = domain.tenant_id

        assert domain_tenant_id == tenant_id

        # Domain should be deleted with tenant (CASCADE)
        tenant.delete()

        assert not Domain.objects.filter(id=domain.id).exists()

    def test_invitation_unique_per_tenant_email(
        self, two_tenants, tenant_invitation_factory, user_factory
    ):
        """Test that same email can be invited to different tenants."""
        tenant1, tenant2 = two_tenants
        inviter = user_factory()

        email = 'shared@example.com'

        # Same email can be invited to both tenants
        inv1 = tenant_invitation_factory(
            tenant=tenant1, email=email, invited_by=inviter
        )
        inv2 = tenant_invitation_factory(
            tenant=tenant2, email=email, invited_by=inviter
        )

        assert inv1.email == inv2.email
        assert inv1.tenant != inv2.tenant
        assert TenantInvitation.objects.filter(email=email).count() == 2

    def test_duplicate_invitation_same_tenant_fails(
        self, tenant, tenant_invitation_factory, user_factory
    ):
        """Test that duplicate invitations to same tenant fail."""
        from django.db import IntegrityError

        inviter = user_factory()
        email = 'unique@example.com'

        tenant_invitation_factory(tenant=tenant, email=email, invited_by=inviter)

        with pytest.raises(IntegrityError):
            tenant_invitation_factory(tenant=tenant, email=email, invited_by=inviter)
