"""
Base Test Cases for Zumodra Multi-Tenant Testing

This module provides base classes for testing tenant-aware functionality:
- TenantTestCase: Base class for tenant-aware Django tests
- APITenantTestCase: Base class for tenant-aware API tests
- Test utilities and helper methods

Usage:
    from tests.base import TenantTestCase, APITenantTestCase

    class MyTest(TenantTestCase):
        def test_something(self):
            with self.tenant_context():
                # Operations happen in tenant schema
                ...
"""

from contextlib import contextmanager
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.test.client import RequestFactory
from django.utils import timezone

from rest_framework.test import APITestCase, APIClient


User = get_user_model()


class TenantTestMixin:
    """
    Mixin providing tenant-aware testing utilities.

    Use this mixin with Django TestCase or TransactionTestCase.
    """

    @classmethod
    def setUpClass(cls):
        """Set up test class with lazy imports to avoid circular dependencies."""
        super().setUpClass()

    def setUp(self):
        """Set up test with fresh tenant and user."""
        super().setUp()
        self._setup_tenant_context()

    def _setup_tenant_context(self):
        """Create default tenant and user for tests."""
        from conftest import PlanFactory, TenantFactory, UserFactory, TenantUserFactory

        # Create a plan
        self.plan = PlanFactory()

        # Create primary tenant
        self.tenant = TenantFactory(
            name='Test Company',
            slug='test-company',
            plan=self.plan,
            status='active'
        )

        # Create primary user with owner role
        self.user = UserFactory()
        self.tenant_user = TenantUserFactory(
            user=self.user,
            tenant=self.tenant,
            role='owner',
            is_active=True
        )

    @contextmanager
    def tenant_context(self, tenant=None):
        """
        Context manager to execute code within a tenant's schema.

        Args:
            tenant: Tenant to use. Defaults to self.tenant if not provided.

        Usage:
            with self.tenant_context():
                Job.objects.create(title='Test Job')
        """
        from django_tenants.utils import schema_context, get_public_schema_name

        target_tenant = tenant or self.tenant

        if target_tenant is None:
            with schema_context(get_public_schema_name()):
                yield
        else:
            with schema_context(target_tenant.schema_name):
                yield

    def create_tenant(self, name, slug, **kwargs):
        """
        Create a new tenant for testing.

        Args:
            name: Tenant name
            slug: Tenant slug
            **kwargs: Additional tenant attributes

        Returns:
            Created Tenant instance
        """
        from conftest import TenantFactory

        defaults = {
            'name': name,
            'slug': slug,
            'plan': self.plan,
            'status': 'active',
        }
        defaults.update(kwargs)

        return TenantFactory(**defaults)

    def create_user(self, **kwargs):
        """
        Create a new user for testing.

        Args:
            **kwargs: User attributes

        Returns:
            Created User instance
        """
        from conftest import UserFactory
        return UserFactory(**kwargs)

    def create_tenant_user(self, user=None, tenant=None, role='employee', **kwargs):
        """
        Create a tenant user membership.

        Args:
            user: User instance. Creates new if not provided.
            tenant: Tenant instance. Uses self.tenant if not provided.
            role: User role in tenant
            **kwargs: Additional TenantUser attributes

        Returns:
            Created TenantUser instance
        """
        from conftest import TenantUserFactory, UserFactory

        user = user or UserFactory()
        tenant = tenant or self.tenant

        return TenantUserFactory(
            user=user,
            tenant=tenant,
            role=role,
            is_active=True,
            **kwargs
        )

    def create_request(self, path='/', method='GET', user=None, tenant=None, **kwargs):
        """
        Create a mock request with tenant context.

        Args:
            path: Request path
            method: HTTP method
            user: User for request. Uses self.user if not provided.
            tenant: Tenant for request. Uses self.tenant if not provided.
            **kwargs: Additional request attributes

        Returns:
            Mock request object with tenant context
        """
        from conftest import MockTenantRequest

        return MockTenantRequest(
            user=user or self.user,
            tenant=tenant or self.tenant,
            method=method,
            **kwargs
        )

    def assert_tenant_isolated(self, queryset, tenant=None):
        """
        Assert that queryset is properly isolated to tenant.

        Args:
            queryset: Django queryset to check
            tenant: Expected tenant. Uses self.tenant if not provided.
        """
        tenant = tenant or self.tenant

        for obj in queryset:
            if hasattr(obj, 'tenant'):
                self.assertEqual(
                    obj.tenant, tenant,
                    f"Object {obj} belongs to wrong tenant"
                )


class TenantTestCase(TenantTestMixin, TestCase):
    """
    Base test case for tenant-aware Django tests.

    Provides:
    - Automatic tenant and user setup
    - Tenant context manager for schema switching
    - Helper methods for creating test data
    - Tenant isolation assertions

    Usage:
        class TestMyFeature(TenantTestCase):
            def test_something(self):
                # self.tenant and self.user are available
                with self.tenant_context():
                    # Operations in tenant schema
                    ...
    """

    def setUp(self):
        """Set up test with tenant context."""
        super().setUp()


class TenantTransactionTestCase(TenantTestMixin, TransactionTestCase):
    """
    Base test case for tenant-aware tests requiring transaction support.

    Use this for tests that need:
    - Database rollback between tests
    - Testing transaction behavior
    - Concurrent access testing

    Note: Slower than TenantTestCase due to database cleanup.
    """

    def setUp(self):
        """Set up test with tenant context."""
        super().setUp()


class APITenantTestMixin:
    """
    Mixin providing tenant-aware API testing utilities.

    Use with DRF's APITestCase.
    """

    @classmethod
    def setUpClass(cls):
        """Set up test class."""
        super().setUpClass()

    def setUp(self):
        """Set up test with API client and tenant context."""
        super().setUp()
        self._setup_api_tenant_context()

    def _setup_api_tenant_context(self):
        """Create tenant, user, and authenticated API client."""
        from conftest import (
            PlanFactory, TenantFactory, UserFactory,
            TenantUserFactory, TenantSettingsFactory
        )

        # Create plan
        self.plan = PlanFactory()

        # Create tenant with settings
        self.tenant = TenantFactory(
            name='API Test Company',
            slug='api-test-company',
            plan=self.plan,
            status='active'
        )
        self.tenant_settings = TenantSettingsFactory(tenant=self.tenant)

        # Create user with owner role
        self.user = UserFactory()
        self.tenant_user = TenantUserFactory(
            user=self.user,
            tenant=self.tenant,
            role='owner',
            is_active=True
        )

        # Create authenticated API client
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def authenticate_as(self, user):
        """
        Authenticate API client as specific user.

        Args:
            user: User to authenticate as
        """
        self.client.force_authenticate(user=user)

    def authenticate_as_role(self, role):
        """
        Create user with role and authenticate.

        Args:
            role: Role for new user

        Returns:
            Created user
        """
        from conftest import UserFactory, TenantUserFactory

        user = UserFactory()
        TenantUserFactory(
            user=user,
            tenant=self.tenant,
            role=role,
            is_active=True
        )
        self.authenticate_as(user)
        return user

    def unauthenticate(self):
        """Remove authentication from API client."""
        self.client.force_authenticate(user=None)

    def get_with_tenant(self, path, **kwargs):
        """
        Make GET request with tenant context header.

        Args:
            path: Request path
            **kwargs: Additional request kwargs

        Returns:
            Response object
        """
        kwargs.setdefault('HTTP_X_TENANT', self.tenant.slug)
        return self.client.get(path, **kwargs)

    def post_with_tenant(self, path, data=None, **kwargs):
        """
        Make POST request with tenant context header.

        Args:
            path: Request path
            data: Request data
            **kwargs: Additional request kwargs

        Returns:
            Response object
        """
        kwargs.setdefault('HTTP_X_TENANT', self.tenant.slug)
        kwargs.setdefault('format', 'json')
        return self.client.post(path, data, **kwargs)

    def put_with_tenant(self, path, data=None, **kwargs):
        """
        Make PUT request with tenant context header.

        Args:
            path: Request path
            data: Request data
            **kwargs: Additional request kwargs

        Returns:
            Response object
        """
        kwargs.setdefault('HTTP_X_TENANT', self.tenant.slug)
        kwargs.setdefault('format', 'json')
        return self.client.put(path, data, **kwargs)

    def patch_with_tenant(self, path, data=None, **kwargs):
        """
        Make PATCH request with tenant context header.

        Args:
            path: Request path
            data: Request data
            **kwargs: Additional request kwargs

        Returns:
            Response object
        """
        kwargs.setdefault('HTTP_X_TENANT', self.tenant.slug)
        kwargs.setdefault('format', 'json')
        return self.client.patch(path, data, **kwargs)

    def delete_with_tenant(self, path, **kwargs):
        """
        Make DELETE request with tenant context header.

        Args:
            path: Request path
            **kwargs: Additional request kwargs

        Returns:
            Response object
        """
        kwargs.setdefault('HTTP_X_TENANT', self.tenant.slug)
        return self.client.delete(path, **kwargs)

    def assert_permission_denied(self, response):
        """Assert response indicates permission denied."""
        self.assertIn(
            response.status_code,
            [401, 403],
            f"Expected permission denied, got {response.status_code}"
        )

    def assert_not_found(self, response):
        """Assert response indicates not found."""
        self.assertEqual(
            response.status_code, 404,
            f"Expected not found, got {response.status_code}"
        )

    def assert_success(self, response):
        """Assert response indicates success (2xx)."""
        self.assertTrue(
            200 <= response.status_code < 300,
            f"Expected success, got {response.status_code}: {response.data}"
        )

    def assert_created(self, response):
        """Assert response indicates created (201)."""
        self.assertEqual(
            response.status_code, 201,
            f"Expected created, got {response.status_code}: {response.data}"
        )

    def assert_bad_request(self, response):
        """Assert response indicates bad request (400)."""
        self.assertEqual(
            response.status_code, 400,
            f"Expected bad request, got {response.status_code}"
        )


class APITenantTestCase(APITenantTestMixin, APITestCase):
    """
    Base test case for tenant-aware API tests.

    Provides:
    - Automatic tenant and authenticated user setup
    - Helper methods for making tenant-scoped requests
    - Role-based authentication helpers
    - Response assertion helpers

    Usage:
        class TestMyAPI(APITenantTestCase):
            def test_list_endpoint(self):
                response = self.get_with_tenant('/api/items/')
                self.assert_success(response)

            def test_admin_only(self):
                self.authenticate_as_role('viewer')
                response = self.post_with_tenant('/api/items/', {'name': 'test'})
                self.assert_permission_denied(response)
    """

    def setUp(self):
        """Set up test with API client."""
        super().setUp()


# ============================================================================
# ADDITIONAL TEST UTILITIES
# ============================================================================

class PermissionTestMixin:
    """
    Mixin for testing permission classes.

    Provides utilities for testing DRF permission classes
    with tenant context.
    """

    def check_permission(self, permission_class, user, tenant=None, method='GET'):
        """
        Check if user has permission.

        Args:
            permission_class: DRF permission class to test
            user: User to check
            tenant: Tenant context
            method: HTTP method

        Returns:
            Boolean indicating permission result
        """
        from conftest import MockTenantRequest

        request = MockTenantRequest(
            user=user,
            tenant=tenant or self.tenant,
            method=method
        )

        permission = permission_class()
        return permission.has_permission(request, None)

    def check_object_permission(
        self, permission_class, user, obj, tenant=None, method='GET'
    ):
        """
        Check if user has object-level permission.

        Args:
            permission_class: DRF permission class to test
            user: User to check
            obj: Object to check permission for
            tenant: Tenant context
            method: HTTP method

        Returns:
            Boolean indicating permission result
        """
        from conftest import MockTenantRequest

        request = MockTenantRequest(
            user=user,
            tenant=tenant or self.tenant,
            method=method
        )

        permission = permission_class()
        return permission.has_object_permission(request, None, obj)


class IsolationTestMixin:
    """
    Mixin for testing tenant data isolation.

    Provides utilities for verifying data isolation
    between tenants.
    """

    def create_two_tenants(self):
        """
        Create two separate tenants for isolation testing.

        Returns:
            Tuple of (tenant1, tenant2)
        """
        from conftest import TenantFactory, PlanFactory

        plan = PlanFactory()

        tenant1 = TenantFactory(
            name='Tenant One',
            slug='tenant-one',
            plan=plan
        )
        tenant2 = TenantFactory(
            name='Tenant Two',
            slug='tenant-two',
            plan=plan
        )

        return tenant1, tenant2

    def assert_data_isolated(self, model_class, tenant1, tenant2):
        """
        Assert that model data is isolated between tenants.

        Args:
            model_class: Django model class to check
            tenant1: First tenant
            tenant2: Second tenant
        """
        if hasattr(model_class, 'tenant'):
            t1_count = model_class.objects.filter(tenant=tenant1).count()
            t2_count = model_class.objects.filter(tenant=tenant2).count()

            # Verify each tenant only sees its own data
            t1_objects = model_class.objects.filter(tenant=tenant1)
            for obj in t1_objects:
                self.assertEqual(obj.tenant, tenant1)

            t2_objects = model_class.objects.filter(tenant=tenant2)
            for obj in t2_objects:
                self.assertEqual(obj.tenant, tenant2)


# ============================================================================
# FACTORY HELPER CLASS
# ============================================================================

class FactoryHelper:
    """
    Helper class providing access to all factories.

    Usage:
        class MyTest(TenantTestCase):
            def test_something(self):
                helper = FactoryHelper()
                user = helper.user()
                tenant = helper.tenant(plan=self.plan)
    """

    @staticmethod
    def user(**kwargs):
        """Create a user."""
        from conftest import UserFactory
        return UserFactory(**kwargs)

    @staticmethod
    def superuser(**kwargs):
        """Create a superuser."""
        from conftest import SuperUserFactory
        return SuperUserFactory(**kwargs)

    @staticmethod
    def plan(**kwargs):
        """Create a plan."""
        from conftest import PlanFactory
        return PlanFactory(**kwargs)

    @staticmethod
    def free_plan(**kwargs):
        """Create a free plan."""
        from conftest import FreePlanFactory
        return FreePlanFactory(**kwargs)

    @staticmethod
    def enterprise_plan(**kwargs):
        """Create an enterprise plan."""
        from conftest import EnterprisePlanFactory
        return EnterprisePlanFactory(**kwargs)

    @staticmethod
    def tenant(**kwargs):
        """Create a tenant."""
        from conftest import TenantFactory
        return TenantFactory(**kwargs)

    @staticmethod
    def tenant_user(**kwargs):
        """Create a tenant user."""
        from conftest import TenantUserFactory
        return TenantUserFactory(**kwargs)

    @staticmethod
    def owner_tenant_user(**kwargs):
        """Create an owner tenant user."""
        from conftest import OwnerTenantUserFactory
        return OwnerTenantUserFactory(**kwargs)

    @staticmethod
    def admin_tenant_user(**kwargs):
        """Create an admin tenant user."""
        from conftest import AdminTenantUserFactory
        return AdminTenantUserFactory(**kwargs)

    @staticmethod
    def tenant_settings(**kwargs):
        """Create tenant settings."""
        from conftest import TenantSettingsFactory
        return TenantSettingsFactory(**kwargs)

    @staticmethod
    def domain(**kwargs):
        """Create a domain."""
        from conftest import DomainFactory
        return DomainFactory(**kwargs)

    @staticmethod
    def user_profile(**kwargs):
        """Create a user profile."""
        from conftest import UserProfileFactory
        return UserProfileFactory(**kwargs)

    @staticmethod
    def kyc_verification(**kwargs):
        """Create a KYC verification."""
        from conftest import KYCVerificationFactory
        return KYCVerificationFactory(**kwargs)

    @staticmethod
    def verified_kyc(**kwargs):
        """Create a verified KYC."""
        from conftest import VerifiedKYCFactory
        return VerifiedKYCFactory(**kwargs)

    @staticmethod
    def login_history(**kwargs):
        """Create a login history record."""
        from conftest import LoginHistoryFactory
        return LoginHistoryFactory(**kwargs)

    @staticmethod
    def audit_log(**kwargs):
        """Create an audit log."""
        from conftest import AuditLogFactory
        return AuditLogFactory(**kwargs)

    @staticmethod
    def progressive_consent(**kwargs):
        """Create a progressive consent."""
        from conftest import ProgressiveConsentFactory
        return ProgressiveConsentFactory(**kwargs)
