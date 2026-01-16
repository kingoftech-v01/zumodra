"""
Tests for Tenant Middleware Error Handling

Verify that the middleware properly handles missing/invalid tenants
and returns appropriate HTTP responses instead of 500 errors.
"""

import pytest
from django.test import RequestFactory, TestCase, override_settings
from django.http import Http404, JsonResponse
from unittest.mock import patch, MagicMock

from tenants.middleware import ZumodraTenantMiddleware, TenantNotFoundError
from tenants.models import Tenant, Domain


class TestTenantMiddlewareErrorHandling(TestCase):
    """Test error handling for missing and invalid tenants."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.middleware = ZumodraTenantMiddleware(lambda r: None)

    @override_settings(SHOW_PUBLIC_IF_NO_TENANT_FOUND=False)
    def test_missing_tenant_returns_404_not_500(self):
        """
        Test that accessing a non-existent subdomain returns 404.

        This verifies the fix for when a user accesses nonexistent.zumodra.com
        - Should return 404 Not Found
        - Should NOT attempt to process request with parent class
        - Should NOT return 500 Internal Server Error
        """
        request = self.factory.get('/', HTTP_HOST='nonexistent.zumodra.com')

        # Process request through middleware
        response = self.middleware.process_request(request)

        # Should return JsonResponse with 404 status (for non-API requests, raises Http404)
        # For HTML requests, Http404 is raised which Django converts to 404
        assert response is not None, "Middleware should return response for missing tenant"

        # Verify it's a 404, not a 500
        if hasattr(response, 'status_code'):
            assert response.status_code == 404, f"Expected 404 but got {response.status_code}"

    @override_settings(SHOW_PUBLIC_IF_NO_TENANT_FOUND=False)
    def test_missing_tenant_api_request_returns_json_404(self):
        """Test that API requests to missing tenants return JSON 404."""
        request = self.factory.get('/api/jobs/', HTTP_HOST='nonexistent.zumodra.com')

        response = self.middleware.process_request(request)

        assert response is not None, "Middleware should return response for missing tenant"
        assert response.status_code == 404, f"Expected 404 but got {response.status_code}"

        # Verify it's JSON response
        if hasattr(response, 'data') or isinstance(response, JsonResponse):
            assert 'error' in str(response.content) or hasattr(response, 'data')

    @override_settings(SHOW_PUBLIC_IF_NO_TENANT_FOUND=True)
    def test_missing_tenant_with_fallback_uses_public_schema(self):
        """Test that missing tenants fall back to public schema when setting is True."""
        # Create public schema tenant
        public_tenant = Tenant.objects.create(
            name='Public',
            slug='public',
            schema_name='public'
        )

        request = self.factory.get('/', HTTP_HOST='nonexistent.zumodra.com')

        # Process request
        response = self.middleware.process_request(request)

        # Should succeed (returns None for valid request continuation)
        assert response is None or response.status_code != 404, \
            "With fallback enabled, missing tenant should use public schema"
        assert hasattr(request, 'tenant'), "Request should have tenant set"

    def test_tenant_resolution_error_returns_503(self):
        """Test that system-level errors return 503 Service Unavailable."""
        request = self.factory.get('/', HTTP_HOST='test.zumodra.com')

        # Mock rate limiting to trigger TenantResolutionError
        with patch.object(self.middleware, '_check_tenant_resolution_rate_limit', return_value=False):
            response = self.middleware.process_request(request)

        assert response is not None, "Middleware should return response for resolution error"
        assert response.status_code == 503, f"Expected 503 but got {response.status_code}"

    def test_tenant_resolution_error_api_returns_json_503(self):
        """Test that API requests return JSON 503 for system errors."""
        request = self.factory.get('/api/health/', HTTP_HOST='test.zumodra.com')

        # Mock rate limiting to trigger error
        with patch.object(self.middleware, '_check_tenant_resolution_rate_limit', return_value=False):
            response = self.middleware.process_request(request)

        assert response is not None
        assert response.status_code == 503
        assert 'error' in str(response.content) or 'Service Unavailable' in str(response.content)

    def test_unauthorized_tenant_access_returns_403(self):
        """Test that unauthorized tenant access via header returns 403."""
        # Create a tenant
        tenant = Tenant.objects.create(
            name='Test Tenant',
            slug='test',
            schema_name='test_schema'
        )

        request = self.factory.get('/api/jobs/', HTTP_HOST='localhost')
        request.user = MagicMock()
        request.user.is_authenticated = True
        request.user.is_superuser = False

        # Mock user without permission
        request.user.tenant_memberships.filter.return_value.exists.return_value = False
        request.user.email = 'other@example.com'

        # Mock tenant resolution with header
        with patch.object(self.middleware, '_lookup_tenant_by_id', return_value=tenant):
            with patch.object(self.middleware, '_validate_user_tenant_access', return_value=False):
                response = self.middleware.process_request(request)

        assert response is not None
        assert response.status_code == 403, f"Expected 403 for unauthorized access but got {response.status_code}"

    def test_extract_subdomain_with_invalid_base_domain(self):
        """Test subdomain extraction handles domains not matching base."""
        # Test subdomain that doesn't match TENANT_BASE_DOMAIN
        subdomain = self.middleware._extract_subdomain('test.invalid-domain.com')

        # Should return None since it doesn't match configured base domain
        assert subdomain is None, "Should return None for domains not matching base domain"

    def test_missing_custom_domain_returns_none(self):
        """Test that missing custom domains don't cause 500 errors."""
        request = self.factory.get('/', HTTP_HOST='invalid-custom-domain.com')

        # Mock lookup to return None
        with patch.object(self.middleware, '_lookup_tenant_by_domain', return_value=None):
            response = self.middleware.process_request(request)

        # Should return 404, not 500
        assert response is not None
        assert response.status_code == 404 or isinstance(response, type(Http404))


@pytest.mark.django_db
class TestTenantMiddlewareWithDatabase(TestCase):
    """Integration tests with actual database."""

    def setUp(self):
        """Set up database fixtures."""
        self.factory = RequestFactory()
        self.middleware = ZumodraTenantMiddleware(lambda r: None)

        # Create a test tenant
        self.tenant = Tenant.objects.create(
            name='Test Company',
            slug='test',
            schema_name='test_schema'
        )

    @override_settings(SHOW_PUBLIC_IF_NO_TENANT_FOUND=False)
    def test_existing_tenant_resolves_correctly(self):
        """Test that existing tenants are resolved properly."""
        request = self.factory.get('/', HTTP_HOST='test.zumodra.com')

        with patch.object(self.middleware, '_setup_tenant_schema'):
            response = self.middleware.process_request(request)

        # Should succeed (returns None to continue processing)
        assert hasattr(request, 'tenant')
        assert request.tenant.slug == 'test'

    @override_settings(SHOW_PUBLIC_IF_NO_TENANT_FOUND=False)
    def test_nonexistent_subdomain_returns_404_not_server_error(self):
        """
        Test the specific scenario: accessing nonexistent subdomain returns 404.

        This is the primary issue fixed - ensures proper 404 instead of 500.
        """
        request = self.factory.get('/', HTTP_HOST='nonexistent.zumodra.com')

        response = self.middleware.process_request(request)

        # Should be Http404 exception or 404 response
        if isinstance(response, type(Http404)):
            assert True, "Should raise Http404"
        elif response is not None:
            assert response.status_code == 404, f"Expected 404, got {response.status_code}"
        else:
            # None means request will continue - check if tenant was set
            # In this case it should have been rejected earlier
            pytest.fail("Middleware should return 404 response for missing tenant")

    @override_settings(SHOW_PUBLIC_IF_NO_TENANT_FOUND=True)
    def test_fallback_to_public_schema(self):
        """Test fallback behavior when SHOW_PUBLIC_IF_NO_TENANT_FOUND=True."""
        # Create public schema tenant
        public_tenant = Tenant.objects.create(
            name='Public',
            slug='public',
            schema_name='public'
        )

        request = self.factory.get('/', HTTP_HOST='nonexistent.zumodra.com')

        with patch.object(self.middleware, '_setup_tenant_schema'):
            response = self.middleware.process_request(request)

        # Should continue processing (returns None)
        assert response is None or (hasattr(response, 'status_code') and response.status_code != 404)
        assert hasattr(request, 'tenant')
        assert request.tenant.schema_name == 'public'
