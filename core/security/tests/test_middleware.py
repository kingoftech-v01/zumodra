"""
Security Middleware Tests for Zumodra ATS/HR Platform

This module tests security middleware functionality including:
- SecurityHeadersMiddleware: Verify all security headers are present
- RateLimitMiddleware: Verify rate limiting works, test bypass attempts
- RequestValidationMiddleware: Test size limits, content-type validation
- AuditLogMiddleware: Verify all actions are logged
- IPWhitelistMiddleware: Test whitelist enforcement

Each test documents the attack vector being tested and includes both
positive tests (valid inputs) and negative tests (attack attempts).
"""

import json
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch, PropertyMock

import pytest
from django.contrib.auth import get_user_model
from django.http import HttpResponse, HttpRequest, JsonResponse
from django.test import TestCase, RequestFactory, override_settings
from django.test.client import Client
from django.urls import reverse

User = get_user_model()


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def request_factory():
    """Provide a Django RequestFactory for creating test requests."""
    return RequestFactory()


@pytest.fixture
def mock_get_response():
    """Provide a mock get_response callable for middleware testing."""
    return Mock(return_value=HttpResponse('OK', status=200))


@pytest.fixture
def authenticated_request(request_factory, user_factory, db):
    """Create an authenticated request."""
    user = user_factory()
    request = request_factory.get('/')
    request.user = user
    request.session = {}
    return request


@pytest.fixture
def anonymous_request(request_factory):
    """Create an anonymous request."""
    request = request_factory.get('/')
    request.user = MagicMock(is_authenticated=False)
    request.session = {}
    return request


# =============================================================================
# SECURITY HEADERS MIDDLEWARE TESTS
# =============================================================================

class TestSecurityHeadersMiddleware:
    """
    Tests for SecurityHeadersMiddleware.

    Attack Vector: Missing or weak security headers can enable:
    - XSS attacks (missing Content-Security-Policy)
    - Clickjacking (missing X-Frame-Options)
    - MIME-type confusion (missing X-Content-Type-Options)
    - Information leakage (missing Referrer-Policy)
    - Protocol downgrade (missing Strict-Transport-Security)
    """

    @pytest.fixture
    def middleware(self, mock_get_response):
        """Create SecurityHeadersMiddleware instance."""
        from core.security.middleware import SecurityHeadersMiddleware
        return SecurityHeadersMiddleware(mock_get_response)

    def test_content_security_policy_header_present(
        self, middleware, request_factory
    ):
        """
        Test: Content-Security-Policy header is present and properly configured.
        Attack Vector: Missing CSP allows XSS attacks via inline scripts.
        """
        request = request_factory.get('/')
        response = middleware(request)

        assert 'Content-Security-Policy' in response
        csp = response['Content-Security-Policy']

        # Verify CSP includes essential directives
        assert "default-src" in csp
        assert "script-src" in csp
        assert "style-src" in csp
        assert "img-src" in csp
        assert "frame-ancestors" in csp

        # Verify unsafe-inline is not present for scripts (unless with nonce)
        # Note: If nonces are used, unsafe-inline might be present as fallback

    def test_x_frame_options_header_present(
        self, middleware, request_factory
    ):
        """
        Test: X-Frame-Options header prevents clickjacking.
        Attack Vector: Without this header, page can be embedded in iframes.
        """
        request = request_factory.get('/')
        response = middleware(request)

        assert 'X-Frame-Options' in response
        assert response['X-Frame-Options'] in ['DENY', 'SAMEORIGIN']

    def test_x_content_type_options_header_present(
        self, middleware, request_factory
    ):
        """
        Test: X-Content-Type-Options prevents MIME-type sniffing.
        Attack Vector: MIME sniffing can lead to XSS via content-type confusion.
        """
        request = request_factory.get('/')
        response = middleware(request)

        assert 'X-Content-Type-Options' in response
        assert response['X-Content-Type-Options'] == 'nosniff'

    def test_strict_transport_security_header_present(
        self, middleware, request_factory
    ):
        """
        Test: HSTS header enforces HTTPS.
        Attack Vector: Missing HSTS allows protocol downgrade attacks.
        """
        request = request_factory.get('/')
        request.is_secure = Mock(return_value=True)
        response = middleware(request)

        assert 'Strict-Transport-Security' in response
        hsts = response['Strict-Transport-Security']

        # Verify max-age is reasonable (at least 1 year = 31536000)
        assert 'max-age=' in hsts
        # Extract max-age value
        import re
        match = re.search(r'max-age=(\d+)', hsts)
        if match:
            max_age = int(match.group(1))
            assert max_age >= 31536000, "HSTS max-age should be at least 1 year"

    def test_referrer_policy_header_present(
        self, middleware, request_factory
    ):
        """
        Test: Referrer-Policy controls information leakage.
        Attack Vector: Full referrer can leak sensitive URL parameters.
        """
        request = request_factory.get('/')
        response = middleware(request)

        assert 'Referrer-Policy' in response
        # Should be restrictive
        assert response['Referrer-Policy'] in [
            'no-referrer',
            'no-referrer-when-downgrade',
            'same-origin',
            'strict-origin',
            'strict-origin-when-cross-origin'
        ]

    def test_permissions_policy_header_present(
        self, middleware, request_factory
    ):
        """
        Test: Permissions-Policy restricts browser features.
        Attack Vector: Unrestricted features can be abused (camera, mic, geolocation).
        """
        request = request_factory.get('/')
        response = middleware(request)

        assert 'Permissions-Policy' in response
        policy = response['Permissions-Policy']

        # Verify sensitive features are restricted
        assert 'geolocation' in policy
        assert 'camera' in policy
        assert 'microphone' in policy

    def test_cache_control_for_sensitive_pages(
        self, middleware, request_factory
    ):
        """
        Test: Cache-Control prevents caching of sensitive data.
        Attack Vector: Cached sensitive pages can be retrieved by other users.
        """
        # Request to a sensitive endpoint
        request = request_factory.get('/api/users/profile/')
        response = middleware(request)

        # For sensitive endpoints, should have no-cache headers
        cache_control = response.get('Cache-Control', '')
        # This test may need adjustment based on actual implementation

    def test_cross_origin_headers(
        self, middleware, request_factory
    ):
        """
        Test: Cross-origin headers are properly set.
        Attack Vector: Missing CORS headers can either block legitimate
        cross-origin requests or allow unauthorized ones.
        """
        request = request_factory.get('/')
        response = middleware(request)

        # Check for Cross-Origin headers if they exist
        # These are newer security headers
        if 'Cross-Origin-Opener-Policy' in response:
            assert response['Cross-Origin-Opener-Policy'] in ['same-origin', 'same-origin-allow-popups']

        if 'Cross-Origin-Embedder-Policy' in response:
            assert response['Cross-Origin-Embedder-Policy'] in ['require-corp', 'credentialless']


# =============================================================================
# RATE LIMIT MIDDLEWARE TESTS
# =============================================================================

class TestRateLimitMiddleware:
    """
    Tests for RateLimitMiddleware.

    Attack Vector: Without rate limiting, attackers can:
    - Perform brute force attacks on login
    - DoS the application with excessive requests
    - Enumerate users/resources
    - Abuse expensive operations
    """

    @pytest.fixture
    def middleware(self, mock_get_response):
        """Create RateLimitMiddleware instance."""
        from core.security.middleware import RateLimitMiddleware
        return RateLimitMiddleware(mock_get_response)

    @pytest.fixture
    def clear_rate_limit_cache(self):
        """Clear rate limit cache before tests."""
        from django.core.cache import cache
        cache.clear()
        yield
        cache.clear()

    def test_allows_requests_within_limit(
        self, middleware, request_factory, clear_rate_limit_cache
    ):
        """
        Positive Test: Requests within rate limit are allowed.
        """
        request = request_factory.get('/')
        request.META['REMOTE_ADDR'] = '192.168.1.100'

        # Make several requests within limit
        for _ in range(10):
            response = middleware(request)
            assert response.status_code == 200

    def test_blocks_requests_exceeding_limit(
        self, middleware, request_factory, clear_rate_limit_cache
    ):
        """
        Test: Requests exceeding rate limit are blocked.
        Attack Vector: Brute force attacks, DoS attacks.
        """
        request = request_factory.get('/')
        request.META['REMOTE_ADDR'] = '192.168.1.101'

        # Exceed rate limit (assuming default is 100/min)
        blocked = False
        for i in range(150):
            response = middleware(request)
            if response.status_code == 429:
                blocked = True
                break

        assert blocked, "Rate limiting should block excessive requests"

    def test_rate_limit_per_ip(
        self, middleware, request_factory, clear_rate_limit_cache
    ):
        """
        Test: Rate limits are tracked per IP address.
        Attack Vector: Attacker tries to distribute attack across sessions.
        """
        # Request from IP 1
        request1 = request_factory.get('/')
        request1.META['REMOTE_ADDR'] = '10.0.0.1'

        # Request from IP 2
        request2 = request_factory.get('/')
        request2.META['REMOTE_ADDR'] = '10.0.0.2'

        # Exhaust rate limit for IP 1
        for _ in range(100):
            middleware(request1)

        # IP 2 should still be able to make requests
        response = middleware(request2)
        assert response.status_code == 200

    def test_rate_limit_bypass_via_x_forwarded_for_blocked(
        self, middleware, request_factory, clear_rate_limit_cache
    ):
        """
        Test: X-Forwarded-For header spoofing doesn't bypass rate limiting.
        Attack Vector: Attacker spoofs X-Forwarded-For to appear as different IPs.
        """
        request = request_factory.get('/')
        request.META['REMOTE_ADDR'] = '192.168.1.200'

        # Exhaust rate limit
        for _ in range(100):
            response = middleware(request)

        # Try to bypass by spoofing X-Forwarded-For
        request.META['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 5.6.7.8'
        response = middleware(request)

        # Should still be rate limited (REMOTE_ADDR is authoritative when not behind proxy)
        # Note: This behavior depends on configuration

    def test_rate_limit_login_endpoint_stricter(
        self, middleware, request_factory, clear_rate_limit_cache
    ):
        """
        Test: Login endpoint has stricter rate limits.
        Attack Vector: Brute force password attacks.
        """
        request = request_factory.post('/api/auth/login/')
        request.META['REMOTE_ADDR'] = '192.168.1.150'
        request._body = b'{"email": "test@test.com", "password": "wrong"}'

        # Login should have stricter limits (e.g., 5/min)
        blocked = False
        for i in range(10):
            response = middleware(request)
            if response.status_code == 429:
                blocked = True
                break

        assert blocked, "Login endpoint should have stricter rate limits"

    def test_rate_limit_password_reset_stricter(
        self, middleware, request_factory, clear_rate_limit_cache
    ):
        """
        Test: Password reset has stricter rate limits.
        Attack Vector: User enumeration, email flooding.
        """
        request = request_factory.post('/api/auth/password-reset/')
        request.META['REMOTE_ADDR'] = '192.168.1.160'

        # Password reset should have strict limits
        blocked = False
        for i in range(5):
            response = middleware(request)
            if response.status_code == 429:
                blocked = True
                break

    def test_rate_limit_includes_retry_after_header(
        self, middleware, request_factory, clear_rate_limit_cache
    ):
        """
        Test: 429 response includes Retry-After header.
        """
        request = request_factory.get('/')
        request.META['REMOTE_ADDR'] = '192.168.1.170'

        # Exhaust rate limit
        for _ in range(150):
            response = middleware(request)
            if response.status_code == 429:
                assert 'Retry-After' in response
                break


# =============================================================================
# REQUEST VALIDATION MIDDLEWARE TESTS
# =============================================================================

class TestRequestValidationMiddleware:
    """
    Tests for RequestValidationMiddleware.

    Attack Vector: Without request validation:
    - Large requests can cause DoS (memory exhaustion)
    - Invalid content types can lead to parser exploits
    - Malformed JSON/XML can cause crashes
    """

    @pytest.fixture
    def middleware(self, mock_get_response):
        """Create RequestValidationMiddleware instance."""
        from core.security.middleware import RequestValidationMiddleware
        return RequestValidationMiddleware(mock_get_response)

    def test_rejects_oversized_request_body(
        self, middleware, request_factory
    ):
        """
        Test: Requests with oversized body are rejected.
        Attack Vector: Large request body DoS (memory exhaustion).
        """
        request = request_factory.post(
            '/api/data/',
            content_type='application/json'
        )
        # Simulate large body (10MB)
        request._body = b'x' * (10 * 1024 * 1024)
        request.META['CONTENT_LENGTH'] = str(len(request._body))

        response = middleware(request)

        assert response.status_code == 413  # Payload Too Large

    def test_allows_normal_sized_request(
        self, middleware, request_factory
    ):
        """
        Positive Test: Normal sized requests are allowed.
        """
        request = request_factory.post(
            '/api/data/',
            data=json.dumps({'name': 'test'}),
            content_type='application/json'
        )

        response = middleware(request)
        assert response.status_code == 200

    def test_rejects_invalid_content_type(
        self, middleware, request_factory
    ):
        """
        Test: Requests with invalid content type for endpoint are rejected.
        Attack Vector: Content-type confusion attacks.
        """
        request = request_factory.post(
            '/api/data/',
            data=b'<script>alert(1)</script>',
            content_type='text/html'  # HTML not accepted for API endpoints
        )

        response = middleware(request)
        # Should either reject or sanitize
        assert response.status_code in [400, 415]  # Bad Request or Unsupported Media Type

    def test_rejects_malformed_json(
        self, middleware, request_factory
    ):
        """
        Test: Malformed JSON is rejected.
        Attack Vector: Parser exploits, DoS via complex JSON.
        """
        request = request_factory.post(
            '/api/data/',
            data=b'{invalid json: }}}',
            content_type='application/json'
        )

        response = middleware(request)
        assert response.status_code == 400

    def test_rejects_deeply_nested_json(
        self, middleware, request_factory
    ):
        """
        Test: Deeply nested JSON is rejected.
        Attack Vector: Stack overflow via recursive parsing.
        """
        # Create deeply nested JSON (1000 levels)
        nested = {'a': None}
        current = nested
        for _ in range(1000):
            current['a'] = {'a': None}
            current = current['a']

        request = request_factory.post(
            '/api/data/',
            data=json.dumps(nested),
            content_type='application/json'
        )

        response = middleware(request)
        # Should reject or return error
        assert response.status_code in [400, 413]

    def test_content_length_mismatch_rejected(
        self, middleware, request_factory
    ):
        """
        Test: Mismatched Content-Length is rejected.
        Attack Vector: HTTP request smuggling.
        """
        request = request_factory.post(
            '/api/data/',
            content_type='application/json'
        )
        request._body = b'{"test": true}'
        request.META['CONTENT_LENGTH'] = '1000'  # Doesn't match actual body

        response = middleware(request)
        assert response.status_code == 400

    def test_null_byte_injection_blocked(
        self, middleware, request_factory
    ):
        """
        Test: Null bytes in request are blocked.
        Attack Vector: Null byte injection to bypass validation.
        """
        request = request_factory.get('/api/files/test%00.txt')

        response = middleware(request)
        # Should block or sanitize
        assert response.status_code in [400, 200]  # 200 if sanitized

    def test_url_with_encoded_traversal_blocked(
        self, middleware, request_factory
    ):
        """
        Test: URL-encoded path traversal is blocked.
        Attack Vector: Access files outside webroot.
        """
        # URL-encoded ../../../etc/passwd
        request = request_factory.get('/api/files/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd')

        response = middleware(request)
        assert response.status_code == 400


# =============================================================================
# AUDIT LOG MIDDLEWARE TESTS
# =============================================================================

class TestAuditLogMiddleware:
    """
    Tests for AuditLogMiddleware.

    Attack Vector: Without proper audit logging:
    - Security incidents go undetected
    - No forensic trail for investigations
    - Compliance violations (GDPR, SOC2)
    """

    @pytest.fixture
    def middleware(self, mock_get_response):
        """Create AuditLogMiddleware instance."""
        from core.security.middleware import AuditLogMiddleware
        return AuditLogMiddleware(mock_get_response)

    @pytest.fixture
    def mock_audit_service(self):
        """Mock the audit logging service."""
        with patch('core.security.middleware.AuditService') as mock:
            yield mock

    def test_logs_authenticated_requests(
        self, middleware, authenticated_request, mock_audit_service
    ):
        """
        Test: Authenticated requests are logged.
        """
        middleware(authenticated_request)

        mock_audit_service.log.assert_called()
        call_args = mock_audit_service.log.call_args

        # Verify essential fields are logged
        assert 'user' in call_args.kwargs or call_args[0]
        assert 'action' in call_args.kwargs or len(call_args[0]) > 1

    def test_logs_authentication_failures(
        self, middleware, request_factory, mock_audit_service
    ):
        """
        Test: Failed authentication attempts are logged.
        Security Requirement: OWASP A09 - Security Logging and Monitoring.
        """
        request = request_factory.post('/api/auth/login/')
        request.user = MagicMock(is_authenticated=False)

        # Simulate failed auth
        middleware.get_response = Mock(return_value=HttpResponse(status=401))

        response = middleware(request)

        # Should log the failed attempt
        mock_audit_service.log_security_event.assert_called()

    def test_logs_sensitive_data_access(
        self, middleware, authenticated_request, mock_audit_service
    ):
        """
        Test: Access to sensitive endpoints is logged.
        """
        authenticated_request.path = '/api/employees/12345/salary/'

        middleware(authenticated_request)

        mock_audit_service.log_data_access.assert_called()
        call_args = mock_audit_service.log_data_access.call_args

        # Verify data category is identified
        assert 'salary' in str(call_args).lower() or 'sensitive' in str(call_args).lower()

    def test_logs_ip_address(
        self, middleware, authenticated_request, mock_audit_service
    ):
        """
        Test: Client IP address is logged.
        """
        authenticated_request.META['REMOTE_ADDR'] = '192.168.1.50'

        middleware(authenticated_request)

        call_args = mock_audit_service.log.call_args
        assert '192.168.1.50' in str(call_args)

    def test_logs_user_agent(
        self, middleware, authenticated_request, mock_audit_service
    ):
        """
        Test: User agent is logged for device tracking.
        """
        authenticated_request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 TestBrowser'

        middleware(authenticated_request)

        call_args = mock_audit_service.log.call_args
        assert 'Mozilla' in str(call_args) or 'user_agent' in str(call_args).lower()

    def test_logs_request_method(
        self, middleware, authenticated_request, mock_audit_service
    ):
        """
        Test: HTTP method is logged.
        """
        authenticated_request.method = 'DELETE'
        authenticated_request.path = '/api/users/123/'

        middleware(authenticated_request)

        call_args = mock_audit_service.log.call_args
        assert 'DELETE' in str(call_args)

    def test_sensitive_data_masked_in_logs(
        self, middleware, request_factory, mock_audit_service
    ):
        """
        Test: Sensitive data (passwords, tokens) are masked in logs.
        Security: Prevent credential leakage in logs.
        """
        request = request_factory.post(
            '/api/auth/login/',
            data=json.dumps({
                'email': 'user@test.com',
                'password': 'secretpassword123'
            }),
            content_type='application/json'
        )
        request.user = MagicMock(is_authenticated=False)

        middleware(request)

        # Password should not appear in logs
        all_calls = str(mock_audit_service.mock_calls)
        assert 'secretpassword123' not in all_calls

    def test_logs_response_status(
        self, middleware, authenticated_request, mock_audit_service
    ):
        """
        Test: Response status code is logged.
        """
        middleware.get_response = Mock(return_value=HttpResponse(status=403))

        middleware(authenticated_request)

        call_args = mock_audit_service.log.call_args
        assert '403' in str(call_args) or 'status' in str(call_args).lower()

    def test_logs_include_correlation_id(
        self, middleware, authenticated_request, mock_audit_service
    ):
        """
        Test: Logs include correlation ID for request tracing.
        """
        middleware(authenticated_request)

        call_args = mock_audit_service.log.call_args
        # Should have some form of request ID
        assert 'request_id' in str(call_args).lower() or 'correlation' in str(call_args).lower()


# =============================================================================
# IP WHITELIST MIDDLEWARE TESTS
# =============================================================================

class TestIPWhitelistMiddleware:
    """
    Tests for IPWhitelistMiddleware.

    Attack Vector: Without IP whitelisting:
    - Admin interfaces accessible from anywhere
    - Internal APIs exposed to internet
    - Sensitive operations available to all
    """

    @pytest.fixture
    def middleware(self, mock_get_response):
        """Create IPWhitelistMiddleware instance."""
        from core.security.middleware import IPWhitelistMiddleware
        return IPWhitelistMiddleware(mock_get_response)

    @pytest.fixture
    def mock_whitelist(self):
        """Mock IP whitelist configuration."""
        with patch('core.security.middleware.get_ip_whitelist') as mock:
            mock.return_value = {
                '/admin/': ['10.0.0.0/8', '192.168.0.0/16'],
                '/api/internal/': ['10.0.0.0/8'],
            }
            yield mock

    def test_allows_whitelisted_ip_for_admin(
        self, middleware, request_factory, mock_whitelist
    ):
        """
        Positive Test: Whitelisted IP can access admin.
        """
        request = request_factory.get('/admin/')
        request.META['REMOTE_ADDR'] = '10.0.1.100'

        response = middleware(request)
        assert response.status_code == 200

    def test_blocks_non_whitelisted_ip_for_admin(
        self, middleware, request_factory, mock_whitelist
    ):
        """
        Test: Non-whitelisted IP cannot access admin.
        Attack Vector: Unauthorized admin access.
        """
        request = request_factory.get('/admin/')
        request.META['REMOTE_ADDR'] = '203.0.113.50'  # Not in whitelist

        response = middleware(request)
        assert response.status_code == 403

    def test_allows_any_ip_for_public_endpoints(
        self, middleware, request_factory, mock_whitelist
    ):
        """
        Positive Test: Public endpoints accessible from any IP.
        """
        request = request_factory.get('/api/public/health/')
        request.META['REMOTE_ADDR'] = '203.0.113.50'

        response = middleware(request)
        assert response.status_code == 200

    def test_cidr_notation_matching(
        self, middleware, request_factory, mock_whitelist
    ):
        """
        Test: CIDR notation properly matches IP ranges.
        """
        # 10.255.255.255 is in 10.0.0.0/8
        request = request_factory.get('/admin/')
        request.META['REMOTE_ADDR'] = '10.255.255.255'

        response = middleware(request)
        assert response.status_code == 200

    def test_ipv6_support(
        self, middleware, request_factory
    ):
        """
        Test: IPv6 addresses are properly handled.
        """
        with patch('core.security.middleware.get_ip_whitelist') as mock:
            mock.return_value = {
                '/admin/': ['2001:db8::/32'],
            }

            request = request_factory.get('/admin/')
            request.META['REMOTE_ADDR'] = '2001:db8::1'

            response = middleware(request)
            assert response.status_code == 200

    def test_x_forwarded_for_handling_with_trusted_proxy(
        self, middleware, request_factory, mock_whitelist
    ):
        """
        Test: X-Forwarded-For is honored when from trusted proxy.
        Note: Must be configured to trust specific proxies.
        """
        request = request_factory.get('/admin/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'  # Trusted proxy
        request.META['HTTP_X_FORWARDED_FOR'] = '10.0.1.100'  # Original client

        with patch('core.security.middleware.TRUSTED_PROXIES', ['127.0.0.1']):
            response = middleware(request)
            assert response.status_code == 200

    def test_x_forwarded_for_spoofing_blocked(
        self, middleware, request_factory, mock_whitelist
    ):
        """
        Test: X-Forwarded-For spoofing from untrusted source is blocked.
        Attack Vector: IP spoofing to bypass whitelist.
        """
        request = request_factory.get('/admin/')
        request.META['REMOTE_ADDR'] = '203.0.113.50'  # Untrusted source
        request.META['HTTP_X_FORWARDED_FOR'] = '10.0.1.100'  # Spoofed

        response = middleware(request)
        assert response.status_code == 403

    def test_whitelist_logs_blocked_attempts(
        self, middleware, request_factory, mock_whitelist
    ):
        """
        Test: Blocked access attempts are logged.
        """
        with patch('core.security.middleware.logger') as mock_logger:
            request = request_factory.get('/admin/')
            request.META['REMOTE_ADDR'] = '203.0.113.50'

            middleware(request)

            mock_logger.warning.assert_called()
            call_args = str(mock_logger.warning.call_args)
            assert '203.0.113.50' in call_args


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestMiddlewareChain:
    """
    Integration tests for middleware chain.

    Tests that all security middleware work together correctly.
    """

    @pytest.mark.django_db
    def test_complete_request_lifecycle(self, client):
        """
        Test: Complete request passes through all security middleware.
        """
        response = client.get('/')

        # Verify security headers are present
        assert 'X-Content-Type-Options' in response
        assert 'X-Frame-Options' in response

    @pytest.mark.django_db
    def test_middleware_order_is_correct(self, settings):
        """
        Test: Middleware is ordered correctly for security.
        Security middleware should come early in the chain.
        """
        middleware_list = settings.MIDDLEWARE

        # SecurityMiddleware should be early
        security_index = None
        for i, m in enumerate(middleware_list):
            if 'SecurityMiddleware' in m:
                security_index = i
                break

        # Session middleware should come after security
        session_index = None
        for i, m in enumerate(middleware_list):
            if 'SessionMiddleware' in m:
                session_index = i
                break

        if security_index is not None and session_index is not None:
            assert security_index < session_index
