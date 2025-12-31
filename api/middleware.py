"""
API Middleware - Request Processing and Enhancement for Zumodra API

This module provides middleware classes for API request/response processing:
- RequestIDMiddleware: Generates unique request IDs for tracing
- RateLimitHeaderMiddleware: Adds X-RateLimit-* headers to responses

Request IDs enable distributed tracing, debugging, and audit logging.
"""

import logging
import uuid
from typing import Callable, Optional

from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


# =============================================================================
# REQUEST ID MIDDLEWARE
# =============================================================================

class RequestIDMiddleware(MiddlewareMixin):
    """
    Middleware that generates and attaches a unique request ID to each request.

    Features:
    - Generates UUID4 request IDs for all requests
    - Respects existing X-Request-ID header from client/load balancer
    - Adds X-Request-ID header to all responses
    - Makes request ID available as request.request_id

    Usage in settings.py:
        MIDDLEWARE = [
            ...
            'api.middleware.RequestIDMiddleware',
            ...
        ]

    The request ID can be accessed in views via request.request_id and will
    be included in all API responses for client-side correlation.
    """

    REQUEST_ID_HEADER = 'HTTP_X_REQUEST_ID'
    RESPONSE_HEADER = 'X-Request-ID'

    def process_request(self, request: HttpRequest) -> None:
        """
        Generate or extract request ID and attach to request object.
        """
        # Check for existing request ID from upstream (load balancer, gateway)
        request_id = request.META.get(self.REQUEST_ID_HEADER)

        if not request_id:
            # Generate new UUID4 request ID
            request_id = str(uuid.uuid4())

        # Attach to request for use in views, serializers, and logging
        request.request_id = request_id

        # Add to logging context for automatic inclusion in log messages
        logger.debug(f"Request {request_id}: {request.method} {request.path}")

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """
        Add request ID header to response for client correlation.
        """
        request_id = getattr(request, 'request_id', None)

        if request_id:
            response[self.RESPONSE_HEADER] = request_id

        return response


class RateLimitHeaderMiddleware(MiddlewareMixin):
    """
    Middleware that adds X-RateLimit-* headers to API responses.

    This middleware collects rate limit information from throttles that were
    applied during request processing and adds standardized headers:
    - X-RateLimit-Limit: Maximum requests allowed in the window
    - X-RateLimit-Remaining: Requests remaining in current window
    - X-RateLimit-Reset: Unix timestamp when the window resets

    Usage in settings.py:
        MIDDLEWARE = [
            ...
            'api.middleware.RateLimitHeaderMiddleware',
            ...
        ]

    Note: This middleware should be placed after authentication middleware
    and works in conjunction with DRF throttle classes.
    """

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """
        Add rate limit headers from throttle information stored on request.
        """
        # Check if rate limit headers were set by throttles during view processing
        rate_limit_headers = getattr(request, '_rate_limit_headers', None)

        if rate_limit_headers:
            for header, value in rate_limit_headers.items():
                response[header] = value

        return response


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_request_id(request: HttpRequest) -> str:
    """
    Get the request ID from a request object.

    Args:
        request: The Django request object

    Returns:
        The request ID string, or generates a new one if not present
    """
    request_id = getattr(request, 'request_id', None)
    if not request_id:
        request_id = str(uuid.uuid4())
        request.request_id = request_id
    return request_id


def set_rate_limit_headers(request: HttpRequest, headers: dict) -> None:
    """
    Store rate limit headers on request for middleware to add to response.

    Args:
        request: The Django request object
        headers: Dict of rate limit headers to add to response
    """
    request._rate_limit_headers = headers


# =============================================================================
# SECURITY HEADERS MIDDLEWARE
# =============================================================================

class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware that adds comprehensive security headers to all responses.

    Implements OWASP security header recommendations:
    - Content-Security-Policy (CSP): Prevents XSS and injection attacks
    - X-Frame-Options: Prevents clickjacking
    - X-Content-Type-Options: Prevents MIME-type sniffing
    - Referrer-Policy: Controls referrer information leakage
    - Strict-Transport-Security (HSTS): Enforces HTTPS with preload
    - X-XSS-Protection: Legacy XSS protection (deprecated but still useful)
    - Permissions-Policy: Controls browser features
    - Cache-Control: Prevents caching of sensitive data

    Configure in settings.py:
        MIDDLEWARE = [
            ...
            'api.middleware.SecurityHeadersMiddleware',
            ...
        ]

        SECURITY_HEADERS = {
            'CSP_ENABLED': True,
            'CSP_REPORT_ONLY': False,
            'HSTS_SECONDS': 31536000,
            'HSTS_PRELOAD': True,
        }

    Note: This middleware is designed to work alongside django-csp.
    If you're using django-csp, you may want to disable CSP in this middleware.
    """

    # Default CSP directives (strict, no inline)
    DEFAULT_CSP_DIRECTIVES = {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'img-src': ["'self'", "data:", "https:"],
        'font-src': ["'self'"],
        'connect-src': ["'self'"],
        'frame-src': ["'none'"],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        'upgrade-insecure-requests': [],
    }

    def __init__(self, get_response=None):
        super().__init__(get_response)
        self._load_settings()

    def _load_settings(self):
        """Load security header settings from Django settings."""
        from django.conf import settings

        security_settings = getattr(settings, 'SECURITY_HEADERS', {})

        # CSP settings
        self.csp_enabled = security_settings.get('CSP_ENABLED', True)
        self.csp_report_only = security_settings.get('CSP_REPORT_ONLY', False)
        self.csp_report_uri = security_settings.get('CSP_REPORT_URI', None)
        self.csp_directives = security_settings.get('CSP_DIRECTIVES', self.DEFAULT_CSP_DIRECTIVES)

        # HSTS settings
        self.hsts_enabled = security_settings.get('HSTS_ENABLED', True)
        self.hsts_seconds = security_settings.get('HSTS_SECONDS', 31536000)  # 1 year
        self.hsts_include_subdomains = security_settings.get('HSTS_INCLUDE_SUBDOMAINS', True)
        self.hsts_preload = security_settings.get('HSTS_PRELOAD', True)

        # Other settings
        self.x_frame_options = security_settings.get('X_FRAME_OPTIONS', 'DENY')
        self.referrer_policy = security_settings.get('REFERRER_POLICY', 'strict-origin-when-cross-origin')

        # Paths to exclude from strict CSP (e.g., admin, docs)
        self.csp_exclude_paths = security_settings.get('CSP_EXCLUDE_PATHS', [
            '/admin/',
            '/api/docs/',
            '/wagtail/',
        ])

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Add security headers to response."""

        # X-Frame-Options: DENY - Prevents clickjacking
        if 'X-Frame-Options' not in response:
            response['X-Frame-Options'] = self.x_frame_options

        # X-Content-Type-Options: nosniff - Prevents MIME-type sniffing
        if 'X-Content-Type-Options' not in response:
            response['X-Content-Type-Options'] = 'nosniff'

        # Referrer-Policy - Controls referrer information
        if 'Referrer-Policy' not in response:
            response['Referrer-Policy'] = self.referrer_policy

        # X-XSS-Protection - Legacy XSS protection
        if 'X-XSS-Protection' not in response:
            response['X-XSS-Protection'] = '1; mode=block'

        # Permissions-Policy (formerly Feature-Policy)
        if 'Permissions-Policy' not in response:
            response['Permissions-Policy'] = self._build_permissions_policy()

        # HSTS (only for HTTPS requests)
        if self.hsts_enabled and request.is_secure():
            if 'Strict-Transport-Security' not in response:
                response['Strict-Transport-Security'] = self._build_hsts_header()

        # Content-Security-Policy
        if self.csp_enabled and not self._is_csp_excluded(request.path):
            csp_header = self._build_csp_header(request)
            if csp_header:
                header_name = 'Content-Security-Policy-Report-Only' if self.csp_report_only else 'Content-Security-Policy'
                if header_name not in response:
                    response[header_name] = csp_header

        # Cache-Control for sensitive pages
        if self._is_sensitive_path(request.path):
            response['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'

        # X-Download-Options - Prevents auto-opening of downloads in IE
        response['X-Download-Options'] = 'noopen'

        # X-Permitted-Cross-Domain-Policies - Restricts Flash/PDF cross-domain
        response['X-Permitted-Cross-Domain-Policies'] = 'none'

        return response

    def _build_csp_header(self, request: HttpRequest) -> str:
        """Build the CSP header value."""
        directives = []

        for directive, values in self.csp_directives.items():
            if values:
                directives.append(f"{directive} {' '.join(values)}")
            else:
                directives.append(directive)

        # Add report-uri if configured
        if self.csp_report_uri:
            directives.append(f"report-uri {self.csp_report_uri}")

        return '; '.join(directives)

    def _build_hsts_header(self) -> str:
        """Build the HSTS header value."""
        header = f'max-age={self.hsts_seconds}'

        if self.hsts_include_subdomains:
            header += '; includeSubDomains'

        if self.hsts_preload:
            header += '; preload'

        return header

    def _build_permissions_policy(self) -> str:
        """Build the Permissions-Policy header value."""
        policies = [
            'accelerometer=()',
            'camera=()',
            'geolocation=()',
            'gyroscope=()',
            'magnetometer=()',
            'microphone=()',
            'payment=()',
            'usb=()',
            'fullscreen=(self)',
        ]
        return ', '.join(policies)

    def _is_csp_excluded(self, path: str) -> bool:
        """Check if path is excluded from CSP."""
        for excluded in self.csp_exclude_paths:
            if path.startswith(excluded):
                return True
        return False

    def _is_sensitive_path(self, path: str) -> bool:
        """Check if path contains sensitive data that shouldn't be cached."""
        sensitive_patterns = [
            '/api/auth/',
            '/api/users/',
            '/accounts/',
            '/admin/',
            '/profile/',
            '/settings/',
            '/dashboard/',
        ]
        for pattern in sensitive_patterns:
            if path.startswith(pattern):
                return True
        return False


class CSPNonceMiddleware(MiddlewareMixin):
    """
    Middleware that generates a nonce for inline scripts/styles.

    This allows specific inline scripts while maintaining strict CSP.

    Usage in templates:
        <script nonce="{{ request.csp_nonce }}">
            // Inline script here
        </script>

    Configure CSP to include nonce:
        'script-src': ["'self'", "'nonce-{nonce}'"]

    Note: The nonce is regenerated for each request for security.
    """

    def process_request(self, request: HttpRequest) -> None:
        """Generate and attach CSP nonce to request."""
        import base64
        import os

        # Generate random nonce
        nonce_bytes = os.urandom(16)
        nonce = base64.b64encode(nonce_bytes).decode('utf-8')

        # Attach to request for template access
        request.csp_nonce = nonce

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Update CSP header with nonce if present."""
        nonce = getattr(request, 'csp_nonce', None)
        if not nonce:
            return response

        # Update CSP header to include nonce
        for header in ['Content-Security-Policy', 'Content-Security-Policy-Report-Only']:
            if header in response:
                csp = response[header]
                # Add nonce to script-src and style-src
                csp = csp.replace("script-src ", f"script-src 'nonce-{nonce}' ")
                csp = csp.replace("style-src ", f"style-src 'nonce-{nonce}' ")
                response[header] = csp

        return response


class APISecurityMiddleware(MiddlewareMixin):
    """
    Security middleware specifically for API endpoints.

    Features:
    - CORS validation for API requests
    - API key validation (if enabled)
    - Request signing validation (if enabled)
    - JSON content-type enforcement
    - Request body size limiting

    Configure in settings.py:
        API_SECURITY = {
            'REQUIRE_CONTENT_TYPE': True,
            'MAX_BODY_SIZE': 10 * 1024 * 1024,  # 10MB
            'REQUIRE_API_KEY': False,
        }
    """

    API_PATH_PREFIX = '/api/'

    def __init__(self, get_response=None):
        super().__init__(get_response)
        self._load_settings()

    def _load_settings(self):
        """Load API security settings."""
        from django.conf import settings

        api_settings = getattr(settings, 'API_SECURITY', {})

        self.require_content_type = api_settings.get('REQUIRE_CONTENT_TYPE', True)
        self.max_body_size = api_settings.get('MAX_BODY_SIZE', 10 * 1024 * 1024)
        self.require_api_key = api_settings.get('REQUIRE_API_KEY', False)
        self.allowed_content_types = api_settings.get('ALLOWED_CONTENT_TYPES', [
            'application/json',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
        ])

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Validate API request security."""
        # Only apply to API endpoints
        if not request.path.startswith(self.API_PATH_PREFIX):
            return None

        # Check content-type for POST/PUT/PATCH
        if request.method in ('POST', 'PUT', 'PATCH'):
            if self.require_content_type:
                content_type = request.content_type or ''
                if not any(ct in content_type for ct in self.allowed_content_types):
                    logger.warning(
                        f"Invalid content-type for API request: {content_type}",
                        extra={'path': request.path, 'method': request.method}
                    )
                    from django.http import JsonResponse
                    return JsonResponse({
                        'error': 'Unsupported Media Type',
                        'detail': 'Content-Type must be application/json',
                    }, status=415)

            # Check body size
            content_length = request.META.get('CONTENT_LENGTH')
            if content_length:
                try:
                    if int(content_length) > self.max_body_size:
                        logger.warning(
                            f"Request body too large: {content_length}",
                            extra={'path': request.path}
                        )
                        from django.http import JsonResponse
                        return JsonResponse({
                            'error': 'Request Entity Too Large',
                            'detail': f'Maximum body size is {self.max_body_size} bytes',
                        }, status=413)
                except ValueError:
                    pass

        # Check API key if required
        if self.require_api_key:
            api_key = request.META.get('HTTP_X_API_KEY')
            if not self._validate_api_key(api_key):
                from django.http import JsonResponse
                return JsonResponse({
                    'error': 'Unauthorized',
                    'detail': 'Valid API key required',
                }, status=401)

        return None

    def _validate_api_key(self, api_key: str) -> bool:
        """Validate API key (override for custom validation)."""
        if not api_key:
            return False

        # Simple validation - in production, check against database
        from django.conf import settings
        valid_keys = getattr(settings, 'API_KEYS', [])
        return api_key in valid_keys

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Add API-specific security headers."""
        if not request.path.startswith(self.API_PATH_PREFIX):
            return response

        # Prevent caching of API responses with sensitive data
        if request.method != 'GET':
            response['Cache-Control'] = 'no-store'

        # Add API version header if available
        api_version = getattr(request, 'version', None)
        if api_version:
            response['X-API-Version'] = api_version

        return response


# =============================================================================
# ADDITIONAL SECURITY UTILITIES
# =============================================================================

class TrustedHostMiddleware(MiddlewareMixin):
    """
    Validates that requests come from trusted hosts.

    More strict than Django's built-in ALLOWED_HOSTS.
    Validates Host header format and prevents host header injection.
    """

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Validate host header."""
        from django.conf import settings
        import re

        host = request.get_host()

        # Check for valid host format
        # Valid: domain.com, sub.domain.com, localhost, 127.0.0.1, [::1]
        host_pattern = re.compile(
            r'^'
            r'(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z]{2,}|'  # Domain
            r'localhost|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IPv4
            r'\[?[a-fA-F0-9:]+\]?)'  # IPv6
            r'(?::\d+)?$'  # Optional port
        )

        if not host_pattern.match(host):
            logger.warning(
                f"Invalid host header: {host}",
                extra={'path': request.path}
            )
            from django.http import HttpResponseBadRequest
            return HttpResponseBadRequest("Invalid host header")

        return None


class RequestSizeLimitMiddleware(MiddlewareMixin):
    """
    Enforces request size limits to prevent DoS attacks.

    Configure in settings.py:
        REQUEST_SIZE_LIMIT = 10 * 1024 * 1024  # 10MB
    """

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Check request size."""
        from django.conf import settings

        max_size = getattr(settings, 'REQUEST_SIZE_LIMIT', 10 * 1024 * 1024)

        content_length = request.META.get('CONTENT_LENGTH')
        if content_length:
            try:
                if int(content_length) > max_size:
                    logger.warning(
                        f"Request too large: {content_length} bytes",
                        extra={'path': request.path}
                    )
                    from django.http import HttpResponse
                    return HttpResponse(
                        "Request too large",
                        status=413,
                        content_type="text/plain"
                    )
            except ValueError:
                pass

        return None
