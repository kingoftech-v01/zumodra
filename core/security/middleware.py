"""
Security Middleware for Zumodra

Comprehensive security middleware components for the multi-tenant ATS/HR SaaS platform:
- SecurityHeadersMiddleware: CSP, X-Frame-Options, X-Content-Type-Options, etc.
- RateLimitMiddleware: Redis-backed rate limiting per-user, per-IP, per-endpoint
- RequestValidationMiddleware: Request size limits, content-type validation
- AuditLogMiddleware: Log all state-changing requests
- IPWhitelistMiddleware: Admin endpoint IP restrictions

All middlewares are tenant-aware and production-ready.
"""

import hashlib
import ipaddress
import json
import logging
import re
import time
from datetime import datetime
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger('security.middleware')


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_client_ip(request: HttpRequest) -> str:
    """
    Securely extract client IP address from request.

    Properly handles X-Forwarded-For with trusted proxy validation
    to prevent IP spoofing attacks.

    Args:
        request: The HTTP request object

    Returns:
        The client's IP address
    """
    trusted_proxy_count = getattr(settings, 'SECURITY_TRUSTED_PROXY_COUNT', 1)

    remote_addr = request.META.get('REMOTE_ADDR', '127.0.0.1')
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')

    if not x_forwarded_for:
        return remote_addr

    # Parse X-Forwarded-For: client, proxy1, proxy2 (rightmost is closest to server)
    forwarded_ips = [ip.strip() for ip in x_forwarded_for.split(',')]

    if len(forwarded_ips) < trusted_proxy_count:
        logger.warning(
            "X-Forwarded-For has fewer IPs than trusted proxy count",
            extra={'x_forwarded_for': x_forwarded_for, 'trusted_count': trusted_proxy_count}
        )
        return remote_addr

    # Client IP is at position -(trusted_proxy_count + 1) from end
    try:
        client_ip_index = -(trusted_proxy_count + 1)
        if abs(client_ip_index) > len(forwarded_ips):
            client_ip = forwarded_ips[0]
        else:
            client_ip = forwarded_ips[client_ip_index]

        # Validate IP format
        ipaddress.ip_address(client_ip)
        return client_ip
    except (IndexError, ValueError):
        return remote_addr


def get_tenant_from_request(request: HttpRequest) -> Optional[Any]:
    """
    Extract tenant from request for multi-tenant context.

    Args:
        request: The HTTP request object

    Returns:
        The tenant object or None
    """
    try:
        from django.db import connection
        return getattr(connection, 'tenant', None)
    except Exception:
        return getattr(request, 'tenant', None)


def get_request_fingerprint(request: HttpRequest) -> str:
    """
    Generate a fingerprint for the request based on various attributes.

    Args:
        request: The HTTP request object

    Returns:
        A hash fingerprint string
    """
    components = [
        get_client_ip(request),
        request.META.get('HTTP_USER_AGENT', ''),
        request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
    ]
    fingerprint_data = '|'.join(components)
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]


# =============================================================================
# SECURITY HEADERS MIDDLEWARE
# =============================================================================

class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Add comprehensive security headers to all responses.

    Headers added:
    - Content-Security-Policy (CSP)
    - X-Frame-Options
    - X-Content-Type-Options
    - Referrer-Policy
    - Permissions-Policy
    - Strict-Transport-Security (HSTS)
    - X-XSS-Protection (legacy browsers)

    Configuration via Django settings:
        SECURITY_CSP_ENABLED: bool = True
        SECURITY_CSP_REPORT_ONLY: bool = False
        SECURITY_CSP_POLICY: dict = {...}
        SECURITY_FRAME_OPTIONS: str = 'DENY'
        SECURITY_REFERRER_POLICY: str = 'strict-origin-when-cross-origin'
        SECURITY_HSTS_SECONDS: int = 31536000
    """

    # Default CSP directives
    DEFAULT_CSP_POLICY = {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'"],  # Adjust as needed
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:", "https:"],
        'font-src': ["'self'", "https://fonts.gstatic.com"],
        'connect-src': ["'self'"],
        'frame-ancestors': ["'none'"],
        'form-action': ["'self'"],
        'base-uri': ["'self'"],
        'object-src': ["'none'"],
    }

    # Default Permissions-Policy
    DEFAULT_PERMISSIONS_POLICY = {
        'accelerometer': '()',
        'camera': '()',
        'geolocation': '()',
        'gyroscope': '()',
        'magnetometer': '()',
        'microphone': '()',
        'payment': '()',
        'usb': '()',
    }

    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.csp_enabled = getattr(settings, 'SECURITY_CSP_ENABLED', True)
        self.csp_report_only = getattr(settings, 'SECURITY_CSP_REPORT_ONLY', False)
        self.csp_policy = getattr(settings, 'SECURITY_CSP_POLICY', self.DEFAULT_CSP_POLICY)
        self.frame_options = getattr(settings, 'SECURITY_FRAME_OPTIONS', 'DENY')
        self.referrer_policy = getattr(
            settings, 'SECURITY_REFERRER_POLICY', 'strict-origin-when-cross-origin'
        )
        self.hsts_seconds = getattr(settings, 'SECURITY_HSTS_SECONDS', 31536000)
        self.hsts_include_subdomains = getattr(settings, 'SECURITY_HSTS_INCLUDE_SUBDOMAINS', True)
        self.hsts_preload = getattr(settings, 'SECURITY_HSTS_PRELOAD', False)
        self.permissions_policy = getattr(
            settings, 'SECURITY_PERMISSIONS_POLICY', self.DEFAULT_PERMISSIONS_POLICY
        )

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        return self.add_security_headers(request, response)

    def add_security_headers(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Add all security headers to the response."""

        # Content-Security-Policy
        if self.csp_enabled:
            csp_header = self._build_csp_header(request)
            header_name = 'Content-Security-Policy-Report-Only' if self.csp_report_only else 'Content-Security-Policy'
            response[header_name] = csp_header

        # X-Frame-Options
        if self.frame_options:
            response['X-Frame-Options'] = self.frame_options

        # X-Content-Type-Options
        response['X-Content-Type-Options'] = 'nosniff'

        # Referrer-Policy
        response['Referrer-Policy'] = self.referrer_policy

        # Permissions-Policy
        permissions = ', '.join(f'{k}={v}' for k, v in self.permissions_policy.items())
        response['Permissions-Policy'] = permissions

        # Strict-Transport-Security (only for HTTPS)
        if request.is_secure() and self.hsts_seconds > 0:
            hsts_value = f'max-age={self.hsts_seconds}'
            if self.hsts_include_subdomains:
                hsts_value += '; includeSubDomains'
            if self.hsts_preload:
                hsts_value += '; preload'
            response['Strict-Transport-Security'] = hsts_value

        # X-XSS-Protection (for legacy browser support)
        response['X-XSS-Protection'] = '1; mode=block'

        # Cross-Origin headers
        response['Cross-Origin-Opener-Policy'] = 'same-origin'
        response['Cross-Origin-Resource-Policy'] = 'same-origin'

        return response

    def _build_csp_header(self, request: HttpRequest) -> str:
        """Build the CSP header string from policy dict."""
        policy = self.csp_policy.copy()

        # Add nonce for scripts if needed
        if hasattr(request, 'csp_nonce'):
            nonce = f"'nonce-{request.csp_nonce}'"
            if 'script-src' in policy:
                policy['script-src'] = policy['script-src'] + [nonce]
            if 'style-src' in policy:
                policy['style-src'] = policy['style-src'] + [nonce]

        # Add report-uri if configured
        report_uri = getattr(settings, 'SECURITY_CSP_REPORT_URI', None)
        if report_uri:
            policy['report-uri'] = [report_uri]

        # Build directive string
        directives = []
        for directive, values in policy.items():
            if isinstance(values, list):
                value_str = ' '.join(values)
            else:
                value_str = values
            directives.append(f'{directive} {value_str}')

        return '; '.join(directives)


# =============================================================================
# RATE LIMIT MIDDLEWARE
# =============================================================================

class RateLimitMiddleware(MiddlewareMixin):
    """
    Redis-backed rate limiting middleware.

    Supports rate limiting by:
    - Per-user (authenticated users)
    - Per-IP (anonymous users)
    - Per-endpoint (specific URL patterns)

    Features:
    - Token bucket algorithm for burst tolerance
    - Sliding window for accurate counting
    - Rate limit headers (X-RateLimit-*)
    - Tenant-aware rate limits

    Configuration via Django settings:
        SECURITY_RATE_LIMIT_ENABLED: bool = True
        SECURITY_RATE_LIMIT_DEFAULT: str = '100/minute'
        SECURITY_RATE_LIMIT_BY_USER: str = '1000/hour'
        SECURITY_RATE_LIMIT_BY_IP: str = '100/minute'
        SECURITY_RATE_LIMIT_ENDPOINTS: dict = {
            '/api/auth/login': '5/minute',
            '/api/auth/register': '3/minute',
        }
        SECURITY_RATE_LIMIT_WHITELIST_IPS: list = []
        SECURITY_RATE_LIMIT_WHITELIST_PATHS: list = []
    """

    CACHE_PREFIX = 'ratelimit:'

    # Rate limit parsing pattern
    RATE_PATTERN = re.compile(r'^(\d+)/(\w+)$')

    # Time unit multipliers in seconds
    TIME_UNITS = {
        'second': 1,
        'seconds': 1,
        'minute': 60,
        'minutes': 60,
        'hour': 3600,
        'hours': 3600,
        'day': 86400,
        'days': 86400,
    }

    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.enabled = getattr(settings, 'SECURITY_RATE_LIMIT_ENABLED', True)
        self.default_limit = getattr(settings, 'SECURITY_RATE_LIMIT_DEFAULT', '100/minute')
        self.user_limit = getattr(settings, 'SECURITY_RATE_LIMIT_BY_USER', '1000/hour')
        self.ip_limit = getattr(settings, 'SECURITY_RATE_LIMIT_BY_IP', '100/minute')
        self.endpoint_limits = getattr(settings, 'SECURITY_RATE_LIMIT_ENDPOINTS', {})
        self.whitelist_ips = set(getattr(settings, 'SECURITY_RATE_LIMIT_WHITELIST_IPS', []))
        self.whitelist_paths = getattr(settings, 'SECURITY_RATE_LIMIT_WHITELIST_PATHS', [])

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if not self.enabled:
            return self.get_response(request)

        # Check whitelist
        if self._is_whitelisted(request):
            return self.get_response(request)

        # Get rate limit for this request
        limit, period = self._get_rate_limit(request)

        # Get rate limit key
        key = self._get_rate_limit_key(request)

        # Check rate limit
        allowed, remaining, reset_time = self._check_rate_limit(key, limit, period)

        if not allowed:
            response = self._rate_limit_exceeded_response(request, reset_time)
            self._add_rate_limit_headers(response, limit, 0, reset_time)
            logger.warning(
                "Rate limit exceeded",
                extra={
                    'key': key,
                    'ip': get_client_ip(request),
                    'path': request.path,
                    'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                }
            )
            return response

        response = self.get_response(request)
        self._add_rate_limit_headers(response, limit, remaining, reset_time)
        return response

    def _is_whitelisted(self, request: HttpRequest) -> bool:
        """Check if request should bypass rate limiting."""
        # Check IP whitelist
        client_ip = get_client_ip(request)
        if client_ip in self.whitelist_ips:
            return True

        # Check path whitelist
        for path_pattern in self.whitelist_paths:
            if re.match(path_pattern, request.path):
                return True

        return False

    def _get_rate_limit(self, request: HttpRequest) -> Tuple[int, int]:
        """
        Determine the rate limit for this request.

        Returns:
            Tuple of (max_requests, period_seconds)
        """
        # Check endpoint-specific limits first
        for pattern, limit_str in self.endpoint_limits.items():
            if re.match(pattern, request.path):
                return self._parse_rate_limit(limit_str)

        # Use user limit for authenticated users
        if hasattr(request, 'user') and request.user.is_authenticated:
            return self._parse_rate_limit(self.user_limit)

        # Use IP limit for anonymous users
        return self._parse_rate_limit(self.ip_limit)

    def _parse_rate_limit(self, rate_str: str) -> Tuple[int, int]:
        """
        Parse rate limit string like '100/minute'.

        Returns:
            Tuple of (max_requests, period_seconds)
        """
        match = self.RATE_PATTERN.match(rate_str)
        if not match:
            logger.warning(f"Invalid rate limit format: {rate_str}, using default")
            return (100, 60)  # Default: 100 per minute

        count = int(match.group(1))
        unit = match.group(2).lower()
        seconds = self.TIME_UNITS.get(unit, 60)

        return (count, seconds)

    def _get_rate_limit_key(self, request: HttpRequest) -> str:
        """Generate a cache key for rate limiting."""
        tenant = get_tenant_from_request(request)
        tenant_id = tenant.id if tenant else 'public'

        if hasattr(request, 'user') and request.user.is_authenticated:
            identifier = f'user:{request.user.id}'
        else:
            identifier = f'ip:{get_client_ip(request)}'

        # Include path for endpoint-specific limits
        path_hash = hashlib.md5(request.path.encode()).hexdigest()[:8]

        return f'{self.CACHE_PREFIX}{tenant_id}:{identifier}:{path_hash}'

    def _check_rate_limit(
        self, key: str, limit: int, period: int
    ) -> Tuple[bool, int, int]:
        """
        Check if request is within rate limit using sliding window.

        Returns:
            Tuple of (allowed, remaining, reset_timestamp)
        """
        now = int(time.time())
        window_start = now - period

        # Use sliding window counter
        window_key = f'{key}:{now // period}'
        prev_window_key = f'{key}:{(now // period) - 1}'

        # Get current and previous window counts
        current_count = cache.get(window_key, 0)
        prev_count = cache.get(prev_window_key, 0)

        # Calculate weighted count (sliding window)
        elapsed_in_window = now % period
        weight = (period - elapsed_in_window) / period
        weighted_count = int(prev_count * weight) + current_count

        if weighted_count >= limit:
            reset_time = ((now // period) + 1) * period
            return (False, 0, reset_time)

        # Increment counter
        if current_count == 0:
            cache.set(window_key, 1, timeout=period * 2)
        else:
            cache.incr(window_key)

        remaining = limit - weighted_count - 1
        reset_time = ((now // period) + 1) * period

        return (True, remaining, reset_time)

    def _add_rate_limit_headers(
        self, response: HttpResponse, limit: int, remaining: int, reset_time: int
    ):
        """Add rate limit headers to response."""
        response['X-RateLimit-Limit'] = str(limit)
        response['X-RateLimit-Remaining'] = str(max(0, remaining))
        response['X-RateLimit-Reset'] = str(reset_time)

    def _rate_limit_exceeded_response(
        self, request: HttpRequest, reset_time: int
    ) -> HttpResponse:
        """Generate rate limit exceeded response."""
        retry_after = reset_time - int(time.time())

        if request.content_type == 'application/json' or request.path.startswith('/api/'):
            response = JsonResponse({
                'error': 'Rate limit exceeded',
                'detail': 'Too many requests. Please try again later.',
                'retry_after': retry_after,
            }, status=429)
        else:
            response = HttpResponse(
                'Rate limit exceeded. Please try again later.',
                status=429,
                content_type='text/plain'
            )

        response['Retry-After'] = str(retry_after)
        return response


# =============================================================================
# REQUEST VALIDATION MIDDLEWARE
# =============================================================================

class RequestValidationMiddleware(MiddlewareMixin):
    """
    Validate incoming requests for security.

    Validates:
    - Request body size limits
    - Content-Type validation
    - Request method restrictions
    - Suspicious patterns in headers

    Configuration via Django settings:
        SECURITY_MAX_BODY_SIZE: int = 10 * 1024 * 1024  # 10MB
        SECURITY_MAX_UPLOAD_SIZE: int = 50 * 1024 * 1024  # 50MB
        SECURITY_ALLOWED_CONTENT_TYPES: list = [...]
        SECURITY_BLOCKED_USER_AGENTS: list = [...]
    """

    # Default allowed content types
    DEFAULT_CONTENT_TYPES = [
        'application/json',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'text/plain',
        'text/html',
    ]

    # Suspicious patterns in headers
    SUSPICIOUS_PATTERNS = [
        r'<script',
        r'javascript:',
        r'data:text/html',
        r'\x00',  # Null byte
        r'\.\./',  # Path traversal
    ]

    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.max_body_size = getattr(
            settings, 'SECURITY_MAX_BODY_SIZE', 10 * 1024 * 1024
        )
        self.max_upload_size = getattr(
            settings, 'SECURITY_MAX_UPLOAD_SIZE', 50 * 1024 * 1024
        )
        self.allowed_content_types = getattr(
            settings, 'SECURITY_ALLOWED_CONTENT_TYPES', self.DEFAULT_CONTENT_TYPES
        )
        self.blocked_user_agents = getattr(
            settings, 'SECURITY_BLOCKED_USER_AGENTS', []
        )
        self.suspicious_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_PATTERNS
        ]

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Validate request
        validation_error = self._validate_request(request)
        if validation_error:
            return validation_error

        return self.get_response(request)

    def _validate_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Validate the incoming request.

        Returns:
            HttpResponse if validation fails, None otherwise
        """
        # Check request body size
        content_length = request.META.get('CONTENT_LENGTH')
        if content_length:
            try:
                size = int(content_length)
                max_size = self.max_upload_size if request.method == 'POST' else self.max_body_size
                if size > max_size:
                    logger.warning(
                        "Request body too large",
                        extra={
                            'size': size,
                            'max_size': max_size,
                            'ip': get_client_ip(request),
                            'path': request.path,
                        }
                    )
                    return HttpResponse(
                        'Request body too large',
                        status=413,
                        content_type='text/plain'
                    )
            except (ValueError, TypeError):
                pass

        # Validate content type for POST/PUT/PATCH requests
        if request.method in ('POST', 'PUT', 'PATCH'):
            content_type = request.content_type
            if content_type:
                # Extract base content type (without charset, boundary, etc.)
                base_type = content_type.split(';')[0].strip()
                if not self._is_allowed_content_type(base_type):
                    logger.warning(
                        "Invalid content type",
                        extra={
                            'content_type': content_type,
                            'ip': get_client_ip(request),
                            'path': request.path,
                        }
                    )
                    return HttpResponse(
                        'Unsupported content type',
                        status=415,
                        content_type='text/plain'
                    )

        # Check blocked user agents
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        for blocked_pattern in self.blocked_user_agents:
            if re.search(blocked_pattern, user_agent, re.IGNORECASE):
                logger.warning(
                    "Blocked user agent",
                    extra={
                        'user_agent': user_agent[:200],
                        'ip': get_client_ip(request),
                    }
                )
                return HttpResponse(
                    'Access denied',
                    status=403,
                    content_type='text/plain'
                )

        # Check for suspicious patterns in headers
        for header_key, header_value in request.META.items():
            if header_key.startswith('HTTP_'):
                for pattern in self.suspicious_patterns:
                    if isinstance(header_value, str) and pattern.search(header_value):
                        logger.warning(
                            "Suspicious header pattern detected",
                            extra={
                                'header': header_key,
                                'pattern': pattern.pattern,
                                'ip': get_client_ip(request),
                            }
                        )
                        return HttpResponse(
                            'Invalid request',
                            status=400,
                            content_type='text/plain'
                        )

        return None

    def _is_allowed_content_type(self, content_type: str) -> bool:
        """Check if content type is allowed."""
        for allowed in self.allowed_content_types:
            if content_type.startswith(allowed):
                return True
        return False


# =============================================================================
# AUDIT LOG MIDDLEWARE
# =============================================================================

class AuditLogMiddleware(MiddlewareMixin):
    """
    Log all state-changing requests for security audit.

    Logs:
    - POST, PUT, PATCH, DELETE requests
    - User authentication events
    - Admin actions
    - API calls with modifications

    Logged data:
    - User ID and email
    - Tenant ID
    - Request method and path
    - IP address
    - User agent
    - Request timestamp
    - Response status

    Configuration via Django settings:
        SECURITY_AUDIT_ENABLED: bool = True
        SECURITY_AUDIT_LOG_BODY: bool = False  # Log request body (careful with PII)
        SECURITY_AUDIT_EXCLUDE_PATHS: list = ['/health', '/metrics']
        SECURITY_AUDIT_INCLUDE_METHODS: list = ['POST', 'PUT', 'PATCH', 'DELETE']
    """

    CACHE_PREFIX = 'audit_log:'

    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.enabled = getattr(settings, 'SECURITY_AUDIT_ENABLED', True)
        self.log_body = getattr(settings, 'SECURITY_AUDIT_LOG_BODY', False)
        self.exclude_paths = getattr(
            settings, 'SECURITY_AUDIT_EXCLUDE_PATHS', ['/health', '/metrics', '/favicon.ico']
        )
        self.include_methods = getattr(
            settings, 'SECURITY_AUDIT_INCLUDE_METHODS',
            ['POST', 'PUT', 'PATCH', 'DELETE']
        )
        # Sensitive fields to mask in logs
        self.sensitive_fields = getattr(
            settings, 'SECURITY_AUDIT_SENSITIVE_FIELDS',
            ['password', 'token', 'secret', 'api_key', 'credit_card', 'ssn', 'nas']
        )

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if not self.enabled:
            return self.get_response(request)

        # Skip excluded paths
        if self._should_skip(request):
            return self.get_response(request)

        # Only log state-changing methods
        if request.method not in self.include_methods:
            return self.get_response(request)

        # Capture request data before processing
        request_data = self._capture_request_data(request)

        # Process request
        start_time = time.time()
        response = self.get_response(request)
        duration = time.time() - start_time

        # Log the audit entry
        self._log_audit_entry(request, response, request_data, duration)

        return response

    def _should_skip(self, request: HttpRequest) -> bool:
        """Check if request should be skipped from audit logging."""
        for path in self.exclude_paths:
            if request.path.startswith(path):
                return True
        return False

    def _capture_request_data(self, request: HttpRequest) -> Dict[str, Any]:
        """Capture relevant request data for audit log."""
        data = {
            'method': request.method,
            'path': request.path,
            'query_string': request.META.get('QUERY_STRING', ''),
            'content_type': request.content_type,
        }

        if self.log_body and request.body:
            try:
                if request.content_type == 'application/json':
                    body = json.loads(request.body.decode('utf-8'))
                    data['body'] = self._mask_sensitive_data(body)
                else:
                    # For other content types, just note the size
                    data['body_size'] = len(request.body)
            except Exception:
                data['body_size'] = len(request.body) if request.body else 0

        return data

    def _mask_sensitive_data(self, data: Any) -> Any:
        """Recursively mask sensitive fields in data."""
        if isinstance(data, dict):
            masked = {}
            for key, value in data.items():
                if any(sensitive in key.lower() for sensitive in self.sensitive_fields):
                    masked[key] = '***MASKED***'
                else:
                    masked[key] = self._mask_sensitive_data(value)
            return masked
        elif isinstance(data, list):
            return [self._mask_sensitive_data(item) for item in data]
        return data

    def _log_audit_entry(
        self,
        request: HttpRequest,
        response: HttpResponse,
        request_data: Dict[str, Any],
        duration: float
    ):
        """Log the audit entry."""
        tenant = get_tenant_from_request(request)
        user = getattr(request, 'user', None)

        audit_entry = {
            'timestamp': timezone.now().isoformat(),
            'tenant_id': str(tenant.id) if tenant else None,
            'user_id': str(user.id) if user and user.is_authenticated else None,
            'user_email': user.email if user and user.is_authenticated else None,
            'ip_address': get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
            'method': request_data['method'],
            'path': request_data['path'],
            'query_string': request_data.get('query_string', ''),
            'status_code': response.status_code,
            'duration_ms': round(duration * 1000, 2),
            'request_id': getattr(request, 'request_id', None),
        }

        if self.log_body and 'body' in request_data:
            audit_entry['request_body'] = request_data['body']

        # Log to Python logger
        logger.info(
            f"AUDIT: {request_data['method']} {request_data['path']} "
            f"- User: {audit_entry['user_email']} - Status: {response.status_code}",
            extra={'audit_entry': audit_entry}
        )

        # Store in cache for recent entries (optional - for quick access)
        if tenant:
            self._store_audit_entry(tenant.id, audit_entry)

        # Optionally write to database (via signal or async task)
        self._persist_audit_entry(audit_entry)

    def _store_audit_entry(self, tenant_id: str, entry: Dict[str, Any]):
        """Store audit entry in cache for quick access."""
        cache_key = f'{self.CACHE_PREFIX}recent:{tenant_id}'
        entries = cache.get(cache_key) or []
        entries.insert(0, entry)
        entries = entries[:100]  # Keep last 100
        cache.set(cache_key, entries, timeout=86400)  # 24 hours

    def _persist_audit_entry(self, entry: Dict[str, Any]):
        """
        Persist audit entry to database.

        This is called after each request. For high-traffic sites,
        consider using async tasks or batch writing.
        """
        try:
            # Import here to avoid circular imports
            from core.security.audit import AuditLogger
            AuditLogger.log_request(entry)
        except ImportError:
            # AuditLogger not available, skip database persistence
            pass
        except Exception as e:
            logger.error(f"Failed to persist audit entry: {e}")


# =============================================================================
# IP WHITELIST MIDDLEWARE
# =============================================================================

class IPWhitelistMiddleware(MiddlewareMixin):
    """
    Restrict access to admin endpoints by IP address.

    Provides IP-based access control for sensitive endpoints:
    - Django admin
    - API admin endpoints
    - Management endpoints

    Configuration via Django settings:
        SECURITY_IP_WHITELIST_ENABLED: bool = True
        SECURITY_IP_WHITELIST_PATHS: list = ['/admin/', '/api/admin/']
        SECURITY_IP_WHITELIST_IPS: list = ['127.0.0.1', '10.0.0.0/8']
        SECURITY_IP_WHITELIST_ALLOW_STAFF: bool = True
    """

    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.enabled = getattr(settings, 'SECURITY_IP_WHITELIST_ENABLED', True)
        self.protected_paths = getattr(
            settings, 'SECURITY_IP_WHITELIST_PATHS', ['/admin/']
        )
        self.allowed_ips = self._parse_ip_list(
            getattr(settings, 'SECURITY_IP_WHITELIST_IPS', ['127.0.0.1'])
        )
        self.allow_staff = getattr(settings, 'SECURITY_IP_WHITELIST_ALLOW_STAFF', True)

    def _parse_ip_list(self, ip_list: List[str]) -> List[Union[ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, ipaddress.IPv6Network]]:
        """Parse IP list including CIDR notation."""
        parsed = []
        for ip_str in ip_list:
            try:
                if '/' in ip_str:
                    parsed.append(ipaddress.ip_network(ip_str, strict=False))
                else:
                    parsed.append(ipaddress.ip_address(ip_str))
            except ValueError as e:
                logger.warning(f"Invalid IP in whitelist: {ip_str} - {e}")
        return parsed

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if not self.enabled:
            return self.get_response(request)

        # Check if path is protected
        if not self._is_protected_path(request.path):
            return self.get_response(request)

        # Check if user is staff (if enabled)
        if self.allow_staff and hasattr(request, 'user') and request.user.is_authenticated:
            if request.user.is_staff or request.user.is_superuser:
                return self.get_response(request)

        # Check IP whitelist
        client_ip = get_client_ip(request)
        if not self._is_ip_allowed(client_ip):
            logger.warning(
                "IP not in whitelist for protected path",
                extra={
                    'ip': client_ip,
                    'path': request.path,
                    'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                }
            )
            return HttpResponse(
                'Access denied',
                status=403,
                content_type='text/plain'
            )

        return self.get_response(request)

    def _is_protected_path(self, path: str) -> bool:
        """Check if path is in protected list."""
        for protected in self.protected_paths:
            if path.startswith(protected):
                return True
        return False

    def _is_ip_allowed(self, ip_str: str) -> bool:
        """Check if IP is in the allowed list."""
        try:
            ip = ipaddress.ip_address(ip_str)
            for allowed in self.allowed_ips:
                if isinstance(allowed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    if ip in allowed:
                        return True
                else:
                    if ip == allowed:
                        return True
            return False
        except ValueError:
            return False


# =============================================================================
# HELPER DECORATORS
# =============================================================================

def rate_limit(limit: str = '10/minute', key_func: Callable = None):
    """
    Decorator to apply rate limiting to a view.

    Args:
        limit: Rate limit string like '10/minute'
        key_func: Function to generate custom rate limit key

    Usage:
        @rate_limit('5/minute')
        def my_view(request):
            ...
    """
    def decorator(view_func: Callable):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Parse rate limit
            rate_pattern = re.compile(r'^(\d+)/(\w+)$')
            match = rate_pattern.match(limit)
            if not match:
                return view_func(request, *args, **kwargs)

            max_requests = int(match.group(1))
            unit = match.group(2).lower()
            time_units = {
                'second': 1, 'seconds': 1,
                'minute': 60, 'minutes': 60,
                'hour': 3600, 'hours': 3600,
                'day': 86400, 'days': 86400,
            }
            period = time_units.get(unit, 60)

            # Generate key
            if key_func:
                key = key_func(request)
            else:
                if hasattr(request, 'user') and request.user.is_authenticated:
                    key = f'ratelimit:view:{request.user.id}:{view_func.__name__}'
                else:
                    key = f'ratelimit:view:{get_client_ip(request)}:{view_func.__name__}'

            # Check rate limit
            now = int(time.time())
            window_key = f'{key}:{now // period}'
            count = cache.get(window_key, 0)

            if count >= max_requests:
                return JsonResponse({
                    'error': 'Rate limit exceeded',
                    'retry_after': period - (now % period),
                }, status=429)

            # Increment counter
            cache.set(window_key, count + 1, timeout=period * 2)

            return view_func(request, *args, **kwargs)
        return wrapped_view
    return decorator


def require_ip_whitelist(allowed_ips: List[str] = None):
    """
    Decorator to restrict view access by IP.

    Args:
        allowed_ips: List of allowed IP addresses/networks

    Usage:
        @require_ip_whitelist(['192.168.1.0/24', '10.0.0.1'])
        def my_admin_view(request):
            ...
    """
    def decorator(view_func: Callable):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            if not allowed_ips:
                return view_func(request, *args, **kwargs)

            client_ip = get_client_ip(request)

            for allowed in allowed_ips:
                try:
                    if '/' in allowed:
                        network = ipaddress.ip_network(allowed, strict=False)
                        if ipaddress.ip_address(client_ip) in network:
                            return view_func(request, *args, **kwargs)
                    else:
                        if ipaddress.ip_address(client_ip) == ipaddress.ip_address(allowed):
                            return view_func(request, *args, **kwargs)
                except ValueError:
                    continue

            logger.warning(
                f"IP whitelist blocked access to {view_func.__name__}",
                extra={'ip': client_ip}
            )
            return HttpResponse('Access denied', status=403)
        return wrapped_view
    return decorator
