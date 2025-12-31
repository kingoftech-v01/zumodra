"""
Enhanced CSRF Protection Module for Zumodra

Provides comprehensive CSRF protection beyond Django defaults:
- Enhanced CSRF protection for API endpoints
- Double-submit cookie pattern
- Origin validation
- SameSite cookie enforcement

All components are tenant-aware and integrate with the security logging system.
"""

import base64
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden, JsonResponse
from django.middleware.csrf import CsrfViewMiddleware, get_token
from django.utils import timezone
from django.utils.crypto import constant_time_compare, get_random_string
from django.views.decorators.csrf import csrf_exempt

from .owasp import SecurityEvent, SecurityEventLogger, SecurityEventType

logger = logging.getLogger('security.csrf')


# =============================================================================
# Enhanced CSRF Protection
# =============================================================================

class EnhancedCSRFProtection:
    """
    Enhanced CSRF protection for API endpoints.

    Provides additional CSRF validation beyond Django's built-in protection,
    including custom token validation for AJAX and API requests.
    """

    CSRF_HEADER_NAME = 'HTTP_X_CSRFTOKEN'
    CSRF_COOKIE_NAME = 'csrftoken'
    TOKEN_LENGTH = 64
    TOKEN_EXPIRY = 3600  # 1 hour

    def __init__(self):
        self.logger = SecurityEventLogger()
        self.cache_prefix = 'csrf_enhanced:'

    def generate_token(
        self,
        request: HttpRequest,
        user_id: str = None,
        action: str = None
    ) -> str:
        """
        Generate an enhanced CSRF token.

        Args:
            request: The HTTP request
            user_id: Optional user ID for binding
            action: Optional action for scoping

        Returns:
            CSRF token
        """
        # Generate base token
        base_token = secrets.token_urlsafe(self.TOKEN_LENGTH)

        # Create token data
        token_data = {
            'token': base_token,
            'created': timezone.now().isoformat(),
            'ip': self._get_client_ip(request),
            'user_agent_hash': self._hash_user_agent(request),
        }

        if user_id:
            token_data['user_id'] = user_id
        if action:
            token_data['action'] = action

        # Store token metadata
        cache_key = f"{self.cache_prefix}token:{base_token}"
        cache.set(cache_key, token_data, self.TOKEN_EXPIRY)

        return base_token

    def validate_token(
        self,
        request: HttpRequest,
        token: str = None,
        action: str = None
    ) -> Tuple[bool, str]:
        """
        Validate a CSRF token.

        Args:
            request: The HTTP request
            token: The token to validate (if not provided, extracted from request)
            action: Expected action (if any)

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Extract token if not provided
        if not token:
            token = self._extract_token(request)

        if not token:
            self._log_violation(request, 'missing_token')
            return False, 'CSRF token missing'

        # Retrieve token metadata
        cache_key = f"{self.cache_prefix}token:{token}"
        token_data = cache.get(cache_key)

        if not token_data:
            self._log_violation(request, 'invalid_token')
            return False, 'Invalid or expired CSRF token'

        # Validate expiry
        created = datetime.fromisoformat(token_data['created'].replace('Z', '+00:00'))
        if timezone.now() - created > timedelta(seconds=self.TOKEN_EXPIRY):
            self._log_violation(request, 'expired_token')
            return False, 'CSRF token expired'

        # Validate IP binding (optional, can be strict or lenient)
        if getattr(settings, 'CSRF_BIND_IP', False):
            if token_data.get('ip') != self._get_client_ip(request):
                self._log_violation(request, 'ip_mismatch')
                return False, 'CSRF token IP mismatch'

        # Validate user agent (detect major changes)
        if getattr(settings, 'CSRF_BIND_USER_AGENT', True):
            current_ua_hash = self._hash_user_agent(request)
            if token_data.get('user_agent_hash') != current_ua_hash:
                self._log_violation(request, 'ua_mismatch')
                return False, 'CSRF token user agent mismatch'

        # Validate action scope
        if action and token_data.get('action') != action:
            self._log_violation(request, 'action_mismatch')
            return False, 'CSRF token action mismatch'

        # Validate user binding
        user = getattr(request, 'user', None)
        if user and user.is_authenticated:
            if token_data.get('user_id') and str(user.id) != token_data['user_id']:
                self._log_violation(request, 'user_mismatch')
                return False, 'CSRF token user mismatch'

        return True, ''

    def invalidate_token(self, token: str):
        """
        Invalidate a CSRF token (single-use).

        Args:
            token: The token to invalidate
        """
        cache_key = f"{self.cache_prefix}token:{token}"
        cache.delete(cache_key)

    def require_csrf_token(
        self,
        action: str = None,
        single_use: bool = False
    ) -> Callable:
        """
        Decorator to require enhanced CSRF token validation.

        Args:
            action: Expected action scope
            single_use: Whether to invalidate after use

        Returns:
            Decorator function
        """
        def decorator(view_func: Callable) -> Callable:
            @wraps(view_func)
            def wrapper(request, *args, **kwargs):
                is_valid, error = self.validate_token(request, action=action)

                if not is_valid:
                    return JsonResponse(
                        {'error': error, 'code': 'csrf_failed'},
                        status=403
                    )

                if single_use:
                    token = self._extract_token(request)
                    if token:
                        self.invalidate_token(token)

                return view_func(request, *args, **kwargs)
            return wrapper
        return decorator

    def _extract_token(self, request: HttpRequest) -> Optional[str]:
        """Extract CSRF token from request."""
        # Check header first (for AJAX)
        token = request.META.get(self.CSRF_HEADER_NAME)
        if token:
            return token

        # Check X-CSRFToken header (alternative)
        token = request.META.get('HTTP_X_CSRF_TOKEN')
        if token:
            return token

        # Check POST data
        token = request.POST.get('csrfmiddlewaretoken')
        if token:
            return token

        return None

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    def _hash_user_agent(self, request: HttpRequest) -> str:
        """Hash user agent for comparison."""
        ua = request.META.get('HTTP_USER_AGENT', '')
        # Take first part of UA for stability across minor updates
        ua_prefix = ua[:100] if len(ua) > 100 else ua
        return hashlib.sha256(ua_prefix.encode()).hexdigest()[:16]

    def _log_violation(self, request: HttpRequest, reason: str):
        """Log a CSRF violation."""
        event = SecurityEvent(
            event_type=SecurityEventType.CSRF_VIOLATION,
            severity='high',
            message=f'CSRF validation failed: {reason}',
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:200],
            request_path=request.path,
            request_method=request.method,
            details={'reason': reason}
        )
        self.logger.log(event)


# =============================================================================
# Double-Submit Cookie Pattern
# =============================================================================

class DoubleSubmitCookieValidator:
    """
    Implements the Double-Submit Cookie pattern for CSRF protection.

    The token is sent both as a cookie and in a header/form field.
    Validation ensures both match.
    """

    COOKIE_NAME = 'csrf_double_submit'
    HEADER_NAME = 'HTTP_X_CSRF_DOUBLE_SUBMIT'
    TOKEN_LENGTH = 32

    def __init__(self):
        self.logger = SecurityEventLogger()

    def set_token(self, response: HttpResponse) -> str:
        """
        Set a double-submit CSRF token cookie.

        Args:
            response: The HTTP response

        Returns:
            The token value
        """
        token = secrets.token_urlsafe(self.TOKEN_LENGTH)

        response.set_cookie(
            self.COOKIE_NAME,
            token,
            max_age=getattr(settings, 'SESSION_COOKIE_AGE', 1209600),
            secure=getattr(settings, 'SESSION_COOKIE_SECURE', True),
            httponly=False,  # Must be readable by JS to submit in header
            samesite='Strict',
            domain=getattr(settings, 'CSRF_COOKIE_DOMAIN', None),
        )

        return token

    def validate(self, request: HttpRequest) -> Tuple[bool, str]:
        """
        Validate double-submit CSRF tokens.

        Args:
            request: The HTTP request

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Get token from cookie
        cookie_token = request.COOKIES.get(self.COOKIE_NAME)

        if not cookie_token:
            self._log_violation(request, 'missing_cookie')
            return False, 'CSRF cookie missing'

        # Get token from header or form
        header_token = self._get_submitted_token(request)

        if not header_token:
            self._log_violation(request, 'missing_header')
            return False, 'CSRF header/field missing'

        # Compare tokens (timing-safe)
        if not constant_time_compare(cookie_token, header_token):
            self._log_violation(request, 'token_mismatch')
            return False, 'CSRF token mismatch'

        return True, ''

    def require_double_submit(self) -> Callable:
        """
        Decorator to require double-submit CSRF validation.

        Returns:
            Decorator function
        """
        def decorator(view_func: Callable) -> Callable:
            @wraps(view_func)
            def wrapper(request, *args, **kwargs):
                # Only check for state-changing methods
                if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
                    is_valid, error = self.validate(request)
                    if not is_valid:
                        return JsonResponse(
                            {'error': error, 'code': 'csrf_double_submit_failed'},
                            status=403
                        )

                response = view_func(request, *args, **kwargs)

                # Refresh token on response
                if isinstance(response, HttpResponse):
                    self.set_token(response)

                return response
            return wrapper
        return decorator

    def _get_submitted_token(self, request: HttpRequest) -> Optional[str]:
        """Get submitted CSRF token from header or form."""
        # Check header
        token = request.META.get(self.HEADER_NAME)
        if token:
            return token

        # Check alternative header name
        token = request.META.get('HTTP_X_DOUBLE_SUBMIT_TOKEN')
        if token:
            return token

        # Check form field
        token = request.POST.get('double_submit_token')
        if token:
            return token

        return None

    def _log_violation(self, request: HttpRequest, reason: str):
        """Log a double-submit violation."""
        event = SecurityEvent(
            event_type=SecurityEventType.CSRF_VIOLATION,
            severity='high',
            message=f'Double-submit CSRF failed: {reason}',
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', ''),
            request_path=request.path,
            request_method=request.method,
            details={'reason': reason}
        )
        self.logger.log(event)


# =============================================================================
# Origin Validation
# =============================================================================

class OriginValidator:
    """
    Validates request origin to prevent CSRF and cross-origin attacks.

    Checks Origin and Referer headers against allowed origins.
    """

    def __init__(self):
        self.logger = SecurityEventLogger()
        self._allowed_origins = None
        self._allowed_hosts = None

    @property
    def allowed_origins(self) -> Set[str]:
        """Get allowed origins from settings."""
        if self._allowed_origins is None:
            self._allowed_origins = set()

            # Add from CSRF_TRUSTED_ORIGINS
            trusted = getattr(settings, 'CSRF_TRUSTED_ORIGINS', [])
            self._allowed_origins.update(trusted)

            # Add from CORS_ALLOWED_ORIGINS
            cors_origins = getattr(settings, 'CORS_ALLOWED_ORIGINS', [])
            self._allowed_origins.update(cors_origins)

            # Add allowed hosts with https
            hosts = getattr(settings, 'ALLOWED_HOSTS', [])
            for host in hosts:
                if host != '*':
                    self._allowed_origins.add(f'https://{host}')

        return self._allowed_origins

    @property
    def allowed_hosts(self) -> Set[str]:
        """Get allowed hosts from settings."""
        if self._allowed_hosts is None:
            self._allowed_hosts = set(getattr(settings, 'ALLOWED_HOSTS', []))
        return self._allowed_hosts

    def validate_origin(self, request: HttpRequest) -> Tuple[bool, str]:
        """
        Validate the request origin.

        Args:
            request: The HTTP request

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Only validate state-changing requests
        if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            return True, ''

        origin = request.META.get('HTTP_ORIGIN')
        referer = request.META.get('HTTP_REFERER')

        # If neither present, this might be a direct request (could be allowed)
        if not origin and not referer:
            # Check configuration for strict mode
            if getattr(settings, 'CSRF_REQUIRE_ORIGIN', False):
                self._log_violation(request, 'no_origin')
                return False, 'Origin header required'
            return True, ''

        # Validate Origin header
        if origin:
            if not self._is_origin_allowed(origin):
                self._log_violation(request, f'invalid_origin:{origin}')
                return False, f'Origin not allowed: {origin}'

        # Validate Referer header
        if referer and not origin:
            referer_origin = self._extract_origin_from_referer(referer)
            if referer_origin and not self._is_origin_allowed(referer_origin):
                self._log_violation(request, f'invalid_referer:{referer_origin}')
                return False, f'Referer origin not allowed: {referer_origin}'

        return True, ''

    def validate_same_origin(self, request: HttpRequest) -> Tuple[bool, str]:
        """
        Validate that the request is same-origin.

        Args:
            request: The HTTP request

        Returns:
            Tuple of (is_same_origin, error_message)
        """
        origin = request.META.get('HTTP_ORIGIN')
        host = request.get_host()

        if origin:
            origin_parsed = urlparse(origin)
            origin_host = origin_parsed.netloc

            # Compare hosts (with or without port)
            if self._hosts_match(origin_host, host):
                return True, ''

            return False, f'Cross-origin request: {origin}'

        # No origin header - check referer
        referer = request.META.get('HTTP_REFERER')
        if referer:
            referer_parsed = urlparse(referer)
            referer_host = referer_parsed.netloc

            if self._hosts_match(referer_host, host):
                return True, ''

            return False, f'Cross-origin referer: {referer}'

        return True, ''  # No origin info - could be direct request

    def require_origin(self, same_origin: bool = False) -> Callable:
        """
        Decorator to require origin validation.

        Args:
            same_origin: If True, require same-origin requests

        Returns:
            Decorator function
        """
        def decorator(view_func: Callable) -> Callable:
            @wraps(view_func)
            def wrapper(request, *args, **kwargs):
                if same_origin:
                    is_valid, error = self.validate_same_origin(request)
                else:
                    is_valid, error = self.validate_origin(request)

                if not is_valid:
                    return JsonResponse(
                        {'error': error, 'code': 'origin_invalid'},
                        status=403
                    )

                return view_func(request, *args, **kwargs)
            return wrapper
        return decorator

    def _is_origin_allowed(self, origin: str) -> bool:
        """Check if an origin is in the allowed list."""
        if not origin:
            return False

        # Direct match
        if origin in self.allowed_origins:
            return True

        # Extract host from origin
        parsed = urlparse(origin)
        origin_host = parsed.netloc

        # Check against allowed hosts
        if origin_host in self.allowed_hosts:
            return True

        # Check for wildcard host
        if '*' in self.allowed_hosts:
            return True

        # Check for subdomain match
        for allowed in self.allowed_hosts:
            if allowed.startswith('.'):
                if origin_host.endswith(allowed) or origin_host == allowed[1:]:
                    return True

        return False

    def _extract_origin_from_referer(self, referer: str) -> Optional[str]:
        """Extract origin from referer URL."""
        try:
            parsed = urlparse(referer)
            return f"{parsed.scheme}://{parsed.netloc}"
        except:
            return None

    def _hosts_match(self, host1: str, host2: str) -> bool:
        """Check if two hosts match (accounting for ports)."""
        # Remove ports for comparison
        h1 = host1.split(':')[0]
        h2 = host2.split(':')[0]
        return h1 == h2

    def _log_violation(self, request: HttpRequest, reason: str):
        """Log an origin violation."""
        event = SecurityEvent(
            event_type=SecurityEventType.CSRF_VIOLATION,
            severity='high',
            message=f'Origin validation failed: {reason}',
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', ''),
            request_path=request.path,
            request_method=request.method,
            details={
                'reason': reason,
                'origin': request.META.get('HTTP_ORIGIN'),
                'referer': request.META.get('HTTP_REFERER'),
            }
        )
        self.logger.log(event)


# =============================================================================
# SameSite Cookie Enforcer
# =============================================================================

class SameSiteCookieEnforcer:
    """
    Enforces SameSite cookie attribute for CSRF protection.

    Ensures all cookies have appropriate SameSite settings.
    """

    # Cookie settings
    DEFAULT_SAMESITE = 'Lax'
    STRICT_COOKIES = {
        'sessionid', 'csrftoken', 'csrf_double_submit',
        'access_token', 'refresh_token'
    }

    def __init__(self):
        self.logger = SecurityEventLogger()

    def process_response(
        self,
        request: HttpRequest,
        response: HttpResponse
    ) -> HttpResponse:
        """
        Process response to enforce SameSite on cookies.

        Args:
            request: The HTTP request
            response: The HTTP response

        Returns:
            Modified response
        """
        # Get SameSite default from settings
        default_samesite = getattr(
            settings, 'SESSION_COOKIE_SAMESITE', self.DEFAULT_SAMESITE
        )

        # Process all cookies
        for cookie_name in response.cookies:
            cookie = response.cookies[cookie_name]

            # Skip if already set
            if 'samesite' in cookie and cookie['samesite']:
                continue

            # Determine SameSite value
            if cookie_name in self.STRICT_COOKIES:
                samesite = 'Strict'
            else:
                samesite = default_samesite

            # Set SameSite attribute
            cookie['samesite'] = samesite

            # Ensure Secure is set for SameSite=None
            if samesite == 'None' and not cookie.get('secure'):
                cookie['secure'] = True

        return response

    def validate_cookies(self, request: HttpRequest) -> List[Dict[str, str]]:
        """
        Validate incoming cookies for security issues.

        Args:
            request: The HTTP request

        Returns:
            List of cookie security issues
        """
        issues = []

        # Check for overly permissive cookies (client-side check not possible,
        # but we can check what we sent)
        # This would typically be called during security audit

        return issues

    def get_secure_cookie_params(
        self,
        cookie_name: str,
        is_sensitive: bool = False
    ) -> Dict[str, Any]:
        """
        Get secure cookie parameters for a given cookie.

        Args:
            cookie_name: Name of the cookie
            is_sensitive: Whether this is a sensitive cookie

        Returns:
            Dictionary of cookie parameters
        """
        params = {
            'secure': not getattr(settings, 'DEBUG', False),
            'httponly': True,
            'samesite': 'Strict' if is_sensitive or cookie_name in self.STRICT_COOKIES else 'Lax',
        }

        # Domain from settings
        domain = getattr(settings, 'SESSION_COOKIE_DOMAIN', None)
        if domain:
            params['domain'] = domain

        # Path
        params['path'] = getattr(settings, 'SESSION_COOKIE_PATH', '/')

        return params

    def create_middleware(self):
        """
        Create a middleware class for SameSite enforcement.

        Returns:
            Middleware class
        """
        enforcer = self

        class SameSiteMiddleware:
            def __init__(self, get_response):
                self.get_response = get_response

            def __call__(self, request):
                response = self.get_response(request)
                return enforcer.process_response(request, response)

        return SameSiteMiddleware


# =============================================================================
# Combined CSRF Middleware
# =============================================================================

class EnhancedCSRFMiddleware:
    """
    Enhanced CSRF middleware combining all protections.

    Provides comprehensive CSRF protection for the application.
    """

    # Methods that require CSRF validation
    CSRF_METHODS = ('POST', 'PUT', 'DELETE', 'PATCH')

    # Paths exempt from CSRF validation
    CSRF_EXEMPT_PATHS = set()

    def __init__(self, get_response):
        self.get_response = get_response
        self.csrf_protection = EnhancedCSRFProtection()
        self.double_submit = DoubleSubmitCookieValidator()
        self.origin_validator = OriginValidator()
        self.samesite_enforcer = SameSiteCookieEnforcer()
        self.logger = SecurityEventLogger()

        # Load exempt paths from settings
        exempt = getattr(settings, 'CSRF_EXEMPT_PATHS', [])
        self.CSRF_EXEMPT_PATHS = set(exempt)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process the request and response."""
        # Check if exempt
        if self._is_exempt(request):
            return self.get_response(request)

        # Validate on state-changing methods
        if request.method in self.CSRF_METHODS:
            # Validate origin
            origin_valid, origin_error = self.origin_validator.validate_origin(request)
            if not origin_valid:
                return self._csrf_failure_response(request, origin_error)

            # Validate double-submit (if enabled)
            if getattr(settings, 'CSRF_USE_DOUBLE_SUBMIT', False):
                ds_valid, ds_error = self.double_submit.validate(request)
                if not ds_valid:
                    return self._csrf_failure_response(request, ds_error)

        # Get response
        response = self.get_response(request)

        # Enforce SameSite on response cookies
        response = self.samesite_enforcer.process_response(request, response)

        # Set double-submit cookie if enabled
        if getattr(settings, 'CSRF_USE_DOUBLE_SUBMIT', False):
            self.double_submit.set_token(response)

        return response

    def _is_exempt(self, request: HttpRequest) -> bool:
        """Check if request is exempt from CSRF validation."""
        # Check exempt paths
        if request.path in self.CSRF_EXEMPT_PATHS:
            return True

        # Check for exempt path prefixes
        for path in self.CSRF_EXEMPT_PATHS:
            if request.path.startswith(path):
                return True

        # Check for csrf_exempt decorator
        view_func = getattr(request, 'csrf_exempt', False)
        if view_func:
            return True

        return False

    def _csrf_failure_response(
        self,
        request: HttpRequest,
        error: str
    ) -> HttpResponse:
        """Create CSRF failure response."""
        # Log the failure
        event = SecurityEvent(
            event_type=SecurityEventType.CSRF_VIOLATION,
            severity='high',
            message=f'CSRF validation failed: {error}',
            ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                       or request.META.get('REMOTE_ADDR', ''),
            request_path=request.path,
            request_method=request.method,
        )
        self.logger.log(event)

        # Return appropriate response
        if request.content_type == 'application/json':
            return JsonResponse(
                {'error': 'CSRF validation failed', 'detail': error},
                status=403
            )

        return HttpResponseForbidden(
            'CSRF validation failed. Please refresh the page and try again.'
        )


# =============================================================================
# API CSRF Protection
# =============================================================================

class APICsrfProtection:
    """
    CSRF protection specifically for REST API endpoints.

    Provides token-based CSRF protection suitable for SPAs and mobile apps.
    """

    CACHE_PREFIX = 'api_csrf:'
    TOKEN_LIFETIME = 3600  # 1 hour

    def __init__(self):
        self.logger = SecurityEventLogger()

    def get_token(self, request: HttpRequest, user_id: str = None) -> str:
        """
        Get or generate an API CSRF token.

        Args:
            request: The HTTP request
            user_id: Optional user ID for binding

        Returns:
            CSRF token
        """
        # Generate token
        token = secrets.token_urlsafe(32)

        # Create token data
        token_data = {
            'created': timezone.now().isoformat(),
            'user_id': user_id,
            'ip_hash': hashlib.sha256(
                self._get_client_ip(request).encode()
            ).hexdigest()[:8],
        }

        # Store
        cache_key = f"{self.CACHE_PREFIX}token:{token}"
        cache.set(cache_key, token_data, self.TOKEN_LIFETIME)

        return token

    def validate_token(
        self,
        request: HttpRequest,
        token: str = None
    ) -> Tuple[bool, str]:
        """
        Validate an API CSRF token.

        Args:
            request: The HTTP request
            token: Token to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Extract token if not provided
        if not token:
            token = request.META.get('HTTP_X_API_CSRF_TOKEN')

        if not token:
            return False, 'API CSRF token required'

        # Get token data
        cache_key = f"{self.CACHE_PREFIX}token:{token}"
        token_data = cache.get(cache_key)

        if not token_data:
            return False, 'Invalid or expired API CSRF token'

        # Validate user binding
        user = getattr(request, 'user', None)
        if user and user.is_authenticated:
            if token_data.get('user_id') and str(user.id) != token_data['user_id']:
                self._log_violation(request, 'user_mismatch')
                return False, 'API CSRF token user mismatch'

        return True, ''

    def require_token(self) -> Callable:
        """
        Decorator to require API CSRF token.

        Returns:
            Decorator function
        """
        def decorator(view_func: Callable) -> Callable:
            @wraps(view_func)
            def wrapper(request, *args, **kwargs):
                # Skip safe methods
                if request.method in ('GET', 'HEAD', 'OPTIONS'):
                    return view_func(request, *args, **kwargs)

                is_valid, error = self.validate_token(request)
                if not is_valid:
                    return JsonResponse(
                        {'error': error, 'code': 'api_csrf_failed'},
                        status=403
                    )

                return view_func(request, *args, **kwargs)
            return wrapper
        return decorator

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    def _log_violation(self, request: HttpRequest, reason: str):
        """Log API CSRF violation."""
        event = SecurityEvent(
            event_type=SecurityEventType.CSRF_VIOLATION,
            severity='high',
            message=f'API CSRF violation: {reason}',
            ip_address=self._get_client_ip(request),
            request_path=request.path,
            request_method=request.method,
        )
        self.logger.log(event)
