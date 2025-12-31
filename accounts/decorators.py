"""
Accounts Decorators - Security Decorators for Views and Functions

This module provides decorator-based access control:

PERMISSION DECORATORS:
- @require_permission: Check specific permission
- @require_role: Check tenant role
- @require_any_role: Check any of specified roles

KYC DECORATORS:
- @require_kyc_level: Require minimum KYC verification level
- @require_kyc_verified: Require any verified KYC

SECURITY DECORATORS:
- @require_2fa: Require two-factor authentication
- @require_recent_auth: Require recent authentication

TENANT DECORATORS:
- @tenant_required: Require tenant context
- @tenant_admin_required: Require tenant admin role
- @tenant_owner_required: Require tenant owner role

FEATURE DECORATORS:
- @require_feature: Require plan feature
- @require_plan: Require minimum plan tier

RATE LIMITING:
- @rate_limit: Apply rate limiting to view

UTILITY DECORATORS:
- @audit_action: Log action for audit trail
- @cache_per_user: Cache response per user
"""

from functools import wraps
from typing import List, Optional, Callable, Union
import time
import hashlib

from django.http import HttpResponseForbidden, JsonResponse
from django.core.cache import cache
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.conf import settings

from rest_framework import status
from rest_framework.response import Response


# =============================================================================
# PERMISSION DECORATORS
# =============================================================================

def require_permission(permission: str, message: str = None):
    """
    Decorator to require a specific permission.

    Usage:
        @require_permission('view_candidates')
        def my_view(request):
            ...

        # With custom message
        @require_permission('delete_all', message='Deletion requires elevated privileges.')
        def delete_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return _forbidden_response(request, 'Authentication required.')

            from .models import TenantUser

            tenant = getattr(request, 'tenant', None)

            # Check tenant permissions
            if tenant:
                try:
                    tenant_user = TenantUser.objects.get(
                        user=request.user,
                        tenant=tenant,
                        is_active=True
                    )
                    if not tenant_user.has_permission(permission):
                        return _forbidden_response(
                            request,
                            message or f'Permission "{permission}" required.'
                        )
                except TenantUser.DoesNotExist:
                    return _forbidden_response(request, 'Not a member of this organization.')
            else:
                # Fall back to Django permissions
                if not request.user.has_perm(permission):
                    return _forbidden_response(
                        request,
                        message or f'Permission "{permission}" required.'
                    )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_role(role: str, message: str = None):
    """
    Decorator to require a specific tenant role.

    Usage:
        @require_role('hr_manager')
        def hr_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return _forbidden_response(request, 'Authentication required.')

            from .models import TenantUser

            tenant = getattr(request, 'tenant', None)
            if not tenant:
                return _forbidden_response(request, 'Tenant context required.')

            if not TenantUser.objects.filter(
                user=request.user,
                tenant=tenant,
                is_active=True,
                role=role
            ).exists():
                return _forbidden_response(
                    request,
                    message or f'Role "{role}" required for this action.'
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_any_role(roles: List[str], message: str = None):
    """
    Decorator to require any of the specified roles.

    Usage:
        @require_any_role(['admin', 'hr_manager', 'recruiter'])
        def hiring_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return _forbidden_response(request, 'Authentication required.')

            from .models import TenantUser

            tenant = getattr(request, 'tenant', None)
            if not tenant:
                return _forbidden_response(request, 'Tenant context required.')

            if not TenantUser.objects.filter(
                user=request.user,
                tenant=tenant,
                is_active=True,
                role__in=roles
            ).exists():
                roles_str = ', '.join(roles)
                return _forbidden_response(
                    request,
                    message or f'One of the following roles required: {roles_str}'
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# KYC DECORATORS
# =============================================================================

def require_kyc_level(level: str, message: str = None):
    """
    Decorator to require minimum KYC verification level.

    Levels (in order): basic, standard, enhanced, complete

    Usage:
        @require_kyc_level('enhanced')
        def sensitive_view(request):
            ...
    """
    KYC_LEVEL_ORDER = ['basic', 'standard', 'enhanced', 'complete']

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return _forbidden_response(request, 'Authentication required.')

            from .models import KYCVerification

            # Get user's highest verified KYC level
            verification = KYCVerification.objects.filter(
                user=request.user,
                status=KYCVerification.VerificationStatus.VERIFIED,
                expires_at__gt=timezone.now()
            ).order_by('-level').first()

            if not verification:
                return _forbidden_response(
                    request,
                    message or 'KYC verification required for this action.'
                )

            try:
                user_level_index = KYC_LEVEL_ORDER.index(verification.level)
                required_level_index = KYC_LEVEL_ORDER.index(level)

                if user_level_index < required_level_index:
                    return _forbidden_response(
                        request,
                        message or f'KYC level "{level}" or higher required.'
                    )
            except ValueError:
                return _forbidden_response(request, 'Invalid KYC level.')

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_kyc_verified(message: str = None):
    """
    Decorator to require any valid KYC verification.

    Usage:
        @require_kyc_verified()
        def verified_only_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return _forbidden_response(request, 'Authentication required.')

            from .models import KYCVerification

            has_verification = KYCVerification.objects.filter(
                user=request.user,
                status=KYCVerification.VerificationStatus.VERIFIED,
                expires_at__gt=timezone.now()
            ).exists()

            if not has_verification:
                return _forbidden_response(
                    request,
                    message or 'KYC verification required.'
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# SECURITY DECORATORS
# =============================================================================

def require_2fa(message: str = None):
    """
    Decorator to require two-factor authentication.

    Usage:
        @require_2fa()
        def secure_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return _forbidden_response(request, 'Authentication required.')

            # Check if 2FA is enabled
            try:
                from django_otp import devices_for_user
                has_device = any(devices_for_user(request.user, confirmed=True))

                if not has_device:
                    return _forbidden_response(
                        request,
                        message or 'Two-factor authentication must be enabled for this action.'
                    )

                # Check if current session has verified 2FA
                if hasattr(request.user, 'is_verified') and not request.user.is_verified():
                    return _forbidden_response(
                        request,
                        message or 'Please verify your two-factor authentication.'
                    )

            except ImportError:
                pass  # django_otp not installed, skip check

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_recent_auth(minutes: int = 30, message: str = None):
    """
    Decorator to require recent authentication for sensitive actions.

    Usage:
        @require_recent_auth(minutes=15)
        def change_password_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return _forbidden_response(request, 'Authentication required.')

            from datetime import timedelta

            # Check token claims for iat (issued at)
            token = getattr(request, 'auth', None)
            if token and hasattr(token, 'payload'):
                iat = token.payload.get('iat')
                if iat:
                    from datetime import datetime
                    issued_at = datetime.fromtimestamp(iat)
                    if datetime.utcnow() - issued_at > timedelta(minutes=minutes):
                        return _forbidden_response(
                            request,
                            message or f'Please re-authenticate. Session must be less than {minutes} minutes old.'
                        )

            # Check session-based last login
            last_login = request.user.last_login
            if last_login:
                if timezone.now() - last_login > timedelta(minutes=minutes):
                    return _forbidden_response(
                        request,
                        message or f'Please re-authenticate. Last login was more than {minutes} minutes ago.'
                    )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# TENANT DECORATORS
# =============================================================================

def tenant_required(message: str = None):
    """
    Decorator to require tenant context.

    Usage:
        @tenant_required()
        def tenant_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            tenant = getattr(request, 'tenant', None)

            if not tenant:
                return _forbidden_response(
                    request,
                    message or 'This action requires a valid organization context.'
                )

            # Check tenant status
            if not tenant.is_active and tenant.status != 'trial':
                return _forbidden_response(
                    request,
                    'Organization access is currently suspended.'
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def tenant_member_required(message: str = None):
    """
    Decorator to require tenant membership.

    Usage:
        @tenant_member_required()
        def member_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return _forbidden_response(request, 'Authentication required.')

            from .models import TenantUser

            tenant = getattr(request, 'tenant', None)
            if not tenant:
                return _forbidden_response(request, 'Tenant context required.')

            if not TenantUser.objects.filter(
                user=request.user,
                tenant=tenant,
                is_active=True
            ).exists():
                return _forbidden_response(
                    request,
                    message or 'You must be a member of this organization.'
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def tenant_admin_required(message: str = None):
    """
    Decorator to require tenant admin or owner role.

    Usage:
        @tenant_admin_required()
        def admin_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return _forbidden_response(request, 'Authentication required.')

            from .models import TenantUser

            tenant = getattr(request, 'tenant', None)
            if not tenant:
                return _forbidden_response(request, 'Tenant context required.')

            if not TenantUser.objects.filter(
                user=request.user,
                tenant=tenant,
                is_active=True,
                role__in=[TenantUser.UserRole.ADMIN, TenantUser.UserRole.OWNER]
            ).exists():
                return _forbidden_response(
                    request,
                    message or 'Administrator privileges required.'
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def tenant_owner_required(message: str = None):
    """
    Decorator to require tenant owner role.

    Usage:
        @tenant_owner_required()
        def owner_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return _forbidden_response(request, 'Authentication required.')

            from .models import TenantUser

            tenant = getattr(request, 'tenant', None)
            if not tenant:
                return _forbidden_response(request, 'Tenant context required.')

            if not TenantUser.objects.filter(
                user=request.user,
                tenant=tenant,
                is_active=True,
                role=TenantUser.UserRole.OWNER
            ).exists():
                return _forbidden_response(
                    request,
                    message or 'Owner privileges required.'
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# FEATURE DECORATORS
# =============================================================================

def require_feature(feature: str, message: str = None):
    """
    Decorator to require a plan feature.

    Usage:
        @require_feature('feature_ai_matching')
        def ai_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            tenant = getattr(request, 'tenant', None)

            if not tenant:
                return _forbidden_response(request, 'Tenant context required.')

            if not tenant.plan:
                return _forbidden_response(
                    request,
                    'A subscription plan is required.'
                )

            if not getattr(tenant.plan, feature, False):
                feature_name = feature.replace('feature_', '').replace('_', ' ').title()
                return _forbidden_response(
                    request,
                    message or f'Your plan does not include the {feature_name} feature.'
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_plan(minimum_plan: str, message: str = None):
    """
    Decorator to require minimum subscription plan tier.

    Plans (in order): free, starter, professional, enterprise

    Usage:
        @require_plan('professional')
        def pro_view(request):
            ...
    """
    PLAN_HIERARCHY = ['free', 'starter', 'professional', 'enterprise']

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            tenant = getattr(request, 'tenant', None)

            if not tenant:
                return _forbidden_response(request, 'Tenant context required.')

            if not tenant.plan:
                return _forbidden_response(
                    request,
                    'A subscription plan is required.'
                )

            try:
                tenant_plan_index = PLAN_HIERARCHY.index(tenant.plan.plan_type)
                required_plan_index = PLAN_HIERARCHY.index(minimum_plan)

                if tenant_plan_index < required_plan_index:
                    return _forbidden_response(
                        request,
                        message or f'This feature requires a {minimum_plan.title()} plan or higher.'
                    )
            except ValueError:
                return _forbidden_response(request, 'Invalid plan type.')

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# RATE LIMITING DECORATOR
# =============================================================================

def rate_limit(
    rate: str = '100/h',
    key: str = 'user',
    message: str = None,
    block_duration: int = 60
):
    """
    Decorator to apply rate limiting.

    Rate format: "number/period" where period is s, m, h, d (second, minute, hour, day)

    Usage:
        @rate_limit('10/m')  # 10 requests per minute
        def limited_view(request):
            ...

        @rate_limit('100/h', key='ip')  # By IP instead of user
        def ip_limited_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Parse rate
            try:
                count, period = rate.split('/')
                max_requests = int(count)
                period_seconds = {
                    's': 1,
                    'm': 60,
                    'h': 3600,
                    'd': 86400
                }.get(period, 3600)
            except (ValueError, AttributeError):
                max_requests = 100
                period_seconds = 3600

            # Generate cache key
            if key == 'ip':
                identifier = _get_client_ip(request)
            elif key == 'user':
                if request.user.is_authenticated:
                    identifier = f"user_{request.user.id}"
                else:
                    identifier = _get_client_ip(request)
            else:
                identifier = key

            cache_key = f"rate_limit:{view_func.__name__}:{identifier}"

            # Check current count
            data = cache.get(cache_key)
            if data:
                count_val, first_request_time = data
                elapsed = time.time() - first_request_time

                if elapsed < period_seconds:
                    if count_val >= max_requests:
                        # Check if blocked
                        block_key = f"rate_limit_blocked:{view_func.__name__}:{identifier}"
                        if not cache.get(block_key):
                            cache.set(block_key, True, timeout=block_duration)

                        return _rate_limit_response(
                            request,
                            message or f'Rate limit exceeded. Try again in {int(period_seconds - elapsed)} seconds.'
                        )
                    else:
                        # Increment count
                        cache.set(cache_key, (count_val + 1, first_request_time), timeout=period_seconds)
                else:
                    # Reset counter
                    cache.set(cache_key, (1, time.time()), timeout=period_seconds)
            else:
                # First request
                cache.set(cache_key, (1, time.time()), timeout=period_seconds)

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# UTILITY DECORATORS
# =============================================================================

def audit_action(action_type: str, resource_type: str = None):
    """
    Decorator to log action for audit trail.

    Usage:
        @audit_action('create', 'job_posting')
        def create_job(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Execute the view first
            response = view_func(request, *args, **kwargs)

            # Log audit event on success
            if hasattr(response, 'status_code') and 200 <= response.status_code < 300:
                try:
                    from tenants.models import AuditLog

                    tenant = getattr(request, 'tenant', None)
                    if tenant:
                        AuditLog.objects.create(
                            tenant=tenant,
                            user=request.user if request.user.is_authenticated else None,
                            action=action_type,
                            resource_type=resource_type or view_func.__name__,
                            description=f"Action: {action_type} on {resource_type or view_func.__name__}",
                            ip_address=_get_client_ip(request),
                            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
                        )
                except Exception:
                    pass  # Don't fail the request if audit logging fails

            return response
        return wrapper
    return decorator


def cache_per_user(timeout: int = 300, key_prefix: str = None):
    """
    Decorator to cache response per user.

    Usage:
        @cache_per_user(timeout=600)
        def user_dashboard(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Only cache for authenticated users and GET requests
            if not request.user.is_authenticated or request.method != 'GET':
                return view_func(request, *args, **kwargs)

            # Generate cache key
            prefix = key_prefix or view_func.__name__
            tenant = getattr(request, 'tenant', None)
            tenant_id = tenant.id if tenant else 'none'

            cache_key = f"view_cache:{prefix}:{request.user.id}:{tenant_id}:{request.get_full_path()}"

            # Check cache
            cached_response = cache.get(cache_key)
            if cached_response:
                return cached_response

            # Execute view and cache result
            response = view_func(request, *args, **kwargs)

            if hasattr(response, 'status_code') and response.status_code == 200:
                cache.set(cache_key, response, timeout=timeout)

            return response
        return wrapper
    return decorator


def log_security_event(event_type: str):
    """
    Decorator to log security events.

    Usage:
        @log_security_event('password_change')
        def change_password(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            from .security import SecurityEventLogger

            # Log event before execution
            SecurityEventLogger.log_event(
                event_type=event_type,
                user=request.user if request.user.is_authenticated else None,
                ip_address=_get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={'endpoint': request.path}
            )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _forbidden_response(request, message: str):
    """
    Return appropriate forbidden response based on request type.
    """
    # Check if this is an API request
    if _is_api_request(request):
        return JsonResponse(
            {'error': message, 'detail': message},
            status=403
        )
    else:
        return HttpResponseForbidden(message)


def _rate_limit_response(request, message: str):
    """
    Return rate limit response.
    """
    if _is_api_request(request):
        return JsonResponse(
            {'error': message, 'detail': message},
            status=429
        )
    else:
        from django.http import HttpResponse
        response = HttpResponse(message, status=429)
        response['Retry-After'] = '60'
        return response


def _is_api_request(request) -> bool:
    """
    Determine if request is an API request.
    """
    content_type = request.content_type or ''
    accept = request.META.get('HTTP_ACCEPT', '')

    return (
        'application/json' in content_type or
        'application/json' in accept or
        request.path.startswith('/api/')
    )


def _get_client_ip(request) -> str:
    """
    Extract client IP from request.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


# =============================================================================
# DRF-COMPATIBLE DECORATORS (for use with APIView methods)
# =============================================================================

def api_require_permission(permission: str, message: str = None):
    """
    DRF-compatible permission decorator for APIView methods.

    Usage:
        class MyView(APIView):
            @api_require_permission('view_candidates')
            def get(self, request):
                ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            if not request.user.is_authenticated:
                return Response(
                    {'error': 'Authentication required.'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            from .models import TenantUser

            tenant = getattr(request, 'tenant', None)

            if tenant:
                try:
                    tenant_user = TenantUser.objects.get(
                        user=request.user,
                        tenant=tenant,
                        is_active=True
                    )
                    if not tenant_user.has_permission(permission):
                        return Response(
                            {'error': message or f'Permission "{permission}" required.'},
                            status=status.HTTP_403_FORBIDDEN
                        )
                except TenantUser.DoesNotExist:
                    return Response(
                        {'error': 'Not a member of this organization.'},
                        status=status.HTTP_403_FORBIDDEN
                    )
            else:
                if not request.user.has_perm(permission):
                    return Response(
                        {'error': message or f'Permission "{permission}" required.'},
                        status=status.HTTP_403_FORBIDDEN
                    )

            return view_func(self, request, *args, **kwargs)
        return wrapper
    return decorator


def api_tenant_admin_required(message: str = None):
    """
    DRF-compatible tenant admin decorator.

    Usage:
        class MyView(APIView):
            @api_tenant_admin_required()
            def post(self, request):
                ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            if not request.user.is_authenticated:
                return Response(
                    {'error': 'Authentication required.'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            from .models import TenantUser

            tenant = getattr(request, 'tenant', None)
            if not tenant:
                return Response(
                    {'error': 'Tenant context required.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not TenantUser.objects.filter(
                user=request.user,
                tenant=tenant,
                is_active=True,
                role__in=[TenantUser.UserRole.ADMIN, TenantUser.UserRole.OWNER]
            ).exists():
                return Response(
                    {'error': message or 'Administrator privileges required.'},
                    status=status.HTTP_403_FORBIDDEN
                )

            return view_func(self, request, *args, **kwargs)
        return wrapper
    return decorator
