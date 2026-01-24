"""
Core Decorators - Permission Decorators for Function-Based Views

This module provides decorators to enforce security on function-based Django views.
Use these decorators to ensure consistent permission checking across all views.

USAGE:
    from core.decorators import (
        require_tenant_user,
        require_role,
        require_admin,
        require_permission,
        require_feature,
        audit_access,
    )

    @require_tenant_user
    def my_view(request):
        # User is authenticated and is a member of the tenant
        ...

    @require_role(['owner', 'admin', 'hr_manager'])
    def hr_only_view(request):
        # User has one of the specified roles
        ...

    @require_permission('manage_candidates')
    def manage_candidates_view(request):
        # User has the specific permission
        ...

    @require_feature('ai_matching')
    def ai_matching_view(request):
        # Tenant's plan includes the feature
        ...

DECORATORS:

1. @require_tenant: Require tenant context on request
2. @require_tenant_user: Require user to be a member of current tenant
3. @require_role(roles): Require user to have one of the specified roles
4. @require_admin: Shortcut for owner/admin roles
5. @require_hr: Shortcut for HR-related roles
6. @require_recruiter: Shortcut for recruiting roles
7. @require_permission(codename): Require specific permission
8. @require_feature(feature_name): Require tenant plan feature
9. @audit_access(action_name): Log access for security auditing
10. @require_object_permission(perm_class): Object-level permission
11. @rate_limit(scope, limit): Custom rate limiting
"""

import logging
from functools import wraps
from typing import Any, Callable, List, Optional, Type, Union

from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseForbidden,
    JsonResponse,
)
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from rest_framework import permissions

logger = logging.getLogger('security.decorators')


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _get_client_ip(request: HttpRequest) -> str:
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def _is_api_request(request: HttpRequest) -> bool:
    """Check if request is an API request (expecting JSON response)."""
    accept = request.META.get('HTTP_ACCEPT', '')
    content_type = request.META.get('CONTENT_TYPE', '')
    return 'application/json' in accept or 'application/json' in content_type


def _permission_denied_response(request: HttpRequest, message: str) -> HttpResponse:
    """Return appropriate permission denied response based on request type."""
    if _is_api_request(request):
        return JsonResponse(
            {
                'success': False,
                'message': message,
                'error_code': 'PERMISSION_DENIED',
            },
            status=403
        )
    return HttpResponseForbidden(message)


# =============================================================================
# TENANT CONTEXT DECORATORS
# =============================================================================

def require_tenant(view_func: Callable) -> Callable:
    """
    Require tenant context on request.

    Ensures request.tenant is set by tenant middleware.
    Use as the base decorator when you need tenant context.

    Usage:
        @require_tenant
        def my_view(request):
            tenant = request.tenant
            ...
    """
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not hasattr(request, 'tenant') or not request.tenant:
            logger.warning(
                f"PERMISSION_DENIED: No tenant context for {view_func.__name__} "
                f"from IP {_get_client_ip(request)}"
            )
            return _permission_denied_response(
                request,
                "This resource requires a tenant context. Please access via your organization's domain."
            )
        return view_func(request, *args, **kwargs)

    return login_required(wrapper)


def require_tenant_user(view_func: Callable) -> Callable:
    """
    Require user to be a member of current tenant.

    Combines authentication with tenant membership check.
    This is the most common decorator for tenant-scoped views.

    Usage:
        @require_tenant_user
        def my_view(request):
            # User is authenticated and member of request.tenant
            ...
    """
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        # Check tenant context
        if not hasattr(request, 'tenant') or not request.tenant:
            logger.warning(
                f"PERMISSION_DENIED: No tenant context for {view_func.__name__} "
                f"user={getattr(request.user, 'id', None)}"
            )
            return _permission_denied_response(
                request,
                "This resource requires a tenant context."
            )

        # Check tenant membership
        from tenant_profiles.models import TenantUser

        is_member = TenantUser.objects.filter(
            user=request.user,
            tenant=request.tenant,
            is_active=True
        ).exists()

        if not is_member:
            logger.warning(
                f"PERMISSION_DENIED: User {request.user.id} not member of "
                f"tenant {request.tenant.slug} for {view_func.__name__}"
            )
            return _permission_denied_response(
                request,
                "You are not a member of this organization."
            )

        return view_func(request, *args, **kwargs)

    return login_required(wrapper)


# =============================================================================
# ROLE-BASED DECORATORS
# =============================================================================

def require_role(allowed_roles: List[str]) -> Callable:
    """
    Require user to have one of the specified roles.

    Roles: 'owner', 'admin', 'hr_manager', 'recruiter', 'hiring_manager', 'employee', 'viewer'

    Usage:
        @require_role(['owner', 'admin', 'hr_manager'])
        def hr_only_view(request):
            ...
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            # Check tenant context
            if not hasattr(request, 'tenant') or not request.tenant:
                return _permission_denied_response(
                    request,
                    "This resource requires a tenant context."
                )

            # Check role
            from tenant_profiles.models import TenantUser

            has_role = TenantUser.objects.filter(
                user=request.user,
                tenant=request.tenant,
                is_active=True,
                role__in=allowed_roles
            ).exists()

            if not has_role:
                logger.warning(
                    f"PERMISSION_DENIED: User {request.user.id} lacks role "
                    f"{allowed_roles} for {view_func.__name__} in tenant {request.tenant.slug}"
                )
                return _permission_denied_response(
                    request,
                    f"This action requires one of these roles: {', '.join(allowed_roles)}"
                )

            return view_func(request, *args, **kwargs)

        return login_required(wrapper)

    return decorator


def require_admin(view_func: Callable) -> Callable:
    """
    Shortcut decorator for owner/admin roles.

    Usage:
        @require_admin
        def admin_only_view(request):
            ...
    """
    return require_role(['owner', 'admin'])(view_func)


def require_hr(view_func: Callable) -> Callable:
    """
    Shortcut decorator for HR staff roles.

    Allows: owner, admin, hr_manager

    Usage:
        @require_hr
        def hr_view(request):
            ...
    """
    return require_role(['owner', 'admin', 'hr_manager'])(view_func)


def require_recruiter(view_func: Callable) -> Callable:
    """
    Shortcut decorator for recruiting roles.

    Allows: owner, admin, hr_manager, recruiter, hiring_manager

    Usage:
        @require_recruiter
        def recruitment_view(request):
            ...
    """
    return require_role(['owner', 'admin', 'hr_manager', 'recruiter', 'hiring_manager'])(view_func)


def require_owner(view_func: Callable) -> Callable:
    """
    Shortcut decorator for owner-only access.

    Use for critical operations like:
    - Billing management
    - Tenant deletion
    - Ownership transfer

    Usage:
        @require_owner
        def billing_view(request):
            ...
    """
    return require_role(['owner'])(view_func)


# =============================================================================
# PERMISSION-BASED DECORATORS
# =============================================================================

def require_permission(permission_codename: str) -> Callable:
    """
    Require user to have a specific permission.

    Checks TenantUser.has_permission() for the codename.

    Usage:
        @require_permission('manage_candidates')
        def manage_candidates(request):
            ...
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            # Check tenant context
            if not hasattr(request, 'tenant') or not request.tenant:
                return _permission_denied_response(
                    request,
                    "This resource requires a tenant context."
                )

            # Get tenant user and check permission
            from tenant_profiles.models import TenantUser

            try:
                tenant_user = TenantUser.objects.get(
                    user=request.user,
                    tenant=request.tenant,
                    is_active=True
                )
                if not tenant_user.has_permission(permission_codename):
                    logger.warning(
                        f"PERMISSION_DENIED: User {request.user.id} lacks "
                        f"permission {permission_codename} for {view_func.__name__}"
                    )
                    return _permission_denied_response(
                        request,
                        f"You do not have the '{permission_codename}' permission."
                    )
            except TenantUser.DoesNotExist:
                return _permission_denied_response(
                    request,
                    "You are not a member of this organization."
                )

            return view_func(request, *args, **kwargs)

        return login_required(wrapper)

    return decorator


def require_any_permission(*permission_codenames: str) -> Callable:
    """
    Require user to have any of the specified permissions.

    Usage:
        @require_any_permission('view_candidates', 'manage_candidates')
        def candidates_view(request):
            ...
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            if not hasattr(request, 'tenant') or not request.tenant:
                return _permission_denied_response(
                    request,
                    "This resource requires a tenant context."
                )

            from tenant_profiles.models import TenantUser

            try:
                tenant_user = TenantUser.objects.get(
                    user=request.user,
                    tenant=request.tenant,
                    is_active=True
                )
                has_any = any(
                    tenant_user.has_permission(perm)
                    for perm in permission_codenames
                )
                if not has_any:
                    logger.warning(
                        f"PERMISSION_DENIED: User {request.user.id} lacks "
                        f"permissions {permission_codenames} for {view_func.__name__}"
                    )
                    return _permission_denied_response(
                        request,
                        f"You need one of these permissions: {', '.join(permission_codenames)}"
                    )
            except TenantUser.DoesNotExist:
                return _permission_denied_response(
                    request,
                    "You are not a member of this organization."
                )

            return view_func(request, *args, **kwargs)

        return login_required(wrapper)

    return decorator


# =============================================================================
# FEATURE FLAG DECORATORS
# =============================================================================

def require_feature(feature_name: str) -> Callable:
    """
    Require tenant plan to have a specific feature.

    Checks tenant.plan.feature_{feature_name} boolean.

    Usage:
        @require_feature('ai_matching')
        def ai_matching_view(request):
            ...
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            tenant = getattr(request, 'tenant', None)
            if not tenant or not tenant.plan:
                return _permission_denied_response(
                    request,
                    "Feature not available without a subscription plan."
                )

            feature_attr = f'feature_{feature_name}'
            if not getattr(tenant.plan, feature_attr, False):
                logger.warning(
                    f"FEATURE_DENIED: Tenant {tenant.slug} lacks feature "
                    f"{feature_name} for {view_func.__name__}"
                )
                return _permission_denied_response(
                    request,
                    f"The '{feature_name}' feature is not included in your plan. "
                    "Please upgrade to access this functionality."
                )

            return view_func(request, *args, **kwargs)

        return login_required(wrapper)

    return decorator


# =============================================================================
# AUDIT LOGGING DECORATORS
# =============================================================================

def audit_access(action_name: Optional[str] = None) -> Callable:
    """
    Log access to a view for security auditing.

    Use for sensitive views that should be tracked.

    Usage:
        @audit_access('view_employee_data')
        def employee_detail(request, pk):
            ...

        # Or use function name as action
        @audit_access()
        def sensitive_operation(request):
            ...
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            action = action_name or view_func.__name__
            user_id = getattr(request.user, 'id', None)
            tenant = getattr(request, 'tenant', None)
            tenant_slug = getattr(tenant, 'slug', None) if tenant else None

            logger.info(
                f"AUDIT: user={user_id} tenant={tenant_slug} action={action} "
                f"ip={_get_client_ip(request)} path={request.path} "
                f"method={request.method}"
            )

            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def audit_sensitive_access(data_category: str) -> Callable:
    """
    Log access to sensitive data for compliance auditing.

    Use for views that access PII or other sensitive data.

    Usage:
        @audit_sensitive_access('employee_ssn')
        def view_ssn(request, employee_id):
            ...
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            user_id = getattr(request.user, 'id', None)
            tenant = getattr(request, 'tenant', None)
            tenant_slug = getattr(tenant, 'slug', None) if tenant else None

            logger.info(
                f"SENSITIVE_DATA_ACCESS: user={user_id} tenant={tenant_slug} "
                f"category={data_category} view={view_func.__name__} "
                f"ip={_get_client_ip(request)} args={kwargs}"
            )

            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


# =============================================================================
# RATE LIMITING DECORATORS
# =============================================================================

def rate_limit(scope: str, limit: str) -> Callable:
    """
    Rate limit access to a view.

    This is complementary to DRF throttling for function-based views.

    Usage:
        @rate_limit('password_reset', '3/hour')
        def password_reset_view(request):
            ...

        @rate_limit('api_export', '10/day')
        def export_data(request):
            ...
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            # Parse rate limit string
            try:
                num_requests, period = limit.split('/')
                num_requests = int(num_requests)
            except (ValueError, AttributeError):
                return view_func(request, *args, **kwargs)

            # Calculate period in seconds
            period_seconds = {
                'second': 1,
                'minute': 60,
                'hour': 3600,
                'day': 86400,
                'week': 604800,
            }.get(period, 3600)

            # Build cache key
            user_id = request.user.id if request.user.is_authenticated else 'anon'
            tenant = getattr(request, 'tenant', None)
            tenant_id = tenant.id if tenant else 'none'
            cache_key = f'rate_limit:{scope}:{tenant_id}:{user_id}'

            # Check current count
            current_count = cache.get(cache_key, 0)

            if current_count >= num_requests:
                logger.warning(
                    f"RATE_LIMIT_EXCEEDED: user={user_id} tenant={tenant_id} "
                    f"scope={scope} limit={limit} count={current_count}"
                )
                return _permission_denied_response(
                    request,
                    f"Rate limit exceeded. Please try again later."
                )

            # Increment counter
            if current_count == 0:
                cache.set(cache_key, 1, timeout=period_seconds)
            else:
                try:
                    cache.incr(cache_key)
                except ValueError:
                    cache.set(cache_key, 1, timeout=period_seconds)

            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


# =============================================================================
# SECURITY DECORATORS
# =============================================================================

def require_2fa(view_func: Callable) -> Callable:
    """
    Require two-factor authentication to be enabled and verified.

    Usage:
        @require_2fa
        def sensitive_action(request):
            ...
    """
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        try:
            from django_otp import devices_for_user
            has_device = any(devices_for_user(request.user, confirmed=True))
            if not has_device:
                return _permission_denied_response(
                    request,
                    "Two-factor authentication is required for this action. "
                    "Please enable 2FA in your security settings."
                )
        except ImportError:
            pass  # django_otp not installed

        # Check if 2FA is verified for this session
        if hasattr(request.user, 'is_verified') and not request.user.is_verified():
            return _permission_denied_response(
                request,
                "Please verify your two-factor authentication to continue."
            )

        return view_func(request, *args, **kwargs)

    return login_required(wrapper)


def require_recent_login(minutes: int = 30) -> Callable:
    """
    Require recent authentication for sensitive actions.

    Usage:
        @require_recent_login(minutes=15)
        def change_password(request):
            ...
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            from django.utils import timezone
            from datetime import timedelta

            last_login = request.user.last_login
            if last_login:
                if timezone.now() - last_login > timedelta(minutes=minutes):
                    return _permission_denied_response(
                        request,
                        f"This action requires a recent login. "
                        f"Please re-authenticate and try again."
                    )

            return view_func(request, *args, **kwargs)

        return login_required(wrapper)

    return decorator


# =============================================================================
# HTTP METHOD DECORATORS
# =============================================================================

def require_post(view_func: Callable) -> Callable:
    """
    Require POST method for state-changing operations.

    Usage:
        @require_post
        def delete_item(request, pk):
            ...
    """
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if request.method != 'POST':
            return _permission_denied_response(
                request,
                "This action requires a POST request."
            )
        return view_func(request, *args, **kwargs)

    return wrapper


def require_methods(*methods: str) -> Callable:
    """
    Require specific HTTP methods.

    Usage:
        @require_methods('POST', 'PUT')
        def update_item(request, pk):
            ...
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs) -> HttpResponse:
            if request.method not in methods:
                return _permission_denied_response(
                    request,
                    f"This action requires one of these methods: {', '.join(methods)}"
                )
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


# =============================================================================
# COMBINED DECORATORS
# =============================================================================

def secure_view(
    roles: Optional[List[str]] = None,
    permission: Optional[str] = None,
    feature: Optional[str] = None,
    audit: bool = False
) -> Callable:
    """
    Combined decorator for common security requirements.

    Usage:
        @secure_view(roles=['admin', 'hr_manager'], feature='ai_matching', audit=True)
        def ai_candidate_view(request):
            ...
    """
    def decorator(view_func: Callable) -> Callable:
        func = view_func

        # Apply decorators in order (innermost first)
        if audit:
            func = audit_access()(func)

        if feature:
            func = require_feature(feature)(func)

        if permission:
            func = require_permission(permission)(func)

        if roles:
            func = require_role(roles)(func)
        else:
            func = require_tenant_user(func)

        return func

    return decorator


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Tenant context
    'require_tenant',
    'require_tenant_user',

    # Role-based
    'require_role',
    'require_admin',
    'require_hr',
    'require_recruiter',
    'require_owner',

    # Permission-based
    'require_permission',
    'require_any_permission',

    # Feature flags
    'require_feature',

    # Auditing
    'audit_access',
    'audit_sensitive_access',

    # Rate limiting
    'rate_limit',

    # Security
    'require_2fa',
    'require_recent_login',

    # HTTP methods
    'require_post',
    'require_methods',

    # Combined
    'secure_view',
]
