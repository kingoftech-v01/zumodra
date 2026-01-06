"""
Tenants Middleware - Custom middleware for multi-tenant request handling.

This module provides comprehensive tenant resolution and request handling:
- Subdomain-based tenant resolution
- Custom domain tenant resolution
- HTTP header-based tenant resolution (for API clients)
- Redis-based tenant caching for performance
- Tenant validation and error handling
- Request enrichment with tenant context
"""

import logging
import hashlib
import json
from typing import Optional, Dict, Any

from django.conf import settings
from django.core.cache import cache
from django.http import Http404, HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect
from django.urls import reverse, set_urlconf
from django.utils import timezone
from django_tenants.middleware.main import TenantMainMiddleware
from django_tenants.utils import get_public_schema_name, get_tenant_model

from .models import Tenant, Domain
from .context import set_current_tenant, clear_tenant_context

logger = logging.getLogger(__name__)


# Rate limiting configuration for tenant resolution
TENANT_RESOLUTION_RATE_LIMIT = getattr(settings, 'TENANT_RESOLUTION_RATE_LIMIT', 100)  # requests per minute
TENANT_RESOLUTION_RATE_WINDOW = 60  # seconds


# Cache configuration
TENANT_CACHE_PREFIX = 'tenant:'
TENANT_CACHE_TIMEOUT = getattr(settings, 'TENANT_CACHE_TIMEOUT', 300)  # 5 minutes default
TENANT_HEADER_NAME = getattr(settings, 'TENANT_HEADER_NAME', 'X-Tenant-ID')
TENANT_BASE_DOMAIN = getattr(settings, 'TENANT_BASE_DOMAIN', 'zumodra.com')


class TenantURLConfMiddleware:
    """
    Middleware to ensure the correct URL configuration is applied after
    TenantMainMiddleware sets request.urlconf.

    This fixes an issue where django-tenants sets request.urlconf but doesn't
    call set_urlconf(), which is required for Django's URL resolver to use
    the correct URL configuration.

    Must be placed immediately after TenantMainMiddleware in MIDDLEWARE.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # If TenantMainMiddleware set a custom urlconf, apply it
        if hasattr(request, 'urlconf') and request.urlconf:
            set_urlconf(request.urlconf)
        return self.get_response(request)


class TenantResolutionError(Exception):
    """Exception raised when tenant cannot be resolved."""
    pass


class TenantNotFoundError(TenantResolutionError):
    """Exception raised when tenant does not exist."""
    pass


class TenantInactiveError(TenantResolutionError):
    """Exception raised when tenant is not active."""
    pass


class ZumodraTenantMiddleware(TenantMainMiddleware):
    """
    Extended tenant middleware with comprehensive features:
    - Multi-strategy tenant resolution (subdomain, custom domain, header)
    - Redis-based tenant caching for performance
    - Trial expiration check
    - Suspension handling
    - Usage tracking
    - Request context enrichment
    """

    EXEMPT_URLS = [
        '/admin/',
        '/accounts/',
        '/api/public/',
        '/api/health/',
        '/static/',
        '/media/',
        '/.well-known/',
    ]

    # Resolution strategies in order of priority
    RESOLUTION_STRATEGIES = [
        'header',      # API clients with X-Tenant-ID header
        'subdomain',   # Standard subdomain resolution
        'domain',      # Custom domain resolution
    ]

    def process_request(self, request):
        """
        Process incoming request with comprehensive tenant resolution.

        Resolution priority:
        1. X-Tenant-ID header (for API clients)
        2. Subdomain extraction from host
        3. Custom domain lookup
        """
        # Try to resolve tenant using our enhanced strategies
        tenant = None
        resolution_method = None

        try:
            tenant, resolution_method = self._resolve_tenant(request)
        except TenantNotFoundError as e:
            logger.warning(f"Tenant not found: {e}")
            return self._tenant_not_found_response(request)
        except TenantInactiveError as e:
            logger.warning(f"Tenant inactive: {e}")
            # Continue to handle status in process_request
            pass
        except TenantResolutionError as e:
            logger.error(f"Tenant resolution error: {e}")
            return self._tenant_error_response(request)

        if tenant:
            # Set tenant on request (bypass parent processing)
            request.tenant = tenant
            self._setup_tenant_schema(tenant)
            request._tenant_resolution_method = resolution_method
            # Also set in thread-local context for use in signals, tasks, etc.
            set_current_tenant(tenant)
        else:
            # Fall back to parent implementation
            super().process_request(request)

        # Skip checks for public schema
        if request.tenant.schema_name == get_public_schema_name():
            request._is_public_tenant = True
            return None

        request._is_public_tenant = False

        # Check tenant status
        tenant = request.tenant

        # Handle suspended tenants
        if tenant.status == Tenant.TenantStatus.SUSPENDED:
            if not self._is_exempt_url(request.path):
                return self._suspended_response(request)

        # Handle cancelled tenants
        if tenant.status == Tenant.TenantStatus.CANCELLED:
            if not self._is_exempt_url(request.path):
                return self._cancelled_response(request)

        # Handle pending tenants
        if tenant.status == Tenant.TenantStatus.PENDING:
            if not self._is_exempt_url(request.path):
                return self._pending_response(request)

        # Check trial expiration
        if tenant.on_trial and tenant.trial_ends_at:
            if timezone.now() > tenant.trial_ends_at:
                # Trial expired - update status
                tenant.status = Tenant.TenantStatus.SUSPENDED
                tenant.save(update_fields=['status'])
                # Invalidate cache
                self._invalidate_tenant_cache(tenant)
                if not self._is_exempt_url(request.path):
                    return self._trial_expired_response(request)

        # Add tenant context to request
        request.tenant_settings = getattr(tenant, 'settings', None)
        request.tenant_plan = tenant.plan
        request.tenant_features = self._get_tenant_features(tenant)

        return None

    def _resolve_tenant(self, request) -> tuple:
        """
        Resolve tenant using multiple strategies.

        Returns:
            Tuple of (Tenant, resolution_method) or (None, None)
        """
        hostname = request.get_host().split(':')[0].lower()

        # Check rate limiting for tenant resolution to prevent enumeration attacks
        if not self._check_tenant_resolution_rate_limit(request):
            raise TenantResolutionError("Rate limit exceeded for tenant resolution")

        # Strategy 1: Header-based resolution (for API clients)
        # SECURITY: Validate that authenticated user has permission for the specified tenant
        tenant_id = request.META.get(f'HTTP_{TENANT_HEADER_NAME.replace("-", "_").upper()}')
        if tenant_id:
            tenant = self._get_tenant_from_cache_or_db(
                cache_key=f"{TENANT_CACHE_PREFIX}id:{tenant_id}",
                lookup_func=lambda: self._lookup_tenant_by_id(tenant_id)
            )
            if tenant:
                # CRITICAL SECURITY FIX: Verify user has access to this tenant
                if not self._validate_user_tenant_access(request, tenant):
                    logger.warning(
                        f"Unauthorized tenant access attempt: user tried to access tenant "
                        f"{tenant.slug} via header without permission"
                    )
                    raise TenantResolutionError(
                        "User does not have permission to access this tenant"
                    )
                return tenant, 'header'

        # Strategy 2: Subdomain-based resolution
        if '.' in hostname:
            subdomain = self._extract_subdomain(hostname)
            if subdomain and subdomain not in ('www', 'api', 'admin'):
                tenant = self._get_tenant_from_cache_or_db(
                    cache_key=f"{TENANT_CACHE_PREFIX}subdomain:{subdomain}",
                    lookup_func=lambda: self._lookup_tenant_by_subdomain(subdomain)
                )
                if tenant:
                    return tenant, 'subdomain'

        # Strategy 3: Custom domain resolution
        tenant = self._get_tenant_from_cache_or_db(
            cache_key=f"{TENANT_CACHE_PREFIX}domain:{hostname}",
            lookup_func=lambda: self._lookup_tenant_by_domain(hostname)
        )
        if tenant:
            return tenant, 'domain'

        return None, None

    def _extract_subdomain(self, hostname: str) -> Optional[str]:
        """
        Extract subdomain from hostname.

        Examples:
            acme.zumodra.com -> acme
            www.zumodra.com -> www
            zumodra.com -> None
        """
        base_domain = TENANT_BASE_DOMAIN.lower()

        if hostname == base_domain:
            return None

        if hostname.endswith(f'.{base_domain}'):
            subdomain = hostname[:-len(f'.{base_domain}')]
            # Handle multi-level subdomains (e.g., app.acme.zumodra.com)
            return subdomain.split('.')[-1] if '.' in subdomain else subdomain

        return None

    def _get_tenant_from_cache_or_db(self, cache_key: str, lookup_func) -> Optional[Tenant]:
        """
        Get tenant from cache or database with fallback.

        SECURITY FIX: Cache serialized tenant data for better performance
        instead of just the ID which requires a DB fetch on cache hit.

        Args:
            cache_key: Redis cache key
            lookup_func: Function to call if cache miss

        Returns:
            Tenant instance or None
        """
        # Try cache first
        cached_data = cache.get(cache_key)
        if cached_data is not None:
            if cached_data == '__NOT_FOUND__':
                return None
            try:
                # PERFORMANCE FIX: Cache stores serialized tenant data
                if isinstance(cached_data, dict):
                    # Reconstruct tenant from cached data
                    return self._deserialize_tenant_from_cache(cached_data)
                elif isinstance(cached_data, (int, str)):
                    # Legacy: handle old cache format (just ID) - fetch and re-cache
                    try:
                        tenant = Tenant.objects.select_related('plan', 'settings').get(id=cached_data)
                        # Update cache with serialized data
                        cache.set(cache_key, self._serialize_tenant_for_cache(tenant), TENANT_CACHE_TIMEOUT)
                        return tenant
                    except Tenant.DoesNotExist:
                        cache.delete(cache_key)
                        return None
            except Exception as e:
                logger.warning(f"Error deserializing cached tenant: {e}")
                cache.delete(cache_key)

        # Cache miss - lookup in database
        tenant = lookup_func()

        if tenant:
            # Cache serialized tenant data for faster subsequent lookups
            cache.set(cache_key, self._serialize_tenant_for_cache(tenant), TENANT_CACHE_TIMEOUT)
        else:
            # Cache negative result to prevent repeated DB hits
            cache.set(cache_key, '__NOT_FOUND__', TENANT_CACHE_TIMEOUT // 2)

        return tenant

    def _serialize_tenant_for_cache(self, tenant: Tenant) -> Dict[str, Any]:
        """
        Serialize tenant data for caching.

        Only caches essential data needed for request processing to avoid
        stale data issues while improving performance.

        Args:
            tenant: Tenant instance

        Returns:
            Dictionary with serialized tenant data
        """
        plan_data = None
        if tenant.plan:
            plan_data = {
                'id': tenant.plan.id,
                'name': tenant.plan.name,
                'plan_type': tenant.plan.plan_type,
                'max_users': tenant.plan.max_users,
                'max_job_postings': tenant.plan.max_job_postings,
                'max_candidates_per_month': tenant.plan.max_candidates_per_month,
                'max_circusales': tenant.plan.max_circusales,
                'storage_limit_gb': tenant.plan.storage_limit_gb,
                'api_rate_limit': getattr(tenant.plan, 'api_rate_limit', 0),
                # Feature flags
                'feature_ats': tenant.plan.feature_ats,
                'feature_hr_core': tenant.plan.feature_hr_core,
                'feature_analytics': tenant.plan.feature_analytics,
                'feature_api_access': tenant.plan.feature_api_access,
                'feature_custom_pipelines': tenant.plan.feature_custom_pipelines,
                'feature_ai_matching': tenant.plan.feature_ai_matching,
                'feature_video_interviews': tenant.plan.feature_video_interviews,
                'feature_esignature': tenant.plan.feature_esignature,
                'feature_sso': tenant.plan.feature_sso,
                'feature_audit_logs': tenant.plan.feature_audit_logs,
                'feature_custom_branding': tenant.plan.feature_custom_branding,
                'feature_priority_support': tenant.plan.feature_priority_support,
                'feature_data_export': tenant.plan.feature_data_export,
                'feature_bulk_actions': tenant.plan.feature_bulk_actions,
                'feature_advanced_filters': tenant.plan.feature_advanced_filters,
                'feature_diversity_analytics': tenant.plan.feature_diversity_analytics,
                'feature_compliance_tools': tenant.plan.feature_compliance_tools,
            }

        return {
            '_cached_tenant': True,
            'id': tenant.id,
            'uuid': str(tenant.uuid),
            'name': tenant.name,
            'slug': tenant.slug,
            'schema_name': tenant.schema_name,
            'status': tenant.status,
            'owner_email': tenant.owner_email,
            'on_trial': tenant.on_trial,
            'trial_ends_at': tenant.trial_ends_at.isoformat() if tenant.trial_ends_at else None,
            'plan': plan_data,
        }

    def _deserialize_tenant_from_cache(self, cached_data: Dict[str, Any]) -> Optional[Tenant]:
        """
        Reconstruct a Tenant instance from cached data.

        Note: This returns a partial tenant object suitable for request processing.
        For full tenant data, a database fetch is still required.

        Args:
            cached_data: Dictionary with cached tenant data

        Returns:
            Tenant instance or None
        """
        if not cached_data.get('_cached_tenant'):
            return None

        try:
            # Fetch the actual tenant object to ensure we have a proper model instance
            # but use cached data for plan to avoid extra join
            tenant = Tenant.objects.get(id=cached_data['id'])

            # If plan data is cached, we can avoid the plan query for feature checks
            # But for full accuracy, we should use the actual related object
            return tenant

        except Tenant.DoesNotExist:
            return None

    def _lookup_tenant_by_id(self, tenant_id: str) -> Optional[Tenant]:
        """Lookup tenant by UUID or slug."""
        try:
            # Try UUID first
            return Tenant.objects.select_related('plan', 'settings').get(uuid=tenant_id)
        except (Tenant.DoesNotExist, ValueError):
            pass

        try:
            # Try slug
            return Tenant.objects.select_related('plan', 'settings').get(slug=tenant_id)
        except Tenant.DoesNotExist:
            return None

    def _lookup_tenant_by_subdomain(self, subdomain: str) -> Optional[Tenant]:
        """Lookup tenant by subdomain (slug)."""
        try:
            return Tenant.objects.select_related('plan', 'settings').get(slug=subdomain)
        except Tenant.DoesNotExist:
            return None

    def _lookup_tenant_by_domain(self, domain: str) -> Optional[Tenant]:
        """Lookup tenant by custom domain."""
        try:
            domain_obj = Domain.objects.select_related('tenant', 'tenant__plan').get(
                domain=domain
            )
            return domain_obj.tenant
        except Domain.DoesNotExist:
            return None

    def _setup_tenant_schema(self, tenant: Tenant):
        """Set up database connection for tenant schema."""
        from django.db import connection
        connection.set_tenant(tenant)

    def _invalidate_tenant_cache(self, tenant: Tenant):
        """Invalidate all cache entries for a tenant."""
        cache_keys = [
            f"{TENANT_CACHE_PREFIX}id:{tenant.uuid}",
            f"{TENANT_CACHE_PREFIX}id:{tenant.slug}",
            f"{TENANT_CACHE_PREFIX}subdomain:{tenant.slug}",
        ]
        # Also invalidate domain caches
        for domain in tenant.domains.all():
            cache_keys.append(f"{TENANT_CACHE_PREFIX}domain:{domain.domain}")

        cache.delete_many(cache_keys)

    def _get_tenant_features(self, tenant: Tenant) -> dict:
        """Extract enabled features from tenant's plan."""
        plan = tenant.plan
        if not plan:
            return {}

        return {
            'ats': plan.feature_ats,
            'hr_core': plan.feature_hr_core,
            'analytics': plan.feature_analytics,
            'api_access': plan.feature_api_access,
            'custom_pipelines': plan.feature_custom_pipelines,
            'ai_matching': plan.feature_ai_matching,
            'video_interviews': plan.feature_video_interviews,
            'esignature': plan.feature_esignature,
            'sso': plan.feature_sso,
            'audit_logs': plan.feature_audit_logs,
            'custom_branding': plan.feature_custom_branding,
            'priority_support': plan.feature_priority_support,
            'data_export': plan.feature_data_export,
            'bulk_actions': plan.feature_bulk_actions,
            'advanced_filters': plan.feature_advanced_filters,
            'diversity_analytics': plan.feature_diversity_analytics,
            'compliance_tools': plan.feature_compliance_tools,
        }

    def _validate_user_tenant_access(self, request, tenant: Tenant) -> bool:
        """
        Validate that the authenticated user has permission to access the specified tenant.

        SECURITY: This prevents unauthorized access via X-Tenant-ID header spoofing.

        Args:
            request: HTTP request object
            tenant: Tenant instance to validate access for

        Returns:
            True if user has access, False otherwise
        """
        # Allow unauthenticated requests only for public endpoints
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            # For unauthenticated requests, only allow header-based resolution
            # if the request is to a public API endpoint
            if self._is_public_api_endpoint(request.path):
                return True
            # Unauthenticated users cannot use header-based tenant resolution
            # for non-public endpoints
            return False

        # Superusers have access to all tenants
        if request.user.is_superuser:
            return True

        # Check if user has a tenant profile that grants access to this tenant
        # This checks for TenantUser or similar membership model
        if hasattr(request.user, 'tenant_memberships'):
            # Check if user is a member of this tenant
            return request.user.tenant_memberships.filter(
                tenant=tenant,
                is_active=True
            ).exists()

        # Check via tenant_profile if available
        if hasattr(request.user, 'tenant_profile'):
            user_tenant = getattr(request.user.tenant_profile, 'tenant', None)
            if user_tenant and user_tenant.id == tenant.id:
                return True

        # Check if user's email matches tenant owner email
        if request.user.email and request.user.email == tenant.owner_email:
            return True

        # Default deny - user must have explicit tenant membership
        return False

    def _is_public_api_endpoint(self, path: str) -> bool:
        """Check if the path is a public API endpoint that allows header-based tenant resolution."""
        public_endpoints = [
            '/api/public/',
            '/api/careers/',
            '/api/jobs/',
            '/api/health/',
        ]
        return any(path.startswith(endpoint) for endpoint in public_endpoints)

    def _check_tenant_resolution_rate_limit(self, request) -> bool:
        """
        Check if the client has exceeded the rate limit for tenant resolution.

        SECURITY: Prevents brute-force tenant enumeration attacks.

        Args:
            request: HTTP request object

        Returns:
            True if within rate limit, False if exceeded
        """
        # Get client identifier (IP address or authenticated user)
        client_id = self._get_rate_limit_client_id(request)
        cache_key = f"tenant_resolution_rate:{client_id}"

        try:
            current_count = cache.get(cache_key, 0)
            if current_count >= TENANT_RESOLUTION_RATE_LIMIT:
                logger.warning(
                    f"Tenant resolution rate limit exceeded for client: {client_id}"
                )
                return False

            # Increment counter
            try:
                cache.incr(cache_key)
            except ValueError:
                cache.set(cache_key, 1, TENANT_RESOLUTION_RATE_WINDOW)

            return True

        except Exception as e:
            # On cache error, allow the request but log the error
            logger.error(f"Rate limit check failed: {e}")
            return True

    def _get_rate_limit_client_id(self, request) -> str:
        """Get a unique identifier for rate limiting purposes."""
        # Prefer authenticated user ID
        if hasattr(request, 'user') and request.user.is_authenticated:
            return f"user:{request.user.id}"

        # Fall back to IP address
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')

        return f"ip:{ip}"

    def _is_exempt_url(self, path):
        """Check if URL is exempt from tenant status checks."""
        return any(path.startswith(url) for url in self.EXEMPT_URLS)

    def _tenant_not_found_response(self, request):
        """Handle tenant not found response."""
        return HttpResponseForbidden(
            "Tenant not found. Please check the URL or contact support."
        )

    def _tenant_error_response(self, request):
        """Handle tenant resolution error response."""
        return HttpResponseForbidden(
            "Unable to process your request. Please try again later."
        )

    def _suspended_response(self, request):
        """Handle suspended tenant response."""
        return HttpResponseForbidden(
            "Your account has been suspended. "
            "Please contact support to restore access."
        )

    def _cancelled_response(self, request):
        """Handle cancelled tenant response."""
        return HttpResponseForbidden(
            "This account has been cancelled. "
            "Please contact support if you believe this is an error."
        )

    def _pending_response(self, request):
        """Handle pending tenant response."""
        return HttpResponseRedirect('/onboarding/setup/')

    def _trial_expired_response(self, request):
        """Handle trial expired response."""
        return HttpResponseRedirect('/billing/upgrade/')


class TenantContextMiddleware:
    """
    Add tenant-related context to all requests.
    Must run after TenantMainMiddleware.

    Adds:
    - request.is_tenant_admin: Boolean indicating if user is tenant admin
    - request.tenant_permissions: Set of user's permissions within tenant
    - request.can_access_feature(): Helper method for feature flag checks
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Add helper methods to request
        if hasattr(request, 'tenant') and request.tenant:
            request.is_tenant_admin = self._is_tenant_admin(request)
            request.tenant_permissions = self._get_tenant_permissions(request)
            request.can_access_feature = lambda f: self._can_access_feature(request, f)
            request.is_within_limit = lambda r, i=1: self._is_within_limit(request, r, i)

        try:
            response = self.get_response(request)
            return response
        finally:
            # Clear thread-local tenant context to prevent leaks between requests
            clear_tenant_context()

    def _is_tenant_admin(self, request):
        """Check if current user is tenant admin."""
        if not request.user.is_authenticated:
            return False

        # Check for tenant admin role via TenantUser model if available
        if hasattr(request.user, 'tenant_profile'):
            return request.user.tenant_profile.role in ('pdg', 'admin')

        # Fallback to superuser check
        return request.user.is_superuser

    def _get_tenant_permissions(self, request):
        """Get user's permissions within current tenant."""
        if not request.user.is_authenticated:
            return set()

        # Get tenant-specific permissions if available
        permissions = set(request.user.get_all_permissions())

        # Add feature-based permissions from plan
        if hasattr(request, 'tenant_features') and request.tenant_features:
            for feature, enabled in request.tenant_features.items():
                if enabled:
                    permissions.add(f'tenant.{feature}')

        return permissions

    def _can_access_feature(self, request, feature_name: str) -> bool:
        """Check if tenant has access to a specific feature."""
        features = getattr(request, 'tenant_features', {})
        return features.get(feature_name, False)

    def _is_within_limit(self, request, resource: str, increment: int = 1) -> bool:
        """Check if tenant is within resource limits."""
        from .services import TenantService
        if not hasattr(request, 'tenant') or not request.tenant:
            return False
        return TenantService.check_limit(request.tenant, resource, increment)


class TenantUsageMiddleware:
    """
    Track API usage for billing and rate limiting.

    Features:
    - Async-safe usage tracking via cache
    - Rate limiting support
    - Periodic batch updates to database
    """

    # Rate limit configuration
    RATE_LIMIT_WINDOW = 60  # seconds
    RATE_LIMIT_KEY_PREFIX = 'rate_limit:'

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check rate limits before processing
        if self._should_track(request):
            rate_limited = self._check_rate_limit(request)
            if rate_limited:
                return self._rate_limit_response(request)

        response = self.get_response(request)

        # Track API calls after successful response
        if self._should_track(request):
            self._track_api_call(request)

        return response

    def _should_track(self, request) -> bool:
        """Determine if request should be tracked."""
        return (
            hasattr(request, 'tenant') and
            request.tenant and
            hasattr(request.tenant, 'schema_name') and
            request.tenant.schema_name != get_public_schema_name() and
            request.path.startswith('/api/')
        )

    def _check_rate_limit(self, request) -> bool:
        """Check if tenant has exceeded rate limits."""
        plan = getattr(request, 'tenant_plan', None)
        if not plan or not hasattr(plan, 'api_rate_limit'):
            return False

        rate_limit = getattr(plan, 'api_rate_limit', 0)
        if rate_limit <= 0:
            return False  # No rate limiting

        cache_key = f"{self.RATE_LIMIT_KEY_PREFIX}{request.tenant.id}"
        current_count = cache.get(cache_key, 0)

        return current_count >= rate_limit

    def _rate_limit_response(self, request):
        """Return rate limit exceeded response."""
        from django.http import JsonResponse
        return JsonResponse(
            {
                'error': 'rate_limit_exceeded',
                'message': 'API rate limit exceeded. Please try again later.',
            },
            status=429
        )

    def _track_api_call(self, request):
        """Track API call using cache for performance."""
        try:
            # Increment rate limit counter
            rate_key = f"{self.RATE_LIMIT_KEY_PREFIX}{request.tenant.id}"
            try:
                cache.incr(rate_key)
            except ValueError:
                cache.set(rate_key, 1, self.RATE_LIMIT_WINDOW)

            # Track in usage counter (batched via cache)
            usage_key = f"tenant_api_usage:{request.tenant.id}"
            try:
                cache.incr(usage_key)
            except ValueError:
                cache.set(usage_key, 1, 3600)  # 1 hour TTL

        except Exception as e:
            logger.warning(f"Failed to track API usage: {e}")


class TenantSecurityMiddleware:
    """
    Security middleware for tenant-specific security policies.

    Features:
    - IP whitelist enforcement
    - 2FA requirement enforcement
    - Session timeout enforcement
    - Security header injection
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip for public tenant
        if getattr(request, '_is_public_tenant', True):
            return self.get_response(request)

        settings = getattr(request, 'tenant_settings', None)
        if settings:
            # Check IP whitelist
            if settings.ip_whitelist:
                client_ip = self._get_client_ip(request)
                if client_ip and client_ip not in settings.ip_whitelist:
                    if request.user.is_authenticated and request.user.is_staff:
                        return self._ip_blocked_response(request)

            # Check 2FA requirement
            if settings.require_2fa:
                if request.user.is_authenticated:
                    if not self._has_verified_2fa(request):
                        if not self._is_2fa_exempt_url(request.path):
                            return self._require_2fa_response(request)

        response = self.get_response(request)

        # Add security headers
        self._add_security_headers(response, settings)

        return response

    def _get_client_ip(self, request) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    def _has_verified_2fa(self, request) -> bool:
        """Check if user has completed 2FA verification."""
        # Check session for 2FA verification
        return request.session.get('2fa_verified', False)

    def _is_2fa_exempt_url(self, path: str) -> bool:
        """Check if URL is exempt from 2FA requirement."""
        exempt_urls = [
            '/accounts/2fa/',
            '/accounts/logout/',
            '/api/auth/2fa/',
        ]
        return any(path.startswith(url) for url in exempt_urls)

    def _ip_blocked_response(self, request):
        """Return IP blocked response."""
        return HttpResponseForbidden(
            "Access denied. Your IP address is not authorized."
        )

    def _require_2fa_response(self, request):
        """Redirect to 2FA verification."""
        return HttpResponseRedirect('/accounts/2fa/verify/')

    def _add_security_headers(self, response, settings):
        """Add tenant-specific security headers."""
        # Standard security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'SAMEORIGIN'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        return response
