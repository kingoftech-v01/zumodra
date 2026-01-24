"""
API Throttling - Tenant-Aware Rate Limiting for Zumodra API

This module provides throttling classes that respect tenant plans and usage:
- TenantAwareThrottle: Base throttle with tenant context
- PlanBasedThrottle: Different rates per subscription tier
- UserRoleThrottle: Different rates per user role
- IPBasedThrottle: IP-based rate limiting with burst protection
- EndpointThrottle: Per-endpoint rate limiting
- BurstThrottle: Short burst protection

Rate limits are configurable via settings and respect tenant plan limits.
"""

import hashlib
import logging
from typing import Optional, Dict, Any

from django.core.cache import cache
from django.conf import settings
from django.utils import timezone

from rest_framework.throttling import (
    BaseThrottle,
    SimpleRateThrottle,
    UserRateThrottle,
    AnonRateThrottle,
    ScopedRateThrottle
)
from rest_framework.request import Request

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

# Default rate limits per plan type (requests/period)
DEFAULT_PLAN_RATES = {
    'free': {
        'sustained': '100/hour',      # Sustained rate limit
        'burst': '10/minute',         # Burst protection
        'daily': '500/day',           # Daily limit
    },
    'starter': {
        'sustained': '500/hour',
        'burst': '30/minute',
        'daily': '5000/day',
    },
    'professional': {
        'sustained': '2000/hour',
        'burst': '100/minute',
        'daily': '20000/day',
    },
    'enterprise': {
        'sustained': '10000/hour',
        'burst': '500/minute',
        'daily': '100000/day',
    },
}

# Rate limits per user role
USER_ROLE_RATES = {
    'owner': '5000/hour',
    'admin': '3000/hour',
    'supervisor': '2000/hour',
    'hr': '2000/hour',
    'marketer': '2000/hour',
    'employee': '1000/hour',
    'member': '500/hour',
}

# Anonymous user rates
ANON_RATES = {
    'sustained': '30/hour',
    'burst': '5/minute',
}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def parse_rate(rate_string: str) -> tuple:
    """
    Parse rate string like '100/hour' into (num_requests, duration_seconds).
    """
    if not rate_string:
        return (0, 1)

    num, period = rate_string.split('/')
    num_requests = int(num)

    duration_map = {
        'second': 1,
        'sec': 1,
        's': 1,
        'minute': 60,
        'min': 60,
        'm': 60,
        'hour': 3600,
        'hr': 3600,
        'h': 3600,
        'day': 86400,
        'd': 86400,
    }

    duration = duration_map.get(period.lower(), 3600)
    return (num_requests, duration)


def get_tenant_from_request(request: Request) -> Optional[Any]:
    """Extract tenant from request."""
    return getattr(request, 'tenant', None)


def get_user_role(request: Request) -> str:
    """Get user's role in the current tenant."""
    if not request.user.is_authenticated:
        return 'anonymous'

    tenant = get_tenant_from_request(request)
    if not tenant:
        return 'member'

    # Try to get TenantUser role
    try:
        from tenant_profiles.models import TenantUser
        tenant_user = TenantUser.objects.get(
            user=request.user,
            tenant=tenant,
            is_active=True
        )
        return tenant_user.role
    except Exception:
        return 'member'


# =============================================================================
# BASE TENANT-AWARE THROTTLE
# =============================================================================

class TenantAwareThrottle(SimpleRateThrottle):
    """
    Base throttle class that incorporates tenant context.

    Provides:
    - Tenant-scoped rate limiting
    - Plan-aware rate adjustments
    - Usage tracking for billing
    - Cache key generation with tenant isolation
    - X-RateLimit-* headers in responses
    """

    scope = 'tenant'
    cache_format = 'throttle_%(scope)s_%(tenant)s_%(ident)s'

    def get_cache_key(self, request: Request, view) -> Optional[str]:
        """
        Generate cache key including tenant context.
        """
        if not request.user.is_authenticated:
            ident = self.get_ident(request)
        else:
            ident = str(request.user.pk)

        tenant = get_tenant_from_request(request)
        tenant_key = tenant.slug if tenant else 'public'

        return self.cache_format % {
            'scope': self.scope,
            'tenant': tenant_key,
            'ident': ident,
        }

    def get_rate(self) -> str:
        """Get rate from settings or default."""
        return getattr(settings, f'API_THROTTLE_RATE_{self.scope.upper()}', '1000/hour')

    def allow_request(self, request: Request, view) -> bool:
        """Check if request should be allowed."""
        if self.rate is None:
            return True

        self.key = self.get_cache_key(request, view)
        if self.key is None:
            return True

        self.history = self.cache.get(self.key, [])
        self.now = self.timer()

        # Drop old entries
        while self.history and self.history[-1] <= self.now - self.duration:
            self.history.pop()

        if len(self.history) >= self.num_requests:
            # Track rate limit hit for analytics
            self._track_rate_limit_hit(request)
            return self.throttle_failure()

        return self.throttle_success()

    def _track_rate_limit_hit(self, request: Request):
        """Track rate limit hits for analytics."""
        tenant = get_tenant_from_request(request)
        if tenant:
            try:
                # Increment rate limit counter
                cache_key = f'rate_limit_hits:{tenant.pk}:{timezone.now().date()}'
                cache.incr(cache_key)
            except ValueError:
                cache.set(cache_key, 1, timeout=86400 * 7)  # Keep for 7 days

    def get_rate_limit_headers(self) -> Dict[str, str]:
        """
        Generate X-RateLimit-* headers for the response.

        Returns headers:
        - X-RateLimit-Limit: Maximum requests allowed in the window
        - X-RateLimit-Remaining: Requests remaining in the current window
        - X-RateLimit-Reset: Unix timestamp when the window resets
        """
        if not hasattr(self, 'num_requests') or not hasattr(self, 'history'):
            return {}

        remaining = max(0, self.num_requests - len(self.history))
        reset_time = int(self.now + self.duration) if hasattr(self, 'now') else 0

        return {
            'X-RateLimit-Limit': str(self.num_requests),
            'X-RateLimit-Remaining': str(remaining),
            'X-RateLimit-Reset': str(reset_time),
        }


# =============================================================================
# PLAN-BASED THROTTLING
# =============================================================================

class PlanBasedThrottle(TenantAwareThrottle):
    """
    Throttle based on tenant's subscription plan.

    Different plans get different rate limits:
    - Free: 100/hour
    - Starter: 500/hour
    - Professional: 2000/hour
    - Enterprise: 10000/hour

    Enterprise plans can also have custom rate limits.
    """

    scope = 'plan'
    cache_format = 'throttle_plan_%(tenant)s_%(ident)s'

    def get_rate(self) -> str:
        """Get rate based on tenant's plan."""
        request = getattr(self, '_request', None)
        if not request:
            return DEFAULT_PLAN_RATES['free']['sustained']

        tenant = get_tenant_from_request(request)
        if not tenant or not tenant.plan:
            return DEFAULT_PLAN_RATES['free']['sustained']

        plan_type = tenant.plan.plan_type

        # Check for custom rate limit in plan settings
        plan_rates = getattr(settings, 'PLAN_RATE_LIMITS', DEFAULT_PLAN_RATES)
        rates = plan_rates.get(plan_type, plan_rates.get('free', {}))

        return rates.get('sustained', '100/hour')

    def allow_request(self, request: Request, view) -> bool:
        """Store request for rate lookup and check."""
        self._request = request
        self.rate = self.get_rate()
        self.num_requests, self.duration = parse_rate(self.rate)
        return super().allow_request(request, view)


class PlanBurstThrottle(TenantAwareThrottle):
    """
    Burst protection throttle based on tenant's plan.
    Prevents short-term API abuse while allowing sustained usage.
    """

    scope = 'plan_burst'
    cache_format = 'throttle_burst_%(tenant)s_%(ident)s'

    def get_rate(self) -> str:
        """Get burst rate based on tenant's plan."""
        request = getattr(self, '_request', None)
        if not request:
            return DEFAULT_PLAN_RATES['free']['burst']

        tenant = get_tenant_from_request(request)
        if not tenant or not tenant.plan:
            return DEFAULT_PLAN_RATES['free']['burst']

        plan_type = tenant.plan.plan_type
        plan_rates = getattr(settings, 'PLAN_RATE_LIMITS', DEFAULT_PLAN_RATES)
        rates = plan_rates.get(plan_type, plan_rates.get('free', {}))

        return rates.get('burst', '10/minute')

    def allow_request(self, request: Request, view) -> bool:
        """Store request for rate lookup and check."""
        self._request = request
        self.rate = self.get_rate()
        self.num_requests, self.duration = parse_rate(self.rate)
        return super().allow_request(request, view)


class PlanDailyThrottle(TenantAwareThrottle):
    """
    Daily limit throttle based on tenant's plan.
    Ensures tenants don't exceed their daily API quota.
    """

    scope = 'plan_daily'
    cache_format = 'throttle_daily_%(tenant)s_%(date)s_%(ident)s'

    def get_cache_key(self, request: Request, view) -> Optional[str]:
        """Include date in cache key for daily reset."""
        if not request.user.is_authenticated:
            ident = self.get_ident(request)
        else:
            ident = str(request.user.pk)

        tenant = get_tenant_from_request(request)
        tenant_key = tenant.slug if tenant else 'public'

        return self.cache_format % {
            'scope': self.scope,
            'tenant': tenant_key,
            'date': timezone.now().date().isoformat(),
            'ident': ident,
        }

    def get_rate(self) -> str:
        """Get daily rate based on tenant's plan."""
        request = getattr(self, '_request', None)
        if not request:
            return DEFAULT_PLAN_RATES['free']['daily']

        tenant = get_tenant_from_request(request)
        if not tenant or not tenant.plan:
            return DEFAULT_PLAN_RATES['free']['daily']

        plan_type = tenant.plan.plan_type
        plan_rates = getattr(settings, 'PLAN_RATE_LIMITS', DEFAULT_PLAN_RATES)
        rates = plan_rates.get(plan_type, plan_rates.get('free', {}))

        return rates.get('daily', '500/day')

    def allow_request(self, request: Request, view) -> bool:
        """Store request for rate lookup and check."""
        self._request = request
        self.rate = self.get_rate()
        self.num_requests, self.duration = parse_rate(self.rate)
        return super().allow_request(request, view)


# =============================================================================
# USER ROLE THROTTLING
# =============================================================================

class UserRoleThrottle(TenantAwareThrottle):
    """
    Throttle based on user's role within the tenant.

    Different roles get different limits:
    - Owner: 5000/hour
    - Admin: 3000/hour
    - Supervisor/HR/Marketer: 2000/hour
    - Employee: 1000/hour
    - Member: 500/hour
    """

    scope = 'user_role'
    cache_format = 'throttle_role_%(tenant)s_%(role)s_%(ident)s'

    def get_cache_key(self, request: Request, view) -> Optional[str]:
        """Include user role in cache key."""
        if not request.user.is_authenticated:
            return None

        ident = str(request.user.pk)
        tenant = get_tenant_from_request(request)
        tenant_key = tenant.slug if tenant else 'public'
        role = get_user_role(request)

        return self.cache_format % {
            'scope': self.scope,
            'tenant': tenant_key,
            'role': role,
            'ident': ident,
        }

    def get_rate(self) -> str:
        """Get rate based on user's role."""
        request = getattr(self, '_request', None)
        if not request:
            return USER_ROLE_RATES.get('member', '500/hour')

        role = get_user_role(request)
        role_rates = getattr(settings, 'USER_ROLE_RATE_LIMITS', USER_ROLE_RATES)

        return role_rates.get(role, role_rates.get('member', '500/hour'))

    def allow_request(self, request: Request, view) -> bool:
        """Store request for rate lookup and check."""
        self._request = request
        self.rate = self.get_rate()
        self.num_requests, self.duration = parse_rate(self.rate)
        return super().allow_request(request, view)


# =============================================================================
# IP-BASED THROTTLING
# =============================================================================

class IPBasedThrottle(SimpleRateThrottle):
    """
    IP-based throttle for protecting against abuse from specific IPs.
    Works for both authenticated and anonymous users.
    """

    scope = 'ip'
    rate = '1000/hour'
    cache_format = 'throttle_ip_%(ip_hash)s'

    def get_cache_key(self, request: Request, view) -> str:
        """Generate cache key based on hashed IP."""
        ip = self.get_ident(request)
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]

        return self.cache_format % {'ip_hash': ip_hash}


class IPBurstThrottle(SimpleRateThrottle):
    """
    Short-term burst protection per IP.
    Prevents rapid-fire requests from a single IP.
    """

    scope = 'ip_burst'
    rate = '30/minute'
    cache_format = 'throttle_ip_burst_%(ip_hash)s'

    def get_cache_key(self, request: Request, view) -> str:
        """Generate cache key based on hashed IP."""
        ip = self.get_ident(request)
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]

        return self.cache_format % {'ip_hash': ip_hash}


class SuspiciousIPThrottle(SimpleRateThrottle):
    """
    Extra restrictive throttle for flagged suspicious IPs.
    IPs can be flagged based on failed login attempts, abuse patterns, etc.
    """

    scope = 'suspicious_ip'
    rate = '10/hour'
    cache_format = 'throttle_suspicious_%(ip_hash)s'

    def allow_request(self, request: Request, view) -> bool:
        """Only apply to suspicious IPs."""
        ip = self.get_ident(request)

        # Check if IP is flagged
        if not self._is_suspicious(ip):
            return True

        return super().allow_request(request, view)

    def _is_suspicious(self, ip: str) -> bool:
        """Check if IP is flagged as suspicious."""
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        suspicious_key = f'suspicious_ip:{ip_hash}'
        return cache.get(suspicious_key, False)

    def get_cache_key(self, request: Request, view) -> str:
        ip = self.get_ident(request)
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        return self.cache_format % {'ip_hash': ip_hash}

    @staticmethod
    def flag_ip(ip: str, duration: int = 3600):
        """Flag an IP as suspicious for the given duration."""
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        suspicious_key = f'suspicious_ip:{ip_hash}'
        cache.set(suspicious_key, True, timeout=duration)

    @staticmethod
    def unflag_ip(ip: str):
        """Remove suspicious flag from an IP."""
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        suspicious_key = f'suspicious_ip:{ip_hash}'
        cache.delete(suspicious_key)


# =============================================================================
# ANONYMOUS USER THROTTLING
# =============================================================================

class TenantAwareAnonThrottle(AnonRateThrottle):
    """
    Throttle for anonymous users with tenant context.
    Used for public endpoints like career pages.
    """

    scope = 'anon'
    rate = ANON_RATES['sustained']
    cache_format = 'throttle_anon_%(tenant)s_%(ident)s'

    def get_cache_key(self, request: Request, view) -> Optional[str]:
        if request.user.is_authenticated:
            return None  # Authenticated users use different throttle

        ident = self.get_ident(request)
        tenant = get_tenant_from_request(request)
        tenant_key = tenant.slug if tenant else 'public'

        return self.cache_format % {
            'tenant': tenant_key,
            'ident': ident,
        }


class TenantAwareAnonBurstThrottle(TenantAwareAnonThrottle):
    """Burst protection for anonymous users."""

    scope = 'anon_burst'
    rate = ANON_RATES['burst']
    cache_format = 'throttle_anon_burst_%(tenant)s_%(ident)s'


# =============================================================================
# ENDPOINT-SPECIFIC THROTTLING
# =============================================================================

class EndpointThrottle(ScopedRateThrottle):
    """
    Per-endpoint throttle using view's throttle_scope.

    Usage in view:
        class ExpensiveOperationView(TenantAwareAPIView):
            throttle_classes = [EndpointThrottle]
            throttle_scope = 'expensive_operation'

    Settings:
        REST_FRAMEWORK = {
            'DEFAULT_THROTTLE_RATES': {
                'expensive_operation': '10/hour',
            }
        }
    """

    def get_cache_key(self, request: Request, view) -> Optional[str]:
        """Include tenant in endpoint throttle key."""
        if not request.user.is_authenticated:
            ident = self.get_ident(request)
        else:
            ident = str(request.user.pk)

        tenant = get_tenant_from_request(request)
        tenant_key = tenant.slug if tenant else 'public'

        return f'throttle_{self.scope}_{tenant_key}_{ident}'


class WriteOperationThrottle(TenantAwareThrottle):
    """
    Special throttle for write operations (POST, PUT, PATCH, DELETE).
    More restrictive than read operations.
    """

    scope = 'write'
    rate = '100/hour'
    cache_format = 'throttle_write_%(tenant)s_%(ident)s'

    def allow_request(self, request: Request, view) -> bool:
        """Only apply to write methods."""
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True

        return super().allow_request(request, view)


class BulkOperationThrottle(TenantAwareThrottle):
    """
    Very restrictive throttle for bulk operations.
    Protects against resource-intensive bulk imports/exports.
    """

    scope = 'bulk'
    cache_format = 'throttle_bulk_%(tenant)s_%(ident)s'

    def get_rate(self) -> str:
        """Get rate based on tenant's plan for bulk operations."""
        request = getattr(self, '_request', None)
        if not request:
            return '5/hour'

        tenant = get_tenant_from_request(request)
        if not tenant or not tenant.plan:
            return '5/hour'

        # Enterprise gets more bulk operations
        plan_type = tenant.plan.plan_type
        bulk_rates = {
            'free': '5/hour',
            'starter': '20/hour',
            'professional': '50/hour',
            'enterprise': '200/hour',
        }

        return bulk_rates.get(plan_type, '5/hour')

    def allow_request(self, request: Request, view) -> bool:
        self._request = request
        self.rate = self.get_rate()
        self.num_requests, self.duration = parse_rate(self.rate)
        return super().allow_request(request, view)


# =============================================================================
# THROTTLE SETS (Common combinations)
# =============================================================================

# Standard API throttles
StandardAPIThrottles = [
    PlanBasedThrottle,
    PlanBurstThrottle,
    IPBurstThrottle,
]

# Throttles for authenticated endpoints
AuthenticatedThrottles = [
    PlanBasedThrottle,
    UserRoleThrottle,
    PlanBurstThrottle,
]

# Throttles for public endpoints
PublicThrottles = [
    TenantAwareAnonThrottle,
    TenantAwareAnonBurstThrottle,
    IPBurstThrottle,
]

# Throttles for sensitive operations (login, password reset, etc.)
SensitiveOperationThrottles = [
    WriteOperationThrottle,
    IPBurstThrottle,
    SuspiciousIPThrottle,
]

# Throttles for bulk operations
BulkOperationThrottles = [
    BulkOperationThrottle,
    PlanDailyThrottle,
]


# =============================================================================
# RATE LIMIT HEADER UTILITIES
# =============================================================================

def collect_rate_limit_headers(throttles: list) -> Dict[str, str]:
    """
    Collect X-RateLimit-* headers from all throttles.

    Uses the most restrictive (lowest remaining) throttle's values.

    Args:
        throttles: List of throttle instances after allow_request() was called

    Returns:
        Dict with X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset headers
    """
    headers = {}
    min_remaining = float('inf')

    for throttle in throttles:
        if hasattr(throttle, 'get_rate_limit_headers'):
            throttle_headers = throttle.get_rate_limit_headers()
            if throttle_headers:
                remaining = int(throttle_headers.get('X-RateLimit-Remaining', float('inf')))
                if remaining < min_remaining:
                    min_remaining = remaining
                    headers = throttle_headers

    return headers
