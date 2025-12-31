"""
Rate Limiting Algorithms for Zumodra

Comprehensive rate limiting implementations for the multi-tenant ATS/HR SaaS platform:
- TokenBucketRateLimiter: Token bucket algorithm with burst tolerance
- SlidingWindowRateLimiter: Sliding window for accurate rate counting
- RateLimitConfig: Per-endpoint rate limit configuration
- Rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)

All rate limiters are tenant-aware for multi-tenant isolation.
"""

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse

logger = logging.getLogger('security.rate_limiting')


# =============================================================================
# RATE LIMIT CONFIGURATION
# =============================================================================

class RateLimitScope(str, Enum):
    """Scope for rate limiting."""
    GLOBAL = 'global'        # Global limit across all users
    USER = 'user'            # Per-user limit
    IP = 'ip'                # Per-IP limit
    TENANT = 'tenant'        # Per-tenant limit
    ENDPOINT = 'endpoint'    # Per-endpoint limit
    COMBINED = 'combined'    # Combined user + endpoint


@dataclass
class RateLimitConfig:
    """
    Configuration for a rate limit rule.

    Attributes:
        name: Unique name for the rule
        limit: Maximum number of requests
        period: Time period in seconds
        scope: Rate limit scope (user, IP, tenant, etc.)
        burst_limit: Maximum burst size (for token bucket)
        block_duration: How long to block after limit exceeded
        paths: List of path patterns this rule applies to
        methods: HTTP methods this rule applies to
        exclude_paths: Paths to exclude from this rule
        exclude_users: User groups to exclude (staff, superuser)
    """
    name: str
    limit: int
    period: int
    scope: RateLimitScope = RateLimitScope.IP
    burst_limit: Optional[int] = None
    block_duration: int = 0
    paths: List[str] = field(default_factory=lambda: ['.*'])
    methods: List[str] = field(default_factory=lambda: ['*'])
    exclude_paths: List[str] = field(default_factory=list)
    exclude_users: List[str] = field(default_factory=list)

    def __post_init__(self):
        # Compile path patterns
        self._path_patterns = [re.compile(p) for p in self.paths]
        self._exclude_patterns = [re.compile(p) for p in self.exclude_paths]

        # Set default burst limit
        if self.burst_limit is None:
            self.burst_limit = self.limit // 2

    def matches_request(self, request: HttpRequest) -> bool:
        """Check if this rule applies to the request."""
        # Check method
        if '*' not in self.methods and request.method not in self.methods:
            return False

        # Check excluded paths
        for pattern in self._exclude_patterns:
            if pattern.match(request.path):
                return False

        # Check included paths
        for pattern in self._path_patterns:
            if pattern.match(request.path):
                return True

        return False

    @classmethod
    def from_string(cls, rate_str: str, **kwargs) -> 'RateLimitConfig':
        """
        Create RateLimitConfig from a rate string.

        Args:
            rate_str: Rate string like '100/minute' or '1000/hour'
            **kwargs: Additional configuration options

        Returns:
            RateLimitConfig instance
        """
        pattern = re.compile(r'^(\d+)/(\w+)$')
        match = pattern.match(rate_str)

        if not match:
            raise ValueError(f"Invalid rate limit format: {rate_str}")

        limit = int(match.group(1))
        unit = match.group(2).lower()

        time_units = {
            'second': 1, 'seconds': 1, 's': 1,
            'minute': 60, 'minutes': 60, 'm': 60, 'min': 60,
            'hour': 3600, 'hours': 3600, 'h': 3600,
            'day': 86400, 'days': 86400, 'd': 86400,
        }

        period = time_units.get(unit)
        if period is None:
            raise ValueError(f"Unknown time unit: {unit}")

        return cls(
            name=kwargs.pop('name', f'rate_{limit}_{unit}'),
            limit=limit,
            period=period,
            **kwargs
        )


@dataclass
class RateLimitResult:
    """
    Result of a rate limit check.

    Attributes:
        allowed: Whether the request is allowed
        limit: The rate limit
        remaining: Remaining requests in the period
        reset: Unix timestamp when the limit resets
        retry_after: Seconds until the request can be retried (if blocked)
    """
    allowed: bool
    limit: int
    remaining: int
    reset: int
    retry_after: int = 0

    def as_headers(self) -> Dict[str, str]:
        """Return rate limit headers."""
        return {
            'X-RateLimit-Limit': str(self.limit),
            'X-RateLimit-Remaining': str(max(0, self.remaining)),
            'X-RateLimit-Reset': str(self.reset),
        }


# =============================================================================
# TOKEN BUCKET RATE LIMITER
# =============================================================================

class TokenBucketRateLimiter:
    """
    Rate limiter using the Token Bucket algorithm.

    The token bucket algorithm allows for burst tolerance while
    maintaining a long-term rate limit. Tokens are added to the
    bucket at a fixed rate, and each request consumes one token.

    Features:
    - Burst tolerance for traffic spikes
    - Smooth rate limiting over time
    - Redis-backed for distributed systems
    - Tenant-aware for multi-tenant isolation

    Usage:
        limiter = TokenBucketRateLimiter(
            rate=100,      # 100 tokens per period
            period=60,     # 60 seconds
            burst=20       # Allow burst of 20
        )

        result = limiter.check('user:123')
        if not result.allowed:
            return 429 response
    """

    CACHE_PREFIX = 'rate:bucket:'

    def __init__(
        self,
        rate: int,
        period: int,
        burst: int = None,
        tenant_id: str = None
    ):
        """
        Initialize the token bucket rate limiter.

        Args:
            rate: Number of tokens to add per period
            period: Time period in seconds
            burst: Maximum bucket size (burst tolerance)
            tenant_id: Optional tenant ID for isolation
        """
        self.rate = rate
        self.period = period
        self.burst = burst or rate
        self.tenant_id = tenant_id

        # Calculate tokens per second
        self.tokens_per_second = rate / period

    def _get_cache_key(self, identifier: str) -> str:
        """Generate cache key for the identifier."""
        if self.tenant_id:
            return f"{self.CACHE_PREFIX}{self.tenant_id}:{identifier}"
        return f"{self.CACHE_PREFIX}{identifier}"

    def check(self, identifier: str, cost: int = 1) -> RateLimitResult:
        """
        Check if a request is allowed.

        Args:
            identifier: Unique identifier (user ID, IP, etc.)
            cost: Number of tokens this request costs

        Returns:
            RateLimitResult indicating if request is allowed
        """
        now = time.time()
        key = self._get_cache_key(identifier)

        # Get current bucket state
        bucket = cache.get(key)

        if bucket is None:
            # Initialize new bucket
            bucket = {
                'tokens': self.burst,
                'last_update': now
            }
        else:
            # Add tokens based on time elapsed
            elapsed = now - bucket['last_update']
            tokens_to_add = elapsed * self.tokens_per_second
            bucket['tokens'] = min(
                self.burst,
                bucket['tokens'] + tokens_to_add
            )
            bucket['last_update'] = now

        # Check if we have enough tokens
        if bucket['tokens'] >= cost:
            bucket['tokens'] -= cost
            allowed = True
            remaining = int(bucket['tokens'])
        else:
            allowed = False
            remaining = 0

        # Save bucket state
        cache.set(key, bucket, timeout=self.period * 2)

        # Calculate reset time
        if remaining <= 0:
            # Time until one token is available
            tokens_needed = cost - bucket['tokens']
            retry_after = int(tokens_needed / self.tokens_per_second)
            reset_time = int(now + retry_after)
        else:
            reset_time = int(now + self.period)
            retry_after = 0

        return RateLimitResult(
            allowed=allowed,
            limit=self.rate,
            remaining=remaining,
            reset=reset_time,
            retry_after=retry_after
        )

    def reset(self, identifier: str):
        """Reset the bucket for an identifier."""
        key = self._get_cache_key(identifier)
        cache.delete(key)

    def get_status(self, identifier: str) -> RateLimitResult:
        """
        Get current rate limit status without consuming tokens.

        Args:
            identifier: Unique identifier

        Returns:
            RateLimitResult with current status
        """
        now = time.time()
        key = self._get_cache_key(identifier)

        bucket = cache.get(key)

        if bucket is None:
            return RateLimitResult(
                allowed=True,
                limit=self.rate,
                remaining=self.burst,
                reset=int(now + self.period)
            )

        # Calculate current tokens
        elapsed = now - bucket['last_update']
        tokens_to_add = elapsed * self.tokens_per_second
        current_tokens = min(
            self.burst,
            bucket['tokens'] + tokens_to_add
        )

        return RateLimitResult(
            allowed=current_tokens >= 1,
            limit=self.rate,
            remaining=int(current_tokens),
            reset=int(now + self.period)
        )


# =============================================================================
# SLIDING WINDOW RATE LIMITER
# =============================================================================

class SlidingWindowRateLimiter:
    """
    Rate limiter using the Sliding Window algorithm.

    The sliding window algorithm provides accurate rate limiting
    by tracking request counts across overlapping time windows.
    This avoids the "boundary problem" of fixed windows.

    Features:
    - Accurate rate counting
    - No boundary spikes
    - Redis-backed for distributed systems
    - Tenant-aware for multi-tenant isolation

    Usage:
        limiter = SlidingWindowRateLimiter(
            limit=100,     # 100 requests
            period=60      # per 60 seconds
        )

        result = limiter.check('user:123')
        if not result.allowed:
            return 429 response
    """

    CACHE_PREFIX = 'rate:window:'

    def __init__(
        self,
        limit: int,
        period: int,
        tenant_id: str = None
    ):
        """
        Initialize the sliding window rate limiter.

        Args:
            limit: Maximum requests per period
            period: Time period in seconds
            tenant_id: Optional tenant ID for isolation
        """
        self.limit = limit
        self.period = period
        self.tenant_id = tenant_id

    def _get_cache_key(self, identifier: str, window: int) -> str:
        """Generate cache key for a specific window."""
        if self.tenant_id:
            return f"{self.CACHE_PREFIX}{self.tenant_id}:{identifier}:{window}"
        return f"{self.CACHE_PREFIX}{identifier}:{window}"

    def check(self, identifier: str) -> RateLimitResult:
        """
        Check if a request is allowed.

        Uses a weighted sliding window across current and previous
        time periods for accurate rate calculation.

        Args:
            identifier: Unique identifier (user ID, IP, etc.)

        Returns:
            RateLimitResult indicating if request is allowed
        """
        now = time.time()
        current_window = int(now // self.period)
        previous_window = current_window - 1

        # Get cache keys
        current_key = self._get_cache_key(identifier, current_window)
        previous_key = self._get_cache_key(identifier, previous_window)

        # Get counts
        current_count = cache.get(current_key, 0)
        previous_count = cache.get(previous_key, 0)

        # Calculate weighted count
        # Weight previous window by percentage of period elapsed
        elapsed_in_window = now % self.period
        previous_weight = (self.period - elapsed_in_window) / self.period
        weighted_count = int(previous_count * previous_weight) + current_count

        if weighted_count >= self.limit:
            # Calculate retry time
            retry_after = int(self.period - elapsed_in_window)
            reset_time = (current_window + 1) * self.period

            return RateLimitResult(
                allowed=False,
                limit=self.limit,
                remaining=0,
                reset=int(reset_time),
                retry_after=retry_after
            )

        # Increment current window count
        if current_count == 0:
            cache.set(current_key, 1, timeout=self.period * 2)
        else:
            try:
                cache.incr(current_key)
            except ValueError:
                # Key doesn't exist or isn't an integer
                cache.set(current_key, 1, timeout=self.period * 2)

        remaining = self.limit - weighted_count - 1
        reset_time = (current_window + 1) * self.period

        return RateLimitResult(
            allowed=True,
            limit=self.limit,
            remaining=remaining,
            reset=int(reset_time)
        )

    def reset(self, identifier: str):
        """Reset all windows for an identifier."""
        now = time.time()
        current_window = int(now // self.period)

        # Delete current and previous windows
        for i in range(-1, 2):
            key = self._get_cache_key(identifier, current_window + i)
            cache.delete(key)

    def get_status(self, identifier: str) -> RateLimitResult:
        """
        Get current rate limit status without incrementing.

        Args:
            identifier: Unique identifier

        Returns:
            RateLimitResult with current status
        """
        now = time.time()
        current_window = int(now // self.period)
        previous_window = current_window - 1

        current_key = self._get_cache_key(identifier, current_window)
        previous_key = self._get_cache_key(identifier, previous_window)

        current_count = cache.get(current_key, 0)
        previous_count = cache.get(previous_key, 0)

        elapsed_in_window = now % self.period
        previous_weight = (self.period - elapsed_in_window) / self.period
        weighted_count = int(previous_count * previous_weight) + current_count

        return RateLimitResult(
            allowed=weighted_count < self.limit,
            limit=self.limit,
            remaining=max(0, self.limit - weighted_count),
            reset=int((current_window + 1) * self.period)
        )


# =============================================================================
# FIXED WINDOW RATE LIMITER
# =============================================================================

class FixedWindowRateLimiter:
    """
    Simple fixed window rate limiter.

    Counts requests in fixed time windows. Simple but can
    have boundary spikes where 2x the limit passes at window
    boundaries.

    Best for simple use cases where occasional spikes are acceptable.

    Usage:
        limiter = FixedWindowRateLimiter(limit=100, period=60)
        result = limiter.check('user:123')
    """

    CACHE_PREFIX = 'rate:fixed:'

    def __init__(
        self,
        limit: int,
        period: int,
        tenant_id: str = None
    ):
        """
        Initialize the fixed window rate limiter.

        Args:
            limit: Maximum requests per period
            period: Time period in seconds
            tenant_id: Optional tenant ID for isolation
        """
        self.limit = limit
        self.period = period
        self.tenant_id = tenant_id

    def _get_cache_key(self, identifier: str) -> str:
        """Generate cache key with current window."""
        window = int(time.time() // self.period)
        if self.tenant_id:
            return f"{self.CACHE_PREFIX}{self.tenant_id}:{identifier}:{window}"
        return f"{self.CACHE_PREFIX}{identifier}:{window}"

    def check(self, identifier: str) -> RateLimitResult:
        """
        Check if a request is allowed.

        Args:
            identifier: Unique identifier

        Returns:
            RateLimitResult indicating if request is allowed
        """
        now = time.time()
        key = self._get_cache_key(identifier)
        current_window = int(now // self.period)

        count = cache.get(key, 0)

        if count >= self.limit:
            reset_time = (current_window + 1) * self.period
            retry_after = int(reset_time - now)

            return RateLimitResult(
                allowed=False,
                limit=self.limit,
                remaining=0,
                reset=int(reset_time),
                retry_after=retry_after
            )

        # Increment counter
        if count == 0:
            cache.set(key, 1, timeout=self.period)
        else:
            try:
                cache.incr(key)
            except ValueError:
                cache.set(key, 1, timeout=self.period)

        reset_time = (current_window + 1) * self.period

        return RateLimitResult(
            allowed=True,
            limit=self.limit,
            remaining=self.limit - count - 1,
            reset=int(reset_time)
        )


# =============================================================================
# COMPOSITE RATE LIMITER
# =============================================================================

class CompositeRateLimiter:
    """
    Combines multiple rate limiters for layered protection.

    Applies multiple rate limits in order and fails fast if
    any limit is exceeded. Useful for different scopes:
    - Global rate limit (protect infrastructure)
    - Per-tenant rate limit (fair usage)
    - Per-user rate limit (prevent abuse)
    - Per-endpoint rate limit (protect expensive operations)

    Usage:
        limiter = CompositeRateLimiter([
            RateLimitConfig.from_string('10000/hour', scope=RateLimitScope.GLOBAL),
            RateLimitConfig.from_string('1000/hour', scope=RateLimitScope.TENANT),
            RateLimitConfig.from_string('100/minute', scope=RateLimitScope.USER),
        ])

        result = limiter.check(request)
    """

    def __init__(self, configs: List[RateLimitConfig]):
        """
        Initialize composite rate limiter.

        Args:
            configs: List of rate limit configurations
        """
        self.configs = configs
        self._limiters: Dict[str, SlidingWindowRateLimiter] = {}

    def _get_identifier(
        self,
        request: HttpRequest,
        config: RateLimitConfig
    ) -> str:
        """Get identifier based on scope."""
        if config.scope == RateLimitScope.GLOBAL:
            return 'global'

        if config.scope == RateLimitScope.IP:
            return f"ip:{self._get_client_ip(request)}"

        if config.scope == RateLimitScope.USER:
            if hasattr(request, 'user') and request.user.is_authenticated:
                return f"user:{request.user.id}"
            return f"ip:{self._get_client_ip(request)}"

        if config.scope == RateLimitScope.TENANT:
            tenant_id = self._get_tenant_id(request)
            return f"tenant:{tenant_id or 'public'}"

        if config.scope == RateLimitScope.ENDPOINT:
            path_hash = hashlib.md5(request.path.encode()).hexdigest()[:8]
            return f"endpoint:{path_hash}"

        if config.scope == RateLimitScope.COMBINED:
            user_id = 'anon'
            if hasattr(request, 'user') and request.user.is_authenticated:
                user_id = str(request.user.id)
            path_hash = hashlib.md5(request.path.encode()).hexdigest()[:8]
            return f"combined:{user_id}:{path_hash}"

        return f"default:{self._get_client_ip(request)}"

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '127.0.0.1')

    def _get_tenant_id(self, request: HttpRequest) -> Optional[str]:
        """Extract tenant ID from request."""
        try:
            from django.db import connection
            tenant = getattr(connection, 'tenant', None)
            if tenant:
                return str(tenant.id)
        except Exception:
            pass
        return None

    def _get_limiter(
        self,
        config: RateLimitConfig,
        tenant_id: str = None
    ) -> SlidingWindowRateLimiter:
        """Get or create a limiter for a config."""
        key = f"{config.name}:{tenant_id or 'global'}"

        if key not in self._limiters:
            self._limiters[key] = SlidingWindowRateLimiter(
                limit=config.limit,
                period=config.period,
                tenant_id=tenant_id
            )

        return self._limiters[key]

    def check(self, request: HttpRequest) -> RateLimitResult:
        """
        Check all rate limits for a request.

        Args:
            request: The HTTP request

        Returns:
            RateLimitResult from the first exceeded limit,
            or the most restrictive remaining limit
        """
        tenant_id = self._get_tenant_id(request)
        results = []

        for config in self.configs:
            # Check if rule applies to this request
            if not config.matches_request(request):
                continue

            # Check for excluded users
            if hasattr(request, 'user') and request.user.is_authenticated:
                if 'staff' in config.exclude_users and request.user.is_staff:
                    continue
                if 'superuser' in config.exclude_users and request.user.is_superuser:
                    continue

            # Get identifier and check limit
            identifier = self._get_identifier(request, config)
            limiter = self._get_limiter(config, tenant_id)
            result = limiter.check(identifier)

            if not result.allowed:
                logger.warning(
                    f"Rate limit exceeded: {config.name}",
                    extra={
                        'identifier': identifier,
                        'config': config.name,
                        'limit': config.limit,
                        'period': config.period,
                    }
                )
                return result

            results.append(result)

        # Return most restrictive result
        if results:
            return min(results, key=lambda r: r.remaining)

        # No limits applied
        return RateLimitResult(
            allowed=True,
            limit=0,
            remaining=0,
            reset=int(time.time() + 60)
        )


# =============================================================================
# RATE LIMIT DECORATOR
# =============================================================================

def rate_limit(
    limit: str = '100/minute',
    scope: RateLimitScope = RateLimitScope.USER,
    key_func: Callable[[HttpRequest], str] = None,
    block_duration: int = 0
):
    """
    Decorator to apply rate limiting to a view.

    Args:
        limit: Rate limit string like '100/minute'
        scope: Rate limit scope
        key_func: Custom function to generate rate limit key
        block_duration: Seconds to block after limit exceeded

    Usage:
        @rate_limit('10/minute', scope=RateLimitScope.IP)
        def my_view(request):
            ...

        @rate_limit('5/minute', key_func=lambda r: f"login:{r.POST.get('email')}")
        def login_view(request):
            ...
    """
    import functools

    config = RateLimitConfig.from_string(limit, scope=scope)

    def decorator(view_func: Callable):
        @functools.wraps(view_func)
        def wrapped(request: HttpRequest, *args, **kwargs):
            # Get identifier
            if key_func:
                identifier = key_func(request)
            else:
                if scope == RateLimitScope.USER:
                    if hasattr(request, 'user') and request.user.is_authenticated:
                        identifier = f"user:{request.user.id}"
                    else:
                        identifier = f"ip:{_get_client_ip(request)}"
                elif scope == RateLimitScope.IP:
                    identifier = f"ip:{_get_client_ip(request)}"
                else:
                    identifier = f"view:{view_func.__name__}:{_get_client_ip(request)}"

            # Check rate limit
            tenant_id = None
            try:
                from django.db import connection
                tenant = getattr(connection, 'tenant', None)
                if tenant:
                    tenant_id = str(tenant.id)
            except Exception:
                pass

            limiter = SlidingWindowRateLimiter(
                limit=config.limit,
                period=config.period,
                tenant_id=tenant_id
            )
            result = limiter.check(identifier)

            if not result.allowed:
                response = JsonResponse({
                    'error': 'Rate limit exceeded',
                    'detail': f'Too many requests. Please try again in {result.retry_after} seconds.',
                    'retry_after': result.retry_after,
                }, status=429)
                response['Retry-After'] = str(result.retry_after)
                for header, value in result.as_headers().items():
                    response[header] = value
                return response

            # Execute view
            response = view_func(request, *args, **kwargs)

            # Add rate limit headers
            for header, value in result.as_headers().items():
                response[header] = value

            return response

        return wrapped
    return decorator


def _get_client_ip(request: HttpRequest) -> str:
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


# =============================================================================
# DEFAULT RATE LIMIT CONFIGURATIONS
# =============================================================================

# Default rate limits for common endpoints
DEFAULT_RATE_LIMITS = {
    # Authentication
    'login': RateLimitConfig(
        name='login',
        limit=5,
        period=60,  # 5 per minute
        scope=RateLimitScope.IP,
        block_duration=300,  # 5 minute block
        paths=[r'^/api/auth/login', r'^/accounts/login'],
    ),
    'register': RateLimitConfig(
        name='register',
        limit=3,
        period=3600,  # 3 per hour
        scope=RateLimitScope.IP,
        paths=[r'^/api/auth/register', r'^/accounts/register'],
    ),
    'password_reset': RateLimitConfig(
        name='password_reset',
        limit=3,
        period=3600,  # 3 per hour
        scope=RateLimitScope.IP,
        paths=[r'^/api/auth/password-reset', r'^/accounts/password-reset'],
    ),

    # API
    'api_default': RateLimitConfig(
        name='api_default',
        limit=1000,
        period=3600,  # 1000 per hour
        scope=RateLimitScope.USER,
        paths=[r'^/api/'],
        exclude_users=['staff', 'superuser'],
    ),
    'api_search': RateLimitConfig(
        name='api_search',
        limit=60,
        period=60,  # 60 per minute
        scope=RateLimitScope.USER,
        paths=[r'^/api/.*/search'],
    ),
    'api_export': RateLimitConfig(
        name='api_export',
        limit=10,
        period=3600,  # 10 per hour
        scope=RateLimitScope.USER,
        paths=[r'^/api/.*/export'],
    ),

    # File uploads
    'upload': RateLimitConfig(
        name='upload',
        limit=20,
        period=3600,  # 20 per hour
        scope=RateLimitScope.USER,
        paths=[r'^/api/.*/upload', r'^/upload'],
    ),
}


def get_default_rate_limiter() -> CompositeRateLimiter:
    """Get a composite rate limiter with default configurations."""
    return CompositeRateLimiter(list(DEFAULT_RATE_LIMITS.values()))


# =============================================================================
# CUSTOM DRF THROTTLING CLASSES
# =============================================================================

from rest_framework.throttling import SimpleRateThrottle


class IPRateThrottle(SimpleRateThrottle):
    """
    Custom IP-based rate throttle for DRF.
    Limits: 10 requests per minute per IP.

    Usage in settings.py:
        REST_FRAMEWORK = {
            'DEFAULT_THROTTLE_CLASSES': [
                'core.security.rate_limiting.IPRateThrottle',
            ],
        }

    Or per-view:
        class MyView(APIView):
            throttle_classes = [IPRateThrottle]
    """

    scope = 'ip_rate'
    rate = '10/minute'
    cache_format = 'drf_throttle_ip:%(ident)s'

    def get_cache_key(self, request, view) -> str:
        """Get cache key based on client IP."""
        return self.cache_format % {
            'ident': self.get_ident(request)
        }

    def get_rate(self) -> str:
        """Get rate from settings or use default."""
        from django.conf import settings
        return getattr(settings, 'DRF_THROTTLE_IP_RATE', self.rate)


class UserRateThrottle(SimpleRateThrottle):
    """
    Custom user-based rate throttle for DRF.
    Limits: 100 requests per minute per authenticated user.
    Falls back to IP for anonymous users.

    Usage:
        class MyView(APIView):
            throttle_classes = [UserRateThrottle]
    """

    scope = 'user_rate'
    rate = '100/minute'
    cache_format = 'drf_throttle_user:%(ident)s'

    def get_cache_key(self, request, view) -> Optional[str]:
        """Get cache key based on user or IP."""
        if request.user.is_authenticated:
            ident = str(request.user.pk)
        else:
            ident = f"ip:{self.get_ident(request)}"

        return self.cache_format % {'ident': ident}

    def get_rate(self) -> str:
        """Get rate from settings or use default."""
        from django.conf import settings
        return getattr(settings, 'DRF_THROTTLE_USER_RATE', self.rate)


class BurstRateThrottle(SimpleRateThrottle):
    """
    Burst rate throttle to prevent rapid-fire requests.
    Limits: 5 requests per second per IP.

    Useful for protecting expensive endpoints.
    """

    scope = 'burst'
    rate = '5/second'
    cache_format = 'drf_throttle_burst:%(ident)s'

    def get_cache_key(self, request, view) -> str:
        return self.cache_format % {
            'ident': self.get_ident(request)
        }


class SensitiveEndpointThrottle(SimpleRateThrottle):
    """
    Very restrictive throttle for sensitive endpoints (login, password reset, etc.).
    Limits: 5 requests per minute per IP.
    """

    scope = 'sensitive'
    rate = '5/minute'
    cache_format = 'drf_throttle_sensitive:%(ident)s'

    def get_cache_key(self, request, view) -> str:
        return self.cache_format % {
            'ident': self.get_ident(request)
        }


class TenantAwareDRFThrottle(SimpleRateThrottle):
    """
    Tenant-aware throttle for multi-tenant API.
    Isolates rate limits per tenant.
    """

    scope = 'tenant'
    rate = '1000/hour'
    cache_format = 'drf_throttle_tenant:%(tenant)s:%(ident)s'

    def get_cache_key(self, request, view) -> Optional[str]:
        """Include tenant in cache key."""
        # Get tenant from request
        tenant = getattr(request, 'tenant', None)
        tenant_key = tenant.slug if tenant else 'public'

        if request.user.is_authenticated:
            ident = str(request.user.pk)
        else:
            ident = self.get_ident(request)

        return self.cache_format % {
            'tenant': tenant_key,
            'ident': ident
        }


# =============================================================================
# BRUTE FORCE PROTECTION
# =============================================================================

class BruteForceProtection:
    """
    Brute force attack prevention for authentication endpoints.

    Features:
    - Tracks failed login attempts per IP and username
    - Progressive lockout (increasing wait times)
    - IP blocking after threshold
    - Integration with django-axes

    Usage:
        from core.security.rate_limiting import brute_force_protection

        @brute_force_protection.protect
        def login_view(request):
            ...

        # Or manually:
        protection = BruteForceProtection()
        if not protection.is_allowed(ip, username):
            return HttpResponse("Too many attempts", status=429)

        if login_failed:
            protection.record_failure(ip, username)
        else:
            protection.record_success(ip, username)
    """

    # Lockout thresholds
    LOCKOUT_THRESHOLDS = [
        (3, 60),      # After 3 failures: 1 minute lockout
        (5, 300),     # After 5 failures: 5 minute lockout
        (10, 1800),   # After 10 failures: 30 minute lockout
        (20, 86400),  # After 20 failures: 24 hour lockout
    ]

    # IP block threshold
    IP_BLOCK_THRESHOLD = 50
    IP_BLOCK_DURATION = 86400  # 24 hours

    # Cache prefixes
    CACHE_PREFIX_IP = 'brute_force:ip:'
    CACHE_PREFIX_USER = 'brute_force:user:'
    CACHE_PREFIX_COMBO = 'brute_force:combo:'

    def __init__(self):
        self.logger = logging.getLogger('security.brute_force')

    def _hash_identifier(self, identifier: str) -> str:
        """Hash identifier for cache key."""
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]

    def is_allowed(self, ip: str, username: str = None) -> bool:
        """
        Check if login attempt is allowed.

        Args:
            ip: Client IP address
            username: Username being attempted (optional)

        Returns:
            True if attempt is allowed
        """
        # Check IP lockout
        ip_hash = self._hash_identifier(ip)
        ip_key = f"{self.CACHE_PREFIX_IP}{ip_hash}"
        ip_data = cache.get(ip_key, {'failures': 0, 'locked_until': 0})

        if ip_data.get('locked_until', 0) > time.time():
            remaining = int(ip_data['locked_until'] - time.time())
            self.logger.warning(
                f"IP locked out: {ip}",
                extra={'remaining': remaining}
            )
            return False

        # Check username lockout
        if username:
            user_hash = self._hash_identifier(username.lower())
            user_key = f"{self.CACHE_PREFIX_USER}{user_hash}"
            user_data = cache.get(user_key, {'failures': 0, 'locked_until': 0})

            if user_data.get('locked_until', 0) > time.time():
                remaining = int(user_data['locked_until'] - time.time())
                self.logger.warning(
                    f"User locked out: {username}",
                    extra={'remaining': remaining}
                )
                return False

            # Check combo lockout (IP + username)
            combo_key = f"{self.CACHE_PREFIX_COMBO}{ip_hash}:{user_hash}"
            combo_data = cache.get(combo_key, {'failures': 0, 'locked_until': 0})

            if combo_data.get('locked_until', 0) > time.time():
                return False

        return True

    def record_failure(self, ip: str, username: str = None):
        """
        Record a failed login attempt.

        Args:
            ip: Client IP address
            username: Username that was attempted
        """
        now = time.time()

        # Update IP failures
        ip_hash = self._hash_identifier(ip)
        ip_key = f"{self.CACHE_PREFIX_IP}{ip_hash}"
        ip_data = cache.get(ip_key, {'failures': 0, 'locked_until': 0})

        ip_data['failures'] = ip_data.get('failures', 0) + 1
        ip_data['last_failure'] = now

        # Calculate lockout duration
        lockout_duration = self._get_lockout_duration(ip_data['failures'])
        if lockout_duration:
            ip_data['locked_until'] = now + lockout_duration
            self.logger.warning(
                f"IP locked out for {lockout_duration}s after {ip_data['failures']} failures",
                extra={'ip': ip}
            )

        cache.set(ip_key, ip_data, timeout=86400)

        # Block IP after threshold
        if ip_data['failures'] >= self.IP_BLOCK_THRESHOLD:
            self._block_ip(ip)

        # Update username failures
        if username:
            user_hash = self._hash_identifier(username.lower())
            user_key = f"{self.CACHE_PREFIX_USER}{user_hash}"
            user_data = cache.get(user_key, {'failures': 0, 'locked_until': 0})

            user_data['failures'] = user_data.get('failures', 0) + 1
            user_data['last_failure'] = now

            lockout_duration = self._get_lockout_duration(user_data['failures'])
            if lockout_duration:
                user_data['locked_until'] = now + lockout_duration

            cache.set(user_key, user_data, timeout=86400)

            # Update combo failures
            combo_key = f"{self.CACHE_PREFIX_COMBO}{ip_hash}:{user_hash}"
            combo_data = cache.get(combo_key, {'failures': 0, 'locked_until': 0})
            combo_data['failures'] = combo_data.get('failures', 0) + 1
            combo_data['last_failure'] = now

            # Combo gets stricter lockout
            combo_lockout = self._get_lockout_duration(combo_data['failures'] * 2)
            if combo_lockout:
                combo_data['locked_until'] = now + combo_lockout

            cache.set(combo_key, combo_data, timeout=86400)

    def record_success(self, ip: str, username: str = None):
        """
        Record a successful login (clears failure counters).

        Args:
            ip: Client IP address
            username: Username that logged in
        """
        ip_hash = self._hash_identifier(ip)
        ip_key = f"{self.CACHE_PREFIX_IP}{ip_hash}"

        # Don't completely clear, just reset lockout
        ip_data = cache.get(ip_key, {'failures': 0})
        ip_data['locked_until'] = 0
        ip_data['failures'] = max(0, ip_data.get('failures', 0) - 1)  # Decay failures
        cache.set(ip_key, ip_data, timeout=86400)

        if username:
            user_hash = self._hash_identifier(username.lower())

            # Clear user lockout
            user_key = f"{self.CACHE_PREFIX_USER}{user_hash}"
            user_data = cache.get(user_key, {'failures': 0})
            user_data['locked_until'] = 0
            user_data['failures'] = max(0, user_data.get('failures', 0) - 2)
            cache.set(user_key, user_data, timeout=86400)

            # Clear combo
            combo_key = f"{self.CACHE_PREFIX_COMBO}{ip_hash}:{user_hash}"
            cache.delete(combo_key)

    def _get_lockout_duration(self, failures: int) -> int:
        """Get lockout duration based on failure count."""
        for threshold, duration in self.LOCKOUT_THRESHOLDS:
            if failures >= threshold:
                lockout = duration
        return lockout if failures >= self.LOCKOUT_THRESHOLDS[0][0] else 0

    def _block_ip(self, ip: str):
        """Block an IP address."""
        ip_hash = self._hash_identifier(ip)
        block_key = f"brute_force:blocked:{ip_hash}"
        cache.set(block_key, True, timeout=self.IP_BLOCK_DURATION)
        self.logger.warning(f"IP permanently blocked: {ip}")

    def get_remaining_lockout(self, ip: str, username: str = None) -> int:
        """
        Get remaining lockout time.

        Returns:
            Seconds remaining in lockout, or 0 if not locked
        """
        now = time.time()

        ip_hash = self._hash_identifier(ip)
        ip_key = f"{self.CACHE_PREFIX_IP}{ip_hash}"
        ip_data = cache.get(ip_key, {})

        ip_remaining = max(0, ip_data.get('locked_until', 0) - now)

        if username:
            user_hash = self._hash_identifier(username.lower())
            user_key = f"{self.CACHE_PREFIX_USER}{user_hash}"
            user_data = cache.get(user_key, {})
            user_remaining = max(0, user_data.get('locked_until', 0) - now)
            return max(ip_remaining, user_remaining)

        return int(ip_remaining)

    def get_failure_count(self, ip: str, username: str = None) -> Dict[str, int]:
        """
        Get current failure counts.

        Returns:
            Dict with failure counts for ip, user, and combo
        """
        ip_hash = self._hash_identifier(ip)
        ip_key = f"{self.CACHE_PREFIX_IP}{ip_hash}"
        ip_data = cache.get(ip_key, {})

        result = {
            'ip_failures': ip_data.get('failures', 0),
            'user_failures': 0,
            'combo_failures': 0,
        }

        if username:
            user_hash = self._hash_identifier(username.lower())
            user_key = f"{self.CACHE_PREFIX_USER}{user_hash}"
            user_data = cache.get(user_key, {})
            result['user_failures'] = user_data.get('failures', 0)

            combo_key = f"{self.CACHE_PREFIX_COMBO}{ip_hash}:{user_hash}"
            combo_data = cache.get(combo_key, {})
            result['combo_failures'] = combo_data.get('failures', 0)

        return result


# Global instance
brute_force_protection = BruteForceProtection()


def brute_force_protect(view_func: Callable = None, username_param: str = 'username'):
    """
    Decorator to protect a view with brute force protection.

    Usage:
        @brute_force_protect
        def login_view(request):
            ...

        @brute_force_protect(username_param='email')
        def login_view(request):
            ...
    """
    import functools

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapped(request: HttpRequest, *args, **kwargs):
            ip = _get_client_ip(request)
            username = request.POST.get(username_param) or request.data.get(username_param)

            # Check if allowed
            if not brute_force_protection.is_allowed(ip, username):
                remaining = brute_force_protection.get_remaining_lockout(ip, username)
                response = JsonResponse({
                    'error': 'Too many failed attempts',
                    'detail': f'Please try again in {remaining} seconds.',
                    'retry_after': remaining,
                }, status=429)
                response['Retry-After'] = str(remaining)
                return response

            # Execute view
            response = func(request, *args, **kwargs)

            # Track success/failure based on response
            if response.status_code in (200, 201, 302):
                brute_force_protection.record_success(ip, username)
            elif response.status_code in (400, 401, 403):
                brute_force_protection.record_failure(ip, username)

            return response

        return wrapped

    if view_func:
        return decorator(view_func)
    return decorator


# =============================================================================
# LOGIN ATTEMPT TRACKING
# =============================================================================

class LoginAttemptTracker:
    """
    Track login attempts for security monitoring and compliance.

    Features:
    - Logs all login attempts (success and failure)
    - Stores IP, user agent, timestamp
    - Supports querying for security analysis
    - Integration with audit logging

    Usage:
        tracker = LoginAttemptTracker()
        tracker.record_attempt(
            ip='192.168.1.1',
            username='user@example.com',
            success=False,
            user_agent='Mozilla/5.0...'
        )

        # Query recent failures
        failures = tracker.get_recent_failures(hours=24)
    """

    CACHE_PREFIX = 'login_attempt:'
    MAX_STORED_ATTEMPTS = 1000

    def __init__(self):
        self.logger = logging.getLogger('security.login_tracker')

    def record_attempt(
        self,
        ip: str,
        username: str,
        success: bool,
        user_agent: str = None,
        reason: str = None,
        request: HttpRequest = None
    ):
        """
        Record a login attempt.

        Args:
            ip: Client IP address
            username: Username attempted
            success: Whether login succeeded
            user_agent: Client user agent
            reason: Failure reason (if applicable)
            request: Original request (for additional context)
        """
        now = time.time()

        attempt = {
            'timestamp': now,
            'ip': ip,
            'username': username,
            'success': success,
            'user_agent': (user_agent or '')[:200],
            'reason': reason,
        }

        # Add to attempt log
        date_key = datetime.now().strftime('%Y-%m-%d')
        cache_key = f"{self.CACHE_PREFIX}log:{date_key}"

        attempts = cache.get(cache_key, [])
        attempts.append(attempt)

        # Limit stored attempts
        if len(attempts) > self.MAX_STORED_ATTEMPTS:
            attempts = attempts[-self.MAX_STORED_ATTEMPTS:]

        cache.set(cache_key, attempts, timeout=86400 * 30)  # Keep 30 days

        # Log for audit
        log_level = logging.INFO if success else logging.WARNING
        self.logger.log(
            log_level,
            f"Login {'success' if success else 'failure'}: {username} from {ip}",
            extra={
                'ip': ip,
                'username': username,
                'success': success,
                'reason': reason,
            }
        )

        # Update per-IP stats
        self._update_ip_stats(ip, success)

        # Update per-user stats
        self._update_user_stats(username, success)

    def _update_ip_stats(self, ip: str, success: bool):
        """Update per-IP statistics."""
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        stats_key = f"{self.CACHE_PREFIX}ip_stats:{ip_hash}"

        stats = cache.get(stats_key, {
            'total': 0,
            'success': 0,
            'failure': 0,
            'last_attempt': 0,
        })

        stats['total'] += 1
        if success:
            stats['success'] += 1
        else:
            stats['failure'] += 1
        stats['last_attempt'] = time.time()

        cache.set(stats_key, stats, timeout=86400 * 7)

    def _update_user_stats(self, username: str, success: bool):
        """Update per-user statistics."""
        user_hash = hashlib.sha256(username.lower().encode()).hexdigest()[:16]
        stats_key = f"{self.CACHE_PREFIX}user_stats:{user_hash}"

        stats = cache.get(stats_key, {
            'total': 0,
            'success': 0,
            'failure': 0,
            'last_attempt': 0,
            'last_success': 0,
        })

        stats['total'] += 1
        if success:
            stats['success'] += 1
            stats['last_success'] = time.time()
        else:
            stats['failure'] += 1
        stats['last_attempt'] = time.time()

        cache.set(stats_key, stats, timeout=86400 * 30)

    def get_recent_failures(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        """
        Get recent failed login attempts.

        Args:
            hours: Look back period
            limit: Maximum results

        Returns:
            List of failed attempt records
        """
        cutoff = time.time() - (hours * 3600)
        failures = []

        # Check today and yesterday's logs
        for days_ago in range(2):
            date = datetime.now() - timedelta(days=days_ago)
            date_key = date.strftime('%Y-%m-%d')
            cache_key = f"{self.CACHE_PREFIX}log:{date_key}"

            attempts = cache.get(cache_key, [])
            for attempt in attempts:
                if not attempt.get('success') and attempt.get('timestamp', 0) >= cutoff:
                    failures.append(attempt)

        # Sort by timestamp descending
        failures.sort(key=lambda x: x.get('timestamp', 0), reverse=True)

        return failures[:limit]

    def get_ip_stats(self, ip: str) -> Dict:
        """Get login statistics for an IP."""
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        stats_key = f"{self.CACHE_PREFIX}ip_stats:{ip_hash}"
        return cache.get(stats_key, {
            'total': 0,
            'success': 0,
            'failure': 0,
        })

    def get_user_stats(self, username: str) -> Dict:
        """Get login statistics for a username."""
        user_hash = hashlib.sha256(username.lower().encode()).hexdigest()[:16]
        stats_key = f"{self.CACHE_PREFIX}user_stats:{user_hash}"
        return cache.get(stats_key, {
            'total': 0,
            'success': 0,
            'failure': 0,
        })


# Global instance
login_tracker = LoginAttemptTracker()
