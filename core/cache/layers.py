"""
Multi-Layer Caching System for Zumodra - Scaling to 1M+ Users

This module provides a comprehensive caching infrastructure:
- Model cache decorator: Cache model instances
- View cache decorator: Cache view responses with tenant isolation
- Query cache utility: Cache expensive database queries
- Cache invalidation signals: Automatic cache invalidation
- Redis cluster configuration: Production-ready Redis setup

Designed for high-traffic multi-tenant SaaS with proper isolation.
"""

import functools
import hashlib
import json
import logging
import pickle
import time
from datetime import timedelta
from typing import (
    Any, Callable, Dict, List, Optional, Set, Tuple, Type, TypeVar, Union
)

from django.conf import settings
from django.core.cache import cache, caches
from django.db import models
from django.db.models import Model, QuerySet
from django.db.models.signals import post_save, post_delete, m2m_changed
from django.http import HttpRequest, HttpResponse
from django.utils import timezone
from django.utils.decorators import method_decorator

logger = logging.getLogger(__name__)

T = TypeVar('T', bound=Model)


# =============================================================================
# CACHE KEY BUILDERS
# =============================================================================

class CacheKeyBuilder:
    """
    Utility class for building consistent, namespaced cache keys.

    Ensures tenant isolation and prevents key collisions across
    different environments, tenants, and model types.
    """

    # Global prefix for all Zumodra cache keys
    PREFIX = 'zum'

    # Cache version (increment to invalidate all caches)
    VERSION = 1

    @classmethod
    def build(
        cls,
        *parts: str,
        tenant_id: Optional[str] = None,
        include_version: bool = True
    ) -> str:
        """
        Build a namespaced cache key.

        Args:
            *parts: Key components to join
            tenant_id: Tenant ID for isolation
            include_version: Include cache version

        Returns:
            Formatted cache key string
        """
        components = [cls.PREFIX]

        if include_version:
            components.append(f'v{cls.VERSION}')

        if tenant_id:
            components.append(f't:{tenant_id}')

        components.extend(parts)

        return ':'.join(str(c) for c in components)

    @classmethod
    def model_key(
        cls,
        model: Type[Model],
        pk: Any,
        tenant_id: Optional[str] = None
    ) -> str:
        """Build cache key for a model instance."""
        return cls.build(
            'model',
            model._meta.label,
            str(pk),
            tenant_id=tenant_id
        )

    @classmethod
    def queryset_key(
        cls,
        model: Type[Model],
        query_hash: str,
        tenant_id: Optional[str] = None
    ) -> str:
        """Build cache key for a queryset."""
        return cls.build(
            'qs',
            model._meta.label,
            query_hash,
            tenant_id=tenant_id
        )

    @classmethod
    def view_key(
        cls,
        view_name: str,
        args_hash: str,
        tenant_id: Optional[str] = None
    ) -> str:
        """Build cache key for a view response."""
        return cls.build(
            'view',
            view_name,
            args_hash,
            tenant_id=tenant_id
        )

    @classmethod
    def pattern_key(
        cls,
        model: Type[Model],
        tenant_id: Optional[str] = None
    ) -> str:
        """Build pattern key for invalidating all model caches."""
        base = cls.build('model', model._meta.label, tenant_id=tenant_id)
        return f'{base}:*'

    @staticmethod
    def hash_query(query: Union[str, QuerySet]) -> str:
        """Generate hash for a query or queryset."""
        if isinstance(query, QuerySet):
            query = str(query.query)
        return hashlib.md5(query.encode()).hexdigest()[:16]

    @staticmethod
    def hash_args(*args, **kwargs) -> str:
        """Generate hash for function arguments."""
        key_data = json.dumps({
            'args': [str(a) for a in args],
            'kwargs': {k: str(v) for k, v in sorted(kwargs.items())}
        }, sort_keys=True)
        return hashlib.md5(key_data.encode()).hexdigest()[:16]


# =============================================================================
# MODEL CACHE DECORATOR
# =============================================================================

def model_cache(
    timeout: int = 300,
    key_field: str = 'pk',
    tenant_aware: bool = True,
    version: int = 1
) -> Callable:
    """
    Decorator to cache model instance retrieval.

    Caches get() operations on model managers with automatic
    cache invalidation on save/delete.

    Usage:
        class EmployeeManager(models.Manager):
            @model_cache(timeout=600)
            def get(self, *args, **kwargs):
                return super().get(*args, **kwargs)

        # Or as a class decorator on the model
        @model_cache(timeout=600)
        class Employee(models.Model):
            pass
    """
    def decorator(func_or_class: Union[Callable, Type[Model]]):
        if isinstance(func_or_class, type) and issubclass(func_or_class, Model):
            # Class decorator - register signal handlers
            model_class = func_or_class
            _register_model_cache_signals(model_class, tenant_aware, version)
            return model_class

        # Function decorator
        func = func_or_class

        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            # Try to get pk from args/kwargs
            pk = kwargs.get(key_field) or kwargs.get('pk') or (args[0] if args else None)

            if pk is None:
                # Can't cache without PK
                return func(self, *args, **kwargs)

            # Build cache key
            model = self.model
            tenant_id = None
            if tenant_aware:
                tenant_id = _get_current_tenant_id()

            cache_key = CacheKeyBuilder.model_key(model, pk, tenant_id)

            # Try cache
            cached = cache.get(cache_key)
            if cached is not None:
                logger.debug(f"Cache HIT: {cache_key}")
                return cached

            # Cache miss - fetch from DB
            logger.debug(f"Cache MISS: {cache_key}")
            result = func(self, *args, **kwargs)

            # Cache result
            cache.set(cache_key, result, timeout)

            return result

        return wrapper

    return decorator


def _register_model_cache_signals(
    model_class: Type[Model],
    tenant_aware: bool,
    version: int
) -> None:
    """Register cache invalidation signals for a model."""

    def invalidate_cache(sender, instance, **kwargs):
        """Invalidate cache for model instance."""
        tenant_id = None
        if tenant_aware and hasattr(instance, 'tenant_id'):
            tenant_id = str(instance.tenant_id)

        cache_key = CacheKeyBuilder.model_key(model_class, instance.pk, tenant_id)
        cache.delete(cache_key)
        logger.debug(f"Invalidated cache: {cache_key}")

    # Connect signals
    post_save.connect(invalidate_cache, sender=model_class, weak=False)
    post_delete.connect(invalidate_cache, sender=model_class, weak=False)

    logger.info(f"Registered cache invalidation signals for {model_class._meta.label}")


# =============================================================================
# VIEW CACHE DECORATOR
# =============================================================================

def view_cache(
    timeout: int = 60,
    tenant_aware: bool = True,
    vary_on_user: bool = False,
    vary_on_headers: List[str] = None,
    cache_anonymous_only: bool = False
) -> Callable:
    """
    Decorator to cache view responses with tenant isolation.

    Supports:
    - Tenant-isolated caching
    - User-specific cache variations
    - Header-based variations (Accept, Accept-Language, etc.)
    - Anonymous-only caching for public pages

    Usage:
        @view_cache(timeout=300, tenant_aware=True)
        class PublicJobListView(TenantAwareAPIView):
            def get(self, request):
                return Response(get_jobs())

        # Or on individual methods
        class EmployeeViewSet(TenantAwareViewSet):
            @view_cache(timeout=60, vary_on_user=True)
            def list(self, request):
                return super().list(request)
    """
    vary_on_headers = vary_on_headers or []

    def decorator(view_func: Callable) -> Callable:
        @functools.wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            # Skip cache for non-GET requests
            if request.method not in ('GET', 'HEAD'):
                return view_func(self, request, *args, **kwargs)

            # Skip cache for authenticated users if anonymous_only
            if cache_anonymous_only and request.user.is_authenticated:
                return view_func(self, request, *args, **kwargs)

            # Build cache key components
            key_parts = [
                request.path,
                request.META.get('QUERY_STRING', ''),
            ]

            # Add user variation
            if vary_on_user and request.user.is_authenticated:
                key_parts.append(f'user:{request.user.pk}')

            # Add header variations
            for header in vary_on_headers:
                value = request.META.get(f'HTTP_{header.upper().replace("-", "_")}', '')
                key_parts.append(f'{header}:{value}')

            # Get tenant ID
            tenant_id = None
            if tenant_aware:
                tenant_id = _get_current_tenant_id()

            # Build cache key
            args_hash = CacheKeyBuilder.hash_args(*key_parts)
            view_name = f'{self.__class__.__name__}.{view_func.__name__}'
            cache_key = CacheKeyBuilder.view_key(view_name, args_hash, tenant_id)

            # Try cache
            cached = cache.get(cache_key)
            if cached is not None:
                logger.debug(f"View cache HIT: {cache_key}")
                return cached

            # Cache miss - execute view
            logger.debug(f"View cache MISS: {cache_key}")
            response = view_func(self, request, *args, **kwargs)

            # Only cache successful responses
            if hasattr(response, 'status_code') and 200 <= response.status_code < 300:
                # Ensure response is rendered
                if hasattr(response, 'render'):
                    response.render()

                cache.set(cache_key, response, timeout)

            return response

        return wrapper

    return decorator


class ETagCacheMixin:
    """
    Mixin providing ETag-based HTTP caching for API views.

    Implements conditional GET requests using ETags for bandwidth
    optimization. Client can send If-None-Match header to receive
    304 Not Modified for unchanged resources.

    Usage:
        class EmployeeViewSet(ETagCacheMixin, TenantAwareViewSet):
            queryset = Employee.objects.all()

            def get_etag_value(self, request, obj):
                return f'{obj.pk}:{obj.updated_at.isoformat()}'
    """

    def get_etag_value(
        self,
        request: HttpRequest,
        obj: Optional[Model] = None
    ) -> Optional[str]:
        """
        Generate ETag value for a resource.

        Override this method to customize ETag generation.
        Default uses updated_at timestamp if available.
        """
        if obj is None:
            return None

        if hasattr(obj, 'updated_at'):
            return f'{obj.pk}:{obj.updated_at.isoformat()}'

        if hasattr(obj, 'version'):
            return f'{obj.pk}:v{obj.version}'

        return str(obj.pk)

    def get_list_etag_value(
        self,
        request: HttpRequest,
        queryset: QuerySet
    ) -> Optional[str]:
        """
        Generate ETag for list views.

        Uses combination of count and max updated_at.
        """
        count = queryset.count()
        if count == 0:
            return 'empty'

        # Try to get max updated_at
        model = queryset.model
        if hasattr(model, 'updated_at'):
            from django.db.models import Max
            max_updated = queryset.aggregate(max_updated=Max('updated_at'))
            if max_updated['max_updated']:
                return f'{count}:{max_updated["max_updated"].isoformat()}'

        return str(count)

    def check_etag(self, request: HttpRequest, etag: str) -> bool:
        """Check if client's ETag matches current ETag."""
        client_etag = request.META.get('HTTP_IF_NONE_MATCH', '')
        return client_etag == f'"{etag}"'

    def retrieve(self, request, *args, **kwargs):
        """Override retrieve to add ETag support."""
        instance = self.get_object()
        etag = self.get_etag_value(request, instance)

        if etag and self.check_etag(request, etag):
            return HttpResponse(status=304)

        response = super().retrieve(request, *args, **kwargs)

        if etag:
            response['ETag'] = f'"{etag}"'

        return response

    def list(self, request, *args, **kwargs):
        """Override list to add ETag support."""
        queryset = self.filter_queryset(self.get_queryset())
        etag = self.get_list_etag_value(request, queryset)

        if etag and self.check_etag(request, etag):
            return HttpResponse(status=304)

        response = super().list(request, *args, **kwargs)

        if etag:
            response['ETag'] = f'"{etag}"'

        return response


# =============================================================================
# QUERY CACHE UTILITY
# =============================================================================

class QueryCache:
    """
    Utility for caching expensive database queries.

    Provides:
    - Automatic cache key generation from query SQL
    - Tenant-isolated caching
    - Configurable serialization (pickle/json)
    - Batch operations for related data

    Usage:
        qc = QueryCache(timeout=300)

        # Cache a queryset result
        employees = qc.get_or_set(
            Employee.objects.filter(status='active'),
            key='active_employees'
        )

        # Cache with custom generator
        @qc.cached('dashboard_stats')
        def get_dashboard_stats(tenant_id):
            return calculate_stats(tenant_id)
    """

    def __init__(
        self,
        timeout: int = 300,
        tenant_aware: bool = True,
        cache_alias: str = 'default'
    ):
        """
        Initialize query cache.

        Args:
            timeout: Default cache TTL in seconds
            tenant_aware: Include tenant in cache keys
            cache_alias: Django cache alias to use
        """
        self.timeout = timeout
        self.tenant_aware = tenant_aware
        self.cache = caches[cache_alias]

    def get_or_set(
        self,
        queryset: QuerySet,
        key: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> List[Model]:
        """
        Get cached queryset results or execute and cache.

        Args:
            queryset: QuerySet to cache
            key: Optional custom cache key
            timeout: Optional timeout override

        Returns:
            List of model instances
        """
        timeout = timeout or self.timeout
        tenant_id = _get_current_tenant_id() if self.tenant_aware else None

        # Generate cache key
        if key:
            cache_key = CacheKeyBuilder.build('qc', key, tenant_id=tenant_id)
        else:
            query_hash = CacheKeyBuilder.hash_query(queryset)
            cache_key = CacheKeyBuilder.queryset_key(
                queryset.model, query_hash, tenant_id
            )

        # Try cache
        cached = self.cache.get(cache_key)
        if cached is not None:
            logger.debug(f"QueryCache HIT: {cache_key}")
            return cached

        # Execute and cache
        logger.debug(f"QueryCache MISS: {cache_key}")
        results = list(queryset)
        self.cache.set(cache_key, results, timeout)

        return results

    def get_or_compute(
        self,
        key: str,
        compute_func: Callable,
        timeout: Optional[int] = None
    ) -> Any:
        """
        Get cached value or compute and cache.

        Args:
            key: Cache key
            compute_func: Function to compute value on cache miss
            timeout: Optional timeout override

        Returns:
            Cached or computed value
        """
        timeout = timeout or self.timeout
        tenant_id = _get_current_tenant_id() if self.tenant_aware else None
        cache_key = CacheKeyBuilder.build('qc', key, tenant_id=tenant_id)

        # Try cache
        cached = self.cache.get(cache_key)
        if cached is not None:
            logger.debug(f"QueryCache HIT: {cache_key}")
            return cached

        # Compute and cache
        logger.debug(f"QueryCache MISS: {cache_key}")
        result = compute_func()
        self.cache.set(cache_key, result, timeout)

        return result

    def cached(
        self,
        key: str,
        timeout: Optional[int] = None
    ) -> Callable:
        """
        Decorator to cache function results.

        Usage:
            @query_cache.cached('expensive_calculation')
            def expensive_calculation(param):
                return heavy_computation(param)
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Include args in cache key
                args_hash = CacheKeyBuilder.hash_args(*args, **kwargs)
                full_key = f'{key}:{args_hash}'

                return self.get_or_compute(
                    full_key,
                    lambda: func(*args, **kwargs),
                    timeout
                )

            return wrapper

        return decorator

    def invalidate(self, key: str) -> bool:
        """
        Invalidate a specific cache key.

        Args:
            key: Cache key to invalidate

        Returns:
            True if key was deleted
        """
        tenant_id = _get_current_tenant_id() if self.tenant_aware else None
        cache_key = CacheKeyBuilder.build('qc', key, tenant_id=tenant_id)
        return self.cache.delete(cache_key)

    def invalidate_model(self, model: Type[Model]) -> int:
        """
        Invalidate all cached queries for a model.

        Requires Redis cache backend with delete_pattern support.

        Args:
            model: Model class to invalidate

        Returns:
            Number of keys deleted
        """
        tenant_id = _get_current_tenant_id() if self.tenant_aware else None
        pattern = CacheKeyBuilder.pattern_key(model, tenant_id)

        # Redis backend supports delete_pattern
        if hasattr(self.cache, 'delete_pattern'):
            return self.cache.delete_pattern(pattern)

        logger.warning(
            f"Cache backend doesn't support pattern deletion. "
            f"Pattern: {pattern}"
        )
        return 0


# Global query cache instance
query_cache = QueryCache()


# =============================================================================
# CACHE INVALIDATION SIGNALS
# =============================================================================

class CacheInvalidator:
    """
    Centralized cache invalidation manager.

    Tracks model-to-cache-key mappings and automatically invalidates
    related caches when models are modified.

    Usage:
        # Register invalidation rules
        invalidator = CacheInvalidator()
        invalidator.register(Employee, ['employee_list', 'department_stats'])

        # Manual invalidation
        invalidator.invalidate_for_model(Employee)
    """

    def __init__(self, cache_alias: str = 'default'):
        self.cache = caches[cache_alias]
        self._registry: Dict[Type[Model], Set[str]] = {}
        self._signal_connected: Set[Type[Model]] = set()

    def register(
        self,
        model: Type[Model],
        cache_keys: List[str],
        connect_signals: bool = True
    ) -> None:
        """
        Register cache keys to invalidate when model changes.

        Args:
            model: Model class
            cache_keys: List of cache keys to invalidate
            connect_signals: Automatically connect save/delete signals
        """
        if model not in self._registry:
            self._registry[model] = set()

        self._registry[model].update(cache_keys)

        if connect_signals and model not in self._signal_connected:
            self._connect_signals(model)

    def _connect_signals(self, model: Type[Model]) -> None:
        """Connect Django signals for automatic invalidation."""

        def on_change(sender, instance, **kwargs):
            self.invalidate_for_model(sender, instance)

        def on_m2m_change(sender, instance, action, **kwargs):
            if action in ('post_add', 'post_remove', 'post_clear'):
                self.invalidate_for_model(instance.__class__, instance)

        post_save.connect(on_change, sender=model, weak=False)
        post_delete.connect(on_change, sender=model, weak=False)

        # Connect M2M signals for related fields
        for field in model._meta.get_fields():
            if field.many_to_many and hasattr(field, 'through'):
                m2m_changed.connect(on_m2m_change, sender=field.through, weak=False)

        self._signal_connected.add(model)
        logger.info(f"Connected cache invalidation signals for {model._meta.label}")

    def invalidate_for_model(
        self,
        model: Type[Model],
        instance: Optional[Model] = None
    ) -> int:
        """
        Invalidate all registered caches for a model.

        Args:
            model: Model class
            instance: Optional instance for tenant-aware invalidation

        Returns:
            Number of keys invalidated
        """
        keys_to_invalidate = self._registry.get(model, set())

        if not keys_to_invalidate:
            return 0

        # Get tenant ID if available
        tenant_id = None
        if instance and hasattr(instance, 'tenant_id'):
            tenant_id = str(instance.tenant_id)

        count = 0
        for key in keys_to_invalidate:
            cache_key = CacheKeyBuilder.build('qc', key, tenant_id=tenant_id)
            if self.cache.delete(cache_key):
                count += 1
                logger.debug(f"Invalidated cache: {cache_key}")

        return count

    def invalidate_keys(self, keys: List[str], tenant_id: Optional[str] = None) -> int:
        """
        Invalidate specific cache keys.

        Args:
            keys: List of cache keys
            tenant_id: Optional tenant ID for isolation

        Returns:
            Number of keys invalidated
        """
        count = 0
        for key in keys:
            cache_key = CacheKeyBuilder.build('qc', key, tenant_id=tenant_id)
            if self.cache.delete(cache_key):
                count += 1

        return count


# Global invalidator instance
cache_invalidator = CacheInvalidator()


# =============================================================================
# REDIS CLUSTER CONFIGURATION
# =============================================================================

def get_redis_cluster_config() -> Dict[str, Any]:
    """
    Get Redis cluster configuration for production deployment.

    Returns configuration optimized for:
    - High availability with Sentinel
    - Connection pooling
    - Compression for large values
    - Separate databases for different cache tiers
    """
    redis_url = getattr(settings, 'REDIS_URL', 'redis://127.0.0.1:6379')

    return {
        # Main cache (hot data, short TTL)
        'default': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': f'{redis_url}/0',
            'OPTIONS': {
                'CLIENT_CLASS': 'django_redis.client.DefaultClient',
                'CONNECTION_POOL_CLASS': 'redis.connection.BlockingConnectionPool',
                'CONNECTION_POOL_CLASS_KWARGS': {
                    'max_connections': 50,
                    'timeout': 20,
                },
                'MAX_CONNECTIONS': 1000,
                'SOCKET_CONNECT_TIMEOUT': 5,
                'SOCKET_TIMEOUT': 5,
                'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
                'IGNORE_EXCEPTIONS': True,
            },
            'KEY_PREFIX': 'zum:hot',
            'TIMEOUT': 300,  # 5 minutes default
        },

        # Warm cache (medium TTL, frequently accessed)
        'warm': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': f'{redis_url}/1',
            'OPTIONS': {
                'CLIENT_CLASS': 'django_redis.client.DefaultClient',
                'CONNECTION_POOL_CLASS': 'redis.connection.BlockingConnectionPool',
                'CONNECTION_POOL_CLASS_KWARGS': {
                    'max_connections': 30,
                    'timeout': 20,
                },
                'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
                'IGNORE_EXCEPTIONS': True,
            },
            'KEY_PREFIX': 'zum:warm',
            'TIMEOUT': 3600,  # 1 hour default
        },

        # Cold cache (long TTL, rarely changing data)
        'cold': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': f'{redis_url}/2',
            'OPTIONS': {
                'CLIENT_CLASS': 'django_redis.client.DefaultClient',
                'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
                'IGNORE_EXCEPTIONS': True,
            },
            'KEY_PREFIX': 'zum:cold',
            'TIMEOUT': 86400,  # 24 hours default
        },

        # Session storage
        'sessions': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': f'{redis_url}/3',
            'OPTIONS': {
                'CLIENT_CLASS': 'django_redis.client.DefaultClient',
                'SERIALIZER': 'django_redis.serializers.json.JSONSerializer',
            },
            'KEY_PREFIX': 'zum:sess',
            'TIMEOUT': 1209600,  # 2 weeks
        },

        # Rate limiting (separate for isolation)
        'ratelimit': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': f'{redis_url}/4',
            'OPTIONS': {
                'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            },
            'KEY_PREFIX': 'zum:rl',
            'TIMEOUT': 60,
        },

        # Celery results
        'celery': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': f'{redis_url}/5',
            'OPTIONS': {
                'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            },
            'KEY_PREFIX': 'zum:celery',
            'TIMEOUT': 86400,
        },
    }


def get_redis_sentinel_config(
    sentinels: List[Tuple[str, int]],
    master_name: str = 'mymaster'
) -> Dict[str, Any]:
    """
    Get Redis Sentinel configuration for high availability.

    Args:
        sentinels: List of (host, port) tuples for Sentinel nodes
        master_name: Name of the Redis master

    Returns:
        Cache configuration dict for Django settings
    """
    sentinel_config = {
        'default': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': f'redis://{master_name}/0',
            'OPTIONS': {
                'CLIENT_CLASS': 'django_redis.client.SentinelClient',
                'SENTINELS': sentinels,
                'SENTINEL_KWARGS': {
                    'socket_timeout': 1,
                },
                'CONNECTION_POOL_CLASS': 'redis.sentinel.SentinelConnectionPool',
                'CONNECTION_POOL_CLASS_KWARGS': {
                    'max_connections': 50,
                },
            },
            'KEY_PREFIX': 'zum',
            'TIMEOUT': 300,
        },
    }

    return sentinel_config


# =============================================================================
# CACHE WARMING UTILITIES
# =============================================================================

class CacheWarmer:
    """
    Utility for pre-warming caches during deployment or scheduled jobs.

    Usage:
        warmer = CacheWarmer()

        # Warm specific queries
        warmer.warm_queryset(
            Employee.objects.filter(status='active'),
            key='active_employees'
        )

        # Warm using generator function
        @warmer.warmable('dashboard_data')
        def get_dashboard_data():
            return compute_dashboard()

        # Warm all registered
        warmer.warm_all()
    """

    def __init__(self, cache_alias: str = 'default'):
        self.cache = caches[cache_alias]
        self._warmers: Dict[str, Callable] = {}

    def register(self, key: str, generator: Callable, timeout: int = 3600) -> None:
        """Register a cache warmer function."""
        self._warmers[key] = (generator, timeout)

    def warmable(self, key: str, timeout: int = 3600) -> Callable:
        """Decorator to register a warmable function."""
        def decorator(func: Callable) -> Callable:
            self.register(key, func, timeout)
            return func

        return decorator

    def warm_queryset(
        self,
        queryset: QuerySet,
        key: str,
        timeout: int = 3600,
        tenant_id: Optional[str] = None
    ) -> None:
        """Warm cache with queryset results."""
        cache_key = CacheKeyBuilder.build('qc', key, tenant_id=tenant_id)
        results = list(queryset)
        self.cache.set(cache_key, results, timeout)
        logger.info(f"Warmed cache: {cache_key} ({len(results)} items)")

    def warm_key(
        self,
        key: str,
        tenant_id: Optional[str] = None
    ) -> bool:
        """Warm a specific registered cache key."""
        if key not in self._warmers:
            logger.warning(f"No warmer registered for key: {key}")
            return False

        generator, timeout = self._warmers[key]
        cache_key = CacheKeyBuilder.build('qc', key, tenant_id=tenant_id)

        try:
            result = generator()
            self.cache.set(cache_key, result, timeout)
            logger.info(f"Warmed cache: {cache_key}")
            return True
        except Exception as e:
            logger.error(f"Failed to warm cache {cache_key}: {e}")
            return False

    def warm_all(self, tenant_id: Optional[str] = None) -> Dict[str, bool]:
        """Warm all registered caches."""
        results = {}
        for key in self._warmers:
            results[key] = self.warm_key(key, tenant_id)
        return results


# Global cache warmer instance
cache_warmer = CacheWarmer()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _get_current_tenant_id() -> Optional[str]:
    """Get current tenant ID from connection."""
    try:
        from django.db import connection
        tenant = getattr(connection, 'tenant', None)
        if tenant:
            return str(tenant.pk)
    except Exception:
        pass
    return None


def clear_all_caches() -> None:
    """Clear all cache backends. Use with caution in production."""
    for alias in caches:
        caches[alias].clear()
        logger.warning(f"Cleared cache: {alias}")


def get_cache_stats(cache_alias: str = 'default') -> Dict[str, Any]:
    """
    Get cache statistics (Redis only).

    Returns memory usage, hit rate, and other metrics.
    """
    try:
        cache_backend = caches[cache_alias]
        client = cache_backend.client.get_client()

        info = client.info()
        return {
            'used_memory': info.get('used_memory_human'),
            'connected_clients': info.get('connected_clients'),
            'keyspace_hits': info.get('keyspace_hits', 0),
            'keyspace_misses': info.get('keyspace_misses', 0),
            'hit_rate': (
                info.get('keyspace_hits', 0) /
                max(info.get('keyspace_hits', 0) + info.get('keyspace_misses', 0), 1)
            ) * 100,
            'total_commands_processed': info.get('total_commands_processed'),
            'expired_keys': info.get('expired_keys'),
            'evicted_keys': info.get('evicted_keys'),
        }
    except Exception as e:
        logger.error(f"Failed to get cache stats: {e}")
        return {}
