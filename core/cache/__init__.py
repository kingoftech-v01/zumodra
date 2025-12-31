"""
Zumodra Cache Module - Multi-Layer Caching Infrastructure

This module provides a comprehensive caching system:
- Model cache decorator for instance caching
- View cache decorator with tenant isolation
- Query cache utility for expensive queries
- Cache invalidation signals for automatic cleanup
- Redis cluster configuration for production

Usage:
    from core.cache import (
        model_cache, view_cache, query_cache,
        cache_invalidator, CacheKeyBuilder
    )
"""

from core.cache.layers import (
    # Key builders
    CacheKeyBuilder,

    # Decorators
    model_cache,
    view_cache,

    # Mixins
    ETagCacheMixin,

    # Query caching
    QueryCache,
    query_cache,

    # Invalidation
    CacheInvalidator,
    cache_invalidator,

    # Cache warming
    CacheWarmer,
    cache_warmer,

    # Configuration
    get_redis_cluster_config,
    get_redis_sentinel_config,

    # Utilities
    clear_all_caches,
    get_cache_stats,
)

__all__ = [
    'CacheKeyBuilder',
    'model_cache',
    'view_cache',
    'ETagCacheMixin',
    'QueryCache',
    'query_cache',
    'CacheInvalidator',
    'cache_invalidator',
    'CacheWarmer',
    'cache_warmer',
    'get_redis_cluster_config',
    'get_redis_sentinel_config',
    'clear_all_caches',
    'get_cache_stats',
]
