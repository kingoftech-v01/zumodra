"""
Zumodra Cache Module - Multi-Layer Caching Infrastructure

This module provides a comprehensive caching system:
- Model cache decorator for instance caching
- View cache decorator with tenant isolation
- Query cache utility for expensive queries
- Cache invalidation signals for automatic cleanup
- Redis cluster configuration for production
- Tenant-aware cache keys and invalidation

Usage:
    from core.cache import (
        model_cache, view_cache, query_cache,
        cache_invalidator, CacheKeyBuilder,
        TenantCache, invalidate_permission_cache
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

# Import tenant-aware cache utilities
from core.cache.tenant_cache import (
    # Class
    TenantCache,

    # Constants
    PERMISSION_CACHE_TIMEOUT,
    FEATURE_CACHE_TIMEOUT,
    RATING_CACHE_TIMEOUT,
    THROTTLE_CACHE_TIMEOUT,

    # Permission cache functions
    get_user_permissions_key,
    get_user_roles_key,
    get_cached_permissions,
    cache_permissions,
    get_cached_roles,
    cache_roles,
    invalidate_permission_cache,
    invalidate_all_user_permissions,

    # Feature cache functions
    get_tenant_features_key,
    get_cached_features,
    cache_features,
    invalidate_feature_cache,

    # Throttle cache functions
    get_throttle_key,
    get_throttle_count,
    increment_throttle,
    reset_throttle,

    # Rating cache functions
    get_provider_rating_key,
    get_cached_rating,
    cache_rating,
    invalidate_rating_cache,

    # App-specific cache invalidation
    invalidate_services_cache,
    invalidate_service_category_cache,
    invalidate_provider_cache,
    invalidate_blog_cache,
    invalidate_blog_post_cache,
    invalidate_blog_category_cache,
    invalidate_newsletter_cache,
    invalidate_newsletter_stats_cache,
    invalidate_appointment_cache,
    invalidate_appointment_stats_cache,
    invalidate_dashboard_cache,
    invalidate_ats_cache,
    invalidate_hr_cache,
    invalidate_configurations_cache,

    # Signal connectors
    connect_cache_signals,
    connect_services_cache_signals,
    connect_blog_cache_signals,
    connect_newsletter_cache_signals,
    connect_appointment_cache_signals,
    connect_dashboard_cache_signals,
    connect_configurations_cache_signals,
    connect_all_cache_signals,
)

__all__ = [
    # From layers.py
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

    # From tenant_cache.py
    'TenantCache',
    'PERMISSION_CACHE_TIMEOUT',
    'FEATURE_CACHE_TIMEOUT',
    'RATING_CACHE_TIMEOUT',
    'THROTTLE_CACHE_TIMEOUT',
    'get_user_permissions_key',
    'get_user_roles_key',
    'get_cached_permissions',
    'cache_permissions',
    'get_cached_roles',
    'cache_roles',
    'invalidate_permission_cache',
    'invalidate_all_user_permissions',
    'get_tenant_features_key',
    'get_cached_features',
    'cache_features',
    'invalidate_feature_cache',
    'get_throttle_key',
    'get_throttle_count',
    'increment_throttle',
    'reset_throttle',
    'get_provider_rating_key',
    'get_cached_rating',
    'cache_rating',
    'invalidate_rating_cache',
    'invalidate_services_cache',
    'invalidate_service_category_cache',
    'invalidate_provider_cache',
    'invalidate_blog_cache',
    'invalidate_blog_post_cache',
    'invalidate_blog_category_cache',
    'invalidate_newsletter_cache',
    'invalidate_newsletter_stats_cache',
    'invalidate_appointment_cache',
    'invalidate_appointment_stats_cache',
    'invalidate_dashboard_cache',
    'invalidate_ats_cache',
    'invalidate_hr_cache',
    'invalidate_configurations_cache',
    'connect_cache_signals',
    'connect_services_cache_signals',
    'connect_blog_cache_signals',
    'connect_newsletter_cache_signals',
    'connect_appointment_cache_signals',
    'connect_dashboard_cache_signals',
    'connect_configurations_cache_signals',
    'connect_all_cache_signals',
]
