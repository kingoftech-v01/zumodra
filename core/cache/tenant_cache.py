"""
Tenant-aware cache key generation and invalidation.

This module provides:
- Tenant-scoped cache keys
- Cache invalidation signals for permission/role changes
- Feature cache for plan-based access
- Rating cache for service providers
- App-specific cache invalidation

Usage:
    from core.cache import TenantCache, invalidate_permission_cache

    # Get tenant-scoped cache
    cache = TenantCache(tenant_id)
    cache.set('user_permissions', permissions, timeout=300)
    permissions = cache.get('user_permissions')

    # Invalidate permission cache on role change
    invalidate_permission_cache(user_id, tenant_id)
"""

import logging
from typing import Any, List, Optional

from django.core.cache import cache
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.cache')


# Cache timeout constants
PERMISSION_CACHE_TIMEOUT = 300  # 5 minutes
FEATURE_CACHE_TIMEOUT = 600  # 10 minutes
RATING_CACHE_TIMEOUT = 3600  # 1 hour
THROTTLE_CACHE_TIMEOUT = 60  # 1 minute


class TenantCache:
    """
    Tenant-aware cache wrapper.

    Automatically prefixes all cache keys with tenant_id to ensure
    proper isolation between tenants.
    """

    def __init__(self, tenant_id: Optional[int] = None):
        """Initialize with optional tenant_id."""
        self.tenant_id = tenant_id
        self.prefix = f"tenant_{tenant_id}:" if tenant_id else "global:"

    def _make_key(self, key: str) -> str:
        """Generate tenant-scoped cache key."""
        return f"{self.prefix}{key}"

    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache with tenant scope."""
        return cache.get(self._make_key(key), default)

    def set(self, key: str, value: Any, timeout: int = 300) -> None:
        """Set value in cache with tenant scope."""
        cache.set(self._make_key(key), value, timeout)

    def delete(self, key: str) -> None:
        """Delete key from cache with tenant scope."""
        cache.delete(self._make_key(key))

    def delete_pattern(self, pattern: str) -> None:
        """Delete all keys matching pattern using Redis SCAN + DELETE."""
        full_pattern = self._make_key(pattern)
        try:
            # Try to get the underlying Redis client
            # django-redis provides this via get_client()
            client = None
            if hasattr(cache, 'client'):
                # django-redis v5+
                client = cache.client.get_client()
            elif hasattr(cache, '_cache'):
                # Fallback for different cache backends
                if hasattr(cache._cache, 'get_client'):
                    client = cache._cache.get_client()

            if client:
                # Use SCAN to find keys (safer than KEYS for production)
                cursor = 0
                deleted_count = 0
                # Include the cache key prefix in the pattern
                # Django redis uses KEY_PREFIX + KEY_FUNC pattern
                # Default pattern is like ":1:tenant_1:skills:*"
                redis_pattern = f"*{full_pattern}*"
                while True:
                    cursor, keys = client.scan(cursor=cursor, match=redis_pattern, count=100)
                    if keys:
                        client.delete(*keys)
                        deleted_count += len(keys)
                    if cursor == 0:
                        break
                if deleted_count:
                    logger.debug(f"Deleted {deleted_count} keys matching '{redis_pattern}'")
            else:
                # Fallback: try delete_pattern if available
                if hasattr(cache, 'delete_pattern'):
                    cache.delete_pattern(f"{full_pattern}*")
                else:
                    logger.warning(f"Pattern delete not supported for cache backend")
        except Exception as e:
            logger.warning(f"Error during pattern delete: {e}")

    def get_or_set(self, key: str, default_func, timeout: int = 300) -> Any:
        """Get value from cache or set it using default_func."""
        full_key = self._make_key(key)
        value = cache.get(full_key)
        if value is None:
            value = default_func() if callable(default_func) else default_func
            cache.set(full_key, value, timeout)
        return value


# =============================================================================
# PERMISSION CACHE FUNCTIONS
# =============================================================================

def get_user_permissions_key(user_id: int, tenant_id: int) -> str:
    """Generate cache key for user permissions."""
    return f"tenant_{tenant_id}:user_{user_id}:permissions"


def get_user_roles_key(user_id: int, tenant_id: int) -> str:
    """Generate cache key for user roles."""
    return f"tenant_{tenant_id}:user_{user_id}:roles"


def get_cached_permissions(user_id: int, tenant_id: int) -> Optional[set]:
    """Get cached permissions for a user in a tenant."""
    key = get_user_permissions_key(user_id, tenant_id)
    return cache.get(key)


def cache_permissions(user_id: int, tenant_id: int, permissions: set) -> None:
    """Cache permissions for a user in a tenant."""
    key = get_user_permissions_key(user_id, tenant_id)
    cache.set(key, permissions, PERMISSION_CACHE_TIMEOUT)


def get_cached_roles(user_id: int, tenant_id: int) -> Optional[List[str]]:
    """Get cached roles for a user in a tenant."""
    key = get_user_roles_key(user_id, tenant_id)
    return cache.get(key)


def cache_roles(user_id: int, tenant_id: int, roles: List[str]) -> None:
    """Cache roles for a user in a tenant."""
    key = get_user_roles_key(user_id, tenant_id)
    cache.set(key, roles, PERMISSION_CACHE_TIMEOUT)


def invalidate_permission_cache(user_id: int, tenant_id: int) -> None:
    """
    Invalidate permission cache for a user.

    Called when:
    - User role changes
    - User added/removed from groups
    - TenantUser updated
    """
    cache.delete(get_user_permissions_key(user_id, tenant_id))
    cache.delete(get_user_roles_key(user_id, tenant_id))

    security_logger.info(
        f"CACHE_INVALIDATED: type=permissions user={user_id} tenant={tenant_id}"
    )


def invalidate_all_user_permissions(user_id: int) -> None:
    """Invalidate permission cache for a user across all tenants."""
    # This requires pattern matching support in cache backend
    try:
        pattern = f"tenant_*:user_{user_id}:*"
        if hasattr(cache, 'delete_pattern'):
            cache.delete_pattern(pattern)
    except Exception as e:
        logger.warning(f"Could not invalidate all user permissions: {e}")


# =============================================================================
# FEATURE CACHE FUNCTIONS
# =============================================================================

def get_tenant_features_key(tenant_id: int) -> str:
    """Generate cache key for tenant features."""
    return f"tenant_{tenant_id}:features"


def get_cached_features(tenant_id: int) -> Optional[dict]:
    """Get cached features for a tenant."""
    key = get_tenant_features_key(tenant_id)
    return cache.get(key)


def cache_features(tenant_id: int, features: dict) -> None:
    """Cache features for a tenant."""
    key = get_tenant_features_key(tenant_id)
    cache.set(key, features, FEATURE_CACHE_TIMEOUT)


def invalidate_feature_cache(tenant_id: int) -> None:
    """
    Invalidate feature cache for a tenant.

    Called when:
    - Tenant plan changes
    - Feature flags updated
    """
    cache.delete(get_tenant_features_key(tenant_id))

    security_logger.info(
        f"CACHE_INVALIDATED: type=features tenant={tenant_id}"
    )


# =============================================================================
# THROTTLE CACHE FUNCTIONS
# =============================================================================

def get_throttle_key(identifier: str, scope: str) -> str:
    """Generate cache key for rate limiting."""
    return f"throttle:{scope}:{identifier}"


def get_throttle_count(identifier: str, scope: str) -> int:
    """Get current throttle count for an identifier."""
    key = get_throttle_key(identifier, scope)
    return cache.get(key, 0)


def increment_throttle(identifier: str, scope: str, timeout: int = 60) -> int:
    """Increment throttle count for an identifier."""
    key = get_throttle_key(identifier, scope)
    try:
        # Use atomic increment if available
        if hasattr(cache, 'incr'):
            try:
                return cache.incr(key)
            except ValueError:
                # Key doesn't exist
                cache.set(key, 1, timeout)
                return 1
        else:
            count = cache.get(key, 0) + 1
            cache.set(key, count, timeout)
            return count
    except Exception as e:
        logger.error(f"Throttle increment failed: {e}")
        return 0


def reset_throttle(identifier: str, scope: str) -> None:
    """Reset throttle count for an identifier."""
    key = get_throttle_key(identifier, scope)
    cache.delete(key)


# =============================================================================
# RATING CACHE FUNCTIONS
# =============================================================================

def get_provider_rating_key(provider_id: int) -> str:
    """Generate cache key for provider rating."""
    return f"provider_{provider_id}:rating"


def get_cached_rating(provider_id: int) -> Optional[dict]:
    """Get cached rating for a provider."""
    key = get_provider_rating_key(provider_id)
    return cache.get(key)


def cache_rating(provider_id: int, rating_data: dict) -> None:
    """Cache rating data for a provider."""
    key = get_provider_rating_key(provider_id)
    cache.set(key, rating_data, RATING_CACHE_TIMEOUT)


def invalidate_rating_cache(provider_id: int) -> None:
    """
    Invalidate rating cache for a provider.

    Called when:
    - New review added
    - Review updated/deleted
    """
    cache.delete(get_provider_rating_key(provider_id))


# =============================================================================
# APP-SPECIFIC CACHE INVALIDATION FUNCTIONS
# =============================================================================

# Services App Cache Keys
SERVICES_CATEGORIES_CACHE_KEY = "service_categories:list"
SERVICES_FEATURED_CACHE_KEY = "services:featured"
SERVICES_POPULAR_CACHE_KEY = "services:popular"
MARKETPLACE_ANALYTICS_CACHE_KEY = "marketplace:analytics"

# Blog App Cache Keys
BLOG_FEATURED_CACHE_KEY = "blog:featured"
BLOG_CATEGORIES_CACHE_KEY = "blog:categories:list"
BLOG_TAGS_POPULAR_CACHE_KEY = "blog:tags:popular"

# Newsletter App Cache Keys
NEWSLETTER_LIST_CACHE_KEY = "newsletters:list"
NEWSLETTER_STATS_CACHE_KEY = "newsletter:stats"

# Appointment App Cache Keys
APPOINTMENT_SERVICES_CACHE_KEY = "appointment:services:list"
APPOINTMENT_STATS_CACHE_KEY = "appointment:stats"

# Dashboard App Cache Keys
DASHBOARD_OVERVIEW_CACHE_KEY = "dashboard:overview"
DASHBOARD_QUICK_STATS_CACHE_KEY = "dashboard:quick_stats"
DASHBOARD_UPCOMING_INTERVIEWS_CACHE_KEY = "dashboard:upcoming_interviews"
DASHBOARD_ATS_METRICS_CACHE_KEY = "dashboard:ats_metrics"
DASHBOARD_HR_METRICS_CACHE_KEY = "dashboard:hr_metrics"


def invalidate_services_cache(tenant_id: Optional[int] = None) -> None:
    """
    Invalidate all services-related caches.

    Called when:
    - Service created/updated/deleted
    - ServiceCategory created/updated/deleted
    - ServiceProvider verified/updated
    """
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete_pattern(SERVICES_CATEGORIES_CACHE_KEY)
    tenant_cache.delete(SERVICES_FEATURED_CACHE_KEY)
    tenant_cache.delete(SERVICES_POPULAR_CACHE_KEY)
    tenant_cache.delete(MARKETPLACE_ANALYTICS_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=services tenant={tenant_id}")


def invalidate_service_category_cache(tenant_id: Optional[int] = None) -> None:
    """Invalidate service category cache."""
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete_pattern(SERVICES_CATEGORIES_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=service_categories tenant={tenant_id}")


def invalidate_provider_cache(provider_id: int, tenant_id: Optional[int] = None) -> None:
    """
    Invalidate provider-specific caches.

    Called when:
    - Provider profile updated
    - New service added to provider
    - Contract completed
    - Review added
    """
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete(f"provider:{provider_id}:stats")
    # Also invalidate rating cache
    invalidate_rating_cache(provider_id)
    # Invalidate marketplace analytics since provider counts changed
    tenant_cache.delete(MARKETPLACE_ANALYTICS_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=provider provider={provider_id} tenant={tenant_id}")


def invalidate_blog_cache(tenant_id: Optional[int] = None) -> None:
    """
    Invalidate all blog-related caches.

    Called when:
    - BlogPost created/updated/deleted/published
    - Category created/updated/deleted
    - Tag added/removed from post
    """
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete_pattern(BLOG_FEATURED_CACHE_KEY)
    tenant_cache.delete(BLOG_CATEGORIES_CACHE_KEY)
    tenant_cache.delete_pattern(BLOG_TAGS_POPULAR_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=blog tenant={tenant_id}")


def invalidate_blog_post_cache(tenant_id: Optional[int] = None) -> None:
    """Invalidate blog post related caches."""
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete_pattern(BLOG_FEATURED_CACHE_KEY)
    tenant_cache.delete_pattern(BLOG_TAGS_POPULAR_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=blog_posts tenant={tenant_id}")


def invalidate_blog_category_cache(tenant_id: Optional[int] = None) -> None:
    """Invalidate blog category cache."""
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete(BLOG_CATEGORIES_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=blog_categories tenant={tenant_id}")


def invalidate_newsletter_cache(tenant_id: Optional[int] = None) -> None:
    """
    Invalidate all newsletter-related caches.

    Called when:
    - Newsletter created/updated/deleted
    - Subscription created/updated/deleted
    - Message sent
    """
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete_pattern(NEWSLETTER_LIST_CACHE_KEY)
    tenant_cache.delete(NEWSLETTER_STATS_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=newsletter tenant={tenant_id}")


def invalidate_newsletter_stats_cache(tenant_id: Optional[int] = None) -> None:
    """Invalidate newsletter stats cache."""
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete(NEWSLETTER_STATS_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=newsletter_stats tenant={tenant_id}")


def invalidate_appointment_cache(tenant_id: Optional[int] = None) -> None:
    """
    Invalidate all appointment-related caches.

    Called when:
    - Service created/updated/deleted
    - StaffMember created/updated/deleted
    - Appointment created/updated/deleted
    """
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete(APPOINTMENT_SERVICES_CACHE_KEY)
    tenant_cache.delete(APPOINTMENT_STATS_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=appointment tenant={tenant_id}")


def invalidate_appointment_stats_cache(tenant_id: Optional[int] = None) -> None:
    """Invalidate appointment stats cache."""
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete(APPOINTMENT_STATS_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=appointment_stats tenant={tenant_id}")


def invalidate_dashboard_cache(tenant_id: Optional[int] = None, user_id: Optional[int] = None) -> None:
    """
    Invalidate dashboard caches.

    Called when:
    - Job posting created/updated/deleted
    - Candidate created/updated
    - Application status changed
    - Interview scheduled/updated
    - Employee created/updated
    - TimeOff request created/updated
    """
    tenant_cache = TenantCache(tenant_id)

    # Invalidate tenant-wide dashboard caches
    tenant_cache.delete(DASHBOARD_QUICK_STATS_CACHE_KEY)
    tenant_cache.delete_pattern(DASHBOARD_UPCOMING_INTERVIEWS_CACHE_KEY)
    tenant_cache.delete(DASHBOARD_ATS_METRICS_CACHE_KEY)
    tenant_cache.delete(DASHBOARD_HR_METRICS_CACHE_KEY)

    # Invalidate user-specific dashboard overview if user_id provided
    if user_id:
        tenant_cache.delete(f"{DASHBOARD_OVERVIEW_CACHE_KEY}:user_{user_id}")
    else:
        # Invalidate all user overviews for this tenant
        tenant_cache.delete_pattern(DASHBOARD_OVERVIEW_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=dashboard tenant={tenant_id} user={user_id}")


def invalidate_ats_cache(tenant_id: Optional[int] = None) -> None:
    """
    Invalidate ATS-related dashboard caches.

    Called when ATS models change (jobs, candidates, applications, interviews).
    """
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete(DASHBOARD_QUICK_STATS_CACHE_KEY)
    tenant_cache.delete_pattern(DASHBOARD_UPCOMING_INTERVIEWS_CACHE_KEY)
    tenant_cache.delete(DASHBOARD_ATS_METRICS_CACHE_KEY)
    tenant_cache.delete_pattern(DASHBOARD_OVERVIEW_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=ats tenant={tenant_id}")


def invalidate_hr_cache(tenant_id: Optional[int] = None) -> None:
    """
    Invalidate HR-related dashboard caches.

    Called when HR models change (employees, time-off requests).
    """
    tenant_cache = TenantCache(tenant_id)
    tenant_cache.delete(DASHBOARD_HR_METRICS_CACHE_KEY)
    tenant_cache.delete_pattern(DASHBOARD_OVERVIEW_CACHE_KEY)

    logger.info(f"CACHE_INVALIDATED: type=hr tenant={tenant_id}")


def invalidate_configurations_cache(tenant_id: Optional[int] = None) -> None:
    """
    Invalidate configurations-related caches.

    Called when:
    - Skill created/updated/deleted
    - FAQ created/updated/deleted
    - Testimonial created/updated/deleted
    """
    tenant_cache = TenantCache(tenant_id)
    # Use patterns that match the actual cache keys used in viewsets
    tenant_cache.delete_pattern("skills:")
    tenant_cache.delete_pattern("faqs:")
    tenant_cache.delete_pattern("testimonials:")

    logger.info(f"CACHE_INVALIDATED: type=configurations tenant={tenant_id}")


# =============================================================================
# SIGNAL HANDLERS FOR CACHE INVALIDATION
# =============================================================================

def connect_cache_signals():
    """Connect signal handlers for automatic cache invalidation."""
    try:
        from accounts.models import TenantUser

        @receiver(post_save, sender=TenantUser)
        def invalidate_on_tenant_user_change(sender, instance, **kwargs):
            """Invalidate permission cache when TenantUser is updated."""
            if instance.user_id and instance.tenant_id:
                invalidate_permission_cache(instance.user_id, instance.tenant_id)

        @receiver(post_delete, sender=TenantUser)
        def invalidate_on_tenant_user_delete(sender, instance, **kwargs):
            """Invalidate permission cache when TenantUser is deleted."""
            if instance.user_id and instance.tenant_id:
                invalidate_permission_cache(instance.user_id, instance.tenant_id)

        logger.info("Cache invalidation signals connected")

    except ImportError:
        logger.warning("Could not connect cache signals - models not available")


def connect_services_cache_signals():
    """Connect signal handlers for services app cache invalidation."""
    try:
        from services.models import (
            ServiceCategory, Service, ServiceProvider, ServiceContract, ServiceReview
        )

        @receiver(post_save, sender=ServiceCategory)
        @receiver(post_delete, sender=ServiceCategory)
        def invalidate_on_category_change(sender, instance, **kwargs):
            """Invalidate category cache when category changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_service_category_cache(tenant_id)

        @receiver(post_save, sender=Service)
        @receiver(post_delete, sender=Service)
        def invalidate_on_service_change(sender, instance, **kwargs):
            """Invalidate service caches when service changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_services_cache(tenant_id)
            # Also invalidate provider cache if provider exists
            if hasattr(instance, 'provider') and instance.provider:
                invalidate_provider_cache(instance.provider.id, tenant_id)

        @receiver(post_save, sender=ServiceProvider)
        @receiver(post_delete, sender=ServiceProvider)
        def invalidate_on_provider_change(sender, instance, **kwargs):
            """Invalidate provider cache when provider changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_provider_cache(instance.id, tenant_id)

        @receiver(post_save, sender=ServiceContract)
        def invalidate_on_contract_change(sender, instance, **kwargs):
            """Invalidate caches when contract status changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            if hasattr(instance, 'provider') and instance.provider:
                invalidate_provider_cache(instance.provider.id, tenant_id)
            invalidate_services_cache(tenant_id)

        @receiver(post_save, sender=ServiceReview)
        @receiver(post_delete, sender=ServiceReview)
        def invalidate_on_review_change(sender, instance, **kwargs):
            """Invalidate provider cache when review changes."""
            if hasattr(instance, 'provider') and instance.provider:
                tenant_id = getattr(instance.provider, 'tenant_id', None)
                invalidate_provider_cache(instance.provider.id, tenant_id)

        logger.info("Services cache invalidation signals connected")

    except ImportError as e:
        logger.warning(f"Could not connect services cache signals: {e}")


def connect_blog_cache_signals():
    """Connect signal handlers for blog app cache invalidation."""
    try:
        from blog.models import BlogPostPage, CategoryPage

        @receiver(post_save, sender=BlogPostPage)
        @receiver(post_delete, sender=BlogPostPage)
        def invalidate_on_post_change(sender, instance, **kwargs):
            """Invalidate blog cache when post changes."""
            invalidate_blog_post_cache(None)  # Blog is typically global

        @receiver(post_save, sender=CategoryPage)
        @receiver(post_delete, sender=CategoryPage)
        def invalidate_on_blog_category_change(sender, instance, **kwargs):
            """Invalidate category cache when category changes."""
            invalidate_blog_category_cache(None)

        logger.info("Blog cache invalidation signals connected")

    except ImportError as e:
        logger.warning(f"Could not connect blog cache signals: {e}")


def connect_newsletter_cache_signals():
    """Connect signal handlers for newsletter app cache invalidation."""
    try:
        from newsletter.models import Newsletter, Subscription, Message, Submission

        @receiver(post_save, sender=Newsletter)
        @receiver(post_delete, sender=Newsletter)
        def invalidate_on_newsletter_change(sender, instance, **kwargs):
            """Invalidate newsletter cache when newsletter changes."""
            invalidate_newsletter_cache(None)

        @receiver(post_save, sender=Subscription)
        @receiver(post_delete, sender=Subscription)
        def invalidate_on_subscription_change(sender, instance, **kwargs):
            """Invalidate newsletter stats when subscription changes."""
            invalidate_newsletter_stats_cache(None)

        @receiver(post_save, sender=Message)
        @receiver(post_save, sender=Submission)
        def invalidate_on_message_change(sender, instance, **kwargs):
            """Invalidate newsletter stats when message/submission sent."""
            invalidate_newsletter_stats_cache(None)

        logger.info("Newsletter cache invalidation signals connected")

    except ImportError as e:
        logger.warning(f"Could not connect newsletter cache signals: {e}")


def connect_appointment_cache_signals():
    """Connect signal handlers for appointment app cache invalidation."""
    try:
        from appointment.models import Service, StaffMember, Appointment

        @receiver(post_save, sender=Service)
        @receiver(post_delete, sender=Service)
        def invalidate_on_appointment_service_change(sender, instance, **kwargs):
            """Invalidate appointment cache when service changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_appointment_cache(tenant_id)

        @receiver(post_save, sender=StaffMember)
        @receiver(post_delete, sender=StaffMember)
        def invalidate_on_staff_change(sender, instance, **kwargs):
            """Invalidate appointment cache when staff changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_appointment_cache(tenant_id)

        @receiver(post_save, sender=Appointment)
        @receiver(post_delete, sender=Appointment)
        def invalidate_on_appointment_change(sender, instance, **kwargs):
            """Invalidate appointment stats when appointment changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_appointment_stats_cache(tenant_id)

        logger.info("Appointment cache invalidation signals connected")

    except ImportError as e:
        logger.warning(f"Could not connect appointment cache signals: {e}")


def connect_dashboard_cache_signals():
    """Connect signal handlers for dashboard-related cache invalidation."""
    try:
        from ats.models import JobPosting, Candidate, Application, Interview
        from hr_core.models import Employee, TimeOffRequest

        # ATS model signals
        @receiver(post_save, sender=JobPosting)
        @receiver(post_delete, sender=JobPosting)
        def invalidate_on_job_change(sender, instance, **kwargs):
            """Invalidate ATS cache when job changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_ats_cache(tenant_id)

        @receiver(post_save, sender=Candidate)
        @receiver(post_delete, sender=Candidate)
        def invalidate_on_candidate_change(sender, instance, **kwargs):
            """Invalidate ATS cache when candidate changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_ats_cache(tenant_id)

        @receiver(post_save, sender=Application)
        @receiver(post_delete, sender=Application)
        def invalidate_on_application_change(sender, instance, **kwargs):
            """Invalidate ATS cache when application changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_ats_cache(tenant_id)

        @receiver(post_save, sender=Interview)
        @receiver(post_delete, sender=Interview)
        def invalidate_on_interview_change(sender, instance, **kwargs):
            """Invalidate dashboard cache when interview changes."""
            tenant_id = None
            if hasattr(instance, 'application') and instance.application:
                tenant_id = getattr(instance.application, 'tenant_id', None)
            invalidate_ats_cache(tenant_id)

        # HR model signals
        @receiver(post_save, sender=Employee)
        @receiver(post_delete, sender=Employee)
        def invalidate_on_employee_change(sender, instance, **kwargs):
            """Invalidate HR cache when employee changes."""
            tenant_id = None
            if hasattr(instance, 'user') and instance.user:
                tenant_user = getattr(instance.user, 'tenantuser_set', None)
                if tenant_user and tenant_user.exists():
                    tenant_id = tenant_user.first().tenant_id
            invalidate_hr_cache(tenant_id)

        @receiver(post_save, sender=TimeOffRequest)
        @receiver(post_delete, sender=TimeOffRequest)
        def invalidate_on_timeoff_change(sender, instance, **kwargs):
            """Invalidate HR cache when time-off request changes."""
            tenant_id = None
            if hasattr(instance, 'employee') and instance.employee:
                if hasattr(instance.employee, 'user') and instance.employee.user:
                    tenant_user = getattr(instance.employee.user, 'tenantuser_set', None)
                    if tenant_user and tenant_user.exists():
                        tenant_id = tenant_user.first().tenant_id
            invalidate_hr_cache(tenant_id)

        logger.info("Dashboard cache invalidation signals connected")

    except ImportError as e:
        logger.warning(f"Could not connect dashboard cache signals: {e}")


def connect_configurations_cache_signals():
    """Connect signal handlers for configurations app cache invalidation."""
    try:
        from configurations.models import Skill, FAQEntry, Testimonial

        @receiver(post_save, sender=Skill)
        @receiver(post_delete, sender=Skill)
        def invalidate_on_skill_change(sender, instance, **kwargs):
            """Invalidate configurations cache when skill changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_configurations_cache(tenant_id)

        @receiver(post_save, sender=FAQEntry)
        @receiver(post_delete, sender=FAQEntry)
        def invalidate_on_faq_change(sender, instance, **kwargs):
            """Invalidate configurations cache when FAQ changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_configurations_cache(tenant_id)

        @receiver(post_save, sender=Testimonial)
        @receiver(post_delete, sender=Testimonial)
        def invalidate_on_testimonial_change(sender, instance, **kwargs):
            """Invalidate configurations cache when testimonial changes."""
            tenant_id = getattr(instance, 'tenant_id', None)
            invalidate_configurations_cache(tenant_id)

        logger.info("Configurations cache invalidation signals connected")

    except ImportError as e:
        logger.warning(f"Could not connect configurations cache signals: {e}")


def connect_all_cache_signals():
    """Connect all cache invalidation signals."""
    connect_cache_signals()
    connect_services_cache_signals()
    connect_blog_cache_signals()
    connect_newsletter_cache_signals()
    connect_appointment_cache_signals()
    connect_dashboard_cache_signals()
    connect_configurations_cache_signals()
    logger.info("All cache invalidation signals connected")
