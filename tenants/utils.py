"""
Tenants Utils - Helper functions and utilities for multi-tenant operations.

This module provides:
- Schema switching context managers
- Tenant URL generation
- Tenant resolution helpers
- Cache utilities
- Decorator helpers for tenant-aware views
"""

import functools
import logging
from contextlib import contextmanager
from typing import Optional, Callable, Any, List, Union
from urllib.parse import urljoin, urlparse

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.http import HttpRequest

logger = logging.getLogger(__name__)


# Configuration - domain settings from centralized config
# No hard-coded domain fallbacks - use settings.py defaults
TENANT_BASE_DOMAIN = getattr(settings, 'TENANT_BASE_DOMAIN', '')
# Protocol: https for production, http for development (localhost)
_is_dev = getattr(settings, 'DEBUG', False) or 'localhost' in TENANT_BASE_DOMAIN
TENANT_PROTOCOL = getattr(settings, 'TENANT_PROTOCOL', 'http' if _is_dev else 'https')
TENANT_CACHE_PREFIX = 'tenant:'
TENANT_CACHE_TIMEOUT = getattr(settings, 'TENANT_CACHE_TIMEOUT', 300)


# =============================================================================
# Context Managers
# =============================================================================

@contextmanager
def tenant_context(tenant):
    """
    Context manager for executing code within a tenant's schema context.

    DEPRECATED: Use tenants.context.tenant_context() instead for full
    thread-local and ContextVar support with async safety.

    This is a simplified wrapper that only handles schema switching.
    For complete tenant context management (including thread-local storage
    and async support), use the implementation in tenants.context.

    Usage:
        # Preferred approach:
        from tenants.context import tenant_context
        with tenant_context(tenant):
            users = User.objects.all()

        # Legacy approach (schema-only):
        from tenants.utils import tenant_context
        with tenant_context(tenant):
            users = User.objects.all()

    Args:
        tenant: Tenant instance or schema_name string
    """
    from tenants.context import tenant_context as full_tenant_context

    # If string schema name provided, just do schema switch
    if isinstance(tenant, str):
        from django_tenants.utils import schema_context
        with schema_context(tenant):
            yield
    else:
        # Use the full tenant_context from context.py for proper async safety
        with full_tenant_context(tenant, activate_schema=True):
            yield


@contextmanager
def public_schema_context():
    """
    Context manager for executing code in the public schema.

    DEPRECATED: Use tenants.context.public_schema_context() instead for full
    thread-local and ContextVar support with async safety.

    Usage:
        # Preferred approach:
        from tenants.context import public_schema_context
        with public_schema_context():
            tenants = Tenant.objects.all()

        # Legacy approach:
        from tenants.utils import public_schema_context
        with public_schema_context():
            tenants = Tenant.objects.all()
    """
    from tenants.context import public_schema_context as full_public_schema_context
    with full_public_schema_context():
        yield


@contextmanager
def tenant_connection(tenant):
    """
    Context manager that sets up the database connection for a tenant.

    This is a lower-level context manager that directly manipulates
    the database connection's tenant setting.

    Usage:
        with tenant_connection(tenant):
            # Database connection is now set to tenant's schema
            pass
    """
    previous_tenant = getattr(connection, 'tenant', None)
    try:
        connection.set_tenant(tenant)
        yield
    finally:
        if previous_tenant:
            connection.set_tenant(previous_tenant)
        else:
            # Reset to public schema
            from tenants.models import Tenant
            public_tenant = Tenant.objects.filter(schema_name='public').first()
            if public_tenant:
                connection.set_tenant(public_tenant)


def _is_valid_schema_name(schema_name: str) -> bool:
    """
    Validate that a schema name is safe for use in SQL queries.

    SECURITY: Prevents SQL injection by validating schema name format.

    Args:
        schema_name: Schema name to validate

    Returns:
        True if valid, False otherwise
    """
    import re

    if not schema_name:
        return False

    # Schema names must be alphanumeric with underscores only
    # and must start with a letter or underscore
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', schema_name):
        return False

    # Maximum length for PostgreSQL identifiers is 63 characters
    if len(schema_name) > 63:
        return False

    # Disallow PostgreSQL reserved schemas that could be dangerous
    reserved_schemas = {'pg_catalog', 'information_schema', 'pg_toast', 'pg_temp'}
    if schema_name.lower() in reserved_schemas:
        return False

    return True


@contextmanager
def temporary_schema(schema_name: str):
    """
    Context manager for temporarily switching to a specific schema.

    This is useful for cross-tenant operations or admin tasks.

    SECURITY: Uses psycopg2.sql.Identifier for safe schema name handling
    to prevent SQL injection attacks.

    Usage:
        with temporary_schema('tenant_acme'):
            # Operations use tenant_acme schema
            pass
        # Back to original schema

    Args:
        schema_name: Target schema name

    Raises:
        ValueError: If schema name is invalid
    """
    from django.db import connection as db_connection

    # SECURITY FIX: Validate schema name to prevent injection
    if not _is_valid_schema_name(schema_name):
        raise ValueError(f"Invalid schema name: {schema_name}")

    # Store current schema
    with db_connection.cursor() as cursor:
        cursor.execute("SELECT current_schema()")
        previous_schema = cursor.fetchone()[0]

    try:
        # SECURITY FIX: Use parameterized query with psycopg2.sql.Identifier
        # for safe schema name handling
        with db_connection.cursor() as cursor:
            from psycopg2 import sql
            cursor.execute(
                sql.SQL("SET search_path TO {}").format(
                    sql.Identifier(schema_name)
                )
            )
        yield
    finally:
        # Restore previous schema using safe identifier
        with db_connection.cursor() as cursor:
            from psycopg2 import sql
            if previous_schema and _is_valid_schema_name(previous_schema):
                cursor.execute(
                    sql.SQL("SET search_path TO {}").format(
                        sql.Identifier(previous_schema)
                    )
                )
            else:
                cursor.execute(
                    sql.SQL("SET search_path TO {}").format(
                        sql.Identifier('public')
                    )
                )


@contextmanager
def all_tenants_context(exclude_schemas: List[str] = None):
    """
    Context manager that yields each tenant in sequence.

    Usage:
        with all_tenants_context() as tenants:
            for tenant in tenants:
                with tenant_context(tenant):
                    # Do something in each tenant's schema
                    pass

    Args:
        exclude_schemas: List of schema names to exclude
    """
    from tenants.models import Tenant

    exclude_schemas = exclude_schemas or []
    tenants = Tenant.objects.exclude(
        schema_name__in=['public'] + exclude_schemas
    )

    yield tenants


# =============================================================================
# URL Generation
# =============================================================================

def get_tenant_url(tenant, path: str = '', include_protocol: bool = True) -> str:
    """
    Generate a URL for a specific tenant.

    Args:
        tenant: Tenant instance
        path: Optional path to append
        include_protocol: Whether to include https://

    Returns:
        Full URL for the tenant
    """
    # Get primary domain
    primary_domain = tenant.domains.filter(is_primary=True).first()

    if primary_domain:
        domain = primary_domain.domain
    else:
        # Generate subdomain URL
        domain = f"{tenant.slug}.{TENANT_BASE_DOMAIN}"

    if include_protocol:
        base_url = f"{TENANT_PROTOCOL}://{domain}"
    else:
        base_url = domain

    if path:
        return urljoin(base_url + '/', path.lstrip('/'))

    return base_url


def get_tenant_admin_url(tenant, path: str = '') -> str:
    """
    Generate admin URL for a tenant.

    Args:
        tenant: Tenant instance
        path: Optional admin path

    Returns:
        Admin URL for the tenant
    """
    base_path = f"/admin/{path}" if path else "/admin/"
    return get_tenant_url(tenant, base_path)


def get_tenant_api_url(tenant, endpoint: str = '') -> str:
    """
    Generate API URL for a tenant.

    Args:
        tenant: Tenant instance
        endpoint: API endpoint path

    Returns:
        API URL for the tenant
    """
    api_path = f"/api/v1/{endpoint}" if endpoint else "/api/v1/"
    return get_tenant_url(tenant, api_path)


def get_careers_url(tenant, job_slug: str = None) -> str:
    """
    Generate public careers page URL for a tenant.

    Args:
        tenant: Tenant instance
        job_slug: Optional job posting slug

    Returns:
        Careers page URL
    """
    # Check for dedicated careers domain
    careers_domain = tenant.domains.filter(is_careers_domain=True).first()

    if careers_domain:
        base_url = f"{TENANT_PROTOCOL}://{careers_domain.domain}"
    else:
        base_url = get_tenant_url(tenant, '/careers')

    if job_slug:
        return f"{base_url}/jobs/{job_slug}/"

    return base_url


def build_tenant_url_from_request(request: HttpRequest, path: str = '') -> str:
    """
    Build a URL for the current tenant from a request.

    Args:
        request: HTTP request with tenant context
        path: Optional path to append

    Returns:
        Full URL for current tenant
    """
    if not hasattr(request, 'tenant') or not request.tenant:
        return path

    scheme = 'https' if request.is_secure() else 'http'
    host = request.get_host()

    if path:
        return f"{scheme}://{host}{path}"

    return f"{scheme}://{host}"


# =============================================================================
# Tenant Resolution Helpers
# =============================================================================

def get_tenant_from_request(request: HttpRequest):
    """
    Get tenant from request object.

    Args:
        request: HTTP request

    Returns:
        Tenant instance or None
    """
    return getattr(request, 'tenant', None)


def get_tenant_by_slug(slug: str):
    """
    Get tenant by slug.

    Args:
        slug: Tenant slug

    Returns:
        Tenant instance or None
    """
    from tenants.models import Tenant

    cache_key = f"{TENANT_CACHE_PREFIX}slug:{slug}"
    tenant_id = cache.get(cache_key)

    if tenant_id:
        try:
            return Tenant.objects.get(id=tenant_id)
        except Tenant.DoesNotExist:
            cache.delete(cache_key)

    try:
        tenant = Tenant.objects.get(slug=slug)
        cache.set(cache_key, tenant.id, TENANT_CACHE_TIMEOUT)
        return tenant
    except Tenant.DoesNotExist:
        return None


def get_tenant_by_uuid(uuid_str: str):
    """
    Get tenant by UUID.

    Args:
        uuid_str: Tenant UUID string

    Returns:
        Tenant instance or None
    """
    from tenants.models import Tenant

    cache_key = f"{TENANT_CACHE_PREFIX}uuid:{uuid_str}"
    tenant_id = cache.get(cache_key)

    if tenant_id:
        try:
            return Tenant.objects.get(id=tenant_id)
        except Tenant.DoesNotExist:
            cache.delete(cache_key)

    try:
        tenant = Tenant.objects.get(uuid=uuid_str)
        cache.set(cache_key, tenant.id, TENANT_CACHE_TIMEOUT)
        return tenant
    except Tenant.DoesNotExist:
        return None


def get_tenant_by_domain(domain: str):
    """
    Get tenant by domain name.

    Args:
        domain: Domain name

    Returns:
        Tenant instance or None
    """
    from tenants.models import Domain

    cache_key = f"{TENANT_CACHE_PREFIX}domain:{domain}"
    tenant_id = cache.get(cache_key)

    if tenant_id:
        from tenants.models import Tenant
        try:
            return Tenant.objects.get(id=tenant_id)
        except Tenant.DoesNotExist:
            cache.delete(cache_key)

    try:
        domain_obj = Domain.objects.select_related('tenant').get(domain=domain)
        tenant = domain_obj.tenant
        cache.set(cache_key, tenant.id, TENANT_CACHE_TIMEOUT)
        return tenant
    except Domain.DoesNotExist:
        return None


def get_current_tenant():
    """
    Get the current tenant from thread-local/ContextVar storage.

    DEPRECATED: Use tenants.context.get_current_tenant() directly for consistency.

    This function now delegates to tenants.context.get_current_tenant() which
    provides async-safe tenant context via ContextVar.

    Returns:
        Tenant instance or None
    """
    from tenants.context import get_current_tenant as ctx_get_current_tenant
    return ctx_get_current_tenant()


def get_current_schema() -> str:
    """
    Get the current schema name.

    DEPRECATED: Use tenants.context.get_current_schema() directly for consistency.

    Returns:
        Schema name string
    """
    from tenants.context import get_current_schema as ctx_get_current_schema
    return ctx_get_current_schema()


# =============================================================================
# Cache Utilities
# =============================================================================

def get_tenant_cache_key(tenant, key: str) -> str:
    """
    Generate a tenant-scoped cache key.

    Args:
        tenant: Tenant instance or ID
        key: Base cache key

    Returns:
        Scoped cache key
    """
    tenant_id = tenant.id if hasattr(tenant, 'id') else tenant
    return f"tenant:{tenant_id}:{key}"


def get_tenant_cached(tenant, key: str, default=None):
    """
    Get a tenant-scoped cached value.

    Args:
        tenant: Tenant instance
        key: Cache key
        default: Default value if not found

    Returns:
        Cached value or default
    """
    cache_key = get_tenant_cache_key(tenant, key)
    return cache.get(cache_key, default)


def set_tenant_cached(tenant, key: str, value: Any, timeout: int = None):
    """
    Set a tenant-scoped cached value.

    Args:
        tenant: Tenant instance
        key: Cache key
        value: Value to cache
        timeout: Cache timeout in seconds
    """
    cache_key = get_tenant_cache_key(tenant, key)
    cache.set(cache_key, value, timeout or TENANT_CACHE_TIMEOUT)


def delete_tenant_cached(tenant, key: str):
    """
    Delete a tenant-scoped cached value.

    Args:
        tenant: Tenant instance
        key: Cache key
    """
    cache_key = get_tenant_cache_key(tenant, key)
    cache.delete(cache_key)


def invalidate_tenant_cache(tenant):
    """
    Invalidate all cache entries for a tenant.

    Note: This requires Redis with pattern deletion support.

    Args:
        tenant: Tenant instance
    """
    from django.core.cache import caches

    # Get Redis cache backend if available
    try:
        redis_cache = caches['default']
        if hasattr(redis_cache, 'delete_pattern'):
            pattern = f"tenant:{tenant.id}:*"
            redis_cache.delete_pattern(pattern)
    except Exception as e:
        logger.warning(f"Could not invalidate tenant cache: {e}")


# =============================================================================
# Decorators
# =============================================================================

def tenant_required(view_func: Callable) -> Callable:
    """
    Decorator that ensures a tenant context exists.

    Usage:
        @tenant_required
        def my_view(request):
            # request.tenant is guaranteed to exist
            pass
    """
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        from django.http import HttpResponseForbidden

        if not hasattr(request, 'tenant') or not request.tenant:
            return HttpResponseForbidden("Tenant context required")

        return view_func(request, *args, **kwargs)

    return wrapper


def feature_required(feature_name: str):
    """
    Decorator that checks if tenant has access to a feature.

    Usage:
        @feature_required('analytics')
        def analytics_view(request):
            pass
    """
    def decorator(view_func: Callable) -> Callable:
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            from django.http import HttpResponseForbidden

            if not hasattr(request, 'can_access_feature'):
                return HttpResponseForbidden("Feature check not available")

            if not request.can_access_feature(feature_name):
                return HttpResponseForbidden(
                    f"Feature '{feature_name}' not available in your plan"
                )

            return view_func(request, *args, **kwargs)

        return wrapper
    return decorator


def within_limit(resource: str, increment: int = 1):
    """
    Decorator that checks if tenant is within resource limits.

    Usage:
        @within_limit('users')
        def create_user_view(request):
            pass
    """
    def decorator(view_func: Callable) -> Callable:
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            from django.http import HttpResponseForbidden

            if not hasattr(request, 'is_within_limit'):
                return HttpResponseForbidden("Limit check not available")

            if not request.is_within_limit(resource, increment):
                return HttpResponseForbidden(
                    f"Resource limit reached for '{resource}'. "
                    "Please upgrade your plan."
                )

            return view_func(request, *args, **kwargs)

        return wrapper
    return decorator


def run_in_tenant_schema(tenant):
    """
    Decorator that runs a function in a specific tenant's schema.

    Usage:
        @run_in_tenant_schema(my_tenant)
        def my_function():
            # Runs in my_tenant's schema
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with tenant_context(tenant):
                return func(*args, **kwargs)
        return wrapper
    return decorator


def run_in_public_schema(func: Callable) -> Callable:
    """
    Decorator that runs a function in the public schema.

    Usage:
        @run_in_public_schema
        def my_function():
            # Runs in public schema
            pass
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        with public_schema_context():
            return func(*args, **kwargs)
    return wrapper


# =============================================================================
# Validation Helpers
# =============================================================================

def is_valid_subdomain(subdomain: str) -> bool:
    """
    Validate a subdomain string.

    Args:
        subdomain: Subdomain to validate

    Returns:
        True if valid
    """
    import re

    if not subdomain:
        return False

    # Must be lowercase alphanumeric with hyphens
    if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', subdomain):
        return False

    # Reserved subdomains
    reserved = ['www', 'api', 'admin', 'app', 'mail', 'ftp', 'static', 'cdn']
    if subdomain in reserved:
        return False

    # Length check
    if len(subdomain) < 3 or len(subdomain) > 63:
        return False

    return True


def is_valid_domain(domain: str) -> bool:
    """
    Validate a domain string.

    Args:
        domain: Domain to validate

    Returns:
        True if valid
    """
    import re

    if not domain:
        return False

    # Basic domain validation
    pattern = r'^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$'
    return bool(re.match(pattern, domain.lower()))


def generate_unique_slug(name: str, model_class=None) -> str:
    """
    Generate a unique slug for a tenant.

    Args:
        name: Base name for slug
        model_class: Model class to check uniqueness against

    Returns:
        Unique slug string
    """
    from django.utils.text import slugify

    base_slug = slugify(name)[:50]
    slug = base_slug

    if model_class:
        counter = 1
        while model_class.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1

    return slug


# =============================================================================
# Data Migration Helpers
# =============================================================================

def copy_model_to_tenant(instance, target_tenant, exclude_fields: List[str] = None):
    """
    Copy a model instance to another tenant's schema.

    Args:
        instance: Model instance to copy
        target_tenant: Target tenant
        exclude_fields: Fields to exclude from copy

    Returns:
        New instance in target tenant's schema
    """
    exclude_fields = exclude_fields or ['id', 'pk']

    model_class = type(instance)
    data = {}

    for field in model_class._meta.fields:
        if field.name not in exclude_fields:
            data[field.name] = getattr(instance, field.name)

    with tenant_context(target_tenant):
        new_instance = model_class.objects.create(**data)

    return new_instance


def bulk_execute_in_tenants(
    func: Callable,
    *args,
    tenant_filter: dict = None,
    parallel: bool = False,
    **kwargs
) -> dict:
    """
    Execute a function in multiple tenant schemas.

    Args:
        func: Function to execute
        *args: Positional arguments
        tenant_filter: Filter dict for tenant queryset
        parallel: Whether to run in parallel (requires celery)
        **kwargs: Keyword arguments

    Returns:
        Dict mapping tenant slug to result
    """
    from tenants.models import Tenant

    tenant_filter = tenant_filter or {}
    tenants = Tenant.objects.filter(**tenant_filter).exclude(schema_name='public')

    results = {}

    for tenant in tenants:
        try:
            with tenant_context(tenant):
                results[tenant.slug] = func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error executing in tenant {tenant.slug}: {e}")
            results[tenant.slug] = {'error': str(e)}

    return results
