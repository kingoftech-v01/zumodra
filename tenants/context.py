"""
Tenants Context - Thread-local tenant context management.

This module provides thread-safe tenant context propagation for:
- Background tasks (Celery, Django-Q)
- Signals and hooks
- Utility functions that need tenant awareness
- Management commands

Usage:
    from tenants.context import tenant_context, get_current_tenant

    # Context manager for temporary tenant switching
    with tenant_context(tenant):
        # Code executes in tenant's schema
        do_something()

    # Get current tenant anywhere in code
    tenant = get_current_tenant()
"""

import threading
import logging
from contextvars import ContextVar
from contextlib import contextmanager
from typing import Optional, Any, Callable, TYPE_CHECKING
from functools import wraps

from django.db import connection
from django_tenants.utils import schema_context, get_public_schema_name

if TYPE_CHECKING:
    from tenants.models import Tenant

logger = logging.getLogger(__name__)


# ContextVar for async-safe tenant context (Python 3.7+)
# This works correctly with asyncio, unlike threading.local()
_tenant_context_var: ContextVar[Optional['TenantContext']] = ContextVar(
    'tenant_context', default=None
)

# Thread-local storage for tenant context (fallback for sync operations)
_tenant_context = threading.local()


class TenantContext:
    """
    Thread-local tenant context storage.

    Stores the current tenant and related context for the current thread.
    Used by middleware, background tasks, and utility functions.
    """

    def __init__(self):
        self._tenant: Optional['Tenant'] = None
        self._tenant_settings: Optional[Any] = None
        self._tenant_plan: Optional[Any] = None
        self._stack: list = []  # Stack for nested contexts

    @property
    def tenant(self) -> Optional['Tenant']:
        """Get the current tenant."""
        return self._tenant

    @tenant.setter
    def tenant(self, value: Optional['Tenant']):
        """Set the current tenant."""
        self._tenant = value
        # Clear cached settings when tenant changes
        self._tenant_settings = None
        self._tenant_plan = None

    @property
    def tenant_settings(self) -> Optional[Any]:
        """Get tenant settings, loading lazily if needed."""
        if self._tenant_settings is None and self._tenant:
            try:
                self._tenant_settings = getattr(self._tenant, 'settings', None)
            except Exception:
                pass
        return self._tenant_settings

    @property
    def tenant_plan(self) -> Optional[Any]:
        """Get tenant plan, loading lazily if needed."""
        if self._tenant_plan is None and self._tenant:
            try:
                self._tenant_plan = self._tenant.plan
            except Exception:
                pass
        return self._tenant_plan

    @property
    def schema_name(self) -> str:
        """Get the current schema name."""
        if self._tenant:
            return self._tenant.schema_name
        return get_public_schema_name()

    @property
    def is_public_schema(self) -> bool:
        """Check if current context is public schema."""
        return self.schema_name == get_public_schema_name()

    def push(self):
        """Push current state to stack for nested contexts."""
        self._stack.append({
            'tenant': self._tenant,
            'settings': self._tenant_settings,
            'plan': self._tenant_plan,
        })

    def pop(self):
        """Pop and restore previous state from stack."""
        if self._stack:
            state = self._stack.pop()
            self._tenant = state['tenant']
            self._tenant_settings = state['settings']
            self._tenant_plan = state['plan']
        else:
            self._tenant = None
            self._tenant_settings = None
            self._tenant_plan = None

    def clear(self):
        """Clear all tenant context."""
        self._tenant = None
        self._tenant_settings = None
        self._tenant_plan = None
        self._stack.clear()


def _get_context() -> TenantContext:
    """
    Get or create the tenant context.

    Uses ContextVar for async-safe access (works with asyncio, Celery tasks).
    Falls back to thread-local for sync operations if ContextVar is not set.
    """
    # Try ContextVar first (async-safe)
    ctx = _tenant_context_var.get()
    if ctx is not None:
        return ctx

    # Fallback to thread-local (for backward compatibility with sync code)
    if not hasattr(_tenant_context, 'context'):
        _tenant_context.context = TenantContext()
        # Also set in ContextVar for consistency
        _tenant_context_var.set(_tenant_context.context)
    return _tenant_context.context


def _set_context(ctx: TenantContext) -> None:
    """
    Set the tenant context in both ContextVar and thread-local.

    This ensures consistency across async and sync code paths.
    """
    _tenant_context_var.set(ctx)
    _tenant_context.context = ctx


def get_current_tenant() -> Optional['Tenant']:
    """
    Get the current tenant from thread-local storage.

    Returns:
        Current Tenant instance or None if not in tenant context.

    Example:
        tenant = get_current_tenant()
        if tenant:
            print(f"Current tenant: {tenant.name}")
    """
    return _get_context().tenant


def get_current_tenant_or_fail() -> 'Tenant':
    """
    Get the current tenant, raising an exception if not set.

    Returns:
        Current Tenant instance.

    Raises:
        RuntimeError: If no tenant is set in current context.
    """
    tenant = get_current_tenant()
    if tenant is None:
        raise RuntimeError("No tenant set in current context")
    return tenant


def set_current_tenant(tenant: Optional['Tenant']) -> None:
    """
    Set the current tenant in thread-local storage.

    Args:
        tenant: Tenant instance or None to clear.

    Note:
        Prefer using tenant_context() context manager for temporary switches.
    """
    _get_context().tenant = tenant


def get_current_schema() -> str:
    """
    Get the current schema name.

    Returns:
        Schema name string (tenant schema or 'public').
    """
    return _get_context().schema_name


def is_public_schema() -> bool:
    """
    Check if current context is public schema.

    Returns:
        True if in public schema, False otherwise.
    """
    return _get_context().is_public_schema


def get_tenant_settings() -> Optional[Any]:
    """
    Get the current tenant's settings.

    Returns:
        TenantSettings instance or None.
    """
    return _get_context().tenant_settings


def get_tenant_plan() -> Optional[Any]:
    """
    Get the current tenant's subscription plan.

    Returns:
        Plan instance or None.
    """
    return _get_context().tenant_plan


def clear_tenant_context() -> None:
    """
    Clear all tenant context from both ContextVar and thread-local storage.

    Call this after processing a request or task to prevent context leaks.
    """
    ctx = _tenant_context_var.get()
    if ctx is not None:
        ctx.clear()

    if hasattr(_tenant_context, 'context'):
        _tenant_context.context.clear()

    # Reset ContextVar to None
    _tenant_context_var.set(None)


@contextmanager
def tenant_context(tenant: 'Tenant', activate_schema: bool = True):
    """
    Context manager for executing code in a tenant's context.

    This sets the thread-local tenant and optionally switches the database
    schema. Supports nested usage with proper stack management.

    Args:
        tenant: The tenant to set as current context.
        activate_schema: If True, also switch database schema (default: True).

    Example:
        with tenant_context(tenant):
            # All operations here use tenant's schema
            users = User.objects.all()  # Only this tenant's users

        # Back to previous context

    Note:
        When activate_schema=True, this uses django-tenants schema_context
        internally for proper database isolation.
    """
    ctx = _get_context()
    ctx.push()

    try:
        ctx.tenant = tenant

        if activate_schema and tenant:
            with schema_context(tenant.schema_name):
                logger.debug(f"Entered tenant context: {tenant.schema_name}")
                yield tenant
        else:
            yield tenant
    finally:
        ctx.pop()
        logger.debug("Exited tenant context")


@contextmanager
def public_schema_context():
    """
    Context manager for executing code in the public schema.

    Temporarily switches to public schema, useful when you need to
    access shared data from within a tenant context.

    Example:
        with tenant_context(tenant):
            # In tenant schema
            with public_schema_context():
                # Back to public schema temporarily
                plans = Plan.objects.all()
            # Back to tenant schema
    """
    ctx = _get_context()
    ctx.push()

    try:
        ctx.tenant = None
        with schema_context(get_public_schema_name()):
            yield
    finally:
        ctx.pop()


def tenant_aware(func: Callable) -> Callable:
    """
    Decorator to ensure a function has access to tenant context.

    If called without tenant context, raises RuntimeError.
    Useful for functions that require tenant isolation.

    Example:
        @tenant_aware
        def get_tenant_users():
            tenant = get_current_tenant()
            return User.objects.filter(tenant_memberships__tenant=tenant)
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if get_current_tenant() is None:
            raise RuntimeError(
                f"Function {func.__name__} requires tenant context. "
                "Use tenant_context() context manager or ensure middleware set tenant."
            )
        return func(*args, **kwargs)
    return wrapper


def with_tenant(tenant: 'Tenant'):
    """
    Decorator factory to execute a function in a specific tenant's context.

    Args:
        tenant: The tenant to use for execution.

    Example:
        @with_tenant(my_tenant)
        def do_something():
            # Executes in my_tenant's schema
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            with tenant_context(tenant):
                return func(*args, **kwargs)
        return wrapper
    return decorator


class TenantContextMiddlewareMixin:
    """
    Mixin for middleware that sets tenant context.

    Provides helper methods for setting/clearing tenant context
    that work with both sync and async views.
    """

    def set_tenant_context(self, request, tenant: 'Tenant') -> None:
        """Set tenant in both request and thread-local storage."""
        request.tenant = tenant
        set_current_tenant(tenant)

        # Also cache settings and plan on request for performance
        try:
            request.tenant_settings = getattr(tenant, 'settings', None)
            request.tenant_plan = tenant.plan
        except Exception:
            request.tenant_settings = None
            request.tenant_plan = None

    def clear_tenant_context(self, request) -> None:
        """Clear tenant context after request processing."""
        clear_tenant_context()


# Celery task helpers

def get_tenant_task_kwargs(tenant: 'Tenant') -> dict:
    """
    Get kwargs to pass to a Celery task for tenant context.

    Args:
        tenant: The tenant for task execution.

    Returns:
        Dict with tenant_schema and tenant_id for task restoration.

    Example:
        kwargs = get_tenant_task_kwargs(tenant)
        my_task.delay(**kwargs, other_arg=value)
    """
    return {
        'tenant_schema': tenant.schema_name,
        'tenant_id': tenant.pk,
    }


def restore_tenant_context(tenant_schema: str = None, tenant_id: int = None) -> Optional['Tenant']:
    """
    Restore tenant context in a Celery task.

    Args:
        tenant_schema: Schema name to activate.
        tenant_id: Tenant primary key to load.

    Returns:
        Tenant instance if found, None otherwise.

    Example:
        @shared_task
        def my_task(tenant_schema=None, tenant_id=None, **kwargs):
            tenant = restore_tenant_context(tenant_schema, tenant_id)
            if tenant:
                with tenant_context(tenant):
                    # Task logic here
                    pass
    """
    if not tenant_id:
        return None

    try:
        from tenants.models import Tenant
        tenant = Tenant.objects.get(pk=tenant_id)
        set_current_tenant(tenant)
        return tenant
    except Exception as e:
        logger.error(f"Failed to restore tenant context: {e}")
        return None


class TenantAwareTask:
    """
    Mixin for Celery tasks that require tenant context.

    Automatically restores tenant context from task kwargs and ensures
    proper cleanup after task execution.

    Example:
        from celery import Task

        class MyTask(TenantAwareTask, Task):
            def run(self, *args, **kwargs):
                # self.tenant is available here
                tenant = self.tenant
                ...
    """

    tenant: Optional['Tenant'] = None

    def __call__(self, *args, **kwargs):
        # Extract tenant info from kwargs
        tenant_schema = kwargs.pop('tenant_schema', None)
        tenant_id = kwargs.pop('tenant_id', None)

        try:
            if tenant_id:
                self.tenant = restore_tenant_context(tenant_schema, tenant_id)
                if self.tenant:
                    with tenant_context(self.tenant):
                        return super().__call__(*args, **kwargs)

            return super().__call__(*args, **kwargs)
        finally:
            # CRITICAL: Always clear tenant context after task execution
            # to prevent context leaks between Celery worker task executions
            clear_tenant_context()
            self.tenant = None


# Utility functions for common patterns

def for_each_tenant(func: Callable[['Tenant'], Any], active_only: bool = True) -> list:
    """
    Execute a function for each tenant.

    Args:
        func: Function that takes a Tenant and returns a result.
        active_only: If True, only process active tenants.

    Returns:
        List of (tenant, result) tuples.

    Example:
        def count_users(tenant):
            return User.objects.count()

        results = for_each_tenant(count_users)
        for tenant, count in results:
            print(f"{tenant.name}: {count} users")
    """
    from tenants.models import Tenant

    results = []
    tenants = Tenant.objects.all()

    if active_only:
        tenants = tenants.filter(status=Tenant.TenantStatus.ACTIVE)

    # Exclude public schema
    tenants = tenants.exclude(schema_name=get_public_schema_name())

    for tenant in tenants:
        try:
            with tenant_context(tenant):
                result = func(tenant)
                results.append((tenant, result))
        except Exception as e:
            logger.error(f"Error processing tenant {tenant.name}: {e}")
            results.append((tenant, e))

    return results


def get_tenant_by_request(request) -> Optional['Tenant']:
    """
    Get tenant from request object.

    Checks request.tenant first (set by middleware), then falls back
    to thread-local context.

    Args:
        request: Django HTTP request.

    Returns:
        Tenant instance or None.
    """
    # Try request attribute first (most reliable)
    tenant = getattr(request, 'tenant', None)
    if tenant:
        return tenant

    # Fall back to thread-local
    return get_current_tenant()
