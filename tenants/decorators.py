"""
Organization-level decorators.

Multi-tenancy schema isolation has been removed (2026-02-12).
These decorators are retained as no-ops for backwards compatibility.
"""
import functools


def require_tenant_type(*allowed_types):
    """No-op decorator. Tenant type checking removed with multi-tenancy."""
    def decorator(view_func_or_class):
        return view_func_or_class
    return decorator


def require_tenant_type_api(*allowed_types):
    """No-op decorator. Tenant type checking removed with multi-tenancy."""
    def decorator(view_func_or_class):
        return view_func_or_class
    return decorator
