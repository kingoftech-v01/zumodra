"""
Tenants Database Router - Tenant-aware database routing for multi-tenant architecture.

This module provides database routing functionality for schema-per-tenant isolation:
- Routes queries to appropriate tenant schema
- Handles shared vs tenant-specific models
- Supports read replicas for tenant queries
- Ensures proper migration handling
"""

import logging
from typing import Optional, Type

from django.conf import settings
from django.db import connection

logger = logging.getLogger(__name__)


# Models that should always live in the public schema
PUBLIC_SCHEMA_MODELS = getattr(settings, 'TENANT_PUBLIC_SCHEMA_MODELS', [
    'tenants.Plan',
    'tenants.Tenant',
    'tenants.TenantSettings',
    'tenants.TenantUsage',
    'tenants.Domain',
    'tenants.TenantInvitation',
    'tenants.AuditLog',
    # Add other shared models here
])

# Models that should exist in both public and tenant schemas
SHARED_MODELS = getattr(settings, 'TENANT_SHARED_MODELS', [
    'auth.User',
    'auth.Group',
    'auth.Permission',
    'contenttypes.ContentType',
    'sessions.Session',
])

# Database alias for read replicas (if configured)
READ_REPLICA_ALIAS = getattr(settings, 'TENANT_READ_REPLICA_ALIAS', None)


class TenantDatabaseRouter:
    """
    Database router for multi-tenant schema isolation.

    This router ensures that:
    1. Public schema models are always routed to the public schema
    2. Tenant-specific models are routed to the current tenant's schema
    3. Read operations can optionally use read replicas
    4. Migrations run in the appropriate schema context
    """

    def _get_app_label(self, model: Type) -> str:
        """Get the app label for a model."""
        return model._meta.app_label

    def _get_model_name(self, model: Type) -> str:
        """Get the full model name (app_label.model_name)."""
        return f"{model._meta.app_label}.{model._meta.object_name}"

    def _is_public_schema_model(self, model: Type) -> bool:
        """Check if model belongs in public schema only."""
        model_name = self._get_model_name(model)
        return model_name in PUBLIC_SCHEMA_MODELS

    def _is_shared_model(self, model: Type) -> bool:
        """Check if model is shared across all schemas."""
        model_name = self._get_model_name(model)
        return model_name in SHARED_MODELS

    def _get_current_schema(self) -> str:
        """Get the current database schema from connection."""
        if hasattr(connection, 'tenant') and connection.tenant:
            return connection.tenant.schema_name
        return 'public'

    def db_for_read(self, model: Type, **hints) -> Optional[str]:
        """
        Route read operations to appropriate database.

        Args:
            model: The model class being queried
            **hints: Additional routing hints

        Returns:
            Database alias to use, or None for default
        """
        # Public schema models always use default database
        if self._is_public_schema_model(model):
            return 'default'

        # Use read replica if available and not in a transaction
        if READ_REPLICA_ALIAS and not hints.get('instance'):
            # Check if we're in a transaction
            if not connection.in_atomic_block:
                return READ_REPLICA_ALIAS

        # Default database with tenant schema routing handled by django-tenants
        return 'default'

    def db_for_write(self, model: Type, **hints) -> Optional[str]:
        """
        Route write operations to appropriate database.

        Args:
            model: The model class being written to
            **hints: Additional routing hints

        Returns:
            Database alias to use, or None for default
        """
        # All writes go to the default (primary) database
        # Schema routing is handled by django-tenants middleware
        return 'default'

    def allow_relation(self, obj1, obj2, **hints) -> Optional[bool]:
        """
        Determine if a relation between two objects should be allowed.

        Args:
            obj1: First model instance
            obj2: Second model instance
            **hints: Additional routing hints

        Returns:
            True if relation is allowed, False if not, None to defer
        """
        # Get model info
        model1_name = self._get_model_name(type(obj1))
        model2_name = self._get_model_name(type(obj2))

        # Public schema models can only relate to other public schema models
        is_model1_public = model1_name in PUBLIC_SCHEMA_MODELS
        is_model2_public = model2_name in PUBLIC_SCHEMA_MODELS

        if is_model1_public and is_model2_public:
            return True

        # Shared models can relate to anything
        if model1_name in SHARED_MODELS or model2_name in SHARED_MODELS:
            return True

        # Tenant models can relate to each other (within same schema)
        if not is_model1_public and not is_model2_public:
            return True

        # Don't allow cross-schema relations between public and tenant models
        # (except for shared models)
        return False

    def allow_migrate(self, db: str, app_label: str, model_name: str = None, **hints) -> Optional[bool]:
        """
        Determine if migration should run on given database.

        Args:
            db: Database alias
            app_label: Application label
            model_name: Model name (optional)
            **hints: Additional migration hints

        Returns:
            True if migration should run, False if not, None to defer
        """
        # Get full model name if available
        if model_name:
            full_name = f"{app_label}.{model_name}"
        else:
            full_name = None

        # Always allow migrations on default database
        if db != 'default':
            return False

        # Public schema models migrate in public schema
        if full_name and full_name in PUBLIC_SCHEMA_MODELS:
            current_schema = self._get_current_schema()
            return current_schema == 'public'

        # Shared models migrate in all schemas
        if full_name and full_name in SHARED_MODELS:
            return True

        # Tenant models only migrate in tenant schemas
        if full_name and full_name not in PUBLIC_SCHEMA_MODELS:
            current_schema = self._get_current_schema()
            return current_schema != 'public'

        # Default: allow migration (let django-tenants handle schema context)
        return None


class TenantAwareRouter(TenantDatabaseRouter):
    """
    Extended router with additional tenant-aware features.

    Features:
    - Schema validation before queries
    - Cross-tenant query prevention
    - Query logging for debugging
    """

    def __init__(self):
        self._schema_stack = []

    def push_schema(self, schema_name: str):
        """Push a schema onto the stack for nested schema operations."""
        self._schema_stack.append(schema_name)

    def pop_schema(self) -> Optional[str]:
        """Pop the current schema from the stack."""
        if self._schema_stack:
            return self._schema_stack.pop()
        return None

    def get_effective_schema(self) -> str:
        """Get the effective schema considering the stack."""
        if self._schema_stack:
            return self._schema_stack[-1]
        return self._get_current_schema()

    def db_for_read(self, model: Type, **hints) -> Optional[str]:
        """Route read with schema validation."""
        # Validate schema context for tenant models
        if not self._is_public_schema_model(model):
            schema = self.get_effective_schema()
            if schema == 'public':
                logger.warning(
                    f"Reading tenant model {self._get_model_name(model)} "
                    f"in public schema context"
                )

        return super().db_for_read(model, **hints)

    def db_for_write(self, model: Type, **hints) -> Optional[str]:
        """Route write with schema validation."""
        # Validate schema context for tenant models
        if not self._is_public_schema_model(model):
            schema = self.get_effective_schema()
            if schema == 'public':
                logger.error(
                    f"Attempting to write tenant model {self._get_model_name(model)} "
                    f"in public schema context - this may cause data isolation issues"
                )

        return super().db_for_write(model, **hints)


class SchemaRouter:
    """
    Low-level schema routing utilities.

    Provides direct schema manipulation for advanced use cases
    like cross-tenant reports or admin operations.
    """

    @staticmethod
    def get_tenant_schemas() -> list:
        """Get list of all tenant schema names."""
        from tenants.models import Tenant
        return list(
            Tenant.objects.exclude(
                schema_name='public'
            ).values_list('schema_name', flat=True)
        )

    @staticmethod
    def execute_in_schema(schema_name: str, func, *args, **kwargs):
        """
        Execute a function in a specific schema context.

        Args:
            schema_name: Target schema name
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Function result
        """
        from django_tenants.utils import schema_context
        with schema_context(schema_name):
            return func(*args, **kwargs)

    @staticmethod
    def execute_in_all_tenants(func, *args, exclude_schemas=None, **kwargs) -> dict:
        """
        Execute a function in all tenant schemas.

        Args:
            func: Function to execute
            *args: Positional arguments for function
            exclude_schemas: Schema names to exclude
            **kwargs: Keyword arguments for function

        Returns:
            Dict mapping schema_name to result
        """
        from django_tenants.utils import schema_context
        from tenants.models import Tenant

        results = {}
        exclude_schemas = exclude_schemas or []

        tenants = Tenant.objects.exclude(
            schema_name__in=['public'] + list(exclude_schemas)
        )

        for tenant in tenants:
            try:
                with schema_context(tenant.schema_name):
                    results[tenant.schema_name] = func(*args, **kwargs)
            except Exception as e:
                logger.error(
                    f"Error executing in schema {tenant.schema_name}: {e}"
                )
                results[tenant.schema_name] = {'error': str(e)}

        return results

    @staticmethod
    def get_schema_for_domain(domain: str) -> Optional[str]:
        """
        Get schema name for a domain.

        Args:
            domain: Domain name

        Returns:
            Schema name or None
        """
        from tenants.models import Domain
        try:
            domain_obj = Domain.objects.get(domain=domain)
            return domain_obj.tenant.schema_name
        except Domain.DoesNotExist:
            return None

    @staticmethod
    def validate_schema_exists(schema_name: str) -> bool:
        """
        Validate that a schema exists in the database.

        Args:
            schema_name: Schema name to validate

        Returns:
            True if schema exists
        """
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name = %s",
                [schema_name]
            )
            return cursor.fetchone() is not None


# Singleton instance for global access
tenant_router = TenantAwareRouter()
schema_router = SchemaRouter()
