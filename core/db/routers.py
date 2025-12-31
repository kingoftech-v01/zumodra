"""
Database Routers for Zumodra

This module provides database routing for:
- Read replica routing for read-heavy operations
- Tenant-aware routing for multi-tenancy
- Write consistency for critical operations

Designed for scaling to 1M+ users with read/write splitting.
"""

import logging
import random
from typing import Any, Optional, Type

from django.conf import settings
from django.db import models

logger = logging.getLogger(__name__)


class ReadReplicaRouter:
    """
    Database router that directs read queries to replicas.

    Routing logic:
    - Writes (save, delete) always go to 'default' (primary)
    - Reads (get, filter) go to 'replica' if available
    - Migrations always use 'default'
    - Explicit .using() calls are respected

    Configuration:
        In settings.py:
        DATABASE_ROUTERS = ['core.db.routers.ReadReplicaRouter']

        DATABASES = {
            'default': {...},  # Primary for writes
            'replica': {...},  # Read replica
        }

    Usage:
        # Automatic routing
        Employee.objects.filter(status='active')  # -> replica

        # Explicit primary for consistency
        Employee.objects.using('default').get(pk=1)
    """

    # Models that should always use primary (for strong consistency)
    PRIMARY_ONLY_MODELS = {
        'sessions.Session',
        'auth.User',
        'custom_account_u.CustomUser',
        'finance.Transaction',
        'finance.Payment',
    }

    # Apps that should always use primary
    PRIMARY_ONLY_APPS = {
        'sessions',
        'axes',
        'django_celery_beat',
    }

    def db_for_read(self, model: Type[models.Model], **hints: Any) -> Optional[str]:
        """
        Route read queries to replica if available.

        Args:
            model: The model class being queried
            hints: Additional routing hints

        Returns:
            Database alias to use, or None for default behavior
        """
        # Check if replica is configured
        if 'replica' not in settings.DATABASES:
            return 'default'

        # Check if this model requires primary
        model_label = f'{model._meta.app_label}.{model._meta.model_name}'
        if model_label in self.PRIMARY_ONLY_MODELS:
            logger.debug(f"Routing {model_label} read to primary (PRIMARY_ONLY_MODELS)")
            return 'default'

        # Check if this app requires primary
        if model._meta.app_label in self.PRIMARY_ONLY_APPS:
            logger.debug(f"Routing {model_label} read to primary (PRIMARY_ONLY_APPS)")
            return 'default'

        # Check hints for explicit routing
        if hints.get('instance'):
            # If we have an instance, ensure read follows previous write
            instance = hints['instance']
            if hasattr(instance, '_state') and instance._state.db:
                return instance._state.db

        # Route to replica
        logger.debug(f"Routing {model_label} read to replica")
        return 'replica'

    def db_for_write(self, model: Type[models.Model], **hints: Any) -> str:
        """
        Route all write queries to primary.

        Args:
            model: The model class being written
            hints: Additional routing hints

        Returns:
            Database alias for writes (always 'default')
        """
        return 'default'

    def allow_relation(
        self,
        obj1: models.Model,
        obj2: models.Model,
        **hints: Any
    ) -> Optional[bool]:
        """
        Determine if relations between two objects are allowed.

        Relations are allowed between objects on same database
        or between default and replica (they have same data).

        Args:
            obj1: First model instance
            obj2: Second model instance
            hints: Additional routing hints

        Returns:
            True if relation is allowed, False if not, None for default
        """
        # Allow relations within same database
        if obj1._state.db == obj2._state.db:
            return True

        # Allow relations between default and replica
        if {obj1._state.db, obj2._state.db} <= {'default', 'replica'}:
            return True

        return None

    def allow_migrate(
        self,
        db: str,
        app_label: str,
        model_name: Optional[str] = None,
        **hints: Any
    ) -> Optional[bool]:
        """
        Determine if migrations should run on this database.

        Migrations only run on primary (default) database.

        Args:
            db: Database alias
            app_label: App label
            model_name: Model name
            hints: Additional routing hints

        Returns:
            True to allow migration, False to skip, None for default
        """
        # Only migrate on primary
        return db == 'default'


class WeightedReadReplicaRouter(ReadReplicaRouter):
    """
    Read replica router with weighted load balancing.

    Distributes read queries across multiple replicas based on weights.
    Useful when replicas have different capacities.

    Configuration:
        DATABASES = {
            'default': {...},
            'replica1': {...},
            'replica2': {...},
        }

        READ_REPLICA_WEIGHTS = {
            'replica1': 0.6,  # 60% of reads
            'replica2': 0.4,  # 40% of reads
        }
    """

    def __init__(self):
        """Initialize with replica weights from settings."""
        self.replica_weights = getattr(
            settings,
            'READ_REPLICA_WEIGHTS',
            {'replica': 1.0}  # Default: single replica with full weight
        )
        self._replicas = list(self.replica_weights.keys())
        self._weights = list(self.replica_weights.values())

    def _select_replica(self) -> str:
        """Select a replica based on weights."""
        if not self._replicas:
            return 'default'

        # Random weighted selection
        total = sum(self._weights)
        r = random.uniform(0, total)
        upto = 0
        for replica, weight in zip(self._replicas, self._weights):
            upto += weight
            if r <= upto:
                return replica

        return self._replicas[-1]

    def db_for_read(self, model: Type[models.Model], **hints: Any) -> Optional[str]:
        """Route read queries to a weighted random replica."""
        # Check if should use primary
        parent_result = super().db_for_read(model, **hints)
        if parent_result == 'default':
            return 'default'

        # Select weighted replica
        selected = self._select_replica()

        # Verify replica exists
        if selected in settings.DATABASES:
            return selected

        return 'default'


class TenantAwareDatabaseRouter:
    """
    Database router that supports per-tenant database sharding.

    For extremely large deployments, routes different tenants
    to different database clusters.

    Configuration:
        TENANT_DATABASE_MAPPING = {
            'tenant-slug-1': 'cluster_a',
            'tenant-slug-2': 'cluster_b',
            # Default: 'default'
        }

        DATABASES = {
            'default': {...},
            'cluster_a': {...},
            'cluster_b': {...},
        }

    Note: This is for advanced sharding scenarios. Most deployments
    should use django-tenants schema-based isolation instead.
    """

    def __init__(self):
        """Initialize with tenant-to-database mapping."""
        self.tenant_mapping = getattr(
            settings,
            'TENANT_DATABASE_MAPPING',
            {}
        )

    def _get_tenant_database(self) -> str:
        """Get database for current tenant."""
        try:
            from django.db import connection
            tenant = getattr(connection, 'tenant', None)

            if tenant and tenant.slug in self.tenant_mapping:
                return self.tenant_mapping[tenant.slug]

        except Exception as e:
            logger.warning(f"Error getting tenant database: {e}")

        return 'default'

    def db_for_read(self, model: Type[models.Model], **hints: Any) -> Optional[str]:
        """Route reads to tenant-specific database."""
        return self._get_tenant_database()

    def db_for_write(self, model: Type[models.Model], **hints: Any) -> str:
        """Route writes to tenant-specific database."""
        return self._get_tenant_database()

    def allow_relation(
        self,
        obj1: models.Model,
        obj2: models.Model,
        **hints: Any
    ) -> Optional[bool]:
        """Allow relations only within same database."""
        return obj1._state.db == obj2._state.db

    def allow_migrate(
        self,
        db: str,
        app_label: str,
        model_name: Optional[str] = None,
        **hints: Any
    ) -> Optional[bool]:
        """Allow migrations on all databases."""
        return True


class HybridDatabaseRouter(ReadReplicaRouter, TenantAwareDatabaseRouter):
    """
    Combined router with both read replica and tenant sharding support.

    Routing priority:
    1. Tenant-specific database (if configured)
    2. Read replica for reads (if available)
    3. Primary for writes

    Use this for large multi-tenant deployments with read scaling.
    """

    def db_for_read(self, model: Type[models.Model], **hints: Any) -> Optional[str]:
        """Route reads considering both tenant and replica."""
        # First check tenant-specific database
        tenant_db = TenantAwareDatabaseRouter._get_tenant_database(self)

        if tenant_db != 'default':
            # Tenant has dedicated database
            # Check if tenant database has a replica
            tenant_replica = f'{tenant_db}_replica'
            if tenant_replica in settings.DATABASES:
                return tenant_replica
            return tenant_db

        # Fall back to read replica routing
        return ReadReplicaRouter.db_for_read(self, model, **hints)

    def db_for_write(self, model: Type[models.Model], **hints: Any) -> str:
        """Route writes considering tenant sharding."""
        # Check tenant-specific database
        tenant_db = TenantAwareDatabaseRouter._get_tenant_database(self)

        if tenant_db != 'default':
            return tenant_db

        # Fall back to primary
        return 'default'
