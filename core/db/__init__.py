"""
Core Database Components

This package provides reusable database components for Zumodra:
- managers: Custom QuerySet managers for tenant-aware, soft-delete, and audit operations
- models: Base model classes with common functionality
- fields: Custom field types for encrypted data, money, and phone numbers
- indexes: Index recommendations and utilities for query optimization
- optimizations: Query optimization mixins for 1M+ user scale
- routers: Database routing for read replicas and tenant sharding
"""

from core.db.managers import (
    TenantAwareManager,
    SoftDeleteManager,
    AuditManager,
    TenantAwareQuerySet,
    SoftDeleteQuerySet,
)
from core.db.models import (
    BaseModel,
    TenantAwareModel,
    AuditableModel,
    SoftDeleteModel,
)
from core.db.fields import (
    EncryptedCharField,
    EncryptedTextField,
    MoneyField,
    PhoneNumberField,
)
from core.db.optimizations import (
    SelectRelatedMixin,
    PrefetchRelatedMixin,
    DeferFieldsMixin,
    OptimizedQuerySetMixin,
    CursorPaginationMixin,
    KeysetPaginationMixin,
    CachedQuerySet,
    cached_queryset,
    log_queries,
    QueryProfiler,
    bulk_update_with_batching,
    bulk_create_with_batching,
    bulk_delete_with_batching,
    optimized_count,
    chunked_iterator,
)
from core.db.routers import (
    ReadReplicaRouter,
    WeightedReadReplicaRouter,
    TenantAwareDatabaseRouter,
    HybridDatabaseRouter,
)

__all__ = [
    # Managers
    'TenantAwareManager',
    'SoftDeleteManager',
    'AuditManager',
    'TenantAwareQuerySet',
    'SoftDeleteQuerySet',
    # Models
    'BaseModel',
    'TenantAwareModel',
    'AuditableModel',
    'SoftDeleteModel',
    # Fields
    'EncryptedCharField',
    'EncryptedTextField',
    'MoneyField',
    'PhoneNumberField',
    # Optimizations
    'SelectRelatedMixin',
    'PrefetchRelatedMixin',
    'DeferFieldsMixin',
    'OptimizedQuerySetMixin',
    'CursorPaginationMixin',
    'KeysetPaginationMixin',
    'CachedQuerySet',
    'cached_queryset',
    'log_queries',
    'QueryProfiler',
    'bulk_update_with_batching',
    'bulk_create_with_batching',
    'bulk_delete_with_batching',
    'optimized_count',
    'chunked_iterator',
    # Routers
    'ReadReplicaRouter',
    'WeightedReadReplicaRouter',
    'TenantAwareDatabaseRouter',
    'HybridDatabaseRouter',
]
