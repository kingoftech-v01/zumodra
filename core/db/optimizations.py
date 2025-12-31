"""
Database Optimizations for Zumodra - Scaling to 1M+ Users

This module provides performance optimization utilities:
- SelectRelatedMixin: Automatic FK optimization
- PrefetchRelatedMixin: N+1 query prevention
- PaginationMixin: Cursor-based pagination for large datasets
- CachedQuerySet: Query result caching wrapper
- Query logging and profiling decorators

These optimizations are designed for high-traffic multi-tenant SaaS workloads.
"""

import functools
import hashlib
import logging
import time
from typing import (
    TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence, Tuple, Type, TypeVar
)

from django.conf import settings
from django.core.cache import cache
from django.db import connection, reset_queries
from django.db.models import Model, QuerySet, Prefetch, Q
from django.db.models.query import RawQuerySet

if TYPE_CHECKING:
    from rest_framework.request import Request

logger = logging.getLogger(__name__)

T = TypeVar('T', bound=Model)


# =============================================================================
# QUERY OPTIMIZATION MIXINS
# =============================================================================

class SelectRelatedMixin:
    """
    Mixin providing automatic select_related optimization for querysets.

    Automatically applies select_related for ForeignKey and OneToOneField
    relationships to reduce N+1 queries in list views.

    Usage:
        class EmployeeViewSet(SelectRelatedMixin, TenantAwareViewSet):
            queryset = Employee.objects.all()
            select_related_fields = ['user', 'department', 'manager']

            # Or use auto-detection
            select_related_auto = True
    """

    # Explicit list of fields to include in select_related
    select_related_fields: List[str] = []

    # Auto-detect FK/O2O fields (use with caution on complex models)
    select_related_auto: bool = False

    # Maximum depth for auto-detection (prevents deep joins)
    select_related_max_depth: int = 2

    # Fields to exclude from auto-detection
    select_related_exclude: List[str] = []

    def get_queryset(self) -> QuerySet:
        """Apply select_related optimization to queryset."""
        queryset = super().get_queryset()

        # Get fields to optimize
        fields = self._get_select_related_fields()

        if fields:
            queryset = queryset.select_related(*fields)
            logger.debug(
                f"Applied select_related({fields}) to {self.__class__.__name__}"
            )

        return queryset

    def _get_select_related_fields(self) -> List[str]:
        """Determine which fields to include in select_related."""
        if self.select_related_fields:
            return self.select_related_fields

        if self.select_related_auto:
            return self._auto_detect_select_related_fields()

        return []

    def _auto_detect_select_related_fields(self) -> List[str]:
        """
        Auto-detect ForeignKey and OneToOneField relationships.

        Returns a list of field names suitable for select_related,
        respecting max_depth and exclude settings.
        """
        model = self.queryset.model if hasattr(self, 'queryset') else None
        if not model:
            return []

        fields = []
        self._collect_related_fields(model, '', fields, 0)
        return fields

    def _collect_related_fields(
        self,
        model: Type[Model],
        prefix: str,
        fields: List[str],
        depth: int
    ) -> None:
        """Recursively collect related fields up to max_depth."""
        if depth >= self.select_related_max_depth:
            return

        from django.db.models.fields.related import ForeignKey
        from django.db.models.fields.related import OneToOneField

        for field in model._meta.get_fields():
            # Only FK and O2O fields work with select_related
            if not isinstance(field, (ForeignKey, OneToOneField)):
                continue

            field_name = f"{prefix}{field.name}" if prefix else field.name

            # Skip excluded fields
            if field_name in self.select_related_exclude:
                continue

            # Skip reverse relations
            if field.one_to_many or field.many_to_many:
                continue

            fields.append(field_name)

            # Recurse into related model
            if hasattr(field, 'related_model') and field.related_model:
                self._collect_related_fields(
                    field.related_model,
                    f"{field_name}__",
                    fields,
                    depth + 1
                )


class PrefetchRelatedMixin:
    """
    Mixin providing automatic prefetch_related optimization for querysets.

    Prevents N+1 queries for reverse ForeignKey and ManyToMany relationships.
    Supports custom Prefetch objects for advanced filtering.

    Usage:
        class JobPostingViewSet(PrefetchRelatedMixin, TenantAwareViewSet):
            queryset = JobPosting.objects.all()
            prefetch_related_fields = ['applications', 'required_skills']

            # Or with custom Prefetch objects
            prefetch_related_custom = {
                'applications': Prefetch(
                    'applications',
                    queryset=Application.objects.select_related('candidate')
                )
            }
    """

    # Simple list of fields for prefetch_related
    prefetch_related_fields: List[str] = []

    # Custom Prefetch objects for advanced optimization
    prefetch_related_custom: Dict[str, Prefetch] = {}

    # Auto-detect M2M and reverse FK fields
    prefetch_related_auto: bool = False

    # Fields to exclude from auto-detection
    prefetch_related_exclude: List[str] = []

    def get_queryset(self) -> QuerySet:
        """Apply prefetch_related optimization to queryset."""
        queryset = super().get_queryset()

        # Apply custom Prefetch objects first
        for name, prefetch in self.prefetch_related_custom.items():
            queryset = queryset.prefetch_related(prefetch)

        # Apply simple prefetch_related fields
        fields = self._get_prefetch_related_fields()

        # Filter out fields already covered by custom Prefetch
        fields = [f for f in fields if f not in self.prefetch_related_custom]

        if fields:
            queryset = queryset.prefetch_related(*fields)
            logger.debug(
                f"Applied prefetch_related({fields}) to {self.__class__.__name__}"
            )

        return queryset

    def _get_prefetch_related_fields(self) -> List[str]:
        """Determine which fields to include in prefetch_related."""
        if self.prefetch_related_fields:
            return self.prefetch_related_fields

        if self.prefetch_related_auto:
            return self._auto_detect_prefetch_related_fields()

        return []

    def _auto_detect_prefetch_related_fields(self) -> List[str]:
        """Auto-detect ManyToMany and reverse ForeignKey relationships."""
        model = self.queryset.model if hasattr(self, 'queryset') else None
        if not model:
            return []

        fields = []
        for field in model._meta.get_fields():
            field_name = field.name

            # Skip excluded fields
            if field_name in self.prefetch_related_exclude:
                continue

            # Include M2M fields
            if field.many_to_many:
                fields.append(field_name)

            # Include reverse FK relations
            elif field.one_to_many:
                fields.append(field_name)

        return fields


class DeferFieldsMixin:
    """
    Mixin for deferring heavy fields (text, binary) to reduce memory usage.

    Useful for list views where large text/binary fields aren't displayed.

    Usage:
        class DocumentViewSet(DeferFieldsMixin, TenantAwareViewSet):
            queryset = Document.objects.all()
            defer_fields = ['content', 'binary_data', 'html_body']

            # Or only select specific fields
            only_fields = ['id', 'title', 'created_at', 'status']
    """

    # Fields to defer (exclude from initial query)
    defer_fields: List[str] = []

    # Only load these specific fields (overrides defer_fields)
    only_fields: List[str] = []

    # Apply defer/only only in list action
    defer_only_in_list: bool = True

    def get_queryset(self) -> QuerySet:
        """Apply defer/only optimization to queryset."""
        queryset = super().get_queryset()

        # Only apply in list action by default
        if self.defer_only_in_list and getattr(self, 'action', None) != 'list':
            return queryset

        # Apply only() if specified (takes precedence)
        if self.only_fields:
            queryset = queryset.only(*self.only_fields)
            logger.debug(
                f"Applied only({self.only_fields}) to {self.__class__.__name__}"
            )

        # Otherwise apply defer()
        elif self.defer_fields:
            queryset = queryset.defer(*self.defer_fields)
            logger.debug(
                f"Applied defer({self.defer_fields}) to {self.__class__.__name__}"
            )

        return queryset


class OptimizedQuerySetMixin(SelectRelatedMixin, PrefetchRelatedMixin, DeferFieldsMixin):
    """
    Combined mixin providing all query optimization features.

    Usage:
        class EmployeeViewSet(OptimizedQuerySetMixin, TenantAwareViewSet):
            queryset = Employee.objects.all()
            select_related_fields = ['user', 'department']
            prefetch_related_fields = ['skills', 'certifications']
            defer_fields = ['biography', 'notes']
    """
    pass


# =============================================================================
# PAGINATION MIXIN FOR LARGE DATASETS
# =============================================================================

class CursorPaginationMixin:
    """
    Mixin providing efficient cursor-based pagination for large datasets.

    Cursor pagination is more efficient than offset pagination for:
    - Large tables (1M+ rows)
    - Real-time feeds with frequent updates
    - Infinite scroll UIs

    Usage:
        class ActivityFeedViewSet(CursorPaginationMixin, TenantAwareViewSet):
            queryset = Activity.objects.all()
            cursor_ordering = '-created_at'  # Required for cursor pagination
    """

    from rest_framework.pagination import CursorPagination

    # Field to use for cursor ordering (must be unique or combined with PK)
    cursor_ordering: str = '-created_at'

    # Page size for cursor pagination
    cursor_page_size: int = 20

    # Maximum page size
    cursor_max_page_size: int = 100

    def get_pagination_class(self):
        """
        Dynamically create cursor pagination class with view-specific settings.
        """
        from rest_framework.pagination import CursorPagination

        ordering = self.cursor_ordering
        page_size = self.cursor_page_size
        max_page_size = self.cursor_max_page_size

        class DynamicCursorPagination(CursorPagination):
            pass

        DynamicCursorPagination.ordering = ordering
        DynamicCursorPagination.page_size = page_size
        DynamicCursorPagination.max_page_size = max_page_size

        return DynamicCursorPagination

    @property
    def pagination_class(self):
        """Return the dynamic pagination class."""
        return self.get_pagination_class()


class KeysetPaginationMixin:
    """
    Keyset pagination for extremely large datasets (100M+ rows).

    Uses WHERE clause filtering instead of OFFSET for O(1) performance.
    Requires consistent ordering and last-seen key tracking.

    Usage:
        class LogEntryViewSet(KeysetPaginationMixin, TenantAwareViewSet):
            queryset = LogEntry.objects.all()
            keyset_fields = ['created_at', 'id']  # Composite key
    """

    # Fields for keyset pagination (must be consistently ordered)
    keyset_fields: List[str] = ['created_at', 'id']

    # Default page size
    keyset_page_size: int = 50

    def paginate_by_keyset(
        self,
        queryset: QuerySet,
        after: Optional[Dict[str, Any]] = None,
        before: Optional[Dict[str, Any]] = None,
        page_size: Optional[int] = None
    ) -> Tuple[QuerySet, Dict[str, Any]]:
        """
        Apply keyset pagination to queryset.

        Args:
            queryset: Base queryset to paginate
            after: Dict of field values to start after
            before: Dict of field values to end before
            page_size: Items per page

        Returns:
            Tuple of (paginated queryset, pagination info dict)
        """
        page_size = page_size or self.keyset_page_size

        # Build filter conditions
        if after:
            queryset = self._apply_keyset_filter(queryset, after, 'after')

        if before:
            queryset = self._apply_keyset_filter(queryset, before, 'before')

        # Apply limit
        queryset = queryset[:page_size + 1]  # Fetch one extra to check for more

        # Execute and check for more results
        results = list(queryset)
        has_more = len(results) > page_size

        if has_more:
            results = results[:page_size]

        # Build pagination info
        pagination_info = {
            'has_more': has_more,
            'page_size': page_size,
        }

        if results:
            pagination_info['first_key'] = self._extract_keyset(results[0])
            pagination_info['last_key'] = self._extract_keyset(results[-1])

        return results, pagination_info

    def _apply_keyset_filter(
        self,
        queryset: QuerySet,
        keyset: Dict[str, Any],
        direction: str
    ) -> QuerySet:
        """Apply keyset filter to queryset."""
        if direction == 'after':
            # For forward pagination, use > (greater than)
            filter_q = Q()
            for i, field in enumerate(self.keyset_fields):
                if field in keyset:
                    if i == len(self.keyset_fields) - 1:
                        filter_q &= Q(**{f'{field}__gt': keyset[field]})
                    else:
                        filter_q |= Q(**{f'{field}__gt': keyset[field]})
            queryset = queryset.filter(filter_q)

        elif direction == 'before':
            # For backward pagination, use < (less than)
            filter_q = Q()
            for field in self.keyset_fields:
                if field in keyset:
                    filter_q &= Q(**{f'{field}__lt': keyset[field]})
            queryset = queryset.filter(filter_q)

        return queryset

    def _extract_keyset(self, obj: Model) -> Dict[str, Any]:
        """Extract keyset values from a model instance."""
        return {
            field: getattr(obj, field)
            for field in self.keyset_fields
            if hasattr(obj, field)
        }


# =============================================================================
# CACHED QUERYSET WRAPPER
# =============================================================================

class CachedQuerySet:
    """
    Wrapper providing transparent caching for QuerySet results.

    Supports:
    - Automatic cache key generation based on query parameters
    - Tenant-aware cache isolation
    - Configurable TTL
    - Cache invalidation hooks

    Usage:
        # Basic usage
        cached_qs = CachedQuerySet(
            Employee.objects.filter(status='active'),
            cache_key='active_employees',
            timeout=300  # 5 minutes
        )
        results = cached_qs.all()

        # With tenant isolation
        cached_qs = CachedQuerySet(
            Employee.objects.for_current_tenant(),
            tenant_aware=True
        )
    """

    def __init__(
        self,
        queryset: QuerySet,
        cache_key: Optional[str] = None,
        timeout: int = 300,
        tenant_aware: bool = True,
        version: int = 1
    ):
        """
        Initialize cached queryset wrapper.

        Args:
            queryset: Base QuerySet to cache
            cache_key: Custom cache key prefix (auto-generated if None)
            timeout: Cache TTL in seconds
            tenant_aware: Include tenant in cache key for isolation
            version: Cache version (increment to invalidate all)
        """
        self._queryset = queryset
        self._cache_key_prefix = cache_key
        self._timeout = timeout
        self._tenant_aware = tenant_aware
        self._version = version

    def _get_cache_key(self, suffix: str = '') -> str:
        """Generate cache key for this queryset."""
        # Generate query hash from SQL
        sql = str(self._queryset.query)
        query_hash = hashlib.md5(sql.encode()).hexdigest()[:12]

        # Build key components
        parts = [
            f"qs:v{self._version}",
            self._cache_key_prefix or self._queryset.model._meta.label,
            query_hash,
        ]

        # Add tenant isolation
        if self._tenant_aware:
            from django.db import connection
            tenant = getattr(connection, 'tenant', None)
            if tenant:
                parts.insert(1, f"t:{tenant.pk}")

        if suffix:
            parts.append(suffix)

        return ':'.join(parts)

    def all(self) -> List[Model]:
        """Return all results, from cache if available."""
        cache_key = self._get_cache_key('all')

        results = cache.get(cache_key)
        if results is None:
            results = list(self._queryset)
            cache.set(cache_key, results, self._timeout)
            logger.debug(f"Cache MISS: {cache_key}")
        else:
            logger.debug(f"Cache HIT: {cache_key}")

        return results

    def count(self) -> int:
        """Return count, from cache if available."""
        cache_key = self._get_cache_key('count')

        count = cache.get(cache_key)
        if count is None:
            count = self._queryset.count()
            cache.set(cache_key, count, self._timeout)

        return count

    def first(self) -> Optional[Model]:
        """Return first result, from cache if available."""
        cache_key = self._get_cache_key('first')

        result = cache.get(cache_key)
        if result is None:
            result = self._queryset.first()
            if result is not None:
                cache.set(cache_key, result, self._timeout)

        return result

    def exists(self) -> bool:
        """Check if results exist, from cache if available."""
        cache_key = self._get_cache_key('exists')

        exists = cache.get(cache_key)
        if exists is None:
            exists = self._queryset.exists()
            cache.set(cache_key, exists, self._timeout)

        return exists

    def invalidate(self) -> None:
        """Invalidate all cached results for this queryset."""
        # In production, use cache.delete_pattern() with Redis
        # For now, increment version to invalidate
        self._version += 1
        logger.info(f"Invalidated cache for {self._cache_key_prefix}")

    def get_or_set(
        self,
        pk: Any,
        timeout: Optional[int] = None
    ) -> Optional[Model]:
        """Get a single object by PK with caching."""
        cache_key = self._get_cache_key(f'pk:{pk}')

        result = cache.get(cache_key)
        if result is None:
            try:
                result = self._queryset.get(pk=pk)
                cache.set(cache_key, result, timeout or self._timeout)
            except self._queryset.model.DoesNotExist:
                return None

        return result


def cached_queryset(
    timeout: int = 300,
    tenant_aware: bool = True,
    version: int = 1
) -> Callable:
    """
    Decorator to wrap a method returning QuerySet with caching.

    Usage:
        class EmployeeViewSet(TenantAwareViewSet):
            @cached_queryset(timeout=600)
            def get_queryset(self):
                return Employee.objects.filter(status='active')
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            queryset = func(self, *args, **kwargs)
            return CachedQuerySet(
                queryset,
                cache_key=f"{self.__class__.__name__}:{func.__name__}",
                timeout=timeout,
                tenant_aware=tenant_aware,
                version=version
            )
        return wrapper
    return decorator


# =============================================================================
# QUERY LOGGING AND PROFILING
# =============================================================================

def log_queries(
    threshold_ms: float = 100.0,
    log_all: bool = False
) -> Callable:
    """
    Decorator to log database queries executed by a function.

    Logs slow queries exceeding threshold, or all queries if log_all=True.
    Useful for identifying N+1 queries and optimization opportunities.

    Usage:
        @log_queries(threshold_ms=50)
        def get_employees_with_departments():
            return Employee.objects.select_related('department').all()
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Reset query log
            reset_queries()
            settings.DEBUG = True  # Required for query logging

            start_time = time.time()

            try:
                result = func(*args, **kwargs)
            finally:
                end_time = time.time()

                # Analyze queries
                queries = connection.queries
                total_time = (end_time - start_time) * 1000
                query_count = len(queries)

                # Log summary
                logger.info(
                    f"[{func.__name__}] {query_count} queries, "
                    f"{total_time:.2f}ms total"
                )

                # Log individual slow queries
                for query in queries:
                    query_time = float(query['time']) * 1000
                    if log_all or query_time >= threshold_ms:
                        logger.warning(
                            f"[SLOW QUERY] {query_time:.2f}ms: "
                            f"{query['sql'][:200]}..."
                        )

            return result
        return wrapper
    return decorator


class QueryProfiler:
    """
    Context manager for profiling database queries in a code block.

    Usage:
        with QueryProfiler('employee_list') as profiler:
            employees = Employee.objects.select_related('user').all()

        print(profiler.summary())
    """

    def __init__(self, name: str = 'query_profile'):
        self.name = name
        self.queries: List[Dict] = []
        self.start_time: float = 0
        self.end_time: float = 0

    def __enter__(self) -> 'QueryProfiler':
        reset_queries()
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.time()
        self.queries = list(connection.queries)

    @property
    def query_count(self) -> int:
        """Number of queries executed."""
        return len(self.queries)

    @property
    def total_time_ms(self) -> float:
        """Total execution time in milliseconds."""
        return (self.end_time - self.start_time) * 1000

    @property
    def db_time_ms(self) -> float:
        """Total database time in milliseconds."""
        return sum(float(q['time']) * 1000 for q in self.queries)

    def summary(self) -> Dict[str, Any]:
        """Generate profiling summary."""
        return {
            'name': self.name,
            'query_count': self.query_count,
            'total_time_ms': round(self.total_time_ms, 2),
            'db_time_ms': round(self.db_time_ms, 2),
            'python_time_ms': round(self.total_time_ms - self.db_time_ms, 2),
            'avg_query_ms': round(self.db_time_ms / max(self.query_count, 1), 2),
        }

    def get_slow_queries(self, threshold_ms: float = 50.0) -> List[Dict]:
        """Get queries exceeding threshold."""
        return [
            {'time_ms': float(q['time']) * 1000, 'sql': q['sql']}
            for q in self.queries
            if float(q['time']) * 1000 >= threshold_ms
        ]

    def detect_n_plus_one(self) -> List[Dict]:
        """
        Detect potential N+1 query patterns.

        Looks for repeated similar queries that could be optimized
        with prefetch_related or select_related.
        """
        from collections import Counter

        # Normalize queries by removing specific values
        import re
        patterns = []
        for q in self.queries:
            # Replace specific values with placeholders
            normalized = re.sub(r"'[^']*'", "'?'", q['sql'])
            normalized = re.sub(r'\d+', '?', normalized)
            patterns.append(normalized)

        # Find repeated patterns
        counter = Counter(patterns)
        n_plus_one = [
            {
                'pattern': pattern,
                'count': count,
                'suggestion': 'Consider using prefetch_related or select_related'
            }
            for pattern, count in counter.items()
            if count > 3  # More than 3 similar queries indicates N+1
        ]

        return n_plus_one


# =============================================================================
# BULK OPERATION UTILITIES
# =============================================================================

def bulk_update_with_batching(
    queryset: QuerySet,
    updates: Dict[str, Any],
    batch_size: int = 1000
) -> int:
    """
    Perform bulk updates in batches to avoid memory issues.

    Args:
        queryset: QuerySet of objects to update
        updates: Dict of field names and values
        batch_size: Objects per batch

    Returns:
        Total number of updated objects
    """
    total_updated = 0

    # Get all PKs first
    pks = list(queryset.values_list('pk', flat=True))

    # Update in batches
    for i in range(0, len(pks), batch_size):
        batch_pks = pks[i:i + batch_size]
        count = queryset.model.objects.filter(pk__in=batch_pks).update(**updates)
        total_updated += count
        logger.debug(f"Batch updated {count} records (batch {i // batch_size + 1})")

    return total_updated


def bulk_create_with_batching(
    model: Type[Model],
    objects: List[Model],
    batch_size: int = 1000,
    ignore_conflicts: bool = False
) -> List[Model]:
    """
    Perform bulk create in batches to avoid memory issues.

    Args:
        model: Model class
        objects: List of model instances to create
        batch_size: Objects per batch
        ignore_conflicts: Whether to ignore constraint violations

    Returns:
        List of created objects
    """
    created = []

    for i in range(0, len(objects), batch_size):
        batch = objects[i:i + batch_size]
        batch_created = model.objects.bulk_create(
            batch,
            batch_size=batch_size,
            ignore_conflicts=ignore_conflicts
        )
        created.extend(batch_created)
        logger.debug(f"Batch created {len(batch_created)} records (batch {i // batch_size + 1})")

    return created


def bulk_delete_with_batching(
    queryset: QuerySet,
    batch_size: int = 1000
) -> int:
    """
    Perform bulk delete in batches to avoid table locks.

    Args:
        queryset: QuerySet of objects to delete
        batch_size: Objects per batch

    Returns:
        Total number of deleted objects
    """
    total_deleted = 0

    while True:
        # Get batch of PKs
        pks = list(queryset.values_list('pk', flat=True)[:batch_size])

        if not pks:
            break

        # Delete batch
        count, _ = queryset.model.objects.filter(pk__in=pks).delete()
        total_deleted += count
        logger.debug(f"Batch deleted {count} records")

    return total_deleted


# =============================================================================
# QUERY HINTS AND OPTIMIZERS
# =============================================================================

class QueryHints:
    """
    Utility class for adding database query hints.

    Provides methods for common optimizations like:
    - Index hints
    - Query parallelization
    - Read-from-replica routing
    """

    @staticmethod
    def use_index(queryset: QuerySet, index_name: str) -> QuerySet:
        """
        Add index hint to queryset (PostgreSQL).

        Note: PostgreSQL doesn't support index hints directly,
        but we can restructure queries to encourage index usage.
        """
        # For PostgreSQL, we rely on query planner
        # This is a placeholder for databases that support hints
        return queryset

    @staticmethod
    def parallel_query(queryset: QuerySet, workers: int = 4) -> QuerySet:
        """
        Enable parallel query execution (PostgreSQL 9.6+).

        Note: Requires PostgreSQL configuration for parallel queries.
        """
        # PostgreSQL handles this automatically based on query cost
        return queryset

    @staticmethod
    def use_replica(queryset: QuerySet) -> QuerySet:
        """
        Route query to read replica.

        Usage:
            QueryHints.use_replica(Employee.objects.all())
        """
        return queryset.using('replica') if 'replica' in settings.DATABASES else queryset


# =============================================================================
# AGGREGATION OPTIMIZATION
# =============================================================================

def optimized_count(queryset: QuerySet, estimate_threshold: int = 100000) -> int:
    """
    Get count with optimization for large tables.

    For tables above threshold, uses PostgreSQL's estimate
    from pg_class for much faster results (with slight inaccuracy).

    Args:
        queryset: QuerySet to count
        estimate_threshold: Use estimate above this count

    Returns:
        Count (exact or estimated)
    """
    model = queryset.model

    # Try exact count first with a quick check
    if hasattr(queryset, '_result_cache') and queryset._result_cache is not None:
        return len(queryset._result_cache)

    # For PostgreSQL, check if we should use estimate
    if connection.vendor == 'postgresql':
        # Get estimated count from pg_class
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT reltuples::bigint FROM pg_class WHERE relname = %s",
                [model._meta.db_table]
            )
            row = cursor.fetchone()
            if row and row[0] > estimate_threshold:
                logger.debug(f"Using estimated count ({row[0]}) for {model._meta.label}")
                return row[0]

    # Fall back to exact count
    return queryset.count()


def chunked_iterator(queryset: QuerySet, chunk_size: int = 1000):
    """
    Memory-efficient iterator for large querysets.

    Uses server-side cursors in PostgreSQL to avoid loading
    all results into memory at once.

    Usage:
        for employee in chunked_iterator(Employee.objects.all()):
            process(employee)
    """
    pk_field = queryset.model._meta.pk
    last_pk = None

    while True:
        chunk_qs = queryset.order_by(pk_field.name)

        if last_pk is not None:
            chunk_qs = chunk_qs.filter(**{f'{pk_field.name}__gt': last_pk})

        chunk = list(chunk_qs[:chunk_size])

        if not chunk:
            break

        for obj in chunk:
            yield obj

        last_pk = getattr(chunk[-1], pk_field.name)
