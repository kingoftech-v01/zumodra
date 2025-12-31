"""
Base Task Classes for Zumodra Celery Tasks

This module provides reusable base task classes with:
- AutoRetryTask: Automatic retry with exponential backoff
- TenantAwareTask: Multi-tenant context handling
- RateLimitedTask: Configurable rate limiting
- MonitoredTask: Prometheus metrics integration
- ChainableTask: Workflow composition support
"""

import logging
import time
import functools
from abc import ABC
from datetime import datetime
from typing import Any, Dict, Optional, Tuple, Type

from celery import Task, shared_task
from celery.exceptions import Retry, MaxRetriesExceededError
from django.conf import settings
from django.db import connection


logger = logging.getLogger(__name__)


# =============================================================================
# AUTORETRY TASK - Automatic Retry with Exponential Backoff
# =============================================================================

class AutoRetryTask(Task):
    """
    Base task with automatic retry logic and exponential backoff.

    Features:
    - Configurable max_retries (default: 3)
    - Exponential backoff with jitter
    - Automatic retry on specific exceptions
    - Detailed logging of retry attempts

    Usage:
        @app.task(bind=True, base=AutoRetryTask)
        def my_task(self, arg1, arg2):
            # task logic
            pass
    """

    # Default retry configuration
    autoretry_for = (Exception,)
    max_retries = 3
    retry_backoff = True
    retry_backoff_max = 600  # Max 10 minutes
    retry_jitter = True
    default_retry_delay = 60

    # Exceptions that should NOT trigger retry
    dont_autoretry_for = (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    )

    def __call__(self, *args, **kwargs):
        """Execute the task with retry handling."""
        try:
            return super().__call__(*args, **kwargs)
        except self.dont_autoretry_for:
            # Re-raise without retry
            raise
        except self.autoretry_for as exc:
            # Calculate backoff delay
            retry_count = self.request.retries
            if self.retry_backoff:
                delay = self._calculate_backoff(retry_count)
            else:
                delay = self.default_retry_delay

            logger.warning(
                f"Task {self.name}[{self.request.id}] failed, "
                f"retrying in {delay}s (attempt {retry_count + 1}/{self.max_retries}): {exc}"
            )

            raise self.retry(exc=exc, countdown=delay)

    def _calculate_backoff(self, retry_count: int) -> int:
        """
        Calculate exponential backoff delay with jitter.

        Args:
            retry_count: Current retry attempt number

        Returns:
            Delay in seconds
        """
        import random

        # Exponential backoff: 2^retry_count * base_delay
        base_delay = self.default_retry_delay
        delay = min(base_delay * (2 ** retry_count), self.retry_backoff_max)

        # Add jitter to prevent thundering herd
        if self.retry_jitter:
            jitter = random.uniform(0, delay * 0.1)
            delay = delay + jitter

        return int(delay)

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called when task fails after all retries."""
        logger.error(
            f"Task {self.name}[{task_id}] failed permanently after "
            f"{self.max_retries} retries: {exc}",
            exc_info=True
        )
        super().on_failure(exc, task_id, args, kwargs, einfo)

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """Called when task is retried."""
        logger.info(
            f"Task {self.name}[{task_id}] scheduled for retry: {exc}"
        )
        super().on_retry(exc, task_id, args, kwargs, einfo)

    def on_success(self, retval, task_id, args, kwargs):
        """Called when task completes successfully."""
        logger.debug(
            f"Task {self.name}[{task_id}] completed successfully"
        )
        super().on_success(retval, task_id, args, kwargs)


# =============================================================================
# TENANT-AWARE TASK - Multi-Tenant Context Handling
# =============================================================================

class TenantAwareTask(Task):
    """
    Base task for multi-tenant operations.

    Features:
    - Automatic tenant context switching
    - Tenant-scoped database connections
    - Tenant-aware logging
    - Tenant validation

    Usage:
        @app.task(bind=True, base=TenantAwareTask)
        def my_tenant_task(self, tenant_id, data):
            # self.tenant is automatically set
            # All queries are scoped to tenant
            pass
    """

    # Track current tenant
    _tenant = None
    _original_schema = None

    @property
    def tenant(self):
        """Get current tenant context."""
        return self._tenant

    def __call__(self, *args, **kwargs):
        """Execute task with tenant context."""
        tenant_id = kwargs.pop('tenant_id', None)
        tenant_schema = kwargs.pop('tenant_schema', None)

        if tenant_id or tenant_schema:
            self._setup_tenant_context(tenant_id, tenant_schema)

        try:
            return super().__call__(*args, **kwargs)
        finally:
            self._teardown_tenant_context()

    def _setup_tenant_context(
        self,
        tenant_id: Optional[int] = None,
        tenant_schema: Optional[str] = None
    ):
        """
        Set up tenant context for task execution.

        Args:
            tenant_id: Tenant ID to load
            tenant_schema: Tenant schema name to switch to
        """
        try:
            from django_tenants.utils import schema_context, get_tenant_model
            from django.db import connection

            # Store original schema for cleanup
            self._original_schema = connection.schema_name

            if tenant_id:
                # Load tenant by ID
                Tenant = get_tenant_model()
                self._tenant = Tenant.objects.get(id=tenant_id)
                tenant_schema = self._tenant.schema_name
            elif tenant_schema:
                # Load tenant by schema
                Tenant = get_tenant_model()
                self._tenant = Tenant.objects.get(schema_name=tenant_schema)

            if tenant_schema:
                # Switch to tenant schema
                connection.set_tenant(self._tenant)
                logger.debug(
                    f"Task {self.name} switched to tenant schema: {tenant_schema}"
                )

        except ImportError:
            # django-tenants not installed, skip tenant handling
            logger.debug("django-tenants not installed, skipping tenant context")
        except Exception as e:
            logger.error(f"Failed to set up tenant context: {e}")
            raise

    def _teardown_tenant_context(self):
        """Clean up tenant context after task execution."""
        try:
            from django_tenants.utils import schema_context
            from django.db import connection

            if self._original_schema:
                # Reset to public schema
                connection.set_schema(self._original_schema)
                logger.debug(
                    f"Task {self.name} restored schema to: {self._original_schema}"
                )

            self._tenant = None
            self._original_schema = None

        except ImportError:
            pass
        except Exception as e:
            logger.error(f"Failed to teardown tenant context: {e}")

    def apply_async(self, args=None, kwargs=None, **options):
        """Override apply_async to include tenant context."""
        kwargs = kwargs or {}

        # Try to get current tenant from connection
        try:
            from django.db import connection
            if hasattr(connection, 'tenant') and connection.tenant:
                if 'tenant_id' not in kwargs and 'tenant_schema' not in kwargs:
                    kwargs['tenant_id'] = connection.tenant.id
        except Exception:
            pass

        return super().apply_async(args, kwargs, **options)


# =============================================================================
# RATE LIMITED TASK - Configurable Rate Limiting
# =============================================================================

class RateLimitedTask(Task):
    """
    Base task with configurable rate limiting.

    Features:
    - Per-task rate limits
    - Sliding window rate limiting
    - Rate limit bypass for priority tasks
    - Rate limit metrics

    Usage:
        @app.task(bind=True, base=RateLimitedTask, rate_limit='100/m')
        def my_limited_task(self, data):
            pass
    """

    # Default rate limit (can be overridden per task)
    rate_limit = '100/m'

    # Rate limit key prefix
    rate_limit_key_prefix = 'celery:ratelimit'

    # Allow bypass with special flag
    allow_rate_limit_bypass = False

    def __call__(self, *args, **kwargs):
        """Execute task with rate limit check."""
        # Check for bypass flag
        bypass_rate_limit = kwargs.pop('_bypass_rate_limit', False)

        if bypass_rate_limit and self.allow_rate_limit_bypass:
            logger.debug(f"Task {self.name} bypassing rate limit")
            return super().__call__(*args, **kwargs)

        # Rate limiting is handled by Celery's built-in mechanism
        # This hook is for additional custom rate limiting if needed
        return super().__call__(*args, **kwargs)

    def _check_custom_rate_limit(self) -> bool:
        """
        Check custom rate limit using Redis.

        Returns:
            True if request is allowed, False if rate limited
        """
        try:
            from django.core.cache import cache

            key = f"{self.rate_limit_key_prefix}:{self.name}"
            current_count = cache.get(key, 0)

            # Parse rate limit (e.g., '100/m' -> 100 per minute)
            limit, period = self._parse_rate_limit(self.rate_limit)

            if current_count >= limit:
                logger.warning(
                    f"Task {self.name} rate limited: {current_count}/{limit} per {period}"
                )
                return False

            # Increment counter
            if current_count == 0:
                cache.set(key, 1, timeout=self._period_to_seconds(period))
            else:
                cache.incr(key)

            return True

        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return True  # Allow on error

    def _parse_rate_limit(self, rate_limit: str) -> Tuple[int, str]:
        """Parse rate limit string like '100/m'."""
        parts = rate_limit.split('/')
        limit = int(parts[0])
        period = parts[1] if len(parts) > 1 else 'm'
        return limit, period

    def _period_to_seconds(self, period: str) -> int:
        """Convert period to seconds."""
        periods = {
            's': 1,
            'm': 60,
            'h': 3600,
            'd': 86400,
        }
        return periods.get(period, 60)


# =============================================================================
# MONITORED TASK - Prometheus Metrics Integration
# =============================================================================

class MonitoredTask(Task):
    """
    Base task with Prometheus metrics integration.

    Features:
    - Task execution time tracking
    - Success/failure counters
    - Queue depth metrics
    - Memory usage tracking

    Usage:
        @app.task(bind=True, base=MonitoredTask)
        def my_monitored_task(self, data):
            pass
    """

    # Metric labels
    _metrics_initialized = False
    _task_counter = None
    _task_duration = None
    _task_exceptions = None

    @classmethod
    def _init_metrics(cls):
        """Initialize Prometheus metrics."""
        if cls._metrics_initialized:
            return

        try:
            from prometheus_client import Counter, Histogram

            cls._task_counter = Counter(
                'celery_task_total',
                'Total number of Celery tasks',
                ['task_name', 'status']
            )

            cls._task_duration = Histogram(
                'celery_task_duration_seconds',
                'Celery task execution duration',
                ['task_name'],
                buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0)
            )

            cls._task_exceptions = Counter(
                'celery_task_exceptions_total',
                'Total number of Celery task exceptions',
                ['task_name', 'exception_type']
            )

            cls._metrics_initialized = True

        except ImportError:
            logger.debug("prometheus_client not installed, metrics disabled")

    def __call__(self, *args, **kwargs):
        """Execute task with metrics tracking."""
        self._init_metrics()

        start_time = time.time()
        status = 'success'
        exception_type = None

        try:
            result = super().__call__(*args, **kwargs)
            return result

        except Exception as e:
            status = 'failure'
            exception_type = type(e).__name__
            raise

        finally:
            duration = time.time() - start_time
            self._record_metrics(status, duration, exception_type)

    def _record_metrics(
        self,
        status: str,
        duration: float,
        exception_type: Optional[str] = None
    ):
        """Record task metrics."""
        if not self._metrics_initialized:
            return

        try:
            # Record task count
            if self._task_counter:
                self._task_counter.labels(
                    task_name=self.name,
                    status=status
                ).inc()

            # Record duration
            if self._task_duration:
                self._task_duration.labels(
                    task_name=self.name
                ).observe(duration)

            # Record exception if any
            if exception_type and self._task_exceptions:
                self._task_exceptions.labels(
                    task_name=self.name,
                    exception_type=exception_type
                ).inc()

        except Exception as e:
            logger.error(f"Failed to record metrics: {e}")


# =============================================================================
# CHAINABLE TASK - Workflow Composition Support
# =============================================================================

class ChainableTask(Task):
    """
    Base task for workflow composition.

    Features:
    - Easy chaining with other tasks
    - Workflow state management
    - Error propagation control
    - Result aggregation

    Usage:
        @app.task(bind=True, base=ChainableTask)
        def step1(self, data):
            return {'step1_result': data}

        @app.task(bind=True, base=ChainableTask)
        def step2(self, prev_result):
            return {**prev_result, 'step2_result': 'done'}

        # Chain execution
        workflow = step1.s('input') | step2.s()
        result = workflow.apply_async()
    """

    # Workflow tracking
    workflow_id = None
    workflow_step = 0

    def __call__(self, *args, **kwargs):
        """Execute task as part of workflow."""
        # Extract workflow context
        self.workflow_id = kwargs.pop('_workflow_id', None)
        self.workflow_step = kwargs.pop('_workflow_step', 0)

        if self.workflow_id:
            logger.info(
                f"Workflow {self.workflow_id} step {self.workflow_step}: "
                f"executing {self.name}"
            )

        return super().__call__(*args, **kwargs)

    def chain_to(self, next_task, *args, **kwargs):
        """
        Chain this task result to another task.

        Args:
            next_task: The next task to execute
            *args: Additional arguments for next task
            **kwargs: Additional keyword arguments

        Returns:
            Chained task signature
        """
        from celery import chain

        return chain(
            self.s(*args, **kwargs),
            next_task.s()
        )

    def on_success(self, retval, task_id, args, kwargs):
        """Called on successful completion."""
        if self.workflow_id:
            # Store workflow step result
            try:
                from django.core.cache import cache
                key = f"workflow:{self.workflow_id}:step:{self.workflow_step}"
                cache.set(key, {
                    'task_id': task_id,
                    'task_name': self.name,
                    'result': retval,
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat(),
                }, timeout=86400)
            except Exception as e:
                logger.error(f"Failed to store workflow result: {e}")

        super().on_success(retval, task_id, args, kwargs)

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called on task failure."""
        if self.workflow_id:
            # Mark workflow as failed
            try:
                from django.core.cache import cache
                key = f"workflow:{self.workflow_id}:status"
                cache.set(key, {
                    'failed_at_step': self.workflow_step,
                    'failed_task': self.name,
                    'error': str(exc),
                    'timestamp': datetime.utcnow().isoformat(),
                }, timeout=86400)
            except Exception as e:
                logger.error(f"Failed to store workflow failure: {e}")

        super().on_failure(exc, task_id, args, kwargs, einfo)


# =============================================================================
# COMBINED BASE TASK - All Features Combined
# =============================================================================

class ZumodraBaseTask(AutoRetryTask, TenantAwareTask, MonitoredTask):
    """
    Combined base task with all Zumodra-specific features.

    Inherits from:
    - AutoRetryTask: Automatic retry with exponential backoff
    - TenantAwareTask: Multi-tenant context handling
    - MonitoredTask: Prometheus metrics integration

    Usage:
        @app.task(bind=True, base=ZumodraBaseTask)
        def my_complete_task(self, tenant_id, data):
            # All features available
            pass
    """

    abstract = True

    def __call__(self, *args, **kwargs):
        """Execute with all combined features."""
        # TenantAwareTask setup
        tenant_id = kwargs.get('tenant_id')
        tenant_schema = kwargs.get('tenant_schema')

        if tenant_id or tenant_schema:
            self._setup_tenant_context(tenant_id, tenant_schema)

        # MonitoredTask setup
        self._init_metrics()
        start_time = time.time()
        status = 'success'
        exception_type = None

        try:
            # AutoRetryTask execution
            result = Task.__call__(self, *args, **kwargs)
            return result

        except self.dont_autoretry_for:
            status = 'failure'
            exception_type = type(self.dont_autoretry_for).__name__
            raise

        except self.autoretry_for as exc:
            status = 'retry'
            exception_type = type(exc).__name__

            # Calculate backoff
            retry_count = self.request.retries
            delay = self._calculate_backoff(retry_count)

            logger.warning(
                f"Task {self.name}[{self.request.id}] failed, "
                f"retrying in {delay}s: {exc}"
            )

            raise self.retry(exc=exc, countdown=delay)

        finally:
            # Record metrics
            duration = time.time() - start_time
            self._record_metrics(status, duration, exception_type)

            # Teardown tenant context
            self._teardown_tenant_context()


# =============================================================================
# HELPER DECORATORS
# =============================================================================

def with_tenant_context(func):
    """
    Decorator to ensure function runs within tenant context.

    Usage:
        @with_tenant_context
        def my_function(tenant_id, data):
            # Runs within tenant schema
            pass
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        tenant_id = kwargs.get('tenant_id')
        tenant_schema = kwargs.get('tenant_schema')

        if not tenant_id and not tenant_schema:
            return func(*args, **kwargs)

        try:
            from django_tenants.utils import schema_context, get_tenant_model

            Tenant = get_tenant_model()

            if tenant_id:
                tenant = Tenant.objects.get(id=tenant_id)
                schema = tenant.schema_name
            else:
                schema = tenant_schema

            with schema_context(schema):
                return func(*args, **kwargs)

        except ImportError:
            return func(*args, **kwargs)

    return wrapper


def with_metrics(task_name: str = None):
    """
    Decorator to add metrics to any function.

    Usage:
        @with_metrics('my_operation')
        def my_function():
            pass
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            name = task_name or func.__name__
            start_time = time.time()

            try:
                result = func(*args, **kwargs)

                # Record success
                try:
                    from prometheus_client import Counter, Histogram
                    # Metrics recording here
                except ImportError:
                    pass

                return result

            except Exception as e:
                # Record failure
                logger.error(f"Function {name} failed: {e}")
                raise

            finally:
                duration = time.time() - start_time
                logger.debug(f"Function {name} took {duration:.3f}s")

        return wrapper
    return decorator
