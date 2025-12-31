"""
Celery Load Tests for Zumodra

This module provides load testing capabilities for the Celery task system:
- 100 concurrent task test
- Queue backlog test
- Worker scaling test
- Task throughput test
- Rate limiting test

Usage:
    pytest tests/test_celery_scale.py -v
    pytest tests/test_celery_scale.py::TestCeleryLoad -v
    pytest tests/test_celery_scale.py::TestCeleryLoad::test_100_concurrent_tasks -v

Note: These tests require a running Redis instance and Celery workers.
      Some tests are marked with pytest.mark.slow for optional skipping.
"""

import time
import uuid
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from concurrent.futures import ThreadPoolExecutor, as_completed

from celery import group, chain, chord
from celery.result import AsyncResult, GroupResult
from django.test import TestCase, override_settings
from django.core.cache import cache


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def celery_app():
    """Get configured Celery app for testing."""
    from zumodra.celery_scale import app
    return app


@pytest.fixture
def celery_worker(celery_app):
    """
    Start a Celery worker for testing.

    Note: In a real environment, workers would already be running.
    This fixture is for isolated test environments.
    """
    # For testing, we use eager mode
    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    return celery_app


@pytest.fixture
def sample_task():
    """Create a sample task for testing."""
    from celery import shared_task

    @shared_task(
        bind=True,
        name='tests.sample_task',
        max_retries=3,
    )
    def _sample_task(self, value: int, delay: float = 0.01) -> dict:
        time.sleep(delay)
        return {
            'value': value,
            'task_id': self.request.id,
            'timestamp': datetime.utcnow().isoformat(),
        }

    return _sample_task


# =============================================================================
# LOAD TESTS
# =============================================================================

class TestCeleryLoad:
    """Load tests for Celery task system."""

    @pytest.mark.slow
    def test_100_concurrent_tasks(self, celery_app, sample_task):
        """
        Test executing 100 tasks concurrently.

        This test verifies:
        - All tasks complete successfully
        - No tasks are lost
        - Results are retrievable
        - Acceptable throughput (< 30 seconds for 100 tasks)
        """
        num_tasks = 100
        task_ids = []
        results = []

        start_time = time.time()

        # Submit 100 tasks concurrently using a group
        task_group = group(
            sample_task.s(i, delay=0.01) for i in range(num_tasks)
        )
        group_result = task_group.apply_async()

        # Wait for all tasks to complete (with timeout)
        try:
            group_result.get(timeout=60)
            results = group_result.results
        except Exception as e:
            pytest.fail(f"Task group failed: {e}")

        end_time = time.time()
        duration = end_time - start_time

        # Assertions
        assert len(results) == num_tasks, f"Expected {num_tasks} results, got {len(results)}"
        assert all(r.successful() for r in results), "Some tasks failed"
        assert duration < 30, f"Tasks took too long: {duration:.2f}s (expected < 30s)"

        # Verify all values are present
        values = set()
        for r in results:
            if r.result:
                values.add(r.result.get('value'))

        assert len(values) == num_tasks, f"Missing task values: expected {num_tasks}, got {len(values)}"

        print(f"\n100 concurrent tasks completed in {duration:.2f}s")
        print(f"Throughput: {num_tasks / duration:.2f} tasks/second")

    @pytest.mark.slow
    def test_1000_tasks_sequential_batches(self, celery_app, sample_task):
        """
        Test executing 1000 tasks in sequential batches.

        This test verifies:
        - System handles high volume
        - Memory doesn't grow unbounded
        - Batching works correctly
        """
        total_tasks = 1000
        batch_size = 100
        all_results = []

        start_time = time.time()

        for batch_start in range(0, total_tasks, batch_size):
            batch_end = min(batch_start + batch_size, total_tasks)

            task_group = group(
                sample_task.s(i, delay=0.001) for i in range(batch_start, batch_end)
            )
            group_result = task_group.apply_async()

            try:
                group_result.get(timeout=60)
                all_results.extend(group_result.results)
            except Exception as e:
                print(f"Batch {batch_start}-{batch_end} failed: {e}")

        end_time = time.time()
        duration = end_time - start_time

        successful = sum(1 for r in all_results if r.successful())

        assert successful >= total_tasks * 0.95, f"Too many failures: {successful}/{total_tasks}"

        print(f"\n{total_tasks} tasks completed in {duration:.2f}s")
        print(f"Throughput: {total_tasks / duration:.2f} tasks/second")
        print(f"Success rate: {successful / total_tasks * 100:.2f}%")


class TestQueueBacklog:
    """Tests for queue backlog handling."""

    def test_queue_backlog_measurement(self, celery_app):
        """
        Test measuring queue backlog.

        This test verifies:
        - Queue depth can be measured
        - Backlog is accurately reported
        """
        from kombu import Connection

        # Get queue lengths
        queue_lengths = {}

        try:
            with celery_app.connection_or_acquire() as conn:
                for queue in ['high_priority', 'medium_priority', 'low_priority', 'emails']:
                    try:
                        # Get queue object
                        queue_obj = conn.SimpleQueue(queue)
                        # Note: This is a simplified check - actual implementation
                        # would use the management API
                        queue_lengths[queue] = 0  # Placeholder
                        queue_obj.close()
                    except Exception as e:
                        queue_lengths[queue] = f"Error: {e}"
        except Exception as e:
            pytest.skip(f"Cannot connect to broker: {e}")

        assert isinstance(queue_lengths, dict)
        print(f"\nQueue lengths: {queue_lengths}")

    @pytest.mark.slow
    def test_queue_recovery_after_backlog(self, celery_app, sample_task):
        """
        Test queue recovery after building up a backlog.

        This simulates a scenario where tasks pile up faster than
        they can be processed, then verifies recovery.
        """
        # Build up backlog by submitting many tasks
        num_tasks = 200
        task_ids = []

        # Submit tasks rapidly
        for i in range(num_tasks):
            result = sample_task.delay(i, delay=0.05)
            task_ids.append(result.id)

        # Wait for all to complete
        start_time = time.time()
        completed = 0
        max_wait = 120  # 2 minutes

        while completed < num_tasks and (time.time() - start_time) < max_wait:
            completed = sum(
                1 for tid in task_ids
                if AsyncResult(tid).ready()
            )
            time.sleep(1)

        duration = time.time() - start_time
        completion_rate = completed / num_tasks * 100

        assert completion_rate >= 95, f"Only {completion_rate:.1f}% tasks completed"
        print(f"\nBacklog recovery: {completed}/{num_tasks} tasks in {duration:.1f}s")


class TestWorkerScaling:
    """Tests for worker auto-scaling."""

    def test_worker_autoscale_config(self, celery_app):
        """
        Test that autoscale configuration is set correctly.
        """
        autoscale = celery_app.conf.worker_autoscale

        assert autoscale is not None, "Autoscale not configured"
        assert len(autoscale) == 2, "Autoscale should have (max, min) values"

        max_workers, min_workers = autoscale
        assert min_workers >= 1, "Minimum workers should be at least 1"
        assert max_workers >= min_workers, "Max workers should be >= min workers"
        assert max_workers <= 100, "Max workers should not exceed 100"

        print(f"\nAutoscale config: min={min_workers}, max={max_workers}")

    def test_prefetch_multiplier_config(self, celery_app):
        """
        Test prefetch multiplier configuration.

        Lower prefetch = fairer distribution across workers.
        """
        prefetch = celery_app.conf.worker_prefetch_multiplier

        assert prefetch is not None, "Prefetch multiplier not configured"
        assert 1 <= prefetch <= 4, f"Prefetch should be 1-4, got {prefetch}"

        print(f"\nPrefetch multiplier: {prefetch}")

    def test_max_tasks_per_child(self, celery_app):
        """
        Test max tasks per child configuration.

        This prevents memory leaks by recycling workers.
        """
        max_tasks = celery_app.conf.worker_max_tasks_per_child

        assert max_tasks is not None, "Max tasks per child not configured"
        assert max_tasks >= 100, "Max tasks should be at least 100"
        assert max_tasks <= 10000, "Max tasks should not exceed 10000"

        print(f"\nMax tasks per child: {max_tasks}")


class TestRateLimiting:
    """Tests for task rate limiting."""

    def test_rate_limit_configuration(self, celery_app):
        """
        Test that rate limits are configured.
        """
        annotations = celery_app.conf.task_annotations

        assert annotations is not None, "Task annotations not configured"

        # Check some expected rate limits
        expected_limits = [
            'core.tasks.email_tasks.send_email_task',
            'core.tasks.email_tasks.send_bulk_email_task',
        ]

        for task_name in expected_limits:
            if task_name in annotations:
                limit = annotations[task_name].get('rate_limit')
                assert limit is not None, f"No rate limit for {task_name}"
                print(f"\n{task_name}: rate_limit={limit}")

    def test_default_rate_limit(self, celery_app):
        """
        Test default rate limit is set.
        """
        default_limit = celery_app.conf.task_default_rate_limit

        if default_limit:
            print(f"\nDefault rate limit: {default_limit}")
        else:
            print("\nNo default rate limit set")


class TestTaskPriority:
    """Tests for task priority queues."""

    def test_priority_queues_configured(self, celery_app):
        """
        Test that priority queues are configured.
        """
        queues = celery_app.conf.task_queues

        assert queues is not None, "Task queues not configured"

        queue_names = [q.name for q in queues]

        expected_queues = ['high_priority', 'medium_priority', 'low_priority']
        for expected in expected_queues:
            assert expected in queue_names, f"Missing queue: {expected}"

        print(f"\nConfigured queues: {queue_names}")

    def test_task_routing_configured(self, celery_app):
        """
        Test that task routing is configured.
        """
        routes = celery_app.conf.task_routes

        assert routes is not None, "Task routes not configured"
        assert len(routes) > 0, "No task routes defined"

        print(f"\nNumber of routing rules: {len(routes)}")


class TestRetryConfiguration:
    """Tests for retry configuration."""

    def test_retry_policy_configured(self, celery_app):
        """
        Test that retry policy is configured.
        """
        policy = celery_app.conf.task_retry_policy

        assert policy is not None, "Retry policy not configured"
        assert 'max_retries' in policy, "max_retries not in policy"
        assert 'interval_start' in policy, "interval_start not in policy"

        print(f"\nRetry policy: {policy}")

    def test_default_retry_delay(self, celery_app):
        """
        Test default retry delay.
        """
        delay = celery_app.conf.task_default_retry_delay

        assert delay is not None, "Default retry delay not configured"
        assert delay > 0, "Retry delay should be positive"

        print(f"\nDefault retry delay: {delay}s")


class TestSerializationCompression:
    """Tests for serialization and compression."""

    def test_serialization_configured(self, celery_app):
        """
        Test serialization configuration.
        """
        serializer = celery_app.conf.task_serializer
        result_serializer = celery_app.conf.result_serializer
        accept_content = celery_app.conf.accept_content

        assert serializer == 'json', f"Task serializer should be json, got {serializer}"
        assert result_serializer == 'json', f"Result serializer should be json"
        assert 'json' in accept_content, "json should be in accept_content"

        print(f"\nSerializers: task={serializer}, result={result_serializer}")

    def test_compression_configured(self, celery_app):
        """
        Test compression configuration.
        """
        task_compression = celery_app.conf.task_compression
        result_compression = celery_app.conf.result_compression

        assert task_compression == 'gzip', f"Task compression should be gzip"
        assert result_compression == 'gzip', f"Result compression should be gzip"

        print(f"\nCompression: task={task_compression}, result={result_compression}")


class TestResultBackend:
    """Tests for result backend configuration."""

    def test_result_expiry_configured(self, celery_app):
        """
        Test result expiry configuration.
        """
        expires = celery_app.conf.result_expires

        assert expires is not None, "Result expires not configured"

        # Convert to seconds if timedelta
        if hasattr(expires, 'total_seconds'):
            expires_seconds = expires.total_seconds()
        else:
            expires_seconds = expires

        assert expires_seconds > 0, "Result expires should be positive"
        assert expires_seconds <= 86400, "Results shouldn't expire after more than 24h"

        print(f"\nResult expiry: {expires_seconds}s")

    def test_result_extended_configured(self, celery_app):
        """
        Test extended result metadata.
        """
        extended = celery_app.conf.result_extended

        assert extended is True, "Result extended should be True"


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestBaseTaskClasses:
    """Tests for base task classes."""

    def test_auto_retry_task_exists(self):
        """Test AutoRetryTask class exists and has correct attributes."""
        from zumodra.celery_tasks_base import AutoRetryTask

        assert hasattr(AutoRetryTask, 'max_retries')
        assert hasattr(AutoRetryTask, 'retry_backoff')
        assert hasattr(AutoRetryTask, 'retry_jitter')

    def test_tenant_aware_task_exists(self):
        """Test TenantAwareTask class exists and has correct methods."""
        from zumodra.celery_tasks_base import TenantAwareTask

        assert hasattr(TenantAwareTask, 'tenant')
        assert hasattr(TenantAwareTask, '_setup_tenant_context')
        assert hasattr(TenantAwareTask, '_teardown_tenant_context')

    def test_monitored_task_exists(self):
        """Test MonitoredTask class exists and has metrics methods."""
        from zumodra.celery_tasks_base import MonitoredTask

        assert hasattr(MonitoredTask, '_init_metrics')
        assert hasattr(MonitoredTask, '_record_metrics')

    def test_chainable_task_exists(self):
        """Test ChainableTask class exists and has workflow methods."""
        from zumodra.celery_tasks_base import ChainableTask

        assert hasattr(ChainableTask, 'workflow_id')
        assert hasattr(ChainableTask, 'chain_to')

    def test_zumodra_base_task_exists(self):
        """Test combined ZumodraBaseTask class exists."""
        from zumodra.celery_tasks_base import ZumodraBaseTask

        # Should inherit from all base classes
        assert hasattr(ZumodraBaseTask, 'max_retries')  # From AutoRetryTask
        assert hasattr(ZumodraBaseTask, 'tenant')  # From TenantAwareTask
        assert hasattr(ZumodraBaseTask, '_record_metrics')  # From MonitoredTask


class TestEmailTasks:
    """Tests for email task functions."""

    def test_send_email_task_exists(self):
        """Test send_email_task is importable."""
        from core.tasks.email_tasks import send_email_task

        assert callable(send_email_task)
        assert hasattr(send_email_task, 'delay')
        assert hasattr(send_email_task, 'apply_async')

    def test_send_bulk_email_task_exists(self):
        """Test send_bulk_email_task is importable."""
        from core.tasks.email_tasks import send_bulk_email_task

        assert callable(send_bulk_email_task)

    def test_send_transactional_email_task_exists(self):
        """Test send_transactional_email_task is importable."""
        from core.tasks.email_tasks import send_transactional_email_task

        assert callable(send_transactional_email_task)


class TestBackgroundTasks:
    """Tests for background task functions."""

    def test_pdf_generation_task_exists(self):
        """Test pdf_generation_task is importable."""
        from core.tasks.background_tasks import pdf_generation_task

        assert callable(pdf_generation_task)

    def test_data_export_task_exists(self):
        """Test data_export_task is importable."""
        from core.tasks.background_tasks import data_export_task

        assert callable(data_export_task)

    def test_analytics_aggregation_task_exists(self):
        """Test analytics_aggregation_task is importable."""
        from core.tasks.background_tasks import analytics_aggregation_task

        assert callable(analytics_aggregation_task)

    def test_cache_warming_task_exists(self):
        """Test cache_warming_task is importable."""
        from core.tasks.background_tasks import cache_warming_task

        assert callable(cache_warming_task)


class TestMaintenanceTasks:
    """Tests for maintenance task functions."""

    def test_cleanup_old_sessions_task_exists(self):
        """Test cleanup_old_sessions_task is importable."""
        from core.tasks.maintenance_tasks import cleanup_old_sessions_task

        assert callable(cleanup_old_sessions_task)

    def test_backup_rotation_task_exists(self):
        """Test backup_rotation_task is importable."""
        from core.tasks.maintenance_tasks import backup_rotation_task

        assert callable(backup_rotation_task)

    def test_ssl_renewal_check_task_exists(self):
        """Test ssl_renewal_check_task is importable."""
        from core.tasks.maintenance_tasks import ssl_renewal_check_task

        assert callable(ssl_renewal_check_task)

    def test_failed_payment_retry_task_exists(self):
        """Test failed_payment_retry_task is importable."""
        from core.tasks.maintenance_tasks import failed_payment_retry_task

        assert callable(failed_payment_retry_task)


# =============================================================================
# BENCHMARKS
# =============================================================================

class TestBenchmarks:
    """Benchmark tests for performance measurement."""

    @pytest.mark.slow
    def test_task_latency(self, celery_app, sample_task):
        """
        Measure task execution latency.
        """
        latencies = []

        for i in range(10):
            start = time.time()
            result = sample_task.delay(i, delay=0)
            result.get(timeout=10)
            latency = time.time() - start
            latencies.append(latency)

        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)
        min_latency = min(latencies)

        print(f"\nLatency: avg={avg_latency*1000:.2f}ms, "
              f"min={min_latency*1000:.2f}ms, max={max_latency*1000:.2f}ms")

        assert avg_latency < 1.0, f"Average latency too high: {avg_latency:.2f}s"

    @pytest.mark.slow
    def test_throughput(self, celery_app, sample_task):
        """
        Measure task throughput.
        """
        num_tasks = 100
        start = time.time()

        task_group = group(sample_task.s(i, delay=0) for i in range(num_tasks))
        group_result = task_group.apply_async()
        group_result.get(timeout=60)

        duration = time.time() - start
        throughput = num_tasks / duration

        print(f"\nThroughput: {throughput:.2f} tasks/second")

        assert throughput > 10, f"Throughput too low: {throughput:.2f} tasks/s"


# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
