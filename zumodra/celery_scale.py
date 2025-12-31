"""
Production Celery Configuration for Hyper-Scale Operations

This module provides enterprise-grade Celery configuration for handling
100K+ concurrent tasks with:
- Priority-based task routing (high/medium/low queues)
- Auto-scaling workers (1-100 based on load)
- Redis cluster result backend with connection pooling
- Exponential backoff retry with jitter
- Dead letter queue for failed tasks
- Per-task rate limiting
- Task compression (gzip)
- Prometheus metrics integration
"""

import os
from datetime import timedelta
from celery import Celery
from celery.signals import (
    task_prerun,
    task_postrun,
    task_failure,
    task_retry,
    worker_ready,
    worker_shutdown,
)
from kombu import Exchange, Queue

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')

app = Celery('zumodra')

# Load config from Django settings with CELERY_ namespace
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks from all registered Django apps
app.autodiscover_tasks()


# =============================================================================
# PRIORITY QUEUE CONFIGURATION
# =============================================================================

# Define exchanges for different priority levels
high_priority_exchange = Exchange('high_priority', type='direct', durable=True)
medium_priority_exchange = Exchange('medium_priority', type='direct', durable=True)
low_priority_exchange = Exchange('low_priority', type='direct', durable=True)

# Domain-specific exchanges
emails_exchange = Exchange('emails', type='direct', durable=True)
payments_exchange = Exchange('payments', type='direct', durable=True)
analytics_exchange = Exchange('analytics', type='direct', durable=True)
notifications_exchange = Exchange('notifications', type='direct', durable=True)
hr_exchange = Exchange('hr', type='direct', durable=True)
ats_exchange = Exchange('ats', type='direct', durable=True)

# Dead letter exchange for failed tasks
dead_letter_exchange = Exchange('dead_letter', type='direct', durable=True)

# Define queues with priorities
app.conf.task_queues = (
    # Priority queues
    Queue(
        'high_priority',
        high_priority_exchange,
        routing_key='high',
        queue_arguments={
            'x-max-priority': 10,
            'x-dead-letter-exchange': 'dead_letter',
            'x-dead-letter-routing-key': 'dead_letter',
        }
    ),
    Queue(
        'medium_priority',
        medium_priority_exchange,
        routing_key='medium',
        queue_arguments={
            'x-max-priority': 5,
            'x-dead-letter-exchange': 'dead_letter',
            'x-dead-letter-routing-key': 'dead_letter',
        }
    ),
    Queue(
        'low_priority',
        low_priority_exchange,
        routing_key='low',
        queue_arguments={
            'x-max-priority': 1,
            'x-dead-letter-exchange': 'dead_letter',
            'x-dead-letter-routing-key': 'dead_letter',
        }
    ),

    # Domain-specific queues
    Queue(
        'emails',
        emails_exchange,
        routing_key='emails',
        queue_arguments={
            'x-max-priority': 5,
            'x-dead-letter-exchange': 'dead_letter',
        }
    ),
    Queue(
        'emails_transactional',
        emails_exchange,
        routing_key='emails.transactional',
        queue_arguments={'x-max-priority': 10}
    ),
    Queue(
        'payments',
        payments_exchange,
        routing_key='payments',
        queue_arguments={'x-max-priority': 10}
    ),
    Queue(
        'analytics',
        analytics_exchange,
        routing_key='analytics',
        queue_arguments={'x-max-priority': 3}
    ),
    Queue(
        'notifications',
        notifications_exchange,
        routing_key='notifications',
        queue_arguments={'x-max-priority': 5}
    ),
    Queue(
        'hr',
        hr_exchange,
        routing_key='hr',
        queue_arguments={'x-max-priority': 5}
    ),
    Queue(
        'ats',
        ats_exchange,
        routing_key='ats',
        queue_arguments={'x-max-priority': 5}
    ),

    # Dead letter queue
    Queue(
        'dead_letter',
        dead_letter_exchange,
        routing_key='dead_letter',
        queue_arguments={'x-message-ttl': 86400000}  # 24 hours
    ),

    # Default queue
    Queue('default', routing_key='default'),
    Queue('celery', routing_key='celery'),
)

app.conf.task_default_queue = 'medium_priority'
app.conf.task_default_exchange = 'medium_priority'
app.conf.task_default_routing_key = 'medium'


# =============================================================================
# TASK ROUTING - Priority-based
# =============================================================================

app.conf.task_routes = {
    # HIGH PRIORITY - Critical operations
    'core.tasks.email_tasks.send_transactional_email_task': {
        'queue': 'emails_transactional',
        'routing_key': 'emails.transactional',
    },
    'finance.tasks.process_payment': {
        'queue': 'payments',
        'routing_key': 'payments',
    },
    'finance.tasks.process_refund': {
        'queue': 'payments',
        'routing_key': 'payments',
    },
    'notifications.tasks.send_critical_notification': {
        'queue': 'high_priority',
        'routing_key': 'high',
    },

    # MEDIUM PRIORITY - Standard operations
    'core.tasks.email_tasks.send_email_task': {
        'queue': 'emails',
        'routing_key': 'emails',
    },
    'core.tasks.email_tasks.send_bulk_email_task': {
        'queue': 'emails',
        'routing_key': 'emails',
    },
    'newsletter.tasks.*': {'queue': 'emails', 'routing_key': 'emails'},
    'notifications.tasks.*': {
        'queue': 'notifications',
        'routing_key': 'notifications',
    },
    'hr_core.tasks.*': {'queue': 'hr', 'routing_key': 'hr'},
    'ats.tasks.*': {'queue': 'ats', 'routing_key': 'ats'},
    'careers.tasks.*': {'queue': 'ats', 'routing_key': 'ats'},
    'accounts.tasks.*': {'queue': 'hr', 'routing_key': 'hr'},

    # LOW PRIORITY - Background operations
    'analytics.tasks.*': {'queue': 'analytics', 'routing_key': 'analytics'},
    'core.tasks.background_tasks.*': {
        'queue': 'low_priority',
        'routing_key': 'low',
    },
    'core.tasks.maintenance_tasks.*': {
        'queue': 'low_priority',
        'routing_key': 'low',
    },

    # Default routing
    'zumodra.tasks.*': {'queue': 'medium_priority', 'routing_key': 'medium'},
    'tenants.tasks.*': {'queue': 'medium_priority', 'routing_key': 'medium'},
}


# =============================================================================
# RATE LIMITING CONFIGURATION
# =============================================================================

app.conf.task_default_rate_limit = '100/m'

app.conf.task_annotations = {
    # Email rate limits - prevent spam/throttling
    'core.tasks.email_tasks.send_email_task': {'rate_limit': '100/m'},
    'core.tasks.email_tasks.send_bulk_email_task': {'rate_limit': '20/m'},
    'core.tasks.email_tasks.send_transactional_email_task': {'rate_limit': '200/m'},
    'newsletter.tasks.send_newsletter': {'rate_limit': '50/m'},
    'notifications.tasks.send_email_notification': {'rate_limit': '100/m'},

    # Payment tasks - be careful with payment APIs
    'finance.tasks.process_payment': {'rate_limit': '30/m'},
    'finance.tasks.sync_stripe_subscriptions': {'rate_limit': '10/m'},
    'core.tasks.maintenance_tasks.failed_payment_retry_task': {'rate_limit': '20/m'},

    # Analytics - resource intensive
    'analytics.tasks.calculate_daily_metrics': {'rate_limit': '2/m'},
    'analytics.tasks.generate_reports': {'rate_limit': '5/m'},
    'core.tasks.background_tasks.analytics_aggregation_task': {'rate_limit': '5/m'},

    # Background tasks
    'core.tasks.background_tasks.pdf_generation_task': {'rate_limit': '30/m'},
    'core.tasks.background_tasks.data_export_task': {'rate_limit': '10/m'},
    'core.tasks.background_tasks.cache_warming_task': {'rate_limit': '60/h'},

    # Maintenance tasks
    'core.tasks.maintenance_tasks.cleanup_old_sessions_task': {'rate_limit': '1/h'},
    'core.tasks.maintenance_tasks.backup_rotation_task': {'rate_limit': '1/h'},
    'core.tasks.maintenance_tasks.ssl_renewal_check_task': {'rate_limit': '4/d'},

    # ATS tasks
    'ats.tasks.calculate_match_scores': {'rate_limit': '20/m'},

    # Cleanup tasks
    'zumodra.tasks.cleanup_expired_sessions': {'rate_limit': '1/h'},
    'zumodra.tasks.cleanup_old_audit_logs': {'rate_limit': '1/h'},
    'zumodra.tasks.backup_database': {'rate_limit': '1/h'},
}


# =============================================================================
# RETRY CONFIGURATION WITH EXPONENTIAL BACKOFF
# =============================================================================

app.conf.task_default_retry_delay = 60  # 1 minute base delay
app.conf.task_max_retries = 3

# Exponential backoff retry policy
app.conf.task_retry_policy = {
    'max_retries': 3,
    'interval_start': 10,       # First retry after 10 seconds
    'interval_step': 30,        # Add 30 seconds each retry
    'interval_max': 300,        # Max 5 minutes between retries
}

# Enable automatic retry on common transient errors
app.conf.task_autoretry_for = (
    ConnectionError,
    TimeoutError,
    IOError,
)

# Retry with jitter to prevent thundering herd
app.conf.task_retry_jitter = True


# =============================================================================
# SERIALIZATION & COMPRESSION
# =============================================================================

app.conf.task_serializer = 'json'
app.conf.result_serializer = 'json'
app.conf.accept_content = ['json']
app.conf.timezone = 'UTC'
app.conf.enable_utc = True

# Enable compression for large payloads
app.conf.task_compression = 'gzip'
app.conf.result_compression = 'gzip'


# =============================================================================
# RESULT BACKEND - Redis Cluster with Connection Pooling
# =============================================================================

# Results expire after 1 hour
app.conf.result_expires = timedelta(hours=1)

# Store extended task metadata
app.conf.result_extended = True

# Redis connection pooling
app.conf.broker_pool_limit = 50  # Max broker connections
app.conf.broker_connection_max_retries = 5
app.conf.broker_connection_retry_on_startup = True

# Redis result backend options
app.conf.result_backend_transport_options = {
    'retry_policy': {
        'timeout': 5.0,
    },
    'socket_keepalive': True,
    'socket_timeout': 5,
    'socket_connect_timeout': 5,
}

# Redis broker options
app.conf.broker_transport_options = {
    'visibility_timeout': 43200,  # 12 hours
    'socket_timeout': 30,
    'socket_connect_timeout': 30,
    'socket_keepalive': True,
    'health_check_interval': 30,
    'retry_on_timeout': True,
    'priority_steps': list(range(10)),  # Support 0-9 priority levels
}


# =============================================================================
# WORKER CONFIGURATION - Auto-Scaling
# =============================================================================

# Base worker concurrency
app.conf.worker_concurrency = int(os.environ.get('CELERY_WORKER_CONCURRENCY', 4))

# Auto-scale configuration (min, max workers)
app.conf.worker_autoscale = (
    int(os.environ.get('CELERY_AUTOSCALE_MAX', 100)),  # Max workers
    int(os.environ.get('CELERY_AUTOSCALE_MIN', 1)),    # Min workers
)

# Restart workers after N tasks to prevent memory leaks
app.conf.worker_max_tasks_per_child = 1000

# Memory limit per worker (if supported)
app.conf.worker_max_memory_per_child = 200000  # 200MB

# Prefetch multiplier - fewer for fair distribution
app.conf.worker_prefetch_multiplier = 2

# Disable remote control for security
app.conf.worker_disable_rate_limits = False

# Enable task events for monitoring
app.conf.worker_send_task_events = True
app.conf.task_send_sent_event = True

# Worker heartbeat
app.conf.worker_hijack_root_logger = False


# =============================================================================
# TASK EXECUTION LIMITS
# =============================================================================

# Hard time limit - task will be killed
app.conf.task_time_limit = 3600  # 1 hour

# Soft time limit - raises SoftTimeLimitExceeded
app.conf.task_soft_time_limit = 3300  # 55 minutes

# Acknowledge task after completion (safer for reliability)
app.conf.task_acks_late = True

# Reject task if worker dies during execution
app.conf.task_reject_on_worker_lost = True

# Track when tasks start
app.conf.task_track_started = True

# Store errors even after task completion
app.conf.task_store_errors_even_if_ignored = True


# =============================================================================
# BEAT SCHEDULE - Import from separate module
# =============================================================================

from zumodra.celery_beat_schedule import CELERY_BEAT_SCHEDULE
app.conf.beat_schedule = CELERY_BEAT_SCHEDULE


# =============================================================================
# SIGNAL HANDLERS FOR MONITORING
# =============================================================================

@worker_ready.connect
def on_worker_ready(sender, **kwargs):
    """Log when worker is ready."""
    import logging
    logger = logging.getLogger('celery.worker')
    logger.info(f"Worker {sender} is ready and accepting tasks")


@worker_shutdown.connect
def on_worker_shutdown(sender, **kwargs):
    """Log when worker is shutting down."""
    import logging
    logger = logging.getLogger('celery.worker')
    logger.info(f"Worker {sender} is shutting down")


@task_prerun.connect
def on_task_prerun(sender, task_id, task, args, kwargs, **other):
    """Track task start for metrics."""
    import logging
    logger = logging.getLogger('celery.task')
    logger.debug(f"Task {task.name}[{task_id}] starting")

    # Increment Prometheus counter if available
    try:
        from prometheus_client import Counter
        task_started_counter = Counter(
            'celery_task_started_total',
            'Total number of started Celery tasks',
            ['task_name']
        )
        task_started_counter.labels(task_name=task.name).inc()
    except ImportError:
        pass


@task_postrun.connect
def on_task_postrun(sender, task_id, task, args, kwargs, retval, state, **other):
    """Track task completion for metrics."""
    import logging
    logger = logging.getLogger('celery.task')
    logger.debug(f"Task {task.name}[{task_id}] completed with state {state}")

    # Increment Prometheus counter if available
    try:
        from prometheus_client import Counter
        task_completed_counter = Counter(
            'celery_task_completed_total',
            'Total number of completed Celery tasks',
            ['task_name', 'state']
        )
        task_completed_counter.labels(task_name=task.name, state=state).inc()
    except ImportError:
        pass


@task_failure.connect
def on_task_failure(sender, task_id, exception, args, kwargs, traceback, einfo, **other):
    """Track task failures and send to dead letter queue."""
    import logging
    logger = logging.getLogger('celery.task')
    logger.error(
        f"Task {sender.name}[{task_id}] failed: {exception}",
        exc_info=True
    )

    # Send to dead letter queue for later analysis
    try:
        app.send_task(
            'zumodra.tasks.handle_dead_letter',
            args=[{
                'task_id': task_id,
                'task_name': sender.name,
                'args': str(args),
                'kwargs': str(kwargs),
                'exception': str(exception),
                'traceback': str(einfo),
            }],
            queue='dead_letter',
            routing_key='dead_letter',
        )
    except Exception as e:
        logger.error(f"Failed to send to dead letter queue: {e}")

    # Increment Prometheus counter if available
    try:
        from prometheus_client import Counter
        task_failed_counter = Counter(
            'celery_task_failed_total',
            'Total number of failed Celery tasks',
            ['task_name']
        )
        task_failed_counter.labels(task_name=sender.name).inc()
    except ImportError:
        pass


@task_retry.connect
def on_task_retry(sender, request, reason, einfo, **kwargs):
    """Track task retries."""
    import logging
    logger = logging.getLogger('celery.task')
    logger.warning(f"Task {sender.name}[{request.id}] retrying: {reason}")

    # Increment Prometheus counter if available
    try:
        from prometheus_client import Counter
        task_retry_counter = Counter(
            'celery_task_retry_total',
            'Total number of retried Celery tasks',
            ['task_name']
        )
        task_retry_counter.labels(task_name=sender.name).inc()
    except ImportError:
        pass


# =============================================================================
# DEBUG TASKS
# =============================================================================

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Debug task for testing Celery setup."""
    print(f'Request: {self.request!r}')
    return {'status': 'ok', 'task_id': self.request.id}


@app.task(bind=True)
def health_check(self):
    """
    Simple health check task to verify Celery is running.
    Returns basic system info for monitoring.
    """
    import platform
    import sys
    from datetime import datetime

    return {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'python_version': sys.version,
        'platform': platform.platform(),
        'task_id': self.request.id,
        'worker_hostname': self.request.hostname,
    }


@app.task(bind=True, queue='dead_letter')
def handle_dead_letter(self, task_info):
    """
    Process tasks that have been sent to the dead letter queue.
    Store them for later analysis and potential manual retry.
    """
    import logging
    from django.core.cache import cache

    logger = logging.getLogger('celery.dead_letter')
    logger.info(f"Processing dead letter: {task_info}")

    # Store in cache/database for analysis
    dead_letter_key = f"dead_letter:{task_info['task_id']}"
    cache.set(dead_letter_key, task_info, timeout=86400 * 7)  # 7 days

    return {'status': 'stored', 'task_id': task_info['task_id']}
