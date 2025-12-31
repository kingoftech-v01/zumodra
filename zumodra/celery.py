"""
Celery configuration for Zumodra project.

This module configures Celery for async task processing with:
- Auto-discovery of tasks from all registered Django apps
- Task routing to specialized queues
- Rate limiting configurations
- Error handling and retry policies
- Result backend configuration
"""

import os
from celery import Celery
from celery.schedules import crontab
from kombu import Exchange, Queue

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')

app = Celery('zumodra')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()


# ==================== QUEUE CONFIGURATION ====================

# Define exchanges
default_exchange = Exchange('default', type='direct')
emails_exchange = Exchange('emails', type='direct')
payments_exchange = Exchange('payments', type='direct')
analytics_exchange = Exchange('analytics', type='direct')
notifications_exchange = Exchange('notifications', type='direct')
hr_exchange = Exchange('hr', type='direct')
ats_exchange = Exchange('ats', type='direct')

# Define queues
app.conf.task_queues = (
    Queue('default', default_exchange, routing_key='default'),
    Queue('emails', emails_exchange, routing_key='emails'),
    Queue('payments', payments_exchange, routing_key='payments'),
    Queue('analytics', analytics_exchange, routing_key='analytics'),
    Queue('notifications', notifications_exchange, routing_key='notifications'),
    Queue('hr', hr_exchange, routing_key='hr'),
    Queue('ats', ats_exchange, routing_key='ats'),
    Queue('celery', default_exchange, routing_key='celery'),
)

app.conf.task_default_queue = 'default'
app.conf.task_default_exchange = 'default'
app.conf.task_default_routing_key = 'default'


# ==================== TASK ROUTING ====================

app.conf.task_routes = {
    # Email tasks
    'newsletter.tasks.*': {'queue': 'emails', 'routing_key': 'emails'},
    'notifications.tasks.send_*': {'queue': 'emails', 'routing_key': 'emails'},
    'zumodra.tasks.send_daily_digest': {'queue': 'emails', 'routing_key': 'emails'},

    # Payment tasks
    'finance.tasks.*': {'queue': 'payments', 'routing_key': 'payments'},
    'tenants.tasks.process_subscription_*': {'queue': 'payments', 'routing_key': 'payments'},

    # Analytics tasks
    'analytics.tasks.*': {'queue': 'analytics', 'routing_key': 'analytics'},
    'zumodra.tasks.calculate_daily_metrics': {'queue': 'analytics', 'routing_key': 'analytics'},

    # Notification tasks
    'notifications.tasks.*': {'queue': 'notifications', 'routing_key': 'notifications'},
    'messages_sys.tasks.*': {'queue': 'notifications', 'routing_key': 'notifications'},

    # HR tasks
    'hr_core.tasks.*': {'queue': 'hr', 'routing_key': 'hr'},
    'accounts.tasks.*': {'queue': 'hr', 'routing_key': 'hr'},

    # ATS tasks
    'ats.tasks.*': {'queue': 'ats', 'routing_key': 'ats'},
    'careers.tasks.*': {'queue': 'ats', 'routing_key': 'ats'},

    # Default shared tasks
    'zumodra.tasks.*': {'queue': 'default', 'routing_key': 'default'},
    'tenants.tasks.*': {'queue': 'default', 'routing_key': 'default'},
}


# ==================== RATE LIMITING ====================

app.conf.task_annotations = {
    # Email rate limits - prevent spam/throttling by email providers
    'newsletter.tasks.send_newsletter': {'rate_limit': '50/m'},
    'notifications.tasks.send_email_notification': {'rate_limit': '100/m'},

    # Payment tasks - be careful with payment APIs
    'finance.tasks.process_payment': {'rate_limit': '30/m'},
    'finance.tasks.sync_stripe_subscriptions': {'rate_limit': '10/m'},

    # Analytics - resource intensive tasks
    'analytics.tasks.calculate_daily_metrics': {'rate_limit': '2/m'},
    'analytics.tasks.generate_reports': {'rate_limit': '5/m'},

    # ATS tasks
    'ats.tasks.calculate_match_scores': {'rate_limit': '20/m'},

    # Cleanup tasks
    'zumodra.tasks.cleanup_expired_sessions': {'rate_limit': '1/h'},
    'zumodra.tasks.cleanup_old_audit_logs': {'rate_limit': '1/h'},
    'zumodra.tasks.backup_database': {'rate_limit': '1/h'},
}


# ==================== RETRY CONFIGURATION ====================

app.conf.task_default_retry_delay = 60  # 1 minute
app.conf.task_max_retries = 3

# Specific retry policies for different task types
app.conf.task_retry_policy = {
    'max_retries': 3,
    'interval_start': 0,
    'interval_step': 60,
    'interval_max': 300,
}


# ==================== SERIALIZATION ====================

app.conf.task_serializer = 'json'
app.conf.result_serializer = 'json'
app.conf.accept_content = ['json']
app.conf.timezone = 'UTC'
app.conf.enable_utc = True


# ==================== RESULT BACKEND ====================

# Results will be stored for 24 hours
app.conf.result_expires = 86400

# Task result extended - store additional task metadata
app.conf.result_extended = True


# ==================== WORKER CONFIGURATION ====================

# Prevent memory leaks by restarting workers after N tasks
app.conf.worker_max_tasks_per_child = 1000

# Prefetch multiplier - number of tasks to prefetch per worker
app.conf.worker_prefetch_multiplier = 4

# Worker concurrency - number of concurrent task executions
# This can be overridden via command line: celery -A zumodra worker -c 8
app.conf.worker_concurrency = 4

# Disable task events by default (can enable for monitoring)
app.conf.worker_send_task_events = False
app.conf.task_send_sent_event = False


# ==================== TASK EXECUTION ====================

# Task time limit (hard limit - task will be killed)
app.conf.task_time_limit = 3600  # 1 hour

# Task soft time limit (raises SoftTimeLimitExceeded)
app.conf.task_soft_time_limit = 3300  # 55 minutes

# Task acknowledgment - acknowledge task after completion (safer)
app.conf.task_acks_late = True

# Reject task if worker dies during execution
app.conf.task_reject_on_worker_lost = True


# ==================== TASK COMPRESSION ====================

# Enable compression for large task payloads
app.conf.task_compression = 'gzip'
app.conf.result_compression = 'gzip'


# ==================== BEAT SCHEDULE ====================

# Import beat schedule from separate module for cleaner organization
from zumodra.celery_beat_schedule import CELERY_BEAT_SCHEDULE
app.conf.beat_schedule = CELERY_BEAT_SCHEDULE


# ==================== DEBUG TASK ====================

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
