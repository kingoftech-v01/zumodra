"""
Celery configuration for zumodra project.

This module configures Celery for async task processing.
"""

import os
from celery import Celery

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


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Debug task for testing Celery setup."""
    print(f'Request: {self.request!r}')


# Celery Beat Schedule (for periodic tasks)
app.conf.beat_schedule = {
    # Example: Send newsletter every day at 9 AM
    'send-daily-newsletter': {
        'task': 'newsletter.tasks.send_scheduled_newsletters',
        'schedule': 3600.0,  # Every hour (adjust as needed)
    },
    # Example: Clean up old sessions every week
    'cleanup-sessions': {
        'task': 'zumodra.tasks.cleanup_old_sessions',
        'schedule': 604800.0,  # Every week (7 days)
    },
}

# Celery Task Routes (optional - for directing tasks to specific queues)
app.conf.task_routes = {
    'newsletter.tasks.*': {'queue': 'emails'},
    'finance.tasks.*': {'queue': 'payments'},
    'messages_sys.tasks.*': {'queue': 'realtime'},
}
