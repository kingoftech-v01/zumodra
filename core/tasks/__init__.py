"""
Core Tasks Module for Zumodra

This module provides reusable task implementations for:
- Email delivery (transactional, bulk, scheduled)
- Background processing (PDF generation, data exports)
- Maintenance operations (cleanup, backups, health checks)
"""

from core.tasks.email_tasks import (
    send_email_task,
    send_bulk_email_task,
    send_transactional_email_task,
)
from core.tasks.background_tasks import (
    pdf_generation_task,
    data_export_task,
    analytics_aggregation_task,
    cache_warming_task,
)
from core.tasks.maintenance_tasks import (
    cleanup_old_sessions_task,
    backup_rotation_task,
    ssl_renewal_check_task,
    failed_payment_retry_task,
)

__all__ = [
    # Email tasks
    'send_email_task',
    'send_bulk_email_task',
    'send_transactional_email_task',
    # Background tasks
    'pdf_generation_task',
    'data_export_task',
    'analytics_aggregation_task',
    'cache_warming_task',
    # Maintenance tasks
    'cleanup_old_sessions_task',
    'backup_rotation_task',
    'ssl_renewal_check_task',
    'failed_payment_retry_task',
]
