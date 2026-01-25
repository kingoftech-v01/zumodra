"""
tenants Signals

Django signal handlers for tenants models.
"""

from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)


# Example signal handler (customize per app)
# @receiver(post_save, sender=ModelName)
# def model_saved(sender, instance, created, **kwargs):
#     """
#     Handle model creation/update.
#     
#     Triggers:
#         - Cache invalidation
#         - Async processing task
#         - Notification creation
#         - Webhook dispatch
#     """
#     if created:
#         logger.info(f"Created {sender.__name__}: {instance.id}")
#         
#         # Invalidate related caches
#         cache_key = f"tenants_{sender.__name__}_{instance.id}"
#         cache.delete(cache_key)
#         
#         # Trigger async task (if tasks.py exists)
#         # from .tasks import process_operation
#         # process_operation.delay(instance.id)
#     
#     else:
#         logger.info(f"Updated {sender.__name__}: {instance.id}")


# @receiver(post_delete, sender=ModelName)
# def model_deleted(sender, instance, **kwargs):
#     """Handle model deletion."""
#     logger.info(f"Deleted {sender.__name__}: {instance.id}")
#     
#     # Cleanup logic
#     cache_key = f"tenants_{sender.__name__}_{instance.id}"
#     cache.delete(cache_key)


# @receiver(pre_save, sender=ModelName)
# def model_pre_save(sender, instance, **kwargs):
#     """Handle pre-save operations."""
#     # Validation, data normalization, etc.
#     pass
