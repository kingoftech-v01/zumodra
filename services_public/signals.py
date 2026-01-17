"""
Django signals for syncing tenant Service to public catalog.

Listens to services.Service model signals and triggers Celery tasks
to sync to PublicServiceCatalog.
"""

import logging
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.db import connection
from django_tenants.utils import get_public_schema_name

logger = logging.getLogger(__name__)


@receiver(post_save, sender='services.Service')
def sync_service_to_public_catalog(sender, instance, created, **kwargs):
    """
    Trigger sync of Service to public catalog when saved.

    Only syncs if:
    - Service is active and marked as public
    - Not in public schema (avoid circular signals)

    Args:
        sender: The model class (Service)
        instance: The Service instance being saved
        created: Boolean indicating if this is a new instance
        **kwargs: Additional signal arguments
    """
    # Skip if in public schema (avoid circular signals)
    if connection.schema_name == get_public_schema_name():
        return

    # Only sync if service should be public
    if not getattr(instance, 'is_active', True):
        logger.debug(f"Service {instance.id} not active, skipping public sync")
        return

    if not getattr(instance, 'is_public', True):
        logger.debug(f"Service {instance.id} not marked as public, skipping sync")
        return

    # Defer to Celery task for async processing
    from .tasks import sync_service_to_public

    try:
        tenant_schema = connection.schema_name
        sync_service_to_public.delay(str(instance.id), tenant_schema)
        logger.info(f"Queued sync of service {instance.id} from {tenant_schema} to public catalog")
    except Exception as e:
        logger.error(f"Error queuing public sync for service {instance.id}: {e}")


@receiver(pre_delete, sender='services.Service')
def remove_service_from_public_catalog(sender, instance, **kwargs):
    """
    Remove service from public catalog when deleted.

    Args:
        sender: The model class (Service)
        instance: The Service instance being deleted
        **kwargs: Additional signal arguments
    """
    # Skip if in public schema
    if connection.schema_name == get_public_schema_name():
        return

    # Defer to Celery task for async processing
    from .tasks import remove_service_from_public

    try:
        tenant_schema = connection.schema_name
        remove_service_from_public.delay(str(instance.id), tenant_schema)
        logger.info(f"Queued removal of service {instance.id} from public catalog")
    except Exception as e:
        logger.error(f"Error queuing public catalog removal for service {instance.id}: {e}")
