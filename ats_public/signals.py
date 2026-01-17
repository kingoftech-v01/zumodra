"""
Django signals for syncing tenant JobPosting to public catalog.

Listens to ats.JobPosting model signals and triggers Celery tasks
to sync to PublicJobCatalog.
"""

import logging
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.db import connection
from django_tenants.utils import get_public_schema_name

logger = logging.getLogger(__name__)


@receiver(post_save, sender='ats.JobPosting')
def sync_job_to_public_catalog(sender, instance, created, **kwargs):
    """
    Trigger sync of JobPosting to public catalog when saved.

    Only syncs if:
    - Job is marked as published_on_career_page=True
    - Not in public schema (avoid circular signals)

    Args:
        sender: The model class (JobPosting)
        instance: The JobPosting instance being saved
        created: Boolean indicating if this is a new instance
        **kwargs: Additional signal arguments
    """
    # Skip if in public schema (avoid circular signals)
    if connection.schema_name == get_public_schema_name():
        return

    # Only sync if job should be public
    if not getattr(instance, 'published_on_career_page', False):
        logger.debug(f"Job {instance.id} not marked for career page, skipping public sync")
        return

    # Defer to Celery task for async processing
    from .tasks import sync_job_to_public

    try:
        tenant_schema = connection.schema_name
        sync_job_to_public.delay(str(instance.id), tenant_schema)
        logger.info(f"Queued sync of job {instance.id} from {tenant_schema} to public catalog")
    except Exception as e:
        logger.error(f"Error queuing public sync for job {instance.id}: {e}")


@receiver(pre_delete, sender='ats.JobPosting')
def remove_job_from_public_catalog(sender, instance, **kwargs):
    """
    Remove job from public catalog when deleted.

    Args:
        sender: The model class (JobPosting)
        instance: The JobPosting instance being deleted
        **kwargs: Additional signal arguments
    """
    # Skip if in public schema
    if connection.schema_name == get_public_schema_name():
        return

    # Defer to Celery task for async processing
    from .tasks import remove_job_from_public

    try:
        tenant_schema = connection.schema_name
        remove_job_from_public.delay(str(instance.id), tenant_schema)
        logger.info(f"Queued removal of job {instance.id} from public catalog")
    except Exception as e:
        logger.error(f"Error queuing public catalog removal for job {instance.id}: {e}")
