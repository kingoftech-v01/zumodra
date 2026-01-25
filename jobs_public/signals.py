"""
Jobs Public Catalog Signal Handlers.

Automatically syncs JobPosting instances to public catalog based on visibility rules.

Signal Triggers:
    - JobPosting saved with published_on_career_page=True → sync to public
    - JobPosting status changed to closed → remove from public
    - JobPosting marked as internal_only → remove from public
    - JobPosting deleted → remove from public

Security:
    - Only syncs jobs marked as public and open
    - Sanitizes HTML content before public display
    - No sensitive data (internal notes, candidate info) in public catalog
"""

import logging
from django.db import connection
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django_tenants.utils import get_public_schema_name

logger = logging.getLogger(__name__)


@receiver(post_save, sender='jobs.JobPosting')
def sync_job_to_public_catalog(sender, instance, created, **kwargs):
    """
    Trigger sync of JobPosting to public catalog when saved.

    Sync Conditions (ALL must be true):
        - published_on_career_page=True
        - status='open' (or equivalent active status)
        - NOT is_internal_only
        - NOT in public schema (avoid circular signals)
        - NOT raw save (from fixtures/migrations)

    If conditions not met, removes job from catalog if it exists.

    Args:
        sender: JobPosting model class
        instance: JobPosting instance being saved
        created: Boolean indicating if this is a new instance
        **kwargs: Additional signal arguments (raw, using, update_fields)
    """
    # Skip if in public schema (avoid circular signals)
    if connection.schema_name == get_public_schema_name():
        return

    # Skip raw saves (fixtures, migrations)
    if kwargs.get('raw', False):
        return

    # Determine if job should be synced to public catalog
    should_sync = (
        getattr(instance, 'published_on_career_page', False) and
        getattr(instance, 'status', None) == 'open' and
        not getattr(instance, 'is_internal_only', False)
    )

    from .tasks import sync_job_to_public, remove_job_from_public

    try:
        tenant_schema = connection.schema_name

        if should_sync:
            # Sync to public catalog (async via Celery)
            sync_job_to_public.delay(str(instance.id), tenant_schema)
            logger.info(f"Queued sync of job {instance.id} to public catalog from {tenant_schema}")
        else:
            # Remove from public catalog if exists (job became private/internal/closed)
            remove_job_from_public.delay(str(instance.id), tenant_schema)
            logger.debug(f"Queued removal of job {instance.id} from public catalog (no longer public)")

    except Exception as e:
        logger.error(f"Error queuing public sync/removal for job {instance.id}: {e}", exc_info=True)


@receiver(post_delete, sender='jobs.JobPosting')
def remove_deleted_job_from_public(sender, instance, **kwargs):
    """
    Remove job from public catalog when deleted from tenant.

    Args:
        sender: JobPosting model class
        instance: JobPosting instance being deleted
        **kwargs: Additional signal arguments
    """
    # Skip if in public schema
    if connection.schema_name == get_public_schema_name():
        return

    from .tasks import remove_job_from_public

    try:
        tenant_schema = connection.schema_name
        remove_job_from_public.delay(str(instance.id), tenant_schema)
        logger.info(f"Queued removal of deleted job {instance.id} from public catalog")

    except Exception as e:
        logger.error(f"Error queuing removal for deleted job {instance.id}: {e}", exc_info=True)
