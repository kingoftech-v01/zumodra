"""
ATS Signals - Automatic actions for ATS events.
"""

from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.utils import timezone
from django.utils.text import slugify
import uuid

from .models import JobPosting, Application, ApplicationActivity, Interview


@receiver(pre_save, sender=JobPosting)
def generate_job_reference_code(sender, instance, **kwargs):
    """Generate unique reference code for new jobs."""
    if not instance.reference_code:
        # Format: JOB-YYYYMM-XXXX
        date_part = timezone.now().strftime('%Y%m')
        random_part = uuid.uuid4().hex[:4].upper()
        instance.reference_code = f"JOB-{date_part}-{random_part}"

    if not instance.slug:
        base_slug = slugify(instance.title)[:200]
        instance.slug = f"{base_slug}-{instance.reference_code.lower()}"


@receiver(post_save, sender=Application)
def log_application_created(sender, instance, created, **kwargs):
    """Log when a new application is created."""
    if created:
        ApplicationActivity.objects.create(
            application=instance,
            activity_type=ApplicationActivity.ActivityType.CREATED,
            notes=f"Applied via {instance.candidate.source or 'direct'}"
        )


@receiver(post_save, sender=Application)
def update_candidate_last_activity(sender, instance, **kwargs):
    """Update candidate's last activity timestamp."""
    instance.candidate.last_activity_at = timezone.now()
    instance.candidate.save(update_fields=['last_activity_at'])


@receiver(post_save, sender=Interview)
def log_interview_scheduled(sender, instance, created, **kwargs):
    """Log when an interview is scheduled."""
    if created:
        ApplicationActivity.objects.create(
            application=instance.application,
            activity_type=ApplicationActivity.ActivityType.INTERVIEW_SCHEDULED,
            performed_by=instance.organizer,
            new_value=instance.title,
            metadata={
                'interview_type': instance.interview_type,
                'scheduled_start': instance.scheduled_start.isoformat(),
                'scheduled_end': instance.scheduled_end.isoformat(),
            }
        )


# ==================== Public Catalog Sync Signals ====================

from django.db import connection
import logging

logger = logging.getLogger(__name__)


@receiver(post_save, sender=JobPosting)
def sync_job_to_public_catalog(sender, instance, created, **kwargs):
    """
    Trigger async Celery task to sync JobPosting to PublicJobCatalog.

    This signal fires every time a JobPosting is saved. It queues an async
    task that will:
    1. Check if job meets sync conditions (published, not internal, open)
    2. Extract safe fields and denormalize data
    3. Update or create entry in PublicJobCatalog (public schema)

    Args:
        sender: JobPosting model class
        instance: JobPosting instance being saved
        created: Boolean indicating if this is a new record
        **kwargs: Additional signal arguments
    """
    # Prevent infinite loops from update_fields
    if kwargs.get('update_fields') and 'synced_at' in kwargs.get('update_fields', []):
        return

    # Validate schema (prevent triggering from public schema)
    if connection.schema_name == 'public':
        logger.warning(
            "JobPosting signal fired in public schema - skipping sync. "
            "This should not happen in normal operation."
        )
        return

    # Import here to avoid circular imports
    from ats.tasks import sync_job_to_catalog_task

    # Queue async Celery task
    try:
        sync_job_to_catalog_task.delay(
            job_uuid=str(instance.uuid),
            tenant_schema=connection.schema_name,
            tenant_id=instance.tenant_id,
        )
        logger.debug(
            f"Queued sync task for job {instance.uuid} from {connection.schema_name}"
        )
    except Exception as e:
        logger.error(
            f"Failed to queue sync task for job {instance.uuid}: {e}",
            exc_info=True
        )


@receiver(post_delete, sender=JobPosting)
def remove_job_from_catalog(sender, instance, **kwargs):
    """
    Trigger async Celery task to remove job from PublicJobCatalog.

    Called when a JobPosting is deleted from tenant schema.
    Ensures corresponding entry is removed from public catalog.

    Args:
        sender: JobPosting model class
        instance: JobPosting instance being deleted
        **kwargs: Additional signal arguments
    """
    # Import here to avoid circular imports
    from ats.tasks import remove_job_from_catalog_task

    # Queue async removal task
    try:
        remove_job_from_catalog_task.delay(
            job_uuid=str(instance.uuid),
            tenant_schema=connection.schema_name,
        )
        logger.debug(
            f"Queued removal task for job {instance.uuid} from {connection.schema_name}"
        )
    except Exception as e:
        logger.error(
            f"Failed to queue removal task for job {instance.uuid}: {e}",
            exc_info=True
        )
