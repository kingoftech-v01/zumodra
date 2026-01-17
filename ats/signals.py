"""
ATS Signals

Django signals for ATS models to trigger async tasks and sync operations.
"""

import logging
from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.db import transaction

logger = logging.getLogger(__name__)


# ==================== JOB POSTING SIGNALS ====================

@receiver(post_save, sender='ats.JobPosting')
def sync_job_to_public_catalog_on_save(sender, instance, created, **kwargs):
    """
    Trigger async Celery task to sync JobPosting to PublicJobCatalog.
    
    Workflow:
    1. JobPosting created/updated in tenant schema  
    2. Signal fires after save
    3. Celery task queued to sync data
    4. Update or create entry in PublicJobCatalog (public schema)
    5. Job now browsable by public users
    
    Only syncs if:
    - Job is open (status='open')
    - Job is published on career page (published_on_career_page=True)
    """
    from ats.tasks import sync_job_to_public_catalog, remove_job_from_public_catalog
    
    # Use on_commit to ensure transaction completes before triggering task
    def trigger_sync():
        try:
            # Check if job should be in public catalog
            should_publish = (
                instance.published_on_career_page and 
                instance.status == 'open'
            )
            
            if should_publish:
                logger.info(
                    f"Queuing sync for job {instance.id} ({instance.title}) to PublicJobCatalog"
                )
                sync_job_to_public_catalog.delay(str(instance.id))
            else:
                logger.info(
                    f"Job {instance.id} not publishable, removing from PublicJobCatalog if present"
                )
                remove_job_from_public_catalog.delay(str(instance.id))
                
        except Exception as e:
            logger.error(f"Failed to queue job sync task: {e}", exc_info=True)
    
    transaction.on_commit(trigger_sync)


@receiver(post_delete, sender='ats.JobPosting')
def remove_job_from_public_catalog_on_delete(sender, instance, **kwargs):
    """
    Trigger async Celery task to remove job from PublicJobCatalog.
    
    When a JobPosting is deleted from tenant schema, remove it from
    the public catalog so it's no longer browsable.
    """
    from ats.tasks import remove_job_from_public_catalog
    
    try:
        logger.info(f"Queuing removal of job {instance.id} from PublicJobCatalog")
        remove_job_from_public_catalog.delay(str(instance.id))
    except Exception as e:
        logger.error(f"Failed to queue job removal task: {e}", exc_info=True)


# ==================== APPLICATION SIGNALS ====================

@receiver(post_save, sender='ats.Application')
def increment_public_job_application_count(sender, instance, created, **kwargs):
    """
    Increment application_count on PublicJobCatalog when new application created.
    
    This keeps the public catalog metrics in sync with actual application activity.
    """
    if created:
        def update_count():
            try:
                from tenants.models import PublicJobCatalog
                
                # Find the catalog entry for this job
                catalog_entry = PublicJobCatalog.objects.filter(
                    job_id=instance.job_id
                ).first()
                
                if catalog_entry:
                    catalog_entry.increment_application_count()
                    logger.debug(f"Incremented application count for job {instance.job_id}")
                    
            except Exception as e:
                logger.error(f"Failed to update public catalog application count: {e}")
        
        transaction.on_commit(update_count)
