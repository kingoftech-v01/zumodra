"""
Projects Signal Handlers - Sync to public catalog.

This module connects Django signals to trigger sync tasks:
- post_save → Sync published projects to public catalog
- post_delete → Remove projects from public catalog

Architecture: Signal → Celery Task → Update PublicProjectCatalog
"""

from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver

from .models import Project, ProjectReview, ProjectProvider


@receiver(post_save, sender=Project)
def project_saved(sender, instance, created, **kwargs):
    """
    Sync published projects to public catalog.

    Triggered when:
    - Project is published (is_published=True, status=OPEN)
    - Published project is updated

    Action:
    - Queue Celery task to sync to PublicProjectCatalog
    """
    # Only sync if published and open for proposals
    if instance.is_published and instance.status == Project.Status.OPEN:
        # Import here to avoid circular imports
        from .tasks import sync_project_to_public_catalog

        # Queue async task
        sync_project_to_public_catalog.delay(instance.id)

    # If project was published but is now closed/cancelled, remove from catalog
    elif instance.published_to_catalog and instance.status != Project.Status.OPEN:
        from .tasks import remove_project_from_catalog
        remove_project_from_catalog.delay(instance.id)


@receiver(post_delete, sender=Project)
def project_deleted(sender, instance, **kwargs):
    """
    Remove deleted projects from public catalog.

    Triggered when: Project is deleted
    Action: Remove from PublicProjectCatalog
    """
    if instance.published_to_catalog:
        from .tasks import remove_project_from_catalog
        remove_project_from_catalog.delay(instance.id)


@receiver(post_save, sender=ProjectReview)
def project_review_saved(sender, instance, created, **kwargs):
    """
    Update project/provider stats when review is submitted.

    Triggered when: Review is created or updated
    Action: Recalculate average ratings
    """
    if created:
        # Update provider stats
        if instance.reviewer_type == 'CLIENT' and instance.project.assigned_provider:
            from .tasks import update_provider_stats
            update_provider_stats.delay(instance.project.assigned_provider.id)


@receiver(pre_save, sender=Project)
def track_publication_changes(sender, instance, **kwargs):
    """
    Track when a project is published for the first time.

    Sets published_at timestamp when is_published changes from False to True.
    """
    if instance.pk:  # Only for existing projects
        try:
            old_instance = Project.objects.get(pk=instance.pk)
            # If changing from unpublished to published, set published_at
            if not old_instance.is_published and instance.is_published:
                if not instance.published_at:
                    from django.utils import timezone
                    instance.published_at = timezone.now()
        except Project.DoesNotExist:
            pass
