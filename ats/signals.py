"""
ATS Signals - Automatic actions for ATS events.
"""

from django.db.models.signals import post_save, pre_save
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
