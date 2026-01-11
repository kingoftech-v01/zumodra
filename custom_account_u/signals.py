"""
Signal handlers for custom_account_u app.
Auto-creates PublicProfile when CustomUser is created.
"""

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from .models import PublicProfile


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_public_profile(sender, instance, created, **kwargs):
    """
    Automatically create PublicProfile when a new CustomUser is created.
    This ensures every user has a public marketplace profile from the start.
    """
    if created:
        display_name = f"{instance.first_name} {instance.last_name}".strip()
        if not display_name:
            display_name = instance.email

        PublicProfile.objects.get_or_create(
            user=instance,
            defaults={
                'display_name': display_name,
            }
        )


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def save_public_profile(sender, instance, **kwargs):
    """
    Save PublicProfile when CustomUser is saved.
    Updates display_name if user's name changed.
    """
    if hasattr(instance, 'public_profile'):
        # Update display_name if user's name changed
        new_display_name = f"{instance.first_name} {instance.last_name}".strip()
        if new_display_name and instance.public_profile.display_name != new_display_name:
            instance.public_profile.display_name = new_display_name
            instance.public_profile.save(update_fields=['display_name', 'updated_at'])
