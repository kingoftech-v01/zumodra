"""Signal handlers for messages_sys app."""

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import UserStatus

User = get_user_model()


@receiver(post_save, sender=User)
def create_user_status(sender, instance, created, **kwargs):
    """
    Automatically create a UserStatus record when a new user is created.
    This ensures every user has an associated status for the messaging system.
    """
    if created:
        UserStatus.objects.get_or_create(
            user=instance,
            defaults={
                'is_online': False,
                'last_seen': None
            }
        )
