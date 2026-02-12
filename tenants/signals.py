"""
tenants Signals

Django signal handlers for tenants models.
"""

import secrets
from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)


def generate_invitation_token():
    """Generate a secure random token for tenant invitations."""
    return secrets.token_urlsafe(32)


@receiver(post_save, sender='tenants.Tenant')
def create_tenant_settings(sender, instance, created, **kwargs):
    """
    Automatically create TenantSettings when a new Tenant is created.
    Also sets trial_ends_at if not already set.
    """
    if created:
        from .models import TenantSettings
        TenantSettings.objects.get_or_create(tenant=instance)
        logger.info(f"Created TenantSettings for tenant: {instance.name}")

        # Set trial end date if not already set
        if not instance.trial_ends_at:
            instance.trial_ends_at = timezone.now() + timedelta(days=14)
            instance.save(update_fields=['trial_ends_at'])


@receiver(post_delete, sender='tenants.Tenant')
def cleanup_tenant(sender, instance, **kwargs):
    """
    Clean up related data when a Tenant is deleted.
    Revokes pending invitations and invalidates caches.
    """
    logger.info(f"Cleaning up tenant: {instance.name}")

    # Invalidate related caches
    cache_key = f"tenants_Tenant_{instance.id}"
    cache.delete(cache_key)


@receiver(pre_save, sender='tenants.TenantInvitation')
def set_invitation_token(sender, instance, **kwargs):
    """
    Automatically generate a secure token for new invitations.
    """
    if not instance.token:
        instance.token = generate_invitation_token()
        logger.info(f"Generated token for invitation to {instance.email}")
