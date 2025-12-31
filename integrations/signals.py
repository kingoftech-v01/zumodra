"""
Integrations Signal Handlers

Django signals for integration lifecycle events.
"""

import logging
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver

from .models import Integration, IntegrationCredential, WebhookEndpoint, IntegrationEvent

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Integration)
def on_integration_created(sender, instance, created, **kwargs):
    """Handle new integration creation."""
    if created:
        logger.info(f"New integration created: {instance.name} ({instance.provider})")

        # Log creation event
        IntegrationEvent.objects.create(
            integration=instance,
            event_type='connected' if instance.status == 'active' else 'config_changed',
            message=f'Integration created: {instance.name}',
            triggered_by=instance.connected_by,
        )


@receiver(pre_delete, sender=Integration)
def on_integration_deleted(sender, instance, **kwargs):
    """Handle integration deletion - cleanup."""
    logger.info(f"Integration being deleted: {instance.name}")

    # Revoke tokens if OAuth integration
    if hasattr(instance, 'credentials'):
        try:
            from .views import get_provider_class
            provider_class = get_provider_class(instance.provider)
            if provider_class:
                provider = provider_class(instance)
                provider.disconnect()
        except Exception as e:
            logger.warning(f"Error revoking tokens during deletion: {e}")


@receiver(post_save, sender=IntegrationCredential)
def on_credentials_updated(sender, instance, created, **kwargs):
    """Handle credential updates."""
    if not created:
        # Credentials were updated (likely token refresh)
        logger.info(f"Credentials updated for {instance.integration.name}")


@receiver(post_save, sender=WebhookEndpoint)
def on_webhook_created(sender, instance, created, **kwargs):
    """Handle new webhook endpoint creation."""
    if created:
        logger.info(f"Webhook endpoint created: {instance.name} for {instance.integration.name}")

        IntegrationEvent.objects.create(
            integration=instance.integration,
            event_type='config_changed',
            message=f'Webhook endpoint created: {instance.name}',
            details={
                'endpoint_path': instance.endpoint_path,
                'full_url': instance.get_full_url(),
            }
        )
