"""
Integrations Celery Tasks

Background tasks for:
- Sync operations
- Token refresh
- Webhook retries
- Scheduled syncs
"""

import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone
from django.db import transaction

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def run_integration_sync(self, sync_log_uuid: str):
    """
    Run a synchronization operation for an integration.

    Args:
        sync_log_uuid: UUID of the IntegrationSyncLog to process
    """
    from .models import IntegrationSyncLog, IntegrationEvent
    from .views import get_provider_class

    try:
        sync_log = IntegrationSyncLog.objects.get(uuid=sync_log_uuid)
    except IntegrationSyncLog.DoesNotExist:
        logger.error(f"Sync log not found: {sync_log_uuid}")
        return

    integration = sync_log.integration

    # Mark as running
    sync_log.mark_running()

    logger.info(f"Starting sync for {integration.name} ({sync_log.sync_type})")

    try:
        # Get provider
        provider_class = get_provider_class(integration.provider)
        if not provider_class:
            raise Exception(f"Provider {integration.provider} not supported")

        provider = provider_class(integration)

        # Check credentials
        if hasattr(integration, 'credentials') and integration.credentials.needs_refresh:
            _refresh_credentials(integration, provider)

        # Run sync
        result = provider.sync(
            resource_type=sync_log.resource_type,
            full_sync=(sync_log.sync_type == 'full'),
            cursor=sync_log.sync_cursor,
        )

        # Update sync log with results
        sync_log.mark_completed(
            records_processed=result.get('processed', 0),
            created=result.get('created', 0),
            updated=result.get('updated', 0),
            deleted=result.get('deleted', 0),
        )

        # Store cursor for next incremental sync
        if result.get('cursor'):
            sync_log.sync_cursor = result['cursor']
            sync_log.save(update_fields=['sync_cursor'])

        # Log success event
        IntegrationEvent.objects.create(
            integration=integration,
            event_type='sync_completed',
            message=f'Sync completed: {result.get("processed", 0)} records processed',
            details=result,
        )

        logger.info(f"Sync completed for {integration.name}")

    except Exception as e:
        logger.error(f"Sync failed for {integration.name}: {e}")

        sync_log.mark_failed(
            error_message=str(e),
            error_details={'exception': type(e).__name__}
        )

        # Log error event
        IntegrationEvent.objects.create(
            integration=integration,
            event_type='sync_failed',
            message=f'Sync failed: {str(e)}',
        )

        # Retry if possible
        if sync_log.can_retry:
            raise self.retry(exc=e)


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def refresh_integration_tokens(self, integration_uuid: str):
    """
    Refresh OAuth tokens for an integration.

    Args:
        integration_uuid: UUID of the Integration
    """
    from .models import Integration, IntegrationEvent
    from .views import get_provider_class

    try:
        integration = Integration.objects.get(uuid=integration_uuid)
    except Integration.DoesNotExist:
        logger.error(f"Integration not found: {integration_uuid}")
        return

    if not hasattr(integration, 'credentials'):
        logger.warning(f"No credentials for integration: {integration_uuid}")
        return

    credentials = integration.credentials

    if not credentials.can_refresh:
        logger.warning(f"Cannot refresh tokens for {integration.name}")
        integration.status = 'expired'
        integration.status_message = 'Refresh token expired or unavailable'
        integration.save()
        return

    try:
        provider_class = get_provider_class(integration.provider)
        if not provider_class:
            raise Exception(f"Provider {integration.provider} not supported")

        provider = provider_class(integration)
        tokens = provider.refresh_access_token(credentials.refresh_token)

        credentials.update_tokens(
            access_token=tokens.get('access_token'),
            refresh_token=tokens.get('refresh_token'),
            expires_in=tokens.get('expires_in'),
        )

        IntegrationEvent.objects.create(
            integration=integration,
            event_type='token_refreshed',
            message='Access token refreshed successfully',
        )

        logger.info(f"Token refreshed for {integration.name}")

    except Exception as e:
        logger.error(f"Token refresh failed for {integration.name}: {e}")

        IntegrationEvent.objects.create(
            integration=integration,
            event_type='error',
            message=f'Token refresh failed: {str(e)}',
        )

        # Mark integration as needing reconnection
        integration.status = 'expired'
        integration.status_message = f'Token refresh failed: {str(e)}'
        integration.save()

        raise self.retry(exc=e)


@shared_task(bind=True, max_retries=5, default_retry_delay=60)
def retry_webhook_delivery(self, delivery_uuid: str):
    """
    Retry a failed webhook delivery.

    Args:
        delivery_uuid: UUID of the WebhookDelivery to retry
    """
    from .models import WebhookDelivery
    from .webhooks import process_webhook_delivery

    try:
        delivery = WebhookDelivery.objects.get(uuid=delivery_uuid)
    except WebhookDelivery.DoesNotExist:
        logger.error(f"Webhook delivery not found: {delivery_uuid}")
        return

    if not delivery.can_retry:
        logger.warning(f"Webhook delivery cannot be retried: {delivery_uuid}")
        return

    try:
        process_webhook_delivery(delivery)
        logger.info(f"Webhook delivery retry succeeded: {delivery_uuid}")

    except Exception as e:
        logger.error(f"Webhook delivery retry failed: {e}")

        delivery.mark_failed(str(e), schedule_retry=True)

        if delivery.can_retry:
            # Schedule next retry with exponential backoff
            countdown = 60 * (2 ** delivery.retry_count)
            raise self.retry(exc=e, countdown=countdown)


@shared_task
def process_scheduled_syncs():
    """
    Process all integrations that are due for scheduled sync.
    Runs periodically (e.g., every 5 minutes via Celery Beat).
    """
    from .models import Integration, IntegrationSyncLog

    now = timezone.now()

    # Find integrations due for sync
    integrations = Integration.objects.filter(
        status='active',
        is_enabled=True,
        auto_sync=True,
        next_sync_at__lte=now,
    )

    for integration in integrations:
        logger.info(f"Triggering scheduled sync for {integration.name}")

        # Create sync log
        sync_log = IntegrationSyncLog.objects.create(
            integration=integration,
            sync_type='scheduled',
            direction='inbound',
        )

        # Queue sync task
        run_integration_sync.delay(sync_log.uuid.hex)


@shared_task
def refresh_expiring_tokens():
    """
    Refresh tokens that are expiring soon.
    Runs periodically (e.g., every hour via Celery Beat).
    """
    from .models import IntegrationCredential

    # Refresh tokens expiring within next hour
    threshold = timezone.now() + timedelta(hours=1)

    credentials = IntegrationCredential.objects.filter(
        expires_at__lte=threshold,
        expires_at__gt=timezone.now(),
        integration__status='active',
    ).select_related('integration')

    for cred in credentials:
        if cred.can_refresh:
            logger.info(f"Scheduling token refresh for {cred.integration.name}")
            refresh_integration_tokens.delay(cred.integration.uuid.hex)


@shared_task
def cleanup_old_webhook_deliveries():
    """
    Clean up old webhook delivery records.
    Runs daily via Celery Beat.
    """
    from .models import WebhookDelivery

    # Delete deliveries older than 30 days
    threshold = timezone.now() - timedelta(days=30)

    deleted_count, _ = WebhookDelivery.objects.filter(
        received_at__lt=threshold
    ).delete()

    logger.info(f"Cleaned up {deleted_count} old webhook deliveries")


@shared_task
def cleanup_old_sync_logs():
    """
    Clean up old sync log records.
    Runs daily via Celery Beat.
    """
    from .models import IntegrationSyncLog

    # Delete sync logs older than 90 days
    threshold = timezone.now() - timedelta(days=90)

    deleted_count, _ = IntegrationSyncLog.objects.filter(
        started_at__lt=threshold
    ).delete()

    logger.info(f"Cleaned up {deleted_count} old sync logs")


@shared_task
def cleanup_old_events():
    """
    Clean up old integration events.
    Runs daily via Celery Beat.
    """
    from .models import IntegrationEvent

    # Delete events older than 90 days
    threshold = timezone.now() - timedelta(days=90)

    deleted_count, _ = IntegrationEvent.objects.filter(
        created_at__lt=threshold
    ).delete()

    logger.info(f"Cleaned up {deleted_count} old integration events")


@shared_task
def retry_failed_syncs():
    """
    Retry failed syncs that are due for retry.
    Runs every 15 minutes via Celery Beat.
    """
    from .models import IntegrationSyncLog

    now = timezone.now()

    # Find syncs that are due for retry
    syncs = IntegrationSyncLog.objects.filter(
        status='failed',
        next_retry_at__lte=now,
        retry_count__lt=models.F('max_retries'),
    )

    for sync_log in syncs:
        logger.info(f"Retrying failed sync: {sync_log.uuid}")
        run_integration_sync.delay(sync_log.uuid.hex)


@shared_task
def check_integration_health():
    """
    Check health of all active integrations.
    Runs every 30 minutes via Celery Beat.
    """
    from .models import Integration, IntegrationEvent
    from .views import get_provider_class

    integrations = Integration.objects.filter(
        status='active',
        is_enabled=True,
    )

    for integration in integrations:
        try:
            provider_class = get_provider_class(integration.provider)
            if not provider_class:
                continue

            provider = provider_class(integration)
            success, message = provider.test_connection()

            if not success:
                logger.warning(f"Integration health check failed: {integration.name} - {message}")

                # Update status if connection is failing
                integration.sync_error_count += 1
                if integration.sync_error_count >= 5:
                    integration.status = 'error'
                    integration.status_message = message
                integration.save()

                IntegrationEvent.objects.create(
                    integration=integration,
                    event_type='error',
                    message=f'Health check failed: {message}',
                )
            else:
                # Reset error count on success
                if integration.sync_error_count > 0:
                    integration.sync_error_count = 0
                    integration.save()

        except Exception as e:
            logger.error(f"Health check error for {integration.name}: {e}")


def _refresh_credentials(integration, provider):
    """Helper to refresh integration credentials."""
    credentials = integration.credentials

    if not credentials.can_refresh:
        raise Exception("Cannot refresh tokens - refresh token expired or unavailable")

    tokens = provider.refresh_access_token(credentials.refresh_token)
    credentials.update_tokens(
        access_token=tokens.get('access_token'),
        refresh_token=tokens.get('refresh_token'),
        expires_in=tokens.get('expires_in'),
    )
