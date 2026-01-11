"""
Celery tasks for newsletter operations.

Handles asynchronous operations like syncing with Mailchimp.
"""

import logging
from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def sync_subscription_to_mailchimp(self, subscription_id: int):
    """
    Sync a subscription to Mailchimp asynchronously.

    Args:
        subscription_id: ID of the Subscription to sync
    """
    from .models import Subscription
    from .mailchimp_service import sync_subscription, is_mailchimp_configured

    if not is_mailchimp_configured():
        logger.debug("Mailchimp not configured, skipping sync")
        return

    try:
        subscription = Subscription.objects.get(id=subscription_id)
        result = sync_subscription(subscription)

        if not result.get('success'):
            logger.warning(f"Failed to sync subscription {subscription_id}: {result.get('error')}")
            # Retry on failure
            raise self.retry(exc=Exception(result.get('error')))

        logger.info(f"Successfully synced subscription {subscription_id} to Mailchimp")
        return result

    except Subscription.DoesNotExist:
        logger.error(f"Subscription {subscription_id} not found")
        return {'success': False, 'error': 'Subscription not found'}

    except Exception as e:
        logger.error(f"Error syncing subscription {subscription_id}: {e}")
        raise self.retry(exc=e)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def add_email_to_mailchimp(self, email: str, first_name: str = '', last_name: str = ''):
    """
    Add an email directly to Mailchimp (for footer subscribe form).

    Args:
        email: Email address to subscribe
        first_name: Optional first name
        last_name: Optional last name
    """
    from .mailchimp_service import add_subscriber, is_mailchimp_configured

    if not is_mailchimp_configured():
        logger.debug("Mailchimp not configured, skipping")
        return {'success': False, 'error': 'Mailchimp not configured'}

    try:
        result = add_subscriber(email, first_name, last_name)

        if not result.get('success') and 'already' not in str(result.get('error', '')).lower():
            logger.warning(f"Failed to add {email} to Mailchimp: {result.get('error')}")
            raise self.retry(exc=Exception(result.get('error')))

        logger.info(f"Successfully added {email} to Mailchimp")
        return result

    except Exception as e:
        logger.error(f"Error adding {email} to Mailchimp: {e}")
        raise self.retry(exc=e)


@shared_task
def bulk_sync_subscriptions_to_mailchimp():
    """
    Sync all active subscriptions to Mailchimp.
    Use this for initial sync or periodic reconciliation.
    """
    from .models import Subscription
    from .mailchimp_service import is_mailchimp_configured

    if not is_mailchimp_configured():
        logger.info("Mailchimp not configured, skipping bulk sync")
        return {'success': False, 'error': 'Mailchimp not configured'}

    synced = 0
    failed = 0

    for subscription in Subscription.objects.filter(subscribed=True):
        try:
            sync_subscription_to_mailchimp.delay(subscription.id)
            synced += 1
        except Exception as e:
            logger.error(f"Failed to queue sync for {subscription.email}: {e}")
            failed += 1

    logger.info(f"Queued {synced} subscriptions for Mailchimp sync, {failed} failed")
    return {'synced': synced, 'failed': failed}
