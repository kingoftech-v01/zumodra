# Subscription & Billing Workflow - Implementation Fixes

## Overview
This document provides code fixes and implementations needed to complete the subscription and billing workflow testing.

---

## FIX 1: Stripe Webhook Signature Validation (CRITICAL)

**File**: `integrations/webhooks.py`

**Current Issue**: Weak signature validation, missing timestamp validation, accepting multiple header formats

**Fix**:
```python
import hmac
import hashlib
import time
from django.utils import timezone

class StripeWebhookValidator:
    """Validates Stripe webhooks according to Stripe specifications"""

    def __init__(self, webhook_secret: str):
        self.webhook_secret = webhook_secret

    def validate_signature(self, payload_bytes: bytes, stripe_signature_header: str) -> bool:
        """
        Validate Stripe webhook signature.

        Args:
            payload_bytes: Raw request body as bytes
            stripe_signature_header: Stripe-Signature header value

        Returns:
            True if valid, False otherwise

        Format: Stripe-Signature: t={timestamp},v1={signature}
        """
        if not stripe_signature_header or not self.webhook_secret:
            return False

        # Parse header
        try:
            parts = {}
            for part in stripe_signature_header.split(','):
                key, value = part.split('=', 1)
                parts[key.strip()] = value.strip()

            if 't' not in parts or 'v1' not in parts:
                return False

            timestamp_str = parts['t']
            signature = parts['v1']

            # Validate timestamp (within 5 minutes)
            try:
                timestamp = int(timestamp_str)
                current_time = int(time.time())

                if abs(current_time - timestamp) > 300:
                    return False
            except ValueError:
                return False

            # Compute expected signature
            signed_content = f"{timestamp_str}.{payload_bytes.decode('utf-8')}"
            expected_signature = hmac.new(
                self.webhook_secret.encode('utf-8'),
                signed_content.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(signature, expected_signature)

        except Exception as e:
            logger.error(f"Error parsing Stripe signature: {e}")
            return False


# Usage in webhook view:
@csrf_exempt
def stripe_webhook(request):
    """Handle Stripe webhook events"""
    stripe_signature = request.META.get('HTTP_STRIPE_SIGNATURE')
    payload = request.body

    validator = StripeWebhookValidator(settings.STRIPE_WEBHOOK_SECRET)

    if not validator.validate_signature(payload, stripe_signature):
        logger.warning("Invalid Stripe webhook signature")
        return JsonResponse({'error': 'Invalid signature'}, status=403)

    # Process webhook
    event = json.loads(payload)
    event_id = event['id']

    # Atomic deduplication
    try:
        webhook_event = StripeWebhookEvent.objects.create(
            event_id=event_id,
            json_payload=event,
            processed=False,
        )
    except IntegrityError:
        # Already exists
        webhook_event = StripeWebhookEvent.objects.get(event_id=event_id)
        if webhook_event.processed:
            return JsonResponse({'status': 'already_processed'}, status=200)

    # Process event
    try:
        handler = StripeEventHandler()
        handler.process(event)
        webhook_event.processed = True
        webhook_event.processed_at = timezone.now()
        webhook_event.save()
        return JsonResponse({'status': 'received'}, status=200)

    except Exception as e:
        logger.error(f"Error processing webhook {event_id}: {e}")
        webhook_event.error_message = str(e)
        webhook_event.save()
        return JsonResponse({'error': 'processing_error'}, status=500)
```

---

## FIX 2: Implement Webhook Event Handlers

**File**: `finance/webhook_handlers.py` (New File)

```python
"""
Stripe Webhook Event Handlers

Processes various Stripe webhook events and updates local database state.
"""

import logging
import stripe
from datetime import datetime
from decimal import Decimal

from django.utils import timezone
from django.db import transaction

from finance.models import (
    UserSubscription, Invoice, PaymentTransaction,
    SubscriptionPlan, StripeWebhookEvent
)
from finance.tasks import send_invoice_email, send_payment_failed_notification

logger = logging.getLogger(__name__)


class StripeEventHandler:
    """Handles incoming Stripe webhook events"""

    handlers_map = {
        'customer.subscription.created': 'handle_subscription_created',
        'customer.subscription.updated': 'handle_subscription_updated',
        'customer.subscription.deleted': 'handle_subscription_deleted',
        'customer.subscription.trial_will_end': 'handle_trial_ending',
        'invoice.created': 'handle_invoice_created',
        'invoice.finalized': 'handle_invoice_finalized',
        'invoice.payment_attempted': 'handle_invoice_payment_attempted',
        'invoice.payment_succeeded': 'handle_invoice_payment_succeeded',
        'invoice.payment_failed': 'handle_invoice_payment_failed',
        'invoice.marked_uncollectible': 'handle_invoice_uncollectible',
        'charge.succeeded': 'handle_charge_succeeded',
        'charge.failed': 'handle_charge_failed',
    }

    def process(self, event: dict):
        """
        Process a Stripe webhook event

        Args:
            event: The Stripe event dict

        Raises:
            Exception: If handler fails
        """
        event_type = event.get('type')
        handler_name = self.handlers_map.get(event_type)

        if not handler_name:
            logger.warning(f"No handler for event type: {event_type}")
            return

        handler = getattr(self, handler_name, None)
        if not handler:
            logger.error(f"Handler method not found: {handler_name}")
            raise ValueError(f"Handler not found: {handler_name}")

        logger.info(f"Processing event: {event_type} (ID: {event['id']})")
        handler(event['data']['object'])

    @transaction.atomic
    def handle_subscription_created(self, subscription_data: dict):
        """Handle customer.subscription.created event"""
        stripe_sub_id = subscription_data['id']
        customer_id = subscription_data['customer']
        stripe_plan_id = subscription_data['items']['data'][0]['price']['id']

        try:
            # Get user by Stripe customer ID
            # This assumes you store Stripe customer ID in user profile
            user = self.get_user_from_stripe_customer(customer_id)

            # Get plan
            plan = SubscriptionPlan.objects.get(stripe_price_id=stripe_plan_id)

            # Create or update subscription
            subscription, created = UserSubscription.objects.update_or_create(
                stripe_subscription_id=stripe_sub_id,
                defaults={
                    'user': user,
                    'plan': plan,
                    'status': subscription_data['status'],
                    'current_period_start': self._timestamp_to_datetime(
                        subscription_data['current_period_start']
                    ),
                    'current_period_end': self._timestamp_to_datetime(
                        subscription_data['current_period_end']
                    ),
                }
            )

            action = "created" if created else "updated"
            logger.info(f"Subscription {action}: {stripe_sub_id} for user {user.id}")

        except Exception as e:
            logger.error(f"Failed to create subscription {stripe_sub_id}: {e}")
            raise

    @transaction.atomic
    def handle_subscription_updated(self, subscription_data: dict):
        """Handle customer.subscription.updated event"""
        stripe_sub_id = subscription_data['id']

        try:
            subscription = UserSubscription.objects.get(
                stripe_subscription_id=stripe_sub_id
            )

            # Update subscription details
            subscription.status = subscription_data['status']
            subscription.current_period_start = self._timestamp_to_datetime(
                subscription_data['current_period_start']
            )
            subscription.current_period_end = self._timestamp_to_datetime(
                subscription_data['current_period_end']
            )

            # Update plan if changed
            if subscription_data['items']['data']:
                new_price_id = subscription_data['items']['data'][0]['price']['id']
                if subscription.plan.stripe_price_id != new_price_id:
                    new_plan = SubscriptionPlan.objects.get(stripe_price_id=new_price_id)
                    subscription.plan = new_plan

            subscription.save()
            logger.info(f"Subscription updated: {stripe_sub_id} -> {subscription.status}")

        except UserSubscription.DoesNotExist:
            logger.warning(f"Subscription not found: {stripe_sub_id}")
        except Exception as e:
            logger.error(f"Failed to update subscription {stripe_sub_id}: {e}")
            raise

    @transaction.atomic
    def handle_subscription_deleted(self, subscription_data: dict):
        """Handle customer.subscription.deleted event"""
        stripe_sub_id = subscription_data['id']

        try:
            subscription = UserSubscription.objects.get(
                stripe_subscription_id=stripe_sub_id
            )

            subscription.status = 'canceled'
            subscription.save()

            logger.info(f"Subscription canceled: {stripe_sub_id}")

        except UserSubscription.DoesNotExist:
            logger.warning(f"Subscription not found: {stripe_sub_id}")

    @transaction.atomic
    def handle_invoice_created(self, invoice_data: dict):
        """Handle invoice.created event"""
        stripe_invoice_id = invoice_data['id']

        try:
            customer_id = invoice_data['customer']
            user = self.get_user_from_stripe_customer(customer_id)

            # Create invoice
            Invoice.objects.create(
                user=user,
                invoice_number=invoice_data.get('number', stripe_invoice_id),
                stripe_invoice_id=stripe_invoice_id,
                amount_due=Decimal(str(invoice_data['amount_due'] / 100)),
                currency=invoice_data['currency'].upper(),
                due_date=self._timestamp_to_datetime(
                    invoice_data.get('due_date', invoice_data['created'] + 2592000)
                ),
                paid=invoice_data['paid'],
            )

            logger.info(f"Invoice created: {stripe_invoice_id}")

        except Exception as e:
            logger.error(f"Failed to create invoice {stripe_invoice_id}: {e}")
            raise

    @transaction.atomic
    def handle_invoice_payment_succeeded(self, invoice_data: dict):
        """Handle invoice.payment_succeeded event"""
        stripe_invoice_id = invoice_data['id']

        try:
            invoice = Invoice.objects.get(stripe_invoice_id=stripe_invoice_id)

            invoice.paid = True
            invoice.amount_paid = Decimal(str(invoice_data['amount_paid'] / 100))
            invoice.paid_at = timezone.now()
            invoice.save()

            logger.info(f"Invoice paid: {stripe_invoice_id}")

            # Send payment confirmation email
            send_invoice_email.delay(invoice.id, 'paid')

        except Invoice.DoesNotExist:
            logger.warning(f"Invoice not found: {stripe_invoice_id}")
        except Exception as e:
            logger.error(f"Failed to mark invoice paid {stripe_invoice_id}: {e}")
            raise

    @transaction.atomic
    def handle_invoice_payment_failed(self, invoice_data: dict):
        """Handle invoice.payment_failed event"""
        stripe_invoice_id = invoice_data['id']

        try:
            invoice = Invoice.objects.get(stripe_invoice_id=stripe_invoice_id)

            # Log failed payment
            PaymentTransaction.objects.create(
                user=invoice.user,
                amount=Decimal(str(invoice_data['amount_due'] / 100)),
                currency=invoice_data['currency'].upper(),
                stripe_payment_intent_id=stripe_invoice_id,
                description=f"Failed invoice payment: {invoice.invoice_number}",
                succeeded=False,
                failure_message=invoice_data.get('last_finalization_error', {}).get('message', 'Unknown error'),
            )

            logger.warning(f"Invoice payment failed: {stripe_invoice_id}")

            # Send failure notification
            send_payment_failed_notification.delay(invoice.id)

        except Invoice.DoesNotExist:
            logger.warning(f"Invoice not found: {stripe_invoice_id}")
        except Exception as e:
            logger.error(f"Failed to handle payment failure {stripe_invoice_id}: {e}")
            raise

    @transaction.atomic
    def handle_charge_succeeded(self, charge_data: dict):
        """Handle charge.succeeded event"""
        stripe_charge_id = charge_data['id']

        try:
            customer_id = charge_data.get('customer')
            if not customer_id:
                return

            user = self.get_user_from_stripe_customer(customer_id)

            # Create payment transaction
            PaymentTransaction.objects.update_or_create(
                stripe_payment_intent_id=stripe_charge_id,
                defaults={
                    'user': user,
                    'amount': Decimal(str(charge_data['amount'] / 100)),
                    'currency': charge_data['currency'].upper(),
                    'description': charge_data.get('description', f'Charge {stripe_charge_id}'),
                    'succeeded': True,
                }
            )

            logger.info(f"Charge succeeded: {stripe_charge_id}")

        except Exception as e:
            logger.error(f"Failed to handle charge {stripe_charge_id}: {e}")
            # Don't raise - charge still succeeded on Stripe

    @transaction.atomic
    def handle_charge_failed(self, charge_data: dict):
        """Handle charge.failed event"""
        stripe_charge_id = charge_data['id']

        try:
            customer_id = charge_data.get('customer')
            if not customer_id:
                return

            user = self.get_user_from_stripe_customer(customer_id)

            # Log failed charge
            PaymentTransaction.objects.update_or_create(
                stripe_payment_intent_id=stripe_charge_id,
                defaults={
                    'user': user,
                    'amount': Decimal(str(charge_data['amount'] / 100)),
                    'currency': charge_data['currency'].upper(),
                    'description': charge_data.get('description', f'Failed charge {stripe_charge_id}'),
                    'succeeded': False,
                    'failure_code': charge_data.get('failure_code', 'unknown'),
                    'failure_message': charge_data.get('failure_message', 'Unknown error'),
                }
            )

            logger.warning(f"Charge failed: {stripe_charge_id}")

        except Exception as e:
            logger.error(f"Failed to handle failed charge {stripe_charge_id}: {e}")
            # Don't raise - we still want to log the failure

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def get_user_from_stripe_customer(self, customer_id: str):
        """Get user from Stripe customer ID"""
        from django.contrib.auth import get_user_model
        from tenant_profiles.models import StripeCustomerProfile  # Assuming this model exists

        try:
            profile = StripeCustomerProfile.objects.get(
                stripe_customer_id=customer_id
            )
            return profile.user
        except:
            logger.error(f"User not found for Stripe customer: {customer_id}")
            raise ValueError(f"User not found for customer {customer_id}")

    def _timestamp_to_datetime(self, timestamp: int) -> datetime:
        """Convert Unix timestamp to datetime"""
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
```

---

## FIX 3: Implement Automatic Subscription Renewal

**File**: `finance/tasks.py`

```python
"""
Celery tasks for subscription and billing operations
"""

from celery import shared_task
from celery.utils.log import get_task_logger
from datetime import timedelta
from decimal import Decimal
import stripe

from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail

from finance.models import (
    UserSubscription, Invoice, PaymentTransaction,
    SubscriptionRenewal
)

logger = get_task_logger(__name__)
stripe.api_key = settings.STRIPE_SECRET_KEY


@shared_task(bind=True, max_retries=3)
def process_subscription_renewals(self):
    """
    Process subscriptions that are due for renewal.

    This task should be run hourly by Celery Beat.
    """
    logger.info("Starting subscription renewal process")

    # Find subscriptions expiring within the next 24 hours
    tomorrow = timezone.now() + timedelta(days=1)
    today = timezone.now()

    expiring_subscriptions = UserSubscription.objects.filter(
        status='active',
        current_period_end__lte=tomorrow,
        current_period_end__gte=today
    )

    logger.info(f"Found {expiring_subscriptions.count()} subscriptions to renew")

    for subscription in expiring_subscriptions:
        try:
            renew_subscription(subscription)
        except Exception as e:
            logger.error(f"Error renewing subscription {subscription.id}: {e}")
            # Continue processing other subscriptions

    logger.info("Subscription renewal process completed")


def renew_subscription(subscription: UserSubscription):
    """Renew a single subscription"""
    logger.info(f"Renewing subscription {subscription.stripe_subscription_id}")

    try:
        # Create renewal record
        renewal = SubscriptionRenewal.objects.create(
            subscription=subscription,
            renewal_date=subscription.current_period_end,
            status='pending'
        )

        # Create renewal invoice
        invoice = Invoice.objects.create(
            user=subscription.user,
            invoice_number=f"INV-{timezone.now().strftime('%Y%m%d')}-{subscription.user.id}",
            stripe_invoice_id=None,  # Will be populated after Stripe charge
            amount_due=subscription.plan.price,
            currency=subscription.plan.currency,
            due_date=timezone.now() + timedelta(days=30),
            paid=False,
        )

        renewal.invoice = invoice
        renewal.save()

        # Attempt payment through Stripe
        try:
            # Get Stripe subscription
            stripe_sub = stripe.Subscription.retrieve(
                subscription.stripe_subscription_id
            )

            # Create invoice item for renewal
            invoice_item = stripe.InvoiceItem.create(
                customer=stripe_sub.customer,
                amount=int(subscription.plan.price * 100),
                currency=subscription.plan.currency.lower(),
                description=f"{subscription.plan.name} - {timezone.now().strftime('%B %Y')}",
            )

            # Create and finalize invoice
            stripe_invoice = stripe.Invoice.create(
                customer=stripe_sub.customer,
                collection_method='charge_automatically',
            )

            stripe_invoice = stripe.Invoice.finalize_invoice(stripe_invoice.id)

            # Update renewal
            invoice.stripe_invoice_id = stripe_invoice.id
            invoice.save()

            renewal.status = 'success'
            renewal.save()

            logger.info(f"Successfully renewed subscription {subscription.stripe_subscription_id}")

            # Update subscription period
            subscription.current_period_start = subscription.current_period_end
            subscription.current_period_end = subscription.current_period_end + timedelta(days=30)
            subscription.save()

        except stripe.error.CardError as e:
            logger.warning(f"Card error renewing subscription: {e}")
            renewal.status = 'failed'
            renewal.error_message = str(e)
            renewal.retry_count = 1
            renewal.next_retry = timezone.now() + timedelta(days=3)
            renewal.save()

            # Send user notification
            send_renewal_payment_failed_email.delay(subscription.user.id)

        except Exception as e:
            logger.error(f"Unexpected error renewing subscription: {e}")
            renewal.status = 'failed'
            renewal.error_message = str(e)
            renewal.save()

    except Exception as e:
        logger.error(f"Error creating renewal record: {e}")
        raise


@shared_task(bind=True, max_retries=3)
def retry_failed_renewals(self):
    """
    Retry subscription renewals that previously failed.

    Run every 6 hours.
    """
    logger.info("Starting failed renewal retry process")

    # Find failed renewals with pending retry
    failed_renewals = SubscriptionRenewal.objects.filter(
        status='failed',
        next_retry__lte=timezone.now(),
        retry_count__lt=3
    )

    logger.info(f"Found {failed_renewals.count()} renewals to retry")

    for renewal in failed_renewals:
        try:
            logger.info(f"Retrying renewal {renewal.id}")
            renew_subscription(renewal.subscription)
            renewal.retry_count += 1
            renewal.save()
        except Exception as e:
            logger.error(f"Error retrying renewal {renewal.id}: {e}")

    logger.info("Failed renewal retry process completed")


@shared_task
def sync_stripe_subscriptions():
    """
    Sync all subscriptions from Stripe to local database.

    Run once daily to catch any out-of-sync subscriptions.
    """
    logger.info("Starting Stripe subscription sync")

    try:
        subscriptions = stripe.Subscription.list(limit=100)

        for stripe_sub in subscriptions.auto_paging_iter():
            try:
                local_sub = UserSubscription.objects.get(
                    stripe_subscription_id=stripe_sub.id
                )

                # Update local subscription
                local_sub.status = stripe_sub.status
                local_sub.current_period_start = datetime.fromtimestamp(
                    stripe_sub.current_period_start, tz=timezone.utc
                )
                local_sub.current_period_end = datetime.fromtimestamp(
                    stripe_sub.current_period_end, tz=timezone.utc
                )
                local_sub.save()

            except UserSubscription.DoesNotExist:
                logger.warning(f"Local subscription not found for Stripe ID: {stripe_sub.id}")

        logger.info("Stripe subscription sync completed")

    except Exception as e:
        logger.error(f"Error syncing subscriptions: {e}")


@shared_task
def send_renewal_reminder():
    """
    Send renewal reminders to users with subscriptions expiring in 7 days.

    Run daily.
    """
    logger.info("Sending renewal reminders")

    # Find subscriptions expiring in 7 days
    in_seven_days = timezone.now() + timedelta(days=7)
    subscriptions = UserSubscription.objects.filter(
        status='active',
        current_period_end__date=in_seven_days.date()
    )

    logger.info(f"Sending {subscriptions.count()} renewal reminders")

    for subscription in subscriptions:
        try:
            send_mail(
                subject='Your subscription will renew soon',
                message=f'Your {subscription.plan.name} plan will renew on {subscription.current_period_end.date()}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[subscription.user.email],
            )
        except Exception as e:
            logger.error(f"Error sending reminder to {subscription.user.email}: {e}")

    logger.info("Renewal reminder process completed")


@shared_task
def send_invoice_email(invoice_id: int, email_type: str = 'created'):
    """Send invoice email to user"""
    from finance.models import Invoice

    try:
        invoice = Invoice.objects.get(id=invoice_id)

        if email_type == 'created':
            subject = f"Invoice {invoice.invoice_number}"
            message = f"Your invoice for {invoice.amount_due} {invoice.currency} is ready"
        elif email_type == 'paid':
            subject = f"Invoice {invoice.invoice_number} - Paid"
            message = f"Payment received for invoice {invoice.invoice_number}"
        else:
            return

        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[invoice.user.email],
        )

        logger.info(f"Invoice email sent to {invoice.user.email}")

    except Exception as e:
        logger.error(f"Error sending invoice email: {e}")


@shared_task
def send_payment_failed_notification(invoice_id: int):
    """Send payment failed notification"""
    from finance.models import Invoice

    try:
        invoice = Invoice.objects.get(id=invoice_id)

        send_mail(
            subject=f"Payment Failed - Invoice {invoice.invoice_number}",
            message=f"Payment for invoice {invoice.invoice_number} failed. Please update your payment method.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[invoice.user.email],
        )

        logger.info(f"Payment failure notification sent to {invoice.user.email}")

    except Exception as e:
        logger.error(f"Error sending payment failure notification: {e}")


@shared_task
def send_renewal_payment_failed_email(user_id: int):
    """Send renewal payment failed email"""
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        user = User.objects.get(id=user_id)

        send_mail(
            subject="Your subscription renewal payment failed",
            message="Your subscription renewal payment failed. Please update your payment method to continue service.",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
        )

        logger.info(f"Renewal payment failure notification sent to {user.email}")

    except Exception as e:
        logger.error(f"Error sending renewal payment failure email: {e}")
```

---

## FIX 4: Update Celery Beat Schedule

**File**: `zumodra/celery_beat_schedule.py`

Add these tasks to the schedule:

```python
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    # ... existing tasks ...

    # Subscription renewal tasks
    'process-subscription-renewals': {
        'task': 'finance.tasks.process_subscription_renewals',
        'schedule': crontab(minute=0),  # Every hour
        'options': {'queue': 'default'}
    },

    'retry-failed-renewals': {
        'task': 'finance.tasks.retry_failed_renewals',
        'schedule': crontab(minute=0, hour='*/6'),  # Every 6 hours
        'options': {'queue': 'default'}
    },

    'sync-stripe-subscriptions': {
        'task': 'finance.tasks.sync_stripe_subscriptions',
        'schedule': crontab(hour=2, minute=0),  # Daily at 2 AM
        'options': {'queue': 'default'}
    },

    'send-renewal-reminders': {
        'task': 'finance.tasks.send_renewal_reminder',
        'schedule': crontab(hour=10, minute=0),  # Daily at 10 AM
        'options': {'queue': 'default'}
    },
}
```

---

## FIX 5: Add SubscriptionRenewal Model

**File**: `finance/models.py`

Add this model:

```python
class SubscriptionRenewal(models.Model):
    """Track subscription renewal events and retry logic"""

    RENEWAL_STATUS = [
        ('pending', 'Pending'),
        ('success', 'Successful'),
        ('failed', 'Failed'),
    ]

    subscription = models.ForeignKey(
        UserSubscription,
        on_delete=models.CASCADE,
        related_name='renewals'
    )
    renewal_date = models.DateTimeField(db_index=True)
    invoice = models.ForeignKey(
        Invoice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    status = models.CharField(
        max_length=20,
        choices=RENEWAL_STATUS,
        default='pending',
        db_index=True
    )
    retry_count = models.PositiveIntegerField(default=0)
    next_retry = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-renewal_date']
        indexes = [
            models.Index(fields=['subscription', 'renewal_date']),
            models.Index(fields=['status', 'next_retry']),
        ]

    def __str__(self):
        return f"Renewal {self.id} - {self.status}"
```

---

## FIX 6: Fix Upgrade/Downgrade Implementation

**File**: `finance/api/viewsets.py`

Replace commented code with:

```python
@action(detail=False, methods=['post'])
def upgrade_plan(self, request):
    """Upgrade user subscription to a higher tier plan"""
    try:
        subscription = UserSubscription.objects.get(user=request.user)
    except UserSubscription.DoesNotExist:
        return Response(
            {'error': 'No active subscription'},
            status=status.HTTP_404_NOT_FOUND
        )

    new_plan_id = request.data.get('plan_id')

    try:
        new_plan = SubscriptionPlan.objects.get(id=new_plan_id)
    except SubscriptionPlan.DoesNotExist:
        return Response(
            {'error': 'Plan not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    # Verify this is actually an upgrade
    if new_plan.price <= subscription.plan.price:
        return Response(
            {'error': 'Selected plan must be more expensive than current plan'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        # Update subscription in Stripe with proration
        stripe_sub = stripe.Subscription.retrieve(
            subscription.stripe_subscription_id
        )

        # Get subscription item ID
        item_id = stripe_sub['items']['data'][0]['id']

        # Update with proration
        stripe.Subscription.modify(
            subscription.stripe_subscription_id,
            items=[{
                'id': item_id,
                'price': new_plan.stripe_price_id,
            }],
            proration_behavior='create_prorations',
        )

        # Update local subscription
        subscription.plan = new_plan
        subscription.save()

        logger.info(f"User {request.user.id} upgraded from {subscription.plan.name} to {new_plan.name}")

        return Response({
            'success': True,
            'message': f'Upgraded to {new_plan.name}',
            'plan': SubscriptionPlanSerializer(new_plan).data,
        })

    except stripe.error.StripeError as e:
        logger.error(f"Stripe error upgrading plan: {e}")
        return Response(
            {'error': 'Failed to upgrade plan'},
            status=status.HTTP_400_BAD_REQUEST
        )


@action(detail=False, methods=['post'])
def downgrade_plan(self, request):
    """Downgrade user subscription to a lower tier plan"""
    try:
        subscription = UserSubscription.objects.get(user=request.user)
    except UserSubscription.DoesNotExist:
        return Response(
            {'error': 'No active subscription'},
            status=status.HTTP_404_NOT_FOUND
        )

    new_plan_id = request.data.get('plan_id')

    try:
        new_plan = SubscriptionPlan.objects.get(id=new_plan_id)
    except SubscriptionPlan.DoesNotExist:
        return Response(
            {'error': 'Plan not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    # Verify this is actually a downgrade
    if new_plan.price >= subscription.plan.price:
        return Response(
            {'error': 'Selected plan must be less expensive than current plan'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        # Update subscription in Stripe
        stripe_sub = stripe.Subscription.retrieve(
            subscription.stripe_subscription_id
        )

        item_id = stripe_sub['items']['data'][0]['id']

        # Update subscription (proration will create credit)
        stripe.Subscription.modify(
            subscription.stripe_subscription_id,
            items=[{
                'id': item_id,
                'price': new_plan.stripe_price_id,
            }],
            proration_behavior='create_prorations',
        )

        # Update local subscription
        subscription.plan = new_plan
        subscription.save()

        logger.info(f"User {request.user.id} downgraded to {new_plan.name}")

        return Response({
            'success': True,
            'message': f'Downgraded to {new_plan.name}',
            'plan': SubscriptionPlanSerializer(new_plan).data,
        })

    except stripe.error.StripeError as e:
        logger.error(f"Stripe error downgrading plan: {e}")
        return Response(
            {'error': 'Failed to downgrade plan'},
            status=status.HTTP_400_BAD_REQUEST
        )
```

---

## Testing the Fixes

### Unit Tests
```python
from django.test import TestCase
import stripe
from decimal import Decimal
from finance.models import *
from finance.webhook_handlers import StripeEventHandler

class SubscriptionWebhookTests(TestCase):
    def test_subscription_created_webhook(self):
        """Test subscription.created webhook handling"""
        handler = StripeEventHandler()
        event = {
            'type': 'customer.subscription.created',
            'data': {
                'object': {
                    'id': 'sub_test123',
                    'customer': 'cus_test123',
                    'status': 'active',
                    'current_period_start': 1234567890,
                    'current_period_end': 1234654290,
                    'items': {
                        'data': [{
                            'price': {'id': 'price_test123'}
                        }]
                    }
                }
            }
        }

        # This will raise if user not found, which is expected
        # In real test, create user and stripe profile first

    def test_renewal_process(self):
        """Test subscription renewal process"""
        # Create test subscription
        plan = SubscriptionPlan.objects.create(
            name='Test Plan',
            price=Decimal('99.99'),
            stripe_product_id='prod_test',
            stripe_price_id='price_test',
        )

        user = CustomUser.objects.create_user(email='test@example.com')

        subscription = UserSubscription.objects.create(
            user=user,
            plan=plan,
            stripe_subscription_id='sub_test',
            status='active',
            current_period_start=timezone.now() - timedelta(days=30),
            current_period_end=timezone.now() + timedelta(hours=1),
        )

        # Process renewal
        from finance.tasks import renew_subscription
        # This will attempt to call Stripe, which will fail in test
        # Use mocking for real tests
```

---

## Deployment Checklist

- [ ] Update webhook signature validation code
- [ ] Implement webhook event handlers
- [ ] Add renewal scheduler task
- [ ] Create SubscriptionRenewal model and migration
- [ ] Uncomment and fix upgrade/downgrade code
- [ ] Run migrations: `python manage.py migrate`
- [ ] Configure Celery Beat schedule
- [ ] Test webhook delivery (Stripe dashboard)
- [ ] Test renewal process manually
- [ ] Set up monitoring for failed renewals
- [ ] Train support team on billing workflows

---

**Date**: 2026-01-16
**Status**: Ready for Implementation
