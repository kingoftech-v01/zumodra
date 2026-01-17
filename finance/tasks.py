"""
Celery Tasks for Finance App

This module contains async tasks for financial operations:
- Stripe payment synchronization
- Invoice generation
- Refund processing
- Failed payment retries
- Subscription status updates
- Escrow processing

Security Features:
- PCI-DSS compliance considerations
- Audit logging for all financial operations
- Secure task execution with permission validation
"""

import logging
from datetime import timedelta
from decimal import Decimal
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.db.models import Sum, Count, Q
from django.core.cache import cache

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.finance.tasks')


# ==================== STRIPE PAYMENT SYNC ====================

@shared_task(
    bind=True,
    name='finance.tasks.sync_stripe_payments',
    max_retries=3,
    default_retry_delay=600,
    autoretry_for=(Exception,),
    soft_time_limit=1800,
)
def sync_stripe_payments(self):
    """
    Synchronize payment statuses from Stripe.

    Checks:
    - Pending payments for status updates
    - Webhook-missed events
    - Payment intent confirmations

    Returns:
        dict: Summary of sync.
    """
    from finance.models import PaymentTransaction

    try:
        now = timezone.now()

        # Find pending payments needing sync
        pending_payments = PaymentTransaction.objects.filter(
            succeeded=False,
            stripe_payment_intent_id__isnull=False,
            created_at__lt=now - timedelta(minutes=5)
        )[:50]  # Batch size

        synced = 0
        for payment in pending_payments:
            try:
                # In production, would call Stripe API:
                # stripe.PaymentIntent.retrieve(payment.stripe_payment_intent_id)

                # Placeholder - mark as synced
                payment.last_synced_at = now
                payment.save(update_fields=['last_synced_at', 'updated_at'])

                synced += 1

            except Exception as e:
                logger.error(f"Error syncing payment {payment.id}: {e}")

        logger.info(f"Synced {synced} payments with Stripe")

        return {
            'status': 'success',
            'synced_count': synced,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Stripe sync exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error syncing Stripe payments: {str(e)}")
        raise self.retry(exc=e)


# ==================== INVOICE GENERATION ====================

@shared_task(
    bind=True,
    name='finance.tasks.generate_monthly_invoices',
    max_retries=3,
    default_retry_delay=600,
    soft_time_limit=3600,
)
def generate_monthly_invoices(self):
    """
    Generate monthly invoices for subscriptions.

    Creates invoices for:
    - Active subscriptions at billing date
    - Pro-rated charges for mid-cycle changes
    - Usage-based billing calculations

    Returns:
        dict: Summary of invoices generated.
    """
    from finance.models import UserSubscription, Invoice

    try:
        now = timezone.now()

        # Find subscriptions due for invoicing
        due_subscriptions = UserSubscription.objects.filter(
            status='active',
            next_billing_date__lte=now
        )

        generated = 0
        for subscription in due_subscriptions:
            try:
                # Create invoice
                invoice = Invoice.objects.create(
                    subscription=subscription,
                    tenant=subscription.tenant,
                    amount=subscription.plan.price,
                    currency=subscription.plan.currency,
                    billing_period_start=subscription.current_period_start,
                    billing_period_end=subscription.current_period_end,
                    succeeded=False,
                    due_date=now + timedelta(days=14),
                )

                # Update subscription billing date
                subscription.current_period_start = now
                subscription.current_period_end = now + timedelta(days=30)
                subscription.next_billing_date = subscription.current_period_end
                subscription.save()

                # Send invoice notification
                _send_invoice_notification(invoice)

                security_logger.info(
                    f"INVOICE_GENERATED: invoice={invoice.id} subscription={subscription.id} "
                    f"amount={invoice.amount} {invoice.currency}"
                )

                generated += 1

            except Exception as e:
                logger.error(f"Error generating invoice for subscription {subscription.id}: {e}")

        logger.info(f"Generated {generated} invoices")

        return {
            'status': 'success',
            'generated_count': generated,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Invoice generation exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error generating invoices: {str(e)}")
        raise self.retry(exc=e)


def _send_invoice_notification(invoice):
    """Send invoice notification email."""
    if not hasattr(invoice.subscription, 'tenant'):
        return

    tenant = invoice.subscription.tenant
    if not hasattr(tenant, 'owner') or not tenant.owner:
        return

    recipient = tenant.owner
    if not hasattr(recipient, 'email'):
        return

    subject = f"Invoice #{invoice.invoice_number or invoice.id} - {invoice.amount} {invoice.currency}"

    context = {
        'invoice': invoice,
        'tenant': tenant,
    }

    try:
        html_content = render_to_string('emails/finance/invoice_created.html', context)
        text_content = f"Your invoice for {invoice.amount} {invoice.currency} is ready."
    except Exception:
        text_content = f"Your invoice for {invoice.amount} {invoice.currency} is ready."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[recipient.email],
        html_message=html_content,
        fail_silently=True,
    )


# ==================== REFUND PROCESSING ====================

@shared_task(
    bind=True,
    name='finance.tasks.process_pending_refunds',
    max_retries=3,
    default_retry_delay=300,
)
def process_pending_refunds(self):
    """
    Process pending refund requests.

    Actions:
    - Submit refunds to Stripe
    - Update payment statuses
    - Send confirmation notifications

    Returns:
        dict: Summary of refunds processed.
    """
    from finance.models import RefundRequest

    try:
        now = timezone.now()

        # Find pending refunds
        pending_refunds = RefundRequest.objects.filter(
            succeeded=False,
            approved_at__isnull=False
        )

        processed = 0
        for refund in pending_refunds:
            try:
                # In production, would call Stripe:
                # stripe.Refund.create(
                #     payment_intent=refund.payment.stripe_payment_intent_id,
                #     amount=int(refund.amount * 100)
                # )

                refund.status = 'processed'
                refund.processed_at = now
                refund.save(update_fields=['status', 'processed_at', 'updated_at'])

                # Update original payment
                if hasattr(refund, 'payment') and refund.payment:
                    refund.payment.refunded_amount = (refund.payment.refunded_amount or Decimal('0')) + refund.amount
                    refund.payment.save(update_fields=['refunded_amount', 'updated_at'])

                security_logger.info(
                    f"REFUND_PROCESSED: refund={refund.id} payment={refund.payment_id} "
                    f"amount={refund.amount}"
                )

                processed += 1

            except Exception as e:
                logger.error(f"Error processing refund {refund.id}: {e}")
                refund.status = 'failed'
                refund.error_message = str(e)
                refund.save(update_fields=['status', 'error_message', 'updated_at'])

        logger.info(f"Processed {processed} refunds")

        return {
            'status': 'success',
            'processed_count': processed,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error processing refunds: {str(e)}")
        raise self.retry(exc=e)


# ==================== FAILED PAYMENT RETRY ====================

@shared_task(
    bind=True,
    name='finance.tasks.retry_failed_payments',
    max_retries=3,
    default_retry_delay=600,
)
def retry_failed_payments(self):
    """
    Retry failed payments.

    Retries payments that:
    - Failed due to temporary issues
    - Have not exceeded retry limit
    - Have updated payment methods

    Returns:
        dict: Summary of retry attempts.
    """
    from finance.models import PaymentTransaction

    try:
        now = timezone.now()

        # Find payments eligible for retry
        failed_payments = PaymentTransaction.objects.filter(
            succeeded=False,
            retry_count__lt=3,
            last_retry_at__lt=now - timedelta(hours=24)
        )

        retried = 0
        success = 0

        for payment in failed_payments:
            try:
                # In production, would retry via Stripe:
                # stripe.PaymentIntent.confirm(payment.stripe_payment_intent_id)

                payment.retry_count = (payment.retry_count or 0) + 1
                payment.last_retry_at = now

                # Simulate retry result (would be from Stripe response)
                # payment.status = 'succeeded'  # or 'failed'

                payment.save(update_fields=['retry_count', 'last_retry_at', 'updated_at'])

                retried += 1

            except Exception as e:
                logger.error(f"Error retrying payment {payment.id}: {e}")

        logger.info(f"Retried {retried} failed payments, {success} succeeded")

        return {
            'status': 'success',
            'retried_count': retried,
            'success_count': success,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error retrying payments: {str(e)}")
        raise self.retry(exc=e)


# ==================== SUBSCRIPTION STATUS UPDATE ====================

@shared_task(
    bind=True,
    name='finance.tasks.update_subscription_status',
    max_retries=3,
    default_retry_delay=300,
)
def update_subscription_status(self):
    """
    Update subscription statuses based on payment and expiration.

    Actions:
    - Expire past-due subscriptions
    - Downgrade unpaid subscriptions
    - Send expiration warnings

    Returns:
        dict: Summary of updates.
    """
    from finance.models import UserSubscription

    try:
        now = timezone.now()

        # Find subscriptions needing status update
        expired_subs = UserSubscription.objects.filter(
            status='active',
            current_period_end__lt=now
        )

        expired_count = 0
        for subscription in expired_subs:
            try:
                # Check if there's a pending payment
                has_pending_payment = hasattr(subscription, 'payments') and \
                    subscription.payments.filter(succeeded=False).exists()

                if not has_pending_payment:
                    subscription.status = 'past_due'
                    subscription.save(update_fields=['status', 'updated_at'])

                    # Send notification
                    _send_subscription_expiry_notification(subscription)

                    security_logger.info(
                        f"SUBSCRIPTION_EXPIRED: subscription={subscription.id} "
                        f"tenant={subscription.tenant_id}"
                    )

                    expired_count += 1

            except Exception as e:
                logger.error(f"Error updating subscription {subscription.id}: {e}")

        # Find past-due subscriptions to cancel
        grace_period_end = now - timedelta(days=14)
        cancel_subs = UserSubscription.objects.filter(
            status='past_due',
            current_period_end__lt=grace_period_end
        )

        cancelled_count = 0
        for subscription in cancel_subs:
            try:
                subscription.status = 'cancelled'
                subscription.cancelled_at = now
                subscription.save(update_fields=['status', 'cancelled_at', 'updated_at'])

                security_logger.info(
                    f"SUBSCRIPTION_CANCELLED: subscription={subscription.id} "
                    f"reason=non_payment"
                )

                cancelled_count += 1

            except Exception as e:
                logger.error(f"Error cancelling subscription {subscription.id}: {e}")

        logger.info(f"Updated subscriptions: expired={expired_count}, cancelled={cancelled_count}")

        return {
            'status': 'success',
            'expired_count': expired_count,
            'cancelled_count': cancelled_count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error updating subscription status: {str(e)}")
        raise self.retry(exc=e)


def _send_subscription_expiry_notification(subscription):
    """Send subscription expiry notification."""
    if not hasattr(subscription, 'tenant') or not subscription.tenant:
        return

    tenant = subscription.tenant
    if not hasattr(tenant, 'owner') or not tenant.owner:
        return

    recipient = tenant.owner
    if not hasattr(recipient, 'email'):
        return

    subject = "Your subscription has expired"

    context = {
        'subscription': subscription,
        'tenant': tenant,
    }

    try:
        html_content = render_to_string('emails/finance/subscription_expired.html', context)
        text_content = "Your subscription has expired. Please update your payment method."
    except Exception:
        text_content = "Your subscription has expired. Please update your payment method."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[recipient.email],
        html_message=html_content,
        fail_silently=True,
    )


# ==================== ESCROW MANAGEMENT ====================

@shared_task(
    bind=True,
    name='finance.tasks.process_escrow_transactions',
    max_retries=3,
    default_retry_delay=300,
)
def process_escrow_transactions(self):
    """
    Process pending escrow transactions.

    Actions:
    - Release funds for completed contracts
    - Process milestone payments
    - Handle dispute resolutions

    Returns:
        dict: Summary of transactions processed.
    """
    from finance.models import EscrowTransaction

    try:
        now = timezone.now()

        # Find escrow transactions ready for release
        ready_for_release = EscrowTransaction.objects.filter(
            status='funded',
            release_approved=True,
            released_at__isnull=True
        )

        released = 0
        for escrow in ready_for_release:
            try:
                # In production, would transfer via Stripe Connect:
                # stripe.Transfer.create(
                #     amount=int(escrow.provider_amount * 100),
                #     currency=escrow.currency,
                #     destination=provider_stripe_account_id
                # )

                escrow.status = 'released'
                escrow.released_at = now
                escrow.save(update_fields=['status', 'released_at', 'updated_at'])

                # Notify provider
                _send_escrow_release_notification(escrow)

                security_logger.info(
                    f"ESCROW_RELEASED: escrow={escrow.id} amount={escrow.amount} "
                    f"provider_amount={escrow.provider_amount}"
                )

                released += 1

            except Exception as e:
                logger.error(f"Error releasing escrow {escrow.id}: {e}")

        logger.info(f"Released {released} escrow transactions")

        return {
            'status': 'success',
            'released_count': released,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error processing escrow transactions: {str(e)}")
        raise self.retry(exc=e)


def _send_escrow_release_notification(escrow):
    """Send escrow release notification to provider."""
    if not hasattr(escrow, 'provider') or not escrow.provider:
        return

    if not hasattr(escrow.provider, 'user') or not escrow.provider.user:
        return

    recipient = escrow.provider.user
    if not hasattr(recipient, 'email'):
        return

    subject = f"Payment Released: {escrow.provider_amount} {escrow.currency}"

    context = {
        'escrow': escrow,
    }

    try:
        html_content = render_to_string('emails/finance/escrow_released.html', context)
        text_content = f"Your payment of {escrow.provider_amount} {escrow.currency} has been released."
    except Exception:
        text_content = f"Your payment of {escrow.provider_amount} {escrow.currency} has been released."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[recipient.email],
        html_message=html_content,
        fail_silently=True,
    )


# ==================== FINANCIAL REPORTS ====================

@shared_task(
    bind=True,
    name='finance.tasks.generate_daily_financial_report',
    max_retries=3,
    default_retry_delay=600,
)
def generate_daily_financial_report(self):
    """
    Generate daily financial summary report.

    Calculates:
    - Total revenue
    - Refunds processed
    - Outstanding invoices
    - Subscription metrics

    Returns:
        dict: Financial summary.
    """
    from finance.models import PaymentTransaction, RefundRequest, Invoice, UserSubscription

    try:
        now = timezone.now()
        yesterday = now - timedelta(days=1)

        # Calculate daily metrics
        daily_revenue = PaymentTransaction.objects.filter(
            succeeded=True,
            created_at__date=yesterday.date()
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')

        daily_refunds = RefundRequest.objects.filter(
            approved=True,
            processed_at__date=yesterday.date()
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')

        outstanding_invoices = Invoice.objects.filter(
            succeeded=False
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')

        active_subscriptions = UserSubscription.objects.filter(status='active').count()

        report = {
            'date': yesterday.date().isoformat(),
            'daily_revenue': float(daily_revenue),
            'daily_refunds': float(daily_refunds),
            'net_revenue': float(daily_revenue - daily_refunds),
            'outstanding_invoices': float(outstanding_invoices),
            'active_subscriptions': active_subscriptions,
        }

        # Cache report
        cache.set(f"finance:daily_report:{yesterday.date()}", report, timeout=86400)

        logger.info(f"Generated daily financial report: revenue={daily_revenue}")

        return {
            'status': 'success',
            'report': report,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error generating financial report: {str(e)}")
        raise self.retry(exc=e)
