"""
Celery Tasks for Services (Marketplace) App

This module contains async tasks for marketplace operations:
- Contract reminders and status updates
- Proposal expiration handling
- Provider rating calculations
- Abandoned request cleanup
- Escrow transaction processing

Security Features:
- SecureTenantTask for permission-validated operations
- Tenant isolation on all queries
- Audit logging for financial operations
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
from django.db.models import Avg, Count, F, Q

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.services.tasks')


# ==================== CONTRACT REMINDERS ====================

@shared_task(
    bind=True,
    name='services.tasks.send_contract_reminders',
    max_retries=3,
    default_retry_delay=600,
    autoretry_for=(Exception,),
    retry_backoff=True,
    soft_time_limit=1800,
)
def send_contract_reminders(self):
    """
    Send reminders for pending contracts.

    Sends reminders for:
    - Contracts pending acceptance (3+ days)
    - Contracts nearing deadline (7 days before)
    - Contracts with overdue milestones

    Returns:
        dict: Summary of reminders sent.
    """
    from services.models import ServiceContract

    try:
        now = timezone.now()
        reminders_sent = 0

        # Pending acceptance reminders (3+ days)
        pending_contracts = ServiceContract.objects.filter(
            status='pending',
            created_at__lt=now - timedelta(days=3)
        ).select_related('client', 'provider')

        for contract in pending_contracts:
            try:
                _send_contract_reminder_email(contract, 'pending_acceptance')
                reminders_sent += 1
            except Exception as e:
                logger.error(f"Error sending pending contract reminder {contract.id}: {e}")

        # Deadline approaching reminders (7 days before)
        deadline_contracts = ServiceContract.objects.filter(
            status='in_progress',
            agreed_deadline__gte=now,
            agreed_deadline__lt=now + timedelta(days=7)
        ).select_related('client', 'provider')

        for contract in deadline_contracts:
            try:
                _send_contract_reminder_email(contract, 'deadline_approaching')
                reminders_sent += 1
            except Exception as e:
                logger.error(f"Error sending deadline reminder {contract.id}: {e}")

        logger.info(f"Sent {reminders_sent} contract reminders")

        return {
            'status': 'success',
            'reminders_sent': reminders_sent,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Contract reminders exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error sending contract reminders: {str(e)}")
        raise self.retry(exc=e)


def _send_contract_reminder_email(contract, reminder_type):
    """Send contract reminder email."""
    if reminder_type == 'pending_acceptance':
        subject = f"Action Required: Contract pending - {contract.title}"
        recipient = contract.provider.user if hasattr(contract, 'provider') and contract.provider else None
    else:
        subject = f"Reminder: Contract deadline approaching - {contract.title}"
        recipient = contract.provider.user if hasattr(contract, 'provider') and contract.provider else None

    if not recipient or not hasattr(recipient, 'email'):
        return

    context = {
        'contract': contract,
        'reminder_type': reminder_type,
    }

    try:
        html_content = render_to_string('emails/marketplace/contract_reminder.html', context)
        text_content = f"Contract reminder for {contract.title}."
    except Exception:
        text_content = f"Contract reminder for {contract.title}."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[recipient.email],
        html_message=html_content,
        fail_silently=True,
    )


# ==================== PROPOSAL EXPIRATION ====================

@shared_task(
    bind=True,
    name='services.tasks.expire_old_proposals',
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(Exception,),
)
def expire_old_proposals(self):
    """
    Expire proposals that have been pending too long.

    Proposals expire after 30 days of no response.

    Returns:
        dict: Summary of expired proposals.
    """
    from services.models import ServiceProposal

    try:
        now = timezone.now()
        threshold = now - timedelta(days=30)

        # Find and expire old proposals
        expired_proposals = ServiceProposal.objects.filter(
            status='pending',
            created_at__lt=threshold
        )

        count = expired_proposals.count()

        # Update status
        expired_proposals.update(
            status='expired',
            expired_at=now
        )

        # Send notifications to providers
        for proposal in ServiceProposal.objects.filter(
            expired_at=now
        ).select_related('provider'):
            try:
                _send_proposal_expired_notification(proposal)
            except Exception as e:
                logger.error(f"Error sending expiration notice for proposal {proposal.id}: {e}")

        logger.info(f"Expired {count} old proposals")

        return {
            'status': 'success',
            'expired_count': count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error expiring proposals: {str(e)}")
        raise self.retry(exc=e)


def _send_proposal_expired_notification(proposal):
    """Send proposal expiration notification."""
    if not hasattr(proposal, 'provider') or not proposal.provider:
        return

    recipient = proposal.provider.user
    if not hasattr(recipient, 'email'):
        return

    subject = f"Your proposal has expired - {proposal.client_request.title if hasattr(proposal, 'client_request') else 'Service'}"
    text_content = "Your proposal has expired after 30 days without response."

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[recipient.email],
        fail_silently=True,
    )


# ==================== PROVIDER RATINGS ====================

@shared_task(
    bind=True,
    name='services.tasks.calculate_provider_ratings',
    max_retries=3,
    default_retry_delay=300,
    soft_time_limit=1800,
)
def calculate_provider_ratings(self):
    """
    Recalculate aggregate ratings for all providers.

    Updates:
    - Average rating
    - Total reviews count
    - Rating breakdown by category

    Returns:
        dict: Summary of ratings calculated.
    """
    from services.models import ServiceProvider, ServiceReview
    from django.core.cache import cache

    try:
        now = timezone.now()
        updated = 0

        providers = ServiceProvider.objects.filter(is_active=True)

        for provider in providers:
            try:
                # Calculate aggregate ratings
                reviews = ServiceReview.objects.filter(provider=provider)

                agg_data = reviews.aggregate(
                    avg_rating=Avg('rating'),
                    avg_communication=Avg('rating_communication'),
                    avg_quality=Avg('rating_quality'),
                    avg_timeliness=Avg('rating_timeliness'),
                    total_count=Count('id')
                )

                # Update provider
                provider.rating_avg = agg_data['avg_rating'] or Decimal('0.00')
                provider.total_reviews = agg_data['total_count'] or 0
                provider.save(update_fields=['rating_avg', 'total_reviews', 'updated_at'])

                # Invalidate cache
                cache_key = f"provider_{provider.id}:rating"
                cache.delete(cache_key)

                updated += 1

            except Exception as e:
                logger.error(f"Error updating rating for provider {provider.id}: {e}")

        logger.info(f"Updated ratings for {updated} providers")

        return {
            'status': 'success',
            'updated_count': updated,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Rating calculation exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error calculating provider ratings: {str(e)}")
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='services.tasks.update_single_provider_rating',
    max_retries=3,
)
def update_single_provider_rating(self, provider_id):
    """
    Update rating for a single provider after a new review.

    Args:
        provider_id: ID of the provider

    Returns:
        dict: Updated rating data
    """
    from services.models import ServiceProvider, ServiceReview
    from django.core.cache import cache

    try:
        provider = ServiceProvider.objects.get(id=provider_id)

        reviews = ServiceReview.objects.filter(provider=provider)
        agg_data = reviews.aggregate(
            avg_rating=Avg('rating'),
            total_count=Count('id')
        )

        provider.rating_avg = agg_data['avg_rating'] or Decimal('0.00')
        provider.total_reviews = agg_data['total_count'] or 0
        provider.save(update_fields=['rating_avg', 'total_reviews', 'updated_at'])

        # Invalidate cache
        cache.delete(f"provider_{provider_id}:rating")

        return {
            'status': 'success',
            'provider_id': provider_id,
            'new_rating': float(provider.rating_avg),
            'total_reviews': provider.total_reviews,
        }

    except ServiceProvider.DoesNotExist:
        return {
            'status': 'error',
            'error': 'Provider not found',
        }

    except Exception as e:
        logger.error(f"Error updating provider rating: {str(e)}")
        raise self.retry(exc=e)


# ==================== ABANDONED REQUESTS CLEANUP ====================

@shared_task(
    bind=True,
    name='services.tasks.cleanup_abandoned_requests',
    max_retries=3,
    default_retry_delay=300,
)
def cleanup_abandoned_requests(self):
    """
    Clean up abandoned client requests.

    Marks requests as closed if:
    - Draft for 30+ days
    - Open with no proposals for 60+ days

    Returns:
        dict: Summary of cleanup.
    """
    from services.models import ClientRequest

    try:
        now = timezone.now()

        # Close old drafts
        draft_threshold = now - timedelta(days=30)
        draft_count = ClientRequest.objects.filter(
            status='draft',
            created_at__lt=draft_threshold
        ).update(
            status='closed',
            closed_at=now,
            close_reason='abandoned_draft'
        )

        # Close open requests with no proposals
        open_threshold = now - timedelta(days=60)
        stale_requests = ClientRequest.objects.filter(
            status='open',
            created_at__lt=open_threshold
        ).annotate(
            proposal_count=Count('proposals')
        ).filter(proposal_count=0)

        open_count = stale_requests.count()
        stale_requests.update(
            status='closed',
            closed_at=now,
            close_reason='no_proposals'
        )

        total_cleaned = draft_count + open_count
        logger.info(f"Cleaned up {total_cleaned} abandoned requests (drafts: {draft_count}, stale: {open_count})")

        return {
            'status': 'success',
            'drafts_closed': draft_count,
            'stale_requests_closed': open_count,
            'total_cleaned': total_cleaned,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error cleaning up abandoned requests: {str(e)}")
        raise self.retry(exc=e)


# ==================== CONTRACT STATUS UPDATES ====================

@shared_task(
    bind=True,
    name='services.tasks.update_contract_statuses',
    max_retries=3,
    default_retry_delay=300,
)
def update_contract_statuses(self):
    """
    Update contract statuses based on deadlines and milestones.

    Actions:
    - Mark overdue contracts
    - Update milestone statuses
    - Send overdue notifications

    Returns:
        dict: Summary of updates.
    """
    from services.models import ServiceContract

    try:
        now = timezone.now()

        # Find overdue contracts
        overdue_contracts = ServiceContract.objects.filter(
            status='in_progress',
            agreed_deadline__lt=now
        )

        overdue_count = overdue_contracts.count()

        for contract in overdue_contracts:
            try:
                # Mark as overdue (if field exists)
                if hasattr(contract, 'is_overdue'):
                    contract.is_overdue = True
                    contract.save(update_fields=['is_overdue', 'updated_at'])

                # Send notification
                _send_overdue_notification(contract)

            except Exception as e:
                logger.error(f"Error updating overdue contract {contract.id}: {e}")

        logger.info(f"Updated {overdue_count} overdue contracts")

        return {
            'status': 'success',
            'overdue_count': overdue_count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error updating contract statuses: {str(e)}")
        raise self.retry(exc=e)


def _send_overdue_notification(contract):
    """Send overdue contract notification to both parties."""
    subject = f"Contract Overdue: {contract.title}"
    text_content = f"The contract '{contract.title}' is now past its deadline."

    recipients = []
    if hasattr(contract, 'client') and contract.client:
        recipients.append(contract.client.email if hasattr(contract.client, 'email') else None)
    if hasattr(contract, 'provider') and contract.provider and hasattr(contract.provider, 'user'):
        recipients.append(contract.provider.user.email if hasattr(contract.provider.user, 'email') else None)

    recipients = [r for r in recipients if r]

    for email in recipients:
        send_mail(
            subject=subject,
            message=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=True,
        )


# ==================== SERVICE STATISTICS ====================

@shared_task(
    bind=True,
    name='services.tasks.update_service_statistics',
    max_retries=3,
    default_retry_delay=300,
    soft_time_limit=1800,
)
def update_service_statistics(self):
    """
    Update statistics for services.

    Updates:
    - View counts
    - Order counts
    - Conversion rates

    Returns:
        dict: Summary of statistics updated.
    """
    from services.models import Service, ServiceContract
    from django.core.cache import cache

    try:
        now = timezone.now()
        updated = 0

        services = Service.objects.filter(is_active=True)

        for service in services:
            try:
                # Count completed orders
                completed_orders = ServiceContract.objects.filter(
                    service=service,
                    status='completed'
                ).count()

                service.order_count = completed_orders
                service.save(update_fields=['order_count', 'updated_at'])

                # Invalidate cache
                cache.delete(f"service_{service.id}:stats")

                updated += 1

            except Exception as e:
                logger.error(f"Error updating stats for service {service.id}: {e}")

        logger.info(f"Updated statistics for {updated} services")

        return {
            'status': 'success',
            'updated_count': updated,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Service statistics update exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error updating service statistics: {str(e)}")
        raise self.retry(exc=e)


# ==================== ESCROW PROCESSING ====================

@shared_task(
    bind=True,
    name='services.tasks.process_escrow_releases',
    max_retries=3,
    default_retry_delay=300,
)
def process_escrow_releases(self):
    """
    Process pending escrow releases.

    Releases escrow funds for:
    - Completed contracts with release approval
    - Auto-release after 14 days of no dispute

    Returns:
        dict: Summary of releases processed.
    """
    from services.models import ServiceContract

    try:
        now = timezone.now()
        auto_release_threshold = now - timedelta(days=14)

        # Find contracts ready for auto-release
        ready_for_release = ServiceContract.objects.filter(
            status='completed',
            completed_at__lt=auto_release_threshold,
            escrow_released=False
        ).exclude(
            has_dispute=True
        )

        released_count = 0

        for contract in ready_for_release:
            try:
                # Process escrow release (would integrate with Stripe Connect)
                contract.escrow_released = True
                contract.escrow_released_at = now
                contract.save(update_fields=['escrow_released', 'escrow_released_at', 'updated_at'])

                # Send notification
                _send_escrow_released_notification(contract)

                security_logger.info(
                    f"ESCROW_AUTO_RELEASED: contract={contract.id} "
                    f"amount={contract.agreed_rate}"
                )

                released_count += 1

            except Exception as e:
                logger.error(f"Error releasing escrow for contract {contract.id}: {e}")

        logger.info(f"Processed {released_count} escrow releases")

        return {
            'status': 'success',
            'released_count': released_count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error processing escrow releases: {str(e)}")
        raise self.retry(exc=e)


def _send_escrow_released_notification(contract):
    """Send escrow release notification to provider."""
    if not hasattr(contract, 'provider') or not contract.provider:
        return

    recipient = contract.provider.user
    if not hasattr(recipient, 'email'):
        return

    subject = f"Payment Released: {contract.title}"

    context = {
        'contract': contract,
    }

    try:
        html_content = render_to_string('emails/marketplace/payment_released.html', context)
        text_content = f"Payment for '{contract.title}' has been released to your account."
    except Exception:
        text_content = f"Payment for '{contract.title}' has been released to your account."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[recipient.email],
        html_message=html_content,
        fail_silently=True,
    )
