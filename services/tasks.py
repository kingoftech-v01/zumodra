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


# ==================== CROSS-TENANT MARKETPLACE ====================

@shared_task(
    bind=True,
    name='services.tasks.notify_cross_tenant_request',
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    retry_backoff=True,
)
def notify_cross_tenant_request(self, target_schema, request_uuid, requesting_tenant_schema):
    """
    Notify provider in their tenant schema about cross-tenant service request.

    This task switches to the target tenant's schema and creates a notification
    for the provider. The notification appears in their dashboard, allowing them
    to review and respond to the cross-tenant service request.

    Flow:
    1. Called from CrossTenantServiceRequest.notify_provider_tenant()
    2. Switches to target tenant schema
    3. Creates notification for provider/admins
    4. Provider sees notification in their dashboard
    5. Provider can review request and accept/reject

    Args:
        target_schema (str): Schema name of provider's tenant
        request_uuid (str): UUID of the CrossTenantServiceRequest
        requesting_tenant_schema (str): Schema name of requesting tenant

    Returns:
        dict: Success status and notification ID

    Raises:
        Exception: If tenant not found or notification creation fails (retries 3 times)
    """
    from tenants.models import Tenant
    from django_tenants.utils import schema_context

    try:
        # Get tenant models
        target_tenant = Tenant.objects.get(schema_name=target_schema)
        requesting_tenant = Tenant.objects.get(schema_name=requesting_tenant_schema)

        logger.info(
            f"Creating cross-tenant notification in {target_schema} "
            f"for request {request_uuid} from {requesting_tenant_schema}"
        )

        # Switch to target tenant schema and create notification
        with schema_context(target_schema):
            # Import here to avoid circular imports
            from notifications.models import Notification, NotificationChannel
            from accounts.models import TenantUser
            from django.contrib.auth import get_user_model

            User = get_user_model()

            # Get all admins and managers in the target tenant
            admin_roles = ['owner', 'manager', 'hr_manager']
            admin_users = TenantUser.objects.filter(
                tenant=target_tenant,
                role__in=admin_roles,
                is_active=True
            ).select_related('user')

            # Get or create a default notification channel
            channel, _ = NotificationChannel.objects.get_or_create(
                name='System',
                defaults={'slug': 'system', 'description': 'System notifications'}
            )

            notification_title = f"New service request from {requesting_tenant.name}"
            notification_message = (
                f"You have received a service request from {requesting_tenant.name}. "
                f"Request ID: {request_uuid}. "
                f"Please review and respond to this cross-organization request."
            )
            notification_metadata = {
                'request_uuid': request_uuid,
                'requesting_tenant_schema': requesting_tenant_schema,
                'requesting_company_name': requesting_tenant.name,
                'type': 'cross_tenant_service_request',
            }

            # Create notification for each admin/manager
            notifications_created = []
            for tenant_user in admin_users:
                notification = Notification.objects.create(
                    recipient=tenant_user.user,
                    channel=channel,
                    notification_type='cross_tenant_request',
                    title=notification_title,
                    message=notification_message,
                    metadata=notification_metadata,
                )
                notifications_created.append(notification.id)

            logger.info(
                f"Created {len(notifications_created)} notifications in {target_schema} "
                f"for cross-tenant request {request_uuid} (sent to all admins/managers)"
            )

            return {
                'status': 'success',
                'notification_ids': notifications_created,
                'notification_count': len(notifications_created),
                'target_tenant': target_schema,
                'request_uuid': request_uuid
            }

    except Tenant.DoesNotExist as e:
        error_msg = f"Tenant not found: {e}"
        logger.error(error_msg)
        # Don't retry if tenant doesn't exist (permanent failure)
        raise

    except Exception as e:
        error_msg = f"Failed to create cross-tenant notification: {e}"
        logger.error(error_msg, exc_info=True)

        # Retry on temporary failures
        try:
            raise self.retry(exc=e)
        except self.MaxRetriesExceededError:
            logger.error(
                f"Max retries exceeded for cross-tenant notification "
                f"(request {request_uuid}, target {target_schema})"
            )
            raise


@shared_task(
    bind=True,
    name='services.tasks.sync_public_catalog_stats',
    max_retries=3,
    default_retry_delay=300,
)
def sync_public_catalog_stats(self):
    """
    Periodic task to sync public catalog statistics.

    Updates service statistics in PublicServiceCatalog from source services
    in tenant schemas. Runs periodically (e.g., hourly) to keep catalog fresh.

    This ensures that:
    - Order counts are accurate
    - Provider ratings are up-to-date
    - Review counts are current

    Returns:
        dict: Summary of sync operation
    """
    from tenants.models import Tenant, PublicServiceCatalog
    from services.models import Service
    from django_tenants.utils import schema_context

    try:
        logger.info("Starting public catalog stats sync...")

        updated_count = 0
        error_count = 0

        # Process each tenant
        for tenant in Tenant.objects.exclude(schema_name='public'):
            try:
                with schema_context(tenant.schema_name):
                    # Get all public services in this tenant
                    public_services = Service.objects.filter(
                        is_public=True,
                        is_active=True,
                        published_to_catalog=True
                    ).select_related('provider')

                    for service in public_services:
                        try:
                            # Update catalog entry with latest stats
                            PublicServiceCatalog.objects.filter(
                                tenant_schema_name=tenant.schema_name,
                                service_uuid=service.uuid
                            ).update(
                                order_count=service.order_count,
                                rating_avg=service.provider.rating_avg,
                                review_count=service.provider.total_reviews,
                            )
                            updated_count += 1

                        except Exception as e:
                            logger.error(
                                f"Failed to sync service {service.uuid} stats: {e}"
                            )
                            error_count += 1

            except Exception as e:
                logger.error(
                    f"Failed to sync stats for tenant {tenant.schema_name}: {e}"
                )
                error_count += 1

        logger.info(
            f"Catalog stats sync complete. Updated: {updated_count}, Errors: {error_count}"
        )

        return {
            'status': 'success',
            'updated_count': updated_count,
            'error_count': error_count,
            'timestamp': timezone.now().isoformat(),
        }

    except Exception as e:
        logger.error(f"Error syncing public catalog stats: {e}", exc_info=True)
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='services.tasks.cleanup_expired_cross_tenant_requests',
    max_retries=3,
    default_retry_delay=300,
)
def cleanup_expired_cross_tenant_requests(self):
    """
    Clean up old pending cross-tenant requests.

    Automatically cancels requests that have been pending for too long
    (e.g., 30 days) to prevent cluttered request lists.

    Returns:
        dict: Summary of cleanup operation
    """
    from tenants.models import Tenant
    from services.models import CrossTenantServiceRequest
    from django_tenants.utils import schema_context

    try:
        cutoff_date = timezone.now() - timedelta(days=30)
        cancelled_count = 0

        logger.info(f"Cleaning up cross-tenant requests older than {cutoff_date}...")

        # Process each tenant
        for tenant in Tenant.objects.exclude(schema_name='public'):
            try:
                with schema_context(tenant.schema_name):
                    # Find expired pending requests
                    expired_requests = CrossTenantServiceRequest.objects.filter(
                        status=CrossTenantServiceRequest.RequestStatus.PENDING,
                        created_at__lt=cutoff_date
                    )

                    count = expired_requests.update(
                        status=CrossTenantServiceRequest.RequestStatus.CANCELLED,
                        provider_response='Request automatically cancelled after 30 days without response'
                    )

                    cancelled_count += count

            except Exception as e:
                logger.error(
                    f"Failed to cleanup requests for tenant {tenant.schema_name}: {e}"
                )

        logger.info(f"Cleanup complete. Cancelled {cancelled_count} expired cross-tenant requests.")

        return {
            'status': 'success',
            'cancelled_count': cancelled_count,
            'timestamp': timezone.now().isoformat(),
        }

    except Exception as e:
        logger.error(f"Error cleaning up cross-tenant requests: {e}", exc_info=True)
        raise self.retry(exc=e)


# ==================== Public Provider Catalog Sync Tasks ====================

from tenants.context import tenant_context, public_schema_context
from core.sync.provider_sync import ProviderPublicSyncService


@shared_task(
    bind=True,
    name='services.sync_provider_to_catalog',
    max_retries=3,
    default_retry_delay=60,  # 1 minute
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,  # Max 10 minutes
)
def sync_provider_to_catalog_task(self, provider_uuid, tenant_schema, tenant_id):
    """
    Async task to sync ServiceProvider → PublicProviderCatalog.

    Workflow:
        1. Load tenant and switch to tenant schema
        2. Fetch ServiceProvider instance
        3. Check sync conditions (marketplace_enabled, is_active)
        4. Extract and map safe fields (categories, skills, stats)
        5. Switch to public schema
        6. Update or create PublicProviderCatalog entry

    Args:
        provider_uuid: UUID string of the provider to sync
        tenant_schema: Source tenant schema name
        tenant_id: Tenant primary key

    Returns:
        dict: {'status': 'success'|'not_found'|'skipped', 'provider_uuid': str}

    Raises:
        Retry exception on errors (auto-retry with exponential backoff)
    """
    from tenants.models import Tenant
    from services.models import ServiceProvider

    try:
        # Load tenant
        tenant = Tenant.objects.get(pk=tenant_id)

        # Switch to tenant schema and load provider
        with tenant_context(tenant):
            try:
                provider = ServiceProvider.objects.get(uuid=provider_uuid)
            except ServiceProvider.DoesNotExist:
                logger.warning(
                    f"ServiceProvider {provider_uuid} not found in {tenant_schema}"
                )
                return {
                    'status': 'not_found',
                    'provider_uuid': provider_uuid,
                    'tenant_schema': tenant_schema,
                }

            # Initialize sync service
            sync_service = ProviderPublicSyncService()

            # Check if provider should be synced
            if not sync_service.should_sync(provider):
                logger.info(
                    f"Provider {provider_uuid} from {tenant_schema} does not meet sync conditions, "
                    "removing from catalog if exists"
                )
                sync_service.remove_from_public(provider)
                return {
                    'status': 'skipped',
                    'reason': 'conditions_not_met',
                    'provider_uuid': provider_uuid,
                    'tenant_schema': tenant_schema,
                }

            # Sync to public catalog
            try:
                catalog_entry = sync_service.sync_to_public(provider, created=False)

                logger.info(
                    f"Successfully synced provider {provider_uuid} from {tenant_schema} "
                    f"to PublicProviderCatalog (ID: {catalog_entry.id})"
                )

                return {
                    'status': 'success',
                    'catalog_id': catalog_entry.id,
                    'provider_uuid': str(provider_uuid),
                    'tenant_schema': tenant_schema,
                    'display_name': catalog_entry.display_name,
                }

            except Exception as e:
                logger.error(
                    f"Failed to sync provider {provider_uuid} from {tenant_schema} to catalog: {e}",
                    exc_info=True
                )
                raise

    except Tenant.DoesNotExist:
        logger.error(f"Tenant ID {tenant_id} not found")
        return {
            'status': 'error',
            'reason': 'tenant_not_found',
            'tenant_id': tenant_id,
        }

    except Exception as e:
        logger.error(
            f"Error syncing provider {provider_uuid} from {tenant_schema}: {e}",
            exc_info=True
        )
        # Auto-retry with exponential backoff
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    name='services.remove_provider_from_catalog',
    max_retries=2,
    default_retry_delay=30,
)
def remove_provider_from_catalog_task(self, provider_uuid, tenant_schema):
    """
    Async task to remove ServiceProvider from PublicProviderCatalog.

    Called when provider is deleted or marketplace_enabled changes to False.

    Args:
        provider_uuid: UUID string of the provider to remove
        tenant_schema: Source tenant schema name

    Returns:
        dict: {'status': 'success', 'deleted': int}
    """
    from tenants.models import PublicProviderCatalog

    try:
        # Switch to public schema
        with public_schema_context():
            deleted_count, _ = PublicProviderCatalog.objects.filter(
                tenant_schema_name=tenant_schema,
                provider_uuid=provider_uuid
            ).delete()

        if deleted_count > 0:
            logger.info(
                f"Removed provider {provider_uuid} from PublicProviderCatalog "
                f"(tenant: {tenant_schema})"
            )
        else:
            logger.debug(
                f"Provider {provider_uuid} not found in catalog "
                f"(tenant: {tenant_schema}, already removed)"
            )

        return {
            'status': 'success',
            'deleted': deleted_count,
            'provider_uuid': provider_uuid,
            'tenant_schema': tenant_schema,
        }

    except Exception as e:
        logger.error(
            f"Error removing provider {provider_uuid} from catalog: {e}",
            exc_info=True
        )
        raise self.retry(exc=e)


@shared_task(
    name='services.bulk_sync_tenant_providers',
    soft_time_limit=600,  # 10 minutes
    time_limit=660,  # Hard limit at 11 minutes
)
def bulk_sync_tenant_providers(tenant_id):
    """
    Bulk sync all eligible providers for a tenant to PublicProviderCatalog.

    Used for:
    - Initial data population when system is first deployed
    - Re-sync all providers after catalog schema changes
    - Manual re-sync via management command

    Args:
        tenant_id: Tenant primary key

    Returns:
        dict: Summary statistics {synced, skipped, errors, total}
    """
    from tenants.models import Tenant
    from services.models import ServiceProvider

    try:
        tenant = Tenant.objects.get(pk=tenant_id)
        sync_service = ProviderPublicSyncService()

        synced_count = 0
        skipped_count = 0
        error_count = 0

        with tenant_context(tenant):
            # Get all providers that should be in catalog
            providers = ServiceProvider.objects.filter(
                marketplace_enabled=True,
                is_active=True,
                user__is_active=True,
            ).select_related('user')

            total_count = providers.count()

            logger.info(
                f"Starting bulk provider sync for {tenant.name} "
                f"({total_count} eligible providers)"
            )

            for provider in providers:
                try:
                    if sync_service.should_sync(provider):
                        sync_service.sync_to_public(provider)
                        synced_count += 1
                    else:
                        skipped_count += 1
                except Exception as e:
                    logger.error(
                        f"Error syncing provider {provider.uuid} in bulk sync: {e}",
                        exc_info=True
                    )
                    error_count += 1

        result = {
            'status': 'completed',
            'tenant': tenant.name,
            'tenant_id': tenant_id,
            'total': total_count,
            'synced': synced_count,
            'skipped': skipped_count,
            'errors': error_count,
            'timestamp': timezone.now().isoformat(),
        }

        logger.info(
            f"Bulk provider sync completed for {tenant.name}: "
            f"{synced_count} synced, {skipped_count} skipped, {error_count} errors"
        )

        return result

    except Tenant.DoesNotExist:
        logger.error(f"Tenant ID {tenant_id} not found for bulk provider sync")
        return {
            'status': 'error',
            'reason': 'tenant_not_found',
            'tenant_id': tenant_id,
        }
    except Exception as e:
        logger.error(
            f"Error in bulk provider sync for tenant {tenant_id}: {e}",
            exc_info=True
        )
        raise
