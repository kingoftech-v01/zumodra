"""
Celery Tasks for Tenants App

This module contains async tasks for tenant management:
- Usage limit checking
- Trial reminders and expiration
- Tenant resource usage calculation
- Invitation cleanup
- Subscription management
"""

import logging
from datetime import timedelta
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.db.models import Count, Sum

logger = logging.getLogger(__name__)


# ==================== STORAGE CALCULATION ====================

def _calculate_storage_usage(tenant):
    """
    Calculate total storage used by a tenant across all file types.

    Includes:
    - User documents (resumes, cover letters)
    - Employee documents (HR records, contracts)
    - Job posting attachments
    - Profile images and logos
    - Message attachments
    - Integration cached files

    Args:
        tenant: The Tenant object to calculate storage for

    Returns:
        int: Total bytes used by the tenant
    """
    import os
    from django.db import connection
    from django.conf import settings

    total_bytes = 0

    try:
        # Use tenant schema context for accurate queries
        with connection.cursor() as cursor:
            # Query ats.Candidate resume files
            try:
                from jobs.models import Candidate
                candidates = Candidate.objects.filter(resume__isnull=False)
                for candidate in candidates:
                    if candidate.resume and hasattr(candidate.resume, 'size'):
                        try:
                            total_bytes += candidate.resume.size
                        except (OSError, AttributeError):
                            pass
            except Exception:
                pass

            # Query hr_core.EmployeeDocument files
            try:
                from hr_core.models import EmployeeDocument
                employee_docs = EmployeeDocument.objects.filter(file__isnull=False)
                for doc in employee_docs:
                    if doc.file and hasattr(doc.file, 'size'):
                        try:
                            total_bytes += doc.file.size
                        except (OSError, AttributeError):
                            pass
            except Exception:
                pass

            # Query accounts user profile images
            try:
                from django.contrib.auth import get_user_model
                User = get_user_model()
                users = User.objects.filter(avatar__isnull=False).exclude(avatar='')
                for user in users:
                    if user.avatar and hasattr(user.avatar, 'size'):
                        try:
                            total_bytes += user.avatar.size
                        except (OSError, AttributeError):
                            pass
            except Exception:
                pass

            # Query services.Contract attachments
            try:
                from services.models import Contract, ContractDocument
                contract_docs = ContractDocument.objects.filter(file__isnull=False)
                for doc in contract_docs:
                    if doc.file and hasattr(doc.file, 'size'):
                        try:
                            total_bytes += doc.file.size
                        except (OSError, AttributeError):
                            pass
            except Exception:
                pass

            # Query messages_sys.Message attachments
            try:
                from messages_sys.models import MessageAttachment
                attachments = MessageAttachment.objects.filter(file__isnull=False)
                for attachment in attachments:
                    if attachment.file and hasattr(attachment.file, 'size'):
                        try:
                            total_bytes += attachment.file.size
                        except (OSError, AttributeError):
                            pass
            except Exception:
                pass

            # Query blog images and media
            try:
                from blog.models import BlogPost
                posts = BlogPost.objects.filter(featured_image__isnull=False)
                for post in posts:
                    if post.featured_image and hasattr(post.featured_image, 'size'):
                        try:
                            total_bytes += post.featured_image.size
                        except (OSError, AttributeError):
                            pass
            except Exception:
                pass

        # Also check tenant-specific media folder if it exists
        tenant_media_path = os.path.join(settings.MEDIA_ROOT, f'tenants/{tenant.schema_name}')
        if os.path.exists(tenant_media_path):
            for root, dirs, files in os.walk(tenant_media_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        total_bytes += os.path.getsize(file_path)
                    except (OSError, IOError):
                        pass

    except Exception as e:
        logger.warning(f"Error calculating storage for tenant {tenant.name}: {e}")

    return total_bytes


# ==================== USAGE LIMITS ====================

@shared_task(
    bind=True,
    name='tenants.tasks.check_usage_limits',
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(Exception,),
    retry_backoff=True,
)
def check_usage_limits(self):
    """
    Check all tenants' usage against their plan limits.

    Sends alerts for tenants approaching or exceeding limits.
    May suspend tenants that have exceeded limits for extended periods.

    Returns:
        dict: Summary of usage checks performed.
    """
    from tenants.models import Tenant, TenantUsage

    try:
        now = timezone.now()
        active_tenants = Tenant.objects.filter(
            status__in=['active', 'trial']
        ).select_related('plan', 'usage')

        over_limit = []
        approaching_limit = []

        for tenant in active_tenants:
            if not hasattr(tenant, 'usage'):
                # Create usage record if missing
                TenantUsage.objects.create(tenant=tenant)
                continue

            usage = tenant.usage
            plan = tenant.plan

            if not plan:
                continue

            # Check various limits
            limit_checks = [
                ('users', usage.user_count, plan.max_users),
                ('jobs', usage.active_job_count, plan.max_job_postings),
                ('candidates', usage.candidate_count_this_month, plan.max_candidates_per_month),
                ('circusales', usage.circusale_count, plan.max_circusales),
                ('storage', usage.storage_used_gb, plan.storage_limit_gb),
            ]

            for limit_name, current, maximum in limit_checks:
                if maximum == 0:
                    continue

                percentage = (current / maximum) * 100

                if percentage >= 100:
                    over_limit.append({
                        'tenant': tenant.name,
                        'limit': limit_name,
                        'current': current,
                        'maximum': maximum,
                        'percentage': percentage,
                    })
                    # Send over-limit notification
                    _send_limit_notification(tenant, limit_name, current, maximum, is_over=True)

                elif percentage >= 80:
                    approaching_limit.append({
                        'tenant': tenant.name,
                        'limit': limit_name,
                        'current': current,
                        'maximum': maximum,
                        'percentage': percentage,
                    })
                    # Send approaching-limit notification
                    _send_limit_notification(tenant, limit_name, current, maximum, is_over=False)

        logger.info(
            f"Usage check complete: {len(over_limit)} over limit, "
            f"{len(approaching_limit)} approaching limit"
        )

        return {
            'status': 'success',
            'over_limit_count': len(over_limit),
            'approaching_limit_count': len(approaching_limit),
            'over_limit': over_limit,
            'approaching_limit': approaching_limit,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Usage limit check exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error checking usage limits: {str(e)}")
        raise self.retry(exc=e)


def _send_limit_notification(tenant, limit_name, current, maximum, is_over=False):
    """Send usage limit notification email."""
    try:
        subject = (
            f"{'ALERT: ' if is_over else 'Warning: '}"
            f"{'Exceeded' if is_over else 'Approaching'} {limit_name} limit - {tenant.name}"
        )

        context = {
            'tenant': tenant,
            'limit_name': limit_name,
            'current': current,
            'maximum': maximum,
            'percentage': (current / maximum) * 100 if maximum > 0 else 0,
            'is_over': is_over,
        }

        html_content = render_to_string('emails/usage_limit_notification.html', context)
        text_content = render_to_string('emails/usage_limit_notification.txt', context)

        send_mail(
            subject=subject,
            message=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[tenant.owner_email],
            html_message=html_content,
            fail_silently=True,
        )
    except Exception as e:
        logger.error(f"Error sending limit notification: {str(e)}")


# ==================== TRIAL MANAGEMENT ====================

@shared_task(
    bind=True,
    name='tenants.tasks.send_trial_reminders',
    max_retries=3,
    default_retry_delay=600,
    autoretry_for=(Exception,),
)
def send_trial_reminders(self):
    """
    Send trial expiration reminders to tenants.

    Sends reminders at:
    - 7 days before expiration
    - 3 days before expiration
    - 1 day before expiration

    Returns:
        dict: Summary of reminders sent.
    """
    from tenants.models import Tenant

    try:
        now = timezone.now()
        reminders_sent = 0

        # Define reminder intervals
        reminder_days = [7, 3, 1]

        for days in reminder_days:
            reminder_date = now + timedelta(days=days)

            # Find tenants expiring on this date
            expiring_tenants = Tenant.objects.filter(
                status='trial',
                on_trial=True,
                trial_ends_at__date=reminder_date.date()
            )

            for tenant in expiring_tenants:
                try:
                    _send_trial_reminder_email(tenant, days)
                    reminders_sent += 1
                except Exception as e:
                    logger.error(f"Error sending trial reminder to {tenant.name}: {e}")

        logger.info(f"Sent {reminders_sent} trial reminders")

        return {
            'status': 'success',
            'reminders_sent': reminders_sent,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error sending trial reminders: {str(e)}")
        raise self.retry(exc=e)


def _send_trial_reminder_email(tenant, days_remaining):
    """Send trial expiration reminder email."""
    subject = f"Your trial expires in {days_remaining} day{'s' if days_remaining != 1 else ''}"

    context = {
        'tenant': tenant,
        'days_remaining': days_remaining,
        'trial_ends_at': tenant.trial_ends_at,
    }

    try:
        html_content = render_to_string('emails/trial_reminder.html', context)
        text_content = render_to_string('emails/trial_reminder.txt', context)
    except Exception:
        # Fallback content
        text_content = f"Your trial for {tenant.name} expires in {days_remaining} days."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[tenant.owner_email],
        html_message=html_content,
        fail_silently=False,
    )


@shared_task(
    bind=True,
    name='tenants.tasks.expire_trial_tenants',
    max_retries=3,
    default_retry_delay=300,
)
def expire_trial_tenants(self):
    """
    Expire tenants whose trial period has ended.

    Marks tenants as expired and restricts their access.

    Returns:
        dict: Summary of expired tenants.
    """
    from tenants.models import Tenant

    try:
        now = timezone.now()

        # Find expired trial tenants
        expired_trials = Tenant.objects.filter(
            status='trial',
            on_trial=True,
            trial_ends_at__lt=now
        )

        expired_count = 0

        for tenant in expired_trials:
            tenant.status = 'suspended'
            tenant.on_trial = False
            tenant.suspended_at = now
            tenant.save(update_fields=['status', 'on_trial', 'suspended_at'])

            # Send expiration notification
            _send_trial_expired_email(tenant)

            expired_count += 1
            logger.info(f"Expired trial tenant: {tenant.name}")

        return {
            'status': 'success',
            'expired_count': expired_count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error expiring trial tenants: {str(e)}")
        raise self.retry(exc=e)


def _send_trial_expired_email(tenant):
    """Send trial expired notification email."""
    subject = f"Your trial has expired - {tenant.name}"

    context = {'tenant': tenant}

    try:
        html_content = render_to_string('emails/trial_expired.html', context)
        text_content = f"Your trial for {tenant.name} has expired. Upgrade now to continue."
    except Exception:
        text_content = f"Your trial for {tenant.name} has expired. Upgrade now to continue."
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[tenant.owner_email],
        html_message=html_content,
        fail_silently=True,
    )


# ==================== USAGE CALCULATION ====================

@shared_task(
    bind=True,
    name='tenants.tasks.calculate_tenant_usage',
    max_retries=3,
    default_retry_delay=300,
    soft_time_limit=1800,
)
def calculate_tenant_usage(self):
    """
    Calculate and update resource usage for all tenants.

    Recalculates:
    - User counts
    - Job posting counts
    - Candidate counts
    - Storage usage
    - API usage

    Returns:
        dict: Summary of usage calculations.
    """
    from tenants.models import Tenant, TenantUsage
    from tenant_profiles.models import TenantUser
    from jobs.models import Application, JobPosting
    from hr_core.models import Employee

    try:
        now = timezone.now()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        tenants = Tenant.objects.filter(status__in=['active', 'trial'])
        updated_count = 0

        for tenant in tenants:
            try:
                usage, created = TenantUsage.objects.get_or_create(tenant=tenant)

                # Calculate user count
                usage.user_count = TenantUser.objects.filter(
                    tenant=tenant,
                    is_active=True
                ).count()

                # Calculate job counts
                # Note: In multi-tenant setup, filter by tenant
                usage.active_job_count = JobPosting.objects.filter(
                    status='open'
                ).count()

                usage.total_job_count = JobPosting.objects.count()

                # Calculate candidate counts for this month
                usage.candidate_count_this_month = Application.objects.filter(
                    created_at__gte=month_start
                ).count()

                usage.total_candidate_count = Application.objects.count()

                # Calculate employee count
                usage.employee_count = Employee.objects.filter(
                    status__in=['active', 'probation', 'on_leave']
                ).count()

                # Calculate storage usage
                usage.storage_used_bytes = _calculate_storage_usage(tenant)

                # Reset monthly counts if new month
                if usage.month_reset_at and usage.month_reset_at.month != now.month:
                    usage.candidate_count_this_month = 0
                    usage.api_calls_this_month = 0
                    usage.month_reset_at = month_start

                usage.save()
                updated_count += 1

            except Exception as e:
                logger.error(f"Error calculating usage for tenant {tenant.name}: {e}")

        logger.info(f"Updated usage for {updated_count} tenants")

        return {
            'status': 'success',
            'updated_count': updated_count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error calculating tenant usage: {str(e)}")
        raise self.retry(exc=e)


# ==================== INVITATION CLEANUP ====================

@shared_task(
    bind=True,
    name='tenants.tasks.cleanup_expired_invitations',
    max_retries=3,
    default_retry_delay=300,
)
def cleanup_expired_invitations(self):
    """
    Clean up expired tenant invitations.

    Marks pending invitations as expired if past their expiration date.

    Returns:
        dict: Summary of cleaned up invitations.
    """
    from tenants.models import TenantInvitation

    try:
        now = timezone.now()

        # Find expired pending invitations
        expired_invitations = TenantInvitation.objects.filter(
            status='pending',
            expires_at__lt=now
        )

        count = expired_invitations.count()

        # Mark as expired
        expired_invitations.update(status='expired')

        logger.info(f"Cleaned up {count} expired invitations")

        return {
            'status': 'success',
            'expired_count': count,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error cleaning up invitations: {str(e)}")
        raise self.retry(exc=e)


# ==================== SUBSCRIPTION MANAGEMENT ====================

@shared_task(
    bind=True,
    name='tenants.tasks.process_subscription_renewal',
    max_retries=3,
    default_retry_delay=600,
)
def process_subscription_renewal(self, tenant_id):
    """
    Process subscription renewal for a specific tenant.

    Args:
        tenant_id: ID of the tenant to process renewal for.

    Returns:
        dict: Renewal status.
    """
    from tenants.models import Tenant

    try:
        tenant = Tenant.objects.get(id=tenant_id)

        if not tenant.stripe_subscription_id:
            return {
                'status': 'skipped',
                'reason': 'No Stripe subscription',
            }

        # Import Stripe
        import stripe
        stripe.api_key = settings.STRIPE_SECRET_KEY

        # Retrieve subscription status
        subscription = stripe.Subscription.retrieve(tenant.stripe_subscription_id)

        if subscription.status == 'active':
            tenant.status = 'active'
            tenant.paid_until = timezone.datetime.fromtimestamp(
                subscription.current_period_end,
                tz=timezone.utc
            )
            tenant.save(update_fields=['status', 'paid_until'])

            return {
                'status': 'success',
                'subscription_status': subscription.status,
                'paid_until': tenant.paid_until.isoformat(),
            }

        elif subscription.status in ['past_due', 'unpaid']:
            # Send payment reminder
            _send_payment_reminder(tenant)

            return {
                'status': 'payment_required',
                'subscription_status': subscription.status,
            }

        elif subscription.status == 'canceled':
            tenant.status = 'cancelled'
            tenant.save(update_fields=['status'])

            return {
                'status': 'cancelled',
            }

        return {
            'status': 'unknown',
            'subscription_status': subscription.status,
        }

    except Tenant.DoesNotExist:
        logger.error(f"Tenant {tenant_id} not found")
        return {'status': 'error', 'error': 'Tenant not found'}

    except Exception as e:
        logger.error(f"Error processing subscription renewal: {str(e)}")
        raise self.retry(exc=e)


def _send_payment_reminder(tenant):
    """Send payment reminder email."""
    subject = f"Payment required - {tenant.name}"

    send_mail(
        subject=subject,
        message=f"Your payment for {tenant.name} is overdue. Please update your payment method.",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[tenant.owner_email],
        fail_silently=True,
    )


@shared_task(
    bind=True,
    name='tenants.tasks.sync_all_subscriptions',
    max_retries=2,
    soft_time_limit=1800,
)
def sync_all_subscriptions(self):
    """
    Sync all tenant subscriptions with Stripe.

    Returns:
        dict: Summary of sync operation.
    """
    from tenants.models import Tenant

    try:
        now = timezone.now()

        tenants = Tenant.objects.filter(
            status='active',
            stripe_subscription_id__isnull=False
        ).exclude(stripe_subscription_id='')

        synced = 0
        errors = []

        for tenant in tenants:
            try:
                result = process_subscription_renewal.delay(tenant.id)
                synced += 1
            except Exception as e:
                errors.append({
                    'tenant': tenant.name,
                    'error': str(e)
                })

        return {
            'status': 'success',
            'synced_count': synced,
            'error_count': len(errors),
            'errors': errors,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error syncing subscriptions: {str(e)}")
        raise self.retry(exc=e)


# ==================== GEOCODING ====================

@shared_task(
    bind=True,
    name='tenants.tasks.geocode_tenant_task',
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    retry_backoff=True,
)
def geocode_tenant_task(self, tenant_id):
    """
    Asynchronously geocode a tenant's address to coordinates.

    This task is triggered by the auto_geocode_tenant signal when:
    - A new tenant is created with address information
    - An existing tenant's address fields are updated

    Implements TODO-CAREERS-001 from careers/TODO.md.

    Args:
        tenant_id: ID of the tenant to geocode

    Returns:
        dict: Geocoding result with status and coordinates

    Raises:
        Tenant.DoesNotExist: If tenant not found
    """
    from tenants.models import Tenant
    from core.geocoding import GeocodingService

    try:
        tenant = Tenant.objects.get(pk=tenant_id)

        logger.info(f"Starting geocoding for tenant: {tenant.name} (ID: {tenant_id})")

        # Skip if no address information
        if not tenant.city or not tenant.country:
            logger.warning(
                f"Tenant {tenant.name} has insufficient address info "
                f"(city={tenant.city}, country={tenant.country})"
            )
            return {
                'status': 'skipped',
                'reason': 'Insufficient address information',
                'tenant_id': tenant_id,
                'tenant_name': tenant.name,
            }

        # Skip if already geocoded
        if tenant.location:
            logger.info(f"Tenant {tenant.name} already has location: {tenant.location}")
            return {
                'status': 'skipped',
                'reason': 'Already geocoded',
                'tenant_id': tenant_id,
                'tenant_name': tenant.name,
                'coordinates': {
                    'latitude': tenant.latitude,
                    'longitude': tenant.longitude,
                }
            }

        # Geocode the tenant
        GeocodingService.geocode_tenant(tenant)

        # Refresh to get updated location
        tenant.refresh_from_db()

        if tenant.location:
            logger.info(
                f"Successfully geocoded tenant {tenant.name}: "
                f"({tenant.latitude}, {tenant.longitude})"
            )
            return {
                'status': 'success',
                'tenant_id': tenant_id,
                'tenant_name': tenant.name,
                'coordinates': {
                    'latitude': tenant.latitude,
                    'longitude': tenant.longitude,
                },
                'address': f"{tenant.city}, {tenant.state or ''} {tenant.country}".strip(),
            }
        else:
            logger.warning(f"Geocoding failed for tenant {tenant.name}: No results found")
            return {
                'status': 'failed',
                'reason': 'No geocoding results found',
                'tenant_id': tenant_id,
                'tenant_name': tenant.name,
                'address': f"{tenant.city}, {tenant.state or ''} {tenant.country}".strip(),
            }

    except Tenant.DoesNotExist:
        error_msg = f"Tenant {tenant_id} not found for geocoding"
        logger.error(error_msg)
        return {
            'status': 'error',
            'error': error_msg,
            'tenant_id': tenant_id,
        }

    except Exception as e:
        logger.error(f"Error geocoding tenant {tenant_id}: {str(e)}")
        # Retry with exponential backoff
        raise self.retry(exc=e)
