"""
Maintenance Tasks for Zumodra

This module provides Celery tasks for system maintenance:
- cleanup_old_sessions_task: Remove expired sessions
- backup_rotation_task: Manage backup files
- ssl_renewal_check_task: Check SSL certificate expiration
- failed_payment_retry_task: Retry failed payments

All tasks are designed for low-impact background execution
with proper logging and error handling.
"""

import logging
import os
import ssl
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache

logger = logging.getLogger(__name__)


# =============================================================================
# SESSION CLEANUP TASK
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.maintenance_tasks.cleanup_old_sessions_task',
    max_retries=2,
    default_retry_delay=300,
    rate_limit='1/h',
    queue='low_priority',
    soft_time_limit=300,
    time_limit=600,
)
def cleanup_old_sessions_task(
    self,
    days: int = 30,
    batch_size: int = 1000,
    tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Clean up old and expired sessions from the database.

    Args:
        days: Clean up sessions older than this many days
        batch_size: Number of sessions to delete per batch
        tenant_id: Tenant ID for multi-tenant context

    Returns:
        dict: Cleanup results with counts
    """
    try:
        logger.info(f"Starting session cleanup (older than {days} days)")

        from django.contrib.sessions.models import Session
        from django.db import connection

        now = timezone.now()
        cutoff_date = now - timedelta(days=days)

        # Count sessions to delete
        expired_count = Session.objects.filter(
            expire_date__lt=now
        ).count()

        old_count = Session.objects.filter(
            expire_date__lt=cutoff_date
        ).count()

        total_deleted = 0

        # Delete expired sessions in batches
        while True:
            # Get batch of expired session keys
            session_keys = list(
                Session.objects.filter(expire_date__lt=now)
                .values_list('session_key', flat=True)[:batch_size]
            )

            if not session_keys:
                break

            # Delete batch
            deleted, _ = Session.objects.filter(
                session_key__in=session_keys
            ).delete()

            total_deleted += deleted
            logger.debug(f"Deleted batch of {deleted} sessions")

            # Update progress
            self.update_state(
                state='PROGRESS',
                meta={
                    'status': 'cleaning',
                    'deleted': total_deleted,
                    'remaining': max(0, expired_count - total_deleted),
                }
            )

        # Clean up Django cache sessions if using cache backend
        if 'cache' in settings.SESSION_ENGINE:
            _cleanup_cache_sessions()

        logger.info(f"Session cleanup completed: {total_deleted} sessions deleted")

        return {
            'status': 'success',
            'expired_sessions': expired_count,
            'old_sessions': old_count,
            'deleted_sessions': total_deleted,
            'cutoff_date': cutoff_date.isoformat(),
            'task_id': self.request.id,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Session cleanup exceeded time limit")
        return {
            'status': 'timeout',
            'deleted_sessions': total_deleted,
            'task_id': self.request.id,
        }

    except Exception as e:
        logger.error(f"Session cleanup failed: {e}")
        raise self.retry(exc=e)


def _cleanup_cache_sessions():
    """
    Clean up session keys from cache backend.
    """
    try:
        # This works with Redis cache backend
        from django_redis import get_redis_connection

        redis_conn = get_redis_connection("default")
        pattern = f"{settings.CACHES['default'].get('KEY_PREFIX', '')}:session:*"

        cursor = 0
        deleted = 0

        while True:
            cursor, keys = redis_conn.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                redis_conn.delete(*keys)
                deleted += len(keys)

            if cursor == 0:
                break

        logger.info(f"Cleaned up {deleted} cache session keys")

    except Exception as e:
        logger.debug(f"Cache session cleanup skipped: {e}")


# =============================================================================
# BACKUP ROTATION TASK
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.maintenance_tasks.backup_rotation_task',
    max_retries=2,
    default_retry_delay=300,
    rate_limit='1/h',
    queue='low_priority',
    soft_time_limit=600,
    time_limit=900,
)
def backup_rotation_task(
    self,
    backup_dir: Optional[str] = None,
    retention_days: int = 30,
    max_backups: int = 100,
    min_backups: int = 7,
    tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Rotate old backup files based on retention policy.

    Args:
        backup_dir: Directory containing backups (defaults to settings.BACKUP_DIR)
        retention_days: Keep backups for this many days
        max_backups: Maximum number of backups to keep
        min_backups: Minimum number of backups to always keep
        tenant_id: Tenant ID for multi-tenant context

    Returns:
        dict: Rotation results with deleted files
    """
    try:
        logger.info(f"Starting backup rotation (retention: {retention_days} days)")

        # Determine backup directory
        if backup_dir:
            backup_path = Path(backup_dir)
        else:
            backup_path = Path(settings.BASE_DIR) / 'backups'

        if not backup_path.exists():
            logger.info(f"Backup directory does not exist: {backup_path}")
            return {
                'status': 'skipped',
                'reason': 'Backup directory not found',
                'task_id': self.request.id,
            }

        now = datetime.now()
        cutoff_date = now - timedelta(days=retention_days)

        # Get all backup files sorted by modification time (newest first)
        backup_files = sorted(
            backup_path.glob('backup_*.*'),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )

        total_backups = len(backup_files)
        deleted_files = []
        kept_files = []
        total_size_freed = 0

        # Always keep minimum number of backups
        protected_files = backup_files[:min_backups]

        for backup_file in backup_files:
            # Skip protected files
            if backup_file in protected_files:
                kept_files.append(str(backup_file.name))
                continue

            file_mtime = datetime.fromtimestamp(backup_file.stat().st_mtime)

            # Delete if older than retention period or exceeds max count
            should_delete = (
                file_mtime < cutoff_date or
                len(kept_files) >= max_backups
            )

            if should_delete:
                file_size = backup_file.stat().st_size
                backup_file.unlink()
                deleted_files.append(str(backup_file.name))
                total_size_freed += file_size
                logger.debug(f"Deleted old backup: {backup_file.name}")
            else:
                kept_files.append(str(backup_file.name))

        logger.info(
            f"Backup rotation completed: {len(deleted_files)} deleted, "
            f"{len(kept_files)} kept, {total_size_freed / 1024 / 1024:.2f} MB freed"
        )

        return {
            'status': 'success',
            'total_backups': total_backups,
            'deleted_count': len(deleted_files),
            'kept_count': len(kept_files),
            'deleted_files': deleted_files[:50],  # Limit response size
            'size_freed_bytes': total_size_freed,
            'size_freed_mb': round(total_size_freed / 1024 / 1024, 2),
            'retention_days': retention_days,
            'task_id': self.request.id,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Backup rotation exceeded time limit")
        raise

    except Exception as e:
        logger.error(f"Backup rotation failed: {e}")
        raise self.retry(exc=e)


# =============================================================================
# SSL RENEWAL CHECK TASK
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.maintenance_tasks.ssl_renewal_check_task',
    max_retries=2,
    default_retry_delay=300,
    rate_limit='4/d',
    queue='low_priority',
    soft_time_limit=120,
    time_limit=180,
)
def ssl_renewal_check_task(
    self,
    domains: Optional[List[str]] = None,
    warning_days: int = 30,
    critical_days: int = 7,
    notify_admins: bool = True,
    tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Check SSL certificate expiration for domains.

    Args:
        domains: List of domains to check (defaults to ALLOWED_HOSTS)
        warning_days: Days before expiry to trigger warning
        critical_days: Days before expiry to trigger critical alert
        notify_admins: Whether to send email notifications
        tenant_id: Tenant ID for multi-tenant context

    Returns:
        dict: SSL check results for each domain
    """
    try:
        logger.info("Starting SSL certificate check")

        # Use ALLOWED_HOSTS if no domains specified
        if not domains:
            domains = [
                h for h in settings.ALLOWED_HOSTS
                if h not in ('*', 'localhost', '127.0.0.1', '.localhost')
            ]

        if not domains:
            return {
                'status': 'skipped',
                'reason': 'No domains to check',
                'task_id': self.request.id,
            }

        now = datetime.now()
        results = []
        warnings = []
        criticals = []

        for domain in domains:
            try:
                cert_info = _check_ssl_certificate(domain)

                if cert_info['status'] == 'valid':
                    expiry_date = cert_info['expires']
                    days_remaining = (expiry_date - now).days

                    cert_info['days_remaining'] = days_remaining

                    if days_remaining <= critical_days:
                        cert_info['alert_level'] = 'critical'
                        criticals.append(domain)
                    elif days_remaining <= warning_days:
                        cert_info['alert_level'] = 'warning'
                        warnings.append(domain)
                    else:
                        cert_info['alert_level'] = 'ok'

                results.append({
                    'domain': domain,
                    **cert_info
                })

            except Exception as e:
                results.append({
                    'domain': domain,
                    'status': 'error',
                    'error': str(e),
                })
                logger.warning(f"Failed to check SSL for {domain}: {e}")

        # Send notifications if needed
        if notify_admins and (warnings or criticals):
            _send_ssl_alert(warnings, criticals, results)

        # Store results in cache
        cache_key = 'ssl:check:results'
        cache.set(cache_key, {
            'results': results,
            'checked_at': now.isoformat(),
        }, timeout=86400)

        logger.info(
            f"SSL check completed: {len(results)} domains, "
            f"{len(warnings)} warnings, {len(criticals)} critical"
        )

        return {
            'status': 'success',
            'domains_checked': len(domains),
            'warnings': warnings,
            'criticals': criticals,
            'results': results,
            'task_id': self.request.id,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("SSL check exceeded time limit")
        raise

    except Exception as e:
        logger.error(f"SSL check failed: {e}")
        raise self.retry(exc=e)


def _check_ssl_certificate(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Check SSL certificate for a domain.
    """
    try:
        # Create SSL context
        context = ssl.create_default_context()

        # Connect and get certificate
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # Parse certificate info
        not_after = datetime.strptime(
            cert['notAfter'],
            '%b %d %H:%M:%S %Y %Z'
        )
        not_before = datetime.strptime(
            cert['notBefore'],
            '%b %d %H:%M:%S %Y %Z'
        )

        # Get issuer info
        issuer = dict(x[0] for x in cert['issuer'])

        return {
            'status': 'valid',
            'expires': not_after,
            'expires_str': not_after.isoformat(),
            'valid_from': not_before,
            'valid_from_str': not_before.isoformat(),
            'issuer': issuer.get('organizationName', 'Unknown'),
            'subject': dict(x[0] for x in cert['subject']).get('commonName', domain),
        }

    except ssl.SSLError as e:
        return {
            'status': 'ssl_error',
            'error': str(e),
        }
    except socket.timeout:
        return {
            'status': 'timeout',
            'error': 'Connection timed out',
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
        }


def _send_ssl_alert(
    warnings: List[str],
    criticals: List[str],
    results: List[Dict[str, Any]]
):
    """
    Send SSL expiration alert to admins.
    """
    try:
        from django.core.mail import send_mail
        from django.template.loader import render_to_string

        subject = f"SSL Certificate Alert - {len(warnings)} warnings, {len(criticals)} critical"

        context = {
            'warnings': warnings,
            'criticals': criticals,
            'results': results,
        }

        try:
            html_content = render_to_string('emails/ssl_alert.html', context)
            text_content = render_to_string('emails/ssl_alert.txt', context)
        except Exception:
            # Fallback to simple message
            text_content = (
                f"SSL Certificate Alert\n\n"
                f"Warnings: {', '.join(warnings)}\n"
                f"Critical: {', '.join(criticals)}"
            )
            html_content = text_content

        admin_emails = [admin[1] for admin in getattr(settings, 'ADMINS', [])]

        if admin_emails:
            send_mail(
                subject=subject,
                message=text_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=admin_emails,
                html_message=html_content,
                fail_silently=True,
            )

    except Exception as e:
        logger.error(f"Failed to send SSL alert: {e}")


# =============================================================================
# FAILED PAYMENT RETRY TASK
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.maintenance_tasks.failed_payment_retry_task',
    max_retries=2,
    default_retry_delay=600,
    rate_limit='20/m',
    queue='payments',
    soft_time_limit=600,
    time_limit=900,
)
def failed_payment_retry_task(
    self,
    max_retries: int = 3,
    retry_after_hours: int = 24,
    batch_size: int = 50,
    tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Retry failed payment transactions.

    Args:
        max_retries: Maximum number of retry attempts per payment
        retry_after_hours: Hours to wait before retrying
        batch_size: Number of payments to retry per batch
        tenant_id: Tenant ID for multi-tenant context

    Returns:
        dict: Retry results with success/failure counts
    """
    try:
        logger.info("Starting failed payment retry")

        from django.db import transaction

        now = timezone.now()
        retry_cutoff = now - timedelta(hours=retry_after_hours)

        # Get failed payments eligible for retry
        failed_payments = _get_failed_payments(
            max_retries=max_retries,
            retry_cutoff=retry_cutoff,
            batch_size=batch_size,
            tenant_id=tenant_id,
        )

        if not failed_payments:
            return {
                'status': 'success',
                'message': 'No failed payments to retry',
                'task_id': self.request.id,
                'timestamp': now.isoformat(),
            }

        successful = []
        still_failed = []
        errors = []

        for payment in failed_payments:
            try:
                result = _retry_payment(payment)

                if result['success']:
                    successful.append(payment['id'])
                    logger.info(f"Payment {payment['id']} retry successful")
                else:
                    still_failed.append(payment['id'])
                    logger.warning(
                        f"Payment {payment['id']} retry failed: {result.get('error')}"
                    )

            except Exception as e:
                errors.append({
                    'payment_id': payment['id'],
                    'error': str(e),
                })
                logger.error(f"Payment {payment['id']} retry error: {e}")

        # Send notifications for permanent failures
        permanently_failed = _get_permanently_failed_payments(still_failed, max_retries)
        if permanently_failed:
            _notify_permanent_payment_failures(permanently_failed)

        logger.info(
            f"Payment retry completed: {len(successful)} successful, "
            f"{len(still_failed)} failed, {len(errors)} errors"
        )

        return {
            'status': 'success',
            'total_processed': len(failed_payments),
            'successful': len(successful),
            'still_failed': len(still_failed),
            'errors': len(errors),
            'successful_ids': successful,
            'error_details': errors[:10],  # Limit response size
            'task_id': self.request.id,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Payment retry exceeded time limit")
        raise

    except Exception as e:
        logger.error(f"Payment retry task failed: {e}")
        raise self.retry(exc=e)


def _get_failed_payments(
    max_retries: int,
    retry_cutoff: datetime,
    batch_size: int,
    tenant_id: Optional[int],
) -> List[Dict[str, Any]]:
    """
    Get failed payments eligible for retry.
    """
    try:
        from finance.models import Payment

        queryset = Payment.objects.filter(
            status='failed',
            retry_count__lt=max_retries,
            updated_at__lt=retry_cutoff,
            is_retryable=True,
        ).order_by('updated_at')[:batch_size]

        return list(queryset.values('id', 'amount', 'customer_id', 'payment_method'))

    except Exception as e:
        logger.error(f"Failed to get failed payments: {e}")
        return []


def _retry_payment(payment: Dict[str, Any]) -> Dict[str, Any]:
    """
    Retry a single payment.
    """
    try:
        from finance.models import Payment
        import stripe

        stripe.api_key = settings.STRIPE_SECRET_KEY

        payment_obj = Payment.objects.get(id=payment['id'])

        # Create new payment intent or retry existing
        if payment_obj.stripe_payment_intent_id:
            # Confirm existing intent
            intent = stripe.PaymentIntent.confirm(
                payment_obj.stripe_payment_intent_id,
            )
        else:
            # Create new intent
            intent = stripe.PaymentIntent.create(
                amount=int(payment_obj.amount * 100),
                currency=payment_obj.currency or 'usd',
                customer=payment_obj.stripe_customer_id,
                payment_method=payment_obj.payment_method_id,
                confirm=True,
            )

        if intent.status == 'succeeded':
            payment_obj.status = 'completed'
            payment_obj.stripe_payment_intent_id = intent.id
            payment_obj.save()
            return {'success': True, 'intent_id': intent.id}
        else:
            payment_obj.retry_count += 1
            payment_obj.last_retry_at = timezone.now()
            payment_obj.save()
            return {'success': False, 'status': intent.status}

    except Exception as e:
        # Update retry count on error
        try:
            payment_obj = Payment.objects.get(id=payment['id'])
            payment_obj.retry_count += 1
            payment_obj.last_retry_at = timezone.now()
            payment_obj.last_error = str(e)
            payment_obj.save()
        except Exception:
            pass

        return {'success': False, 'error': str(e)}


def _get_permanently_failed_payments(
    payment_ids: List[int],
    max_retries: int
) -> List[Dict[str, Any]]:
    """
    Get payments that have exceeded retry limit.
    """
    try:
        from finance.models import Payment

        return list(
            Payment.objects.filter(
                id__in=payment_ids,
                retry_count__gte=max_retries,
            ).values('id', 'customer_id', 'amount', 'last_error')
        )

    except Exception:
        return []


def _notify_permanent_payment_failures(payments: List[Dict[str, Any]]):
    """
    Send notification about permanently failed payments.
    """
    try:
        from django.core.mail import send_mail

        subject = f"[Zumodra] {len(payments)} Payments Permanently Failed"

        message = "The following payments have failed after maximum retries:\n\n"
        for p in payments[:20]:
            message += f"- Payment #{p['id']}: ${p['amount']} - {p.get('last_error', 'Unknown error')}\n"

        admin_emails = [admin[1] for admin in getattr(settings, 'ADMINS', [])]

        if admin_emails:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=admin_emails,
                fail_silently=True,
            )

    except Exception as e:
        logger.error(f"Failed to send payment failure notification: {e}")


# =============================================================================
# ADDITIONAL MAINTENANCE TASKS
# =============================================================================

@shared_task(
    bind=True,
    name='core.tasks.maintenance_tasks.cleanup_temp_files_task',
    rate_limit='2/h',
    queue='low_priority',
)
def cleanup_temp_files_task(
    self,
    max_age_hours: int = 24,
    tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Clean up temporary files.
    """
    import tempfile
    import shutil

    try:
        temp_dir = Path(tempfile.gettempdir())
        zumodra_temp = temp_dir / 'zumodra'

        if not zumodra_temp.exists():
            return {'status': 'skipped', 'reason': 'No temp directory'}

        now = datetime.now()
        cutoff = now - timedelta(hours=max_age_hours)
        deleted = 0

        for item in zumodra_temp.iterdir():
            try:
                mtime = datetime.fromtimestamp(item.stat().st_mtime)
                if mtime < cutoff:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                    deleted += 1
            except Exception as e:
                logger.debug(f"Could not delete {item}: {e}")

        return {
            'status': 'success',
            'deleted': deleted,
            'task_id': self.request.id,
        }

    except Exception as e:
        logger.error(f"Temp file cleanup failed: {e}")
        return {'status': 'failed', 'error': str(e)}


@shared_task(
    bind=True,
    name='core.tasks.maintenance_tasks.database_vacuum_task',
    rate_limit='1/d',
    queue='low_priority',
    soft_time_limit=1800,
    time_limit=3600,
)
def database_vacuum_task(
    self,
    tables: Optional[List[str]] = None,
    analyze: bool = True,
) -> Dict[str, Any]:
    """
    Run VACUUM and ANALYZE on PostgreSQL tables.
    """
    from django.db import connection

    try:
        logger.info("Starting database vacuum")

        with connection.cursor() as cursor:
            # Get tables to vacuum
            if tables:
                target_tables = tables
            else:
                cursor.execute("""
                    SELECT tablename FROM pg_tables
                    WHERE schemaname = 'public'
                """)
                target_tables = [row[0] for row in cursor.fetchall()]

            results = []
            for table in target_tables[:50]:  # Limit tables
                try:
                    # Validate table name to prevent SQL injection
                    # Table names must be valid PostgreSQL identifiers
                    import re
                    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', table):
                        results.append({'table': table, 'status': 'error', 'error': 'Invalid table name'})
                        continue
                    # Use quote_ident for safe identifier quoting
                    cursor.execute("SELECT quote_ident(%s)", [table])
                    safe_table = cursor.fetchone()[0]
                    if analyze:
                        cursor.execute(f'VACUUM ANALYZE {safe_table}')
                    else:
                        cursor.execute(f'VACUUM {safe_table}')
                    results.append({'table': table, 'status': 'success'})
                except Exception as e:
                    results.append({'table': table, 'status': 'error', 'error': str(e)})

        logger.info(f"Database vacuum completed: {len(results)} tables")

        return {
            'status': 'success',
            'tables_processed': len(results),
            'results': results,
            'task_id': self.request.id,
        }

    except Exception as e:
        logger.error(f"Database vacuum failed: {e}")
        return {'status': 'failed', 'error': str(e)}
