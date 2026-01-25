"""
Shared Celery Tasks for Zumodra Project

This module contains shared/common tasks that are used across multiple apps:
- Session cleanup
- Audit log maintenance
- Daily digest emails
- Database backups
- Integration health checks
"""

import logging
from datetime import timedelta
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.sessions.models import Session

logger = logging.getLogger(__name__)


# ==================== SESSION MANAGEMENT ====================

@shared_task(
    bind=True,
    name='zumodra.tasks.cleanup_expired_sessions',
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
)
def cleanup_expired_sessions(self):
    """
    Remove expired sessions from the database.

    This task clears out sessions that have passed their expiration date,
    helping to keep the session table lean and improve database performance.

    Returns:
        dict: Summary of cleanup operation with count of deleted sessions.
    """
    try:
        # Get current time
        now = timezone.now()

        # Delete expired sessions
        expired_sessions = Session.objects.filter(expire_date__lt=now)
        count = expired_sessions.count()
        expired_sessions.delete()

        logger.info(f"Cleaned up {count} expired sessions")

        return {
            'status': 'success',
            'deleted_count': count,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Session cleanup task exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error cleaning up sessions: {str(e)}")
        raise self.retry(exc=e)


# ==================== AUDIT LOG MANAGEMENT ====================

@shared_task(
    bind=True,
    name='zumodra.tasks.cleanup_old_audit_logs',
    max_retries=3,
    default_retry_delay=300,
    autoretry_for=(Exception,),
    retry_backoff=True,
)
def cleanup_old_audit_logs(self, days=90):
    """
    Archive and remove old audit logs.

    Audit logs older than the specified number of days are archived
    (if archive storage is configured) and then deleted from the main table.

    Args:
        days: Number of days to keep audit logs. Defaults to 90.

    Returns:
        dict: Summary of cleanup operation.
    """
    from tenants.models import AuditLog
    from auditlog.models import LogEntry

    try:
        now = timezone.now()
        cutoff_date = now - timedelta(days=days)

        # Clean up tenant audit logs
        tenant_logs = AuditLog.objects.filter(created_at__lt=cutoff_date)
        tenant_count = tenant_logs.count()

        # Archive before deletion (optional - implement archive logic)
        # archive_audit_logs(tenant_logs)

        tenant_logs.delete()

        # Clean up Django auditlog entries
        auditlog_entries = LogEntry.objects.filter(timestamp__lt=cutoff_date)
        auditlog_count = auditlog_entries.count()
        auditlog_entries.delete()

        logger.info(
            f"Cleaned up audit logs: {tenant_count} tenant logs, "
            f"{auditlog_count} auditlog entries (older than {days} days)"
        )

        return {
            'status': 'success',
            'tenant_logs_deleted': tenant_count,
            'auditlog_entries_deleted': auditlog_count,
            'cutoff_date': cutoff_date.isoformat(),
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Audit log cleanup task exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error cleaning up audit logs: {str(e)}")
        raise self.retry(exc=e)


# ==================== DAILY DIGEST ====================

@shared_task(
    bind=True,
    name='zumodra.tasks.send_daily_digest',
    max_retries=3,
    default_retry_delay=600,
    autoretry_for=(Exception,),
    rate_limit='10/m',
)
def send_daily_digest(self):
    """
    Send daily activity digest emails to users who have opted in.

    This task gathers daily activity summaries for each tenant and sends
    personalized digest emails to users with daily_digest_enabled in their
    tenant settings.

    Returns:
        dict: Summary of emails sent.
    """
    from tenants.models import Tenant, TenantSettings
    from tenant_profiles.models import TenantUser
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        now = timezone.now()
        yesterday = now - timedelta(days=1)

        # Get tenants with daily digest enabled
        tenant_settings = TenantSettings.objects.filter(
            daily_digest_enabled=True,
            tenant__status='active'
        ).select_related('tenant')

        emails_sent = 0
        errors = []

        for settings in tenant_settings:
            tenant = settings.tenant

            # Get admin users for this tenant
            admin_users = TenantUser.objects.filter(
                tenant=tenant,
                is_active=True,
                role__in=['owner', 'admin', 'hr_manager']
            ).select_related('user')

            # Gather digest data for tenant
            digest_data = _gather_tenant_digest_data(tenant, yesterday, now)

            # Skip if no activity
            if not digest_data.get('has_activity', False):
                continue

            # Send digest to each admin user
            for tenant_user in admin_users:
                try:
                    _send_digest_email(tenant_user.user, tenant, digest_data)
                    emails_sent += 1
                except Exception as e:
                    errors.append({
                        'user': tenant_user.user.email,
                        'error': str(e)
                    })

        logger.info(f"Sent {emails_sent} daily digest emails")

        return {
            'status': 'success',
            'emails_sent': emails_sent,
            'errors': errors,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Daily digest task exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error sending daily digest: {str(e)}")
        raise self.retry(exc=e)


def _gather_tenant_digest_data(tenant, start_date, end_date):
    """
    Gather activity data for tenant digest.

    Args:
        tenant: Tenant object
        start_date: Start datetime
        end_date: End datetime

    Returns:
        dict: Digest data with activity counts
    """
    from jobs.models import Application, JobPosting
    from hr_core.models import TimeOffRequest

    data = {
        'tenant_name': tenant.name,
        'period_start': start_date.isoformat(),
        'period_end': end_date.isoformat(),
        'has_activity': False,
    }

    try:
        # Count new applications
        # Note: In multi-tenant setup, filter by tenant
        new_applications = Application.objects.filter(
            created_at__gte=start_date,
            created_at__lt=end_date
        ).count()
        data['new_applications'] = new_applications

        # Count active job postings
        active_jobs = JobPosting.objects.filter(
            status='open'
        ).count()
        data['active_jobs'] = active_jobs

        # Count pending time-off requests
        pending_time_off = TimeOffRequest.objects.filter(
            status='pending'
        ).count()
        data['pending_time_off'] = pending_time_off

        # Determine if there's activity worth reporting
        data['has_activity'] = (
            new_applications > 0 or
            pending_time_off > 0
        )

    except Exception as e:
        logger.error(f"Error gathering digest data: {str(e)}")

    return data


def _send_digest_email(user, tenant, digest_data):
    """
    Send digest email to a specific user.

    Args:
        user: User object
        tenant: Tenant object
        digest_data: Dictionary with digest content
    """
    subject = f"Daily Digest - {tenant.name}"

    # Render email template
    html_content = render_to_string('emails/daily_digest.html', {
        'user': user,
        'tenant': tenant,
        'digest': digest_data,
    })

    text_content = render_to_string('emails/daily_digest.txt', {
        'user': user,
        'tenant': tenant,
        'digest': digest_data,
    })

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_content,
        fail_silently=False,
    )


# ==================== WEEKLY SUMMARY ====================

@shared_task(
    bind=True,
    name='zumodra.tasks.send_weekly_summary',
    max_retries=3,
    default_retry_delay=600,
)
def send_weekly_summary(self):
    """
    Send weekly summary reports to tenant admins.

    Returns:
        dict: Summary of emails sent.
    """
    from tenants.models import Tenant
    from tenant_profiles.models import TenantUser

    try:
        now = timezone.now()
        week_ago = now - timedelta(days=7)

        # Get active tenants
        tenants = Tenant.objects.filter(status='active')

        emails_sent = 0

        for tenant in tenants:
            # Get owner/admin users
            admins = TenantUser.objects.filter(
                tenant=tenant,
                is_active=True,
                role__in=['owner', 'admin']
            ).select_related('user')

            summary_data = _gather_weekly_summary(tenant, week_ago, now)

            for admin in admins:
                try:
                    _send_weekly_summary_email(admin.user, tenant, summary_data)
                    emails_sent += 1
                except Exception as e:
                    logger.error(f"Error sending weekly summary to {admin.user.email}: {e}")

        logger.info(f"Sent {emails_sent} weekly summary emails")

        return {
            'status': 'success',
            'emails_sent': emails_sent,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error sending weekly summary: {str(e)}")
        raise self.retry(exc=e)


def _gather_weekly_summary(tenant, start_date, end_date):
    """Gather weekly summary data for tenant."""
    from jobs.models import Application, JobPosting
    from hr_core.models import Employee

    return {
        'period_start': start_date.isoformat(),
        'period_end': end_date.isoformat(),
        'new_applications': Application.objects.filter(
            created_at__gte=start_date,
            created_at__lt=end_date
        ).count(),
        'new_hires': Employee.objects.filter(
            hire_date__gte=start_date.date(),
            hire_date__lt=end_date.date()
        ).count(),
        'jobs_filled': JobPosting.objects.filter(
            status='filled',
            updated_at__gte=start_date
        ).count(),
    }


def _send_weekly_summary_email(user, tenant, summary_data):
    """Send weekly summary email to user."""
    subject = f"Weekly Summary - {tenant.name}"

    try:
        html_content = render_to_string('emails/weekly_summary.html', {
            'user': user,
            'tenant': tenant,
            'summary': summary_data,
        })
    except Exception:
        # Fallback if template doesn't exist
        html_content = f"<p>Weekly summary for {tenant.name}</p>"

    send_mail(
        subject=subject,
        message=f"Weekly summary for {tenant.name}",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_content,
        fail_silently=False,
    )


# ==================== DATABASE BACKUP ====================

@shared_task(
    bind=True,
    name='zumodra.tasks.backup_database',
    max_retries=2,
    default_retry_delay=600,
    soft_time_limit=3600,
    time_limit=3900,
)
def backup_database(self):
    """
    Create a database backup.

    This task creates a PostgreSQL dump of the database and optionally
    uploads it to cloud storage (S3, etc.).

    Returns:
        dict: Backup operation summary.
    """
    import subprocess
    import os
    from pathlib import Path

    try:
        now = timezone.now()
        timestamp = now.strftime('%Y%m%d_%H%M%S')

        # Get database settings
        db_settings = settings.DATABASES['default']
        db_name = db_settings['NAME']
        db_user = db_settings['USER']
        db_host = db_settings['HOST']
        db_port = db_settings['PORT']

        # Create backup directory
        backup_dir = Path(settings.BASE_DIR) / 'backups'
        backup_dir.mkdir(exist_ok=True)

        backup_file = backup_dir / f'backup_{db_name}_{timestamp}.sql'

        # Set password environment variable
        env = os.environ.copy()
        env['PGPASSWORD'] = db_settings['PASSWORD']

        # Create backup using pg_dump
        cmd = [
            'pg_dump',
            '-h', db_host,
            '-p', str(db_port),
            '-U', db_user,
            '-d', db_name,
            '-f', str(backup_file),
            '--format=custom',
            '--compress=9',
        ]

        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=3600
        )

        if result.returncode != 0:
            raise Exception(f"pg_dump failed: {result.stderr}")

        # Get backup file size
        backup_size = backup_file.stat().st_size

        # Optionally upload to cloud storage
        # upload_to_s3(backup_file)

        # Clean up old backups (keep last 7)
        _cleanup_old_backups(backup_dir, keep=7)

        logger.info(f"Database backup created: {backup_file} ({backup_size} bytes)")

        return {
            'status': 'success',
            'backup_file': str(backup_file),
            'backup_size': backup_size,
            'timestamp': now.isoformat(),
        }

    except subprocess.TimeoutExpired:
        logger.error("Database backup timed out")
        return {
            'status': 'error',
            'error': 'Backup timed out',
        }

    except Exception as e:
        logger.error(f"Error creating database backup: {str(e)}")
        raise self.retry(exc=e)


def _cleanup_old_backups(backup_dir, keep=7):
    """Remove old backup files, keeping the most recent ones."""
    from pathlib import Path

    backup_files = sorted(
        Path(backup_dir).glob('backup_*.sql'),
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )

    for backup_file in backup_files[keep:]:
        backup_file.unlink()
        logger.info(f"Removed old backup: {backup_file}")


# ==================== HEALTH CHECK ====================

@shared_task(
    bind=True,
    name='zumodra.tasks.health_check_integrations',
    max_retries=1,
    soft_time_limit=60,
    time_limit=90,
)
def health_check_integrations(self):
    """
    Check health of external integrations.

    Verifies connectivity and basic functionality of:
    - Stripe API
    - Email service
    - Redis
    - Database

    Returns:
        dict: Health status of each integration.
    """
    from django.core.cache import cache
    from django.db import connection

    now = timezone.now()
    results = {
        'timestamp': now.isoformat(),
        'integrations': {},
        'overall_status': 'healthy',
    }

    # Check Database
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            results['integrations']['database'] = {
                'status': 'healthy',
                'latency_ms': None,
            }
    except Exception as e:
        results['integrations']['database'] = {
            'status': 'unhealthy',
            'error': str(e),
        }
        results['overall_status'] = 'degraded'

    # Check Redis/Cache
    try:
        cache.set('health_check', 'ok', 10)
        if cache.get('health_check') == 'ok':
            results['integrations']['cache'] = {'status': 'healthy'}
        else:
            results['integrations']['cache'] = {
                'status': 'unhealthy',
                'error': 'Cache read/write failed',
            }
            results['overall_status'] = 'degraded'
    except Exception as e:
        results['integrations']['cache'] = {
            'status': 'unhealthy',
            'error': str(e),
        }
        results['overall_status'] = 'degraded'

    # Check Stripe
    if settings.STRIPE_SECRET_KEY:
        try:
            import stripe
            stripe.api_key = settings.STRIPE_SECRET_KEY
            stripe.Balance.retrieve()
            results['integrations']['stripe'] = {'status': 'healthy'}
        except Exception as e:
            results['integrations']['stripe'] = {
                'status': 'unhealthy',
                'error': str(e),
            }
            results['overall_status'] = 'degraded'
    else:
        results['integrations']['stripe'] = {
            'status': 'not_configured',
        }

    # Check Email
    try:
        from django.core.mail import get_connection
        connection = get_connection()
        connection.open()
        connection.close()
        results['integrations']['email'] = {'status': 'healthy'}
    except Exception as e:
        results['integrations']['email'] = {
            'status': 'unhealthy',
            'error': str(e),
        }
        results['overall_status'] = 'degraded'

    # Log results
    if results['overall_status'] != 'healthy':
        logger.warning(f"Health check detected issues: {results}")
    else:
        logger.info("All integrations healthy")

    return results


# ==================== METRICS CALCULATION ====================

@shared_task(
    bind=True,
    name='zumodra.tasks.calculate_daily_metrics',
    max_retries=3,
    default_retry_delay=300,
)
def calculate_daily_metrics(self):
    """
    Calculate and store daily system metrics.

    This is a wrapper that delegates to the analytics app's
    calculate_daily_metrics task.
    """
    from analytics.tasks import calculate_daily_metrics as analytics_calc

    try:
        return analytics_calc()
    except Exception as e:
        logger.error(f"Error calculating daily metrics: {str(e)}")
        raise self.retry(exc=e)
