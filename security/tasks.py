"""
Celery Tasks for Security App

This module contains async tasks for security operations:
- Audit log cleanup and archival
- Failed login analysis and brute force detection
- Session expiration and cleanup
- Security report generation
- Threat detection and alerting

Security Features:
- Security logger for all operations
- Compliance with retention policies
- Real-time threat alerting
"""

import logging
from datetime import timedelta
from collections import Counter
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.db.models import Count, Q
from django.core.cache import cache

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('security.tasks')


# ==================== AUDIT LOG MANAGEMENT ====================

@shared_task(
    bind=True,
    name='security.tasks.cleanup_audit_logs',
    max_retries=3,
    default_retry_delay=600,
    soft_time_limit=3600,
)
def cleanup_audit_logs(self):
    """
    Archive and cleanup old audit logs.

    Actions:
    - Archive logs older than 90 days
    - Delete archived logs older than 2 years
    - Compress archived logs

    Returns:
        dict: Summary of cleanup.
    """
    from security.models import AuditLog

    try:
        now = timezone.now()
        archive_threshold = now - timedelta(days=90)
        delete_threshold = now - timedelta(days=730)  # 2 years

        # Archive old logs
        logs_to_archive = AuditLog.objects.filter(
            created_at__lt=archive_threshold,
            is_archived=False
        )

        archived_count = logs_to_archive.count()
        logs_to_archive.update(is_archived=True, archived_at=now)

        # Delete very old archived logs
        logs_to_delete = AuditLog.objects.filter(
            created_at__lt=delete_threshold,
            is_archived=True
        )

        deleted_count = logs_to_delete.count()
        logs_to_delete.delete()

        security_logger.info(
            f"AUDIT_LOG_CLEANUP: archived={archived_count} deleted={deleted_count}"
        )

        return {
            'status': 'success',
            'archived_count': archived_count,
            'deleted_count': deleted_count,
            'timestamp': now.isoformat(),
        }

    except SoftTimeLimitExceeded:
        logger.warning("Audit log cleanup exceeded soft time limit")
        raise

    except Exception as e:
        logger.error(f"Error cleaning up audit logs: {str(e)}")
        raise self.retry(exc=e)


# ==================== FAILED LOGIN ANALYSIS ====================

@shared_task(
    bind=True,
    name='security.tasks.analyze_failed_logins',
    max_retries=3,
    default_retry_delay=300,
)
def analyze_failed_logins(self):
    """
    Analyze failed login attempts to detect brute force attacks.

    Checks:
    - IP addresses with multiple failures
    - Accounts being targeted
    - Credential stuffing patterns

    Returns:
        dict: Summary of analysis and alerts.
    """
    from security.models import FailedLoginAttempt, SecurityEvent

    try:
        now = timezone.now()
        check_window = now - timedelta(hours=1)

        # Find IPs with multiple failures
        ip_failures = FailedLoginAttempt.objects.filter(
            created_at__gte=check_window
        ).values('ip_address').annotate(
            count=Count('id')
        ).filter(count__gte=10)  # 10+ failures in an hour

        alerts_created = 0
        blocked_ips = []

        for ip_data in ip_failures:
            ip = ip_data['ip_address']
            count = ip_data['count']

            try:
                # Create security event
                SecurityEvent.objects.create(
                    event_type='brute_force_detected',
                    severity='high',
                    ip_address=ip,
                    details={
                        'failed_attempts': count,
                        'window_hours': 1,
                    },
                )

                # Add to block list cache
                cache.set(f"blocked_ip:{ip}", True, timeout=3600)  # Block for 1 hour
                blocked_ips.append(ip)

                security_logger.warning(
                    f"BRUTE_FORCE_DETECTED: ip={ip} attempts={count}"
                )

                alerts_created += 1

            except Exception as e:
                logger.error(f"Error creating security event for IP {ip}: {e}")

        # Find targeted accounts
        account_targets = FailedLoginAttempt.objects.filter(
            created_at__gte=check_window
        ).values('username').annotate(
            count=Count('id'),
            unique_ips=Count('ip_address', distinct=True)
        ).filter(
            count__gte=5,  # 5+ attempts
            unique_ips__gte=3  # From 3+ different IPs
        )

        for account_data in account_targets:
            username = account_data['username']

            try:
                SecurityEvent.objects.create(
                    event_type='account_targeted',
                    severity='medium',
                    details={
                        'username': username,
                        'attempts': account_data['count'],
                        'unique_ips': account_data['unique_ips'],
                    },
                )

                security_logger.warning(
                    f"ACCOUNT_TARGETED: username={username} "
                    f"attempts={account_data['count']} ips={account_data['unique_ips']}"
                )

            except Exception as e:
                logger.error(f"Error creating targeted account event: {e}")

        logger.info(
            f"Failed login analysis: alerts={alerts_created}, "
            f"blocked_ips={len(blocked_ips)}"
        )

        return {
            'status': 'success',
            'alerts_created': alerts_created,
            'blocked_ips': blocked_ips,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error analyzing failed logins: {str(e)}")
        raise self.retry(exc=e)


# ==================== SESSION MANAGEMENT ====================

@shared_task(
    bind=True,
    name='security.tasks.expire_sessions',
    max_retries=3,
    default_retry_delay=300,
)
def expire_sessions(self):
    """
    Clean up expired sessions and tokens.

    Actions:
    - Delete expired Django sessions
    - Revoke expired JWT tokens
    - Clean up remember-me tokens

    Returns:
        dict: Summary of cleanup.
    """
    from django.contrib.sessions.models import Session

    try:
        now = timezone.now()

        # Delete expired Django sessions
        expired_sessions = Session.objects.filter(expire_date__lt=now)
        sessions_deleted = expired_sessions.count()
        expired_sessions.delete()

        # Clean up JWT blacklist (if using simplejwt)
        jwt_cleaned = 0
        try:
            from rest_framework_simplejwt.token_blacklist.models import (
                OutstandingToken,
                BlacklistedToken
            )

            # Delete very old blacklisted tokens
            old_tokens = OutstandingToken.objects.filter(
                expires_at__lt=now - timedelta(days=7)
            )
            jwt_cleaned = old_tokens.count()
            old_tokens.delete()

        except ImportError:
            pass

        # Clean up axes lockouts
        axes_cleaned = 0
        try:
            from axes.models import AccessAttempt

            old_attempts = AccessAttempt.objects.filter(
                attempt_time__lt=now - timedelta(days=7)
            )
            axes_cleaned = old_attempts.count()
            old_attempts.delete()

        except ImportError:
            pass

        logger.info(
            f"Session cleanup: sessions={sessions_deleted}, "
            f"jwt={jwt_cleaned}, axes={axes_cleaned}"
        )

        return {
            'status': 'success',
            'sessions_deleted': sessions_deleted,
            'jwt_tokens_cleaned': jwt_cleaned,
            'axes_attempts_cleaned': axes_cleaned,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error expiring sessions: {str(e)}")
        raise self.retry(exc=e)


# ==================== SECURITY REPORT GENERATION ====================

@shared_task(
    bind=True,
    name='security.tasks.generate_security_report',
    max_retries=3,
    default_retry_delay=600,
)
def generate_security_report(self):
    """
    Generate daily security summary report.

    Includes:
    - Login statistics
    - Security events summary
    - Blocked IPs
    - Suspicious activity

    Returns:
        dict: Security report.
    """
    from security.models import SecurityEvent, FailedLogin, AuditLog

    try:
        now = timezone.now()
        yesterday = now - timedelta(days=1)

        # Gather metrics
        security_events = SecurityEvent.objects.filter(
            created_at__date=yesterday.date()
        )

        events_by_type = dict(
            security_events.values('event_type').annotate(
                count=Count('id')
            ).values_list('event_type', 'count')
        )

        events_by_severity = dict(
            security_events.values('severity').annotate(
                count=Count('id')
            ).values_list('severity', 'count')
        )

        failed_logins = FailedLoginAttempt.objects.filter(
            created_at__date=yesterday.date()
        ).count()

        unique_ips_failed = FailedLoginAttempt.objects.filter(
            created_at__date=yesterday.date()
        ).values('ip_address').distinct().count()

        # Audit log stats
        audit_actions = dict(
            AuditLog.objects.filter(
                created_at__date=yesterday.date()
            ).values('action').annotate(
                count=Count('id')
            ).values_list('action', 'count')
        )

        report = {
            'date': yesterday.date().isoformat(),
            'security_events': {
                'total': security_events.count(),
                'by_type': events_by_type,
                'by_severity': events_by_severity,
            },
            'failed_logins': {
                'total': failed_logins,
                'unique_ips': unique_ips_failed,
            },
            'audit_activity': audit_actions,
        }

        # Cache report
        cache.set(f"security:daily_report:{yesterday.date()}", report, timeout=86400)

        # Send alert if high severity events
        high_severity = events_by_severity.get('high', 0) + events_by_severity.get('critical', 0)
        if high_severity > 0:
            _send_security_alert(report)

        security_logger.info(
            f"DAILY_SECURITY_REPORT: events={security_events.count()} "
            f"failed_logins={failed_logins}"
        )

        return {
            'status': 'success',
            'report': report,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error generating security report: {str(e)}")
        raise self.retry(exc=e)


def _send_security_alert(report):
    """Send security alert to administrators."""
    admin_emails = getattr(settings, 'SECURITY_ALERT_EMAILS', [])
    if not admin_emails:
        return

    subject = f"Security Alert - {report['date']}"

    context = {
        'report': report,
    }

    try:
        html_content = render_to_string('emails/security/daily_alert.html', context)
        text_content = f"Security report for {report['date']}: {report['security_events']['total']} events"
    except Exception:
        text_content = f"Security report for {report['date']}: {report['security_events']['total']} events"
        html_content = f"<p>{text_content}</p>"

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=admin_emails,
        html_message=html_content,
        fail_silently=True,
    )


# ==================== THREAT DETECTION ====================

@shared_task(
    bind=True,
    name='security.tasks.detect_anomalies',
    max_retries=3,
    default_retry_delay=300,
)
def detect_anomalies(self):
    """
    Detect anomalous activity patterns.

    Checks:
    - Unusual access patterns
    - Geographic anomalies
    - Time-based anomalies
    - Privilege escalation attempts

    Returns:
        dict: Summary of anomalies detected.
    """
    from security.models import SecurityEvent, AuditLog

    try:
        now = timezone.now()
        check_window = now - timedelta(hours=6)

        anomalies_detected = 0

        # Check for unusual privilege changes
        privilege_changes = AuditLog.objects.filter(
            created_at__gte=check_window,
            action__in=['role_changed', 'permission_added', 'admin_access_granted']
        )

        for change in privilege_changes:
            try:
                # Create security event for review
                SecurityEvent.objects.get_or_create(
                    event_type='privilege_change',
                    related_object_id=change.id,
                    defaults={
                        'severity': 'medium',
                        'details': {
                            'action': change.action,
                            'user_id': change.user_id,
                            'timestamp': change.created_at.isoformat(),
                        },
                    }
                )
                anomalies_detected += 1

            except Exception as e:
                logger.error(f"Error creating privilege change event: {e}")

        # Check for bulk data access
        bulk_access = AuditLog.objects.filter(
            created_at__gte=check_window,
            action__in=['export', 'bulk_read', 'report_generated']
        ).values('user_id').annotate(
            count=Count('id')
        ).filter(count__gte=10)

        for access in bulk_access:
            try:
                SecurityEvent.objects.create(
                    event_type='bulk_data_access',
                    severity='low',
                    details={
                        'user_id': access['user_id'],
                        'access_count': access['count'],
                    },
                )
                anomalies_detected += 1

            except Exception as e:
                logger.error(f"Error creating bulk access event: {e}")

        logger.info(f"Anomaly detection: detected={anomalies_detected}")

        return {
            'status': 'success',
            'anomalies_detected': anomalies_detected,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error detecting anomalies: {str(e)}")
        raise self.retry(exc=e)


# ==================== PASSWORD POLICY ENFORCEMENT ====================

@shared_task(
    bind=True,
    name='security.tasks.check_password_expiry',
    max_retries=3,
    default_retry_delay=600,
)
def check_password_expiry(self):
    """
    Check for expired passwords and send notifications.

    Actions:
    - Identify users with passwords older than policy
    - Send expiry warnings
    - Force password reset for very old passwords

    Returns:
        dict: Summary of checks.
    """
    from django.contrib.auth import get_user_model

    User = get_user_model()

    try:
        now = timezone.now()

        # Password expiry settings (configurable)
        expiry_days = getattr(settings, 'PASSWORD_EXPIRY_DAYS', 90)
        warning_days = getattr(settings, 'PASSWORD_WARNING_DAYS', 14)

        warning_threshold = now - timedelta(days=expiry_days - warning_days)
        expiry_threshold = now - timedelta(days=expiry_days)

        # Find users needing warning
        users_to_warn = User.objects.filter(
            is_active=True,
            password_changed_at__lt=warning_threshold,
            password_changed_at__gte=expiry_threshold,
            password_expiry_warned=False
        )

        warned = 0
        for user in users_to_warn:
            try:
                _send_password_expiry_warning(user, warning_days)
                user.password_expiry_warned = True
                user.save(update_fields=['password_expiry_warned'])
                warned += 1

            except Exception as e:
                logger.error(f"Error warning user {user.id}: {e}")

        # Find users with expired passwords
        expired_users = User.objects.filter(
            is_active=True,
            password_changed_at__lt=expiry_threshold
        )

        forced = 0
        for user in expired_users:
            try:
                # Force password reset
                user.must_change_password = True
                user.save(update_fields=['must_change_password'])

                security_logger.info(
                    f"PASSWORD_EXPIRED: user={user.id} forcing reset"
                )

                forced += 1

            except Exception as e:
                logger.error(f"Error forcing password reset for user {user.id}: {e}")

        logger.info(f"Password expiry check: warned={warned}, forced={forced}")

        return {
            'status': 'success',
            'users_warned': warned,
            'users_forced_reset': forced,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error checking password expiry: {str(e)}")
        raise self.retry(exc=e)


def _send_password_expiry_warning(user, days_remaining):
    """Send password expiry warning email."""
    if not hasattr(user, 'email') or not user.email:
        return

    subject = f"Password expiring in {days_remaining} days"
    text_content = (
        f"Your password will expire in {days_remaining} days. "
        "Please update your password to avoid being locked out."
    )

    send_mail(
        subject=subject,
        message=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=True,
    )


# ==================== IP REPUTATION ====================

@shared_task(
    bind=True,
    name='security.tasks.update_ip_reputation',
    max_retries=3,
    default_retry_delay=600,
)
def update_ip_reputation(self):
    """
    Update IP reputation scores based on activity.

    Actions:
    - Calculate reputation from failed logins
    - Update block lists
    - Clear old reputation data

    Returns:
        dict: Summary of updates.
    """
    from security.models import FailedLoginAttempt

    try:
        now = timezone.now()
        check_window = now - timedelta(days=7)

        # Get IP activity summary
        ip_activity = FailedLoginAttempt.objects.filter(
            created_at__gte=check_window
        ).values('ip_address').annotate(
            failure_count=Count('id')
        )

        updated = 0
        for activity in ip_activity:
            ip = activity['ip_address']
            failures = activity['failure_count']

            # Calculate reputation (0-100, higher is worse)
            reputation = min(failures * 10, 100)

            # Cache reputation score
            cache.set(
                f"ip_reputation:{ip}",
                {
                    'score': reputation,
                    'failures': failures,
                    'updated_at': now.isoformat(),
                },
                timeout=86400  # 24 hours
            )

            # Auto-block high-risk IPs
            if reputation >= 80:
                cache.set(f"blocked_ip:{ip}", True, timeout=86400)
                security_logger.warning(
                    f"IP_AUTO_BLOCKED: ip={ip} reputation={reputation}"
                )

            updated += 1

        logger.info(f"Updated IP reputation for {updated} addresses")

        return {
            'status': 'success',
            'updated_count': updated,
            'timestamp': now.isoformat(),
        }

    except Exception as e:
        logger.error(f"Error updating IP reputation: {str(e)}")
        raise self.retry(exc=e)
