"""
Celery Tasks for Notification System.

Provides async task handling for sending notifications, processing scheduled
notifications, sending bulk notifications, and cleanup tasks.
"""

import logging
from datetime import timedelta
from typing import List, Dict, Any, Optional
import uuid as uuid_lib

from celery import shared_task, group, chord
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone

logger = logging.getLogger(__name__)
User = get_user_model()


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,
    queue='notifications'
)
def send_notification_task(
    self,
    recipient_id: int,
    notification_type: str,
    title: str,
    message: str,
    channels: List[str] = None,
    sender_id: int = None,
    action_url: str = None,
    action_text: str = None,
    priority: str = 'normal',
    context_data: dict = None,
    template_name: str = None,
    content_type_id: int = None,
    object_id: int = None,
) -> Dict[str, Any]:
    """
    Celery task to send a notification asynchronously.

    Args:
        recipient_id: ID of the user to send notification to
        notification_type: Type of notification
        title: Notification title
        message: Notification message
        channels: List of channels to send through
        sender_id: ID of the user who triggered the notification
        action_url: URL for notification action
        action_text: Text for action button
        priority: Notification priority
        context_data: Additional context for template rendering
        template_name: Specific template to use
        content_type_id: ContentType ID for related object
        object_id: ID of related object

    Returns:
        Dict with results of send operation
    """
    from .services import notification_service

    try:
        recipient = User.objects.get(pk=recipient_id)
        sender = User.objects.get(pk=sender_id) if sender_id else None

        content_object = None
        if content_type_id and object_id:
            from django.contrib.contenttypes.models import ContentType
            content_type = ContentType.objects.get(pk=content_type_id)
            content_object = content_type.get_object_for_this_type(pk=object_id)

        results = notification_service.send_notification(
            recipient=recipient,
            notification_type=notification_type,
            title=title,
            message=message,
            channels=channels,
            sender=sender,
            action_url=action_url or '',
            action_text=action_text or 'View',
            priority=priority,
            context_data=context_data or {},
            template_name=template_name,
            content_object=content_object,
        )

        return {
            'success': any(r.success for r in results),
            'recipient_id': recipient_id,
            'results': [
                {
                    'channel': r.channel_type,
                    'success': r.success,
                    'notification_id': r.notification_id,
                    'error': r.error_message,
                }
                for r in results
            ]
        }

    except User.DoesNotExist:
        logger.error(f"User {recipient_id} not found for notification")
        return {'success': False, 'error': f'User {recipient_id} not found'}

    except Exception as e:
        logger.error(f"Failed to send notification: {e}")
        raise self.retry(exc=e)


@shared_task(
    bind=True,
    max_retries=2,
    default_retry_delay=120,
    queue='notifications'
)
def send_bulk_notifications(
    self,
    recipient_ids: List[int],
    notification_type: str,
    title: str,
    message: str,
    channels: List[str] = None,
    sender_id: int = None,
    action_url: str = None,
    priority: str = 'normal',
    context_data: dict = None,
    batch_size: int = 100,
) -> Dict[str, Any]:
    """
    Celery task to send bulk notifications.

    Uses chunking to process large recipient lists efficiently.

    Args:
        recipient_ids: List of user IDs to notify
        notification_type: Type of notification
        title: Notification title
        message: Notification message
        channels: Channels to send through
        sender_id: ID of sender
        action_url: Action URL
        priority: Priority level
        context_data: Template context
        batch_size: Number of notifications per batch

    Returns:
        Summary of bulk send operation
    """
    from .services import notification_service

    batch_id = str(uuid_lib.uuid4())
    total = len(recipient_ids)
    success_count = 0
    failed_count = 0
    errors = []

    # Process in batches
    for i in range(0, total, batch_size):
        batch = recipient_ids[i:i + batch_size]

        recipients = User.objects.filter(pk__in=batch)
        sender = User.objects.get(pk=sender_id) if sender_id else None

        try:
            results = notification_service.send_bulk_notification(
                recipients=list(recipients),
                notification_type=notification_type,
                title=title,
                message=message,
                channels=channels,
                sender=sender,
                action_url=action_url or '',
                priority=priority,
                context_data=context_data or {},
                batch_id=batch_id,
            )

            for user_id, user_results in results.items():
                if any(r.success for r in user_results):
                    success_count += 1
                else:
                    failed_count += 1
                    error_msgs = [r.error_message for r in user_results if r.error_message]
                    if error_msgs:
                        errors.append({'user_id': user_id, 'errors': error_msgs})

        except Exception as e:
            logger.error(f"Batch {i}-{i+batch_size} failed: {e}")
            failed_count += len(batch)
            errors.append({'batch': f'{i}-{i+batch_size}', 'error': str(e)})

    return {
        'success': success_count > 0,
        'batch_id': batch_id,
        'total': total,
        'success_count': success_count,
        'failed_count': failed_count,
        'errors': errors[:10],  # Limit error list
    }


@shared_task(queue='notifications')
def process_scheduled_notifications():
    """
    Process all scheduled notifications that are due.

    NOTE: This task must run within tenant schema context.
    Notifications app is in TENANT_APPS, so tables only exist in tenant schemas.

    This task should be run periodically (e.g., every minute) via Celery Beat.
    """
    from .models import ScheduledNotification
    from .services import notification_service
    from django.db import connection
    import logging

    logger = logging.getLogger(__name__)

    # Skip if running in public schema
    if connection.schema_name == 'public':
        logger.info("Skipping scheduled notifications processing in public schema (notifications is TENANT_APPS)")
        return {'status': 'skipped', 'reason': 'public schema'}

    now = timezone.now()

    # Get all active, unprocessed scheduled notifications that are due
    scheduled = ScheduledNotification.objects.filter(
        Q(scheduled_at__lte=now) | Q(next_run_at__lte=now),
        is_active=True,
    ).select_related('template', 'recipient')

    processed_count = 0
    for item in scheduled:
        try:
            # Skip if recurrence and already processed this run
            if item.recurrence != 'once' and item.last_run_at:
                if item.next_run_at and item.next_run_at > now:
                    continue

            # Get recipients
            if item.recipient:
                recipients = [item.recipient]
            elif item.recipient_filter:
                # Build recipient queryset from filter
                recipients = User.objects.filter(**item.recipient_filter)
            else:
                logger.warning(f"Scheduled notification {item.id} has no recipients")
                continue

            # Render template with context
            context = item.context_data or {}
            context['scheduled_notification'] = item

            # Send to all recipients
            for recipient in recipients:
                notification_service.send_notification(
                    recipient=recipient,
                    notification_type=item.template.template_type,
                    title=item.template.render_subject(context),
                    message=item.template.render_body(context),
                    channels=[item.template.channel.channel_type],
                    context_data=context,
                    content_object=item.content_object,
                )

            # Update scheduled notification
            item.last_run_at = now

            if item.recurrence == 'once':
                item.is_processed = True
                item.is_active = False
            else:
                item.calculate_next_run()

            item.save()
            processed_count += 1

        except Exception as e:
            logger.error(f"Failed to process scheduled notification {item.id}: {e}")

    logger.info(f"Processed {processed_count} scheduled notifications")
    return {'processed': processed_count}


@shared_task(queue='notifications')
def retry_failed_notifications(max_age_hours: int = 24):
    """
    Retry failed notifications that haven't exceeded max retries.

    Args:
        max_age_hours: Only retry notifications created within this many hours
    """
    from .models import Notification
    from .services import NotificationService

    cutoff = timezone.now() - timedelta(hours=max_age_hours)

    failed_notifications = Notification.objects.filter(
        status='failed',
        retry_count__lt=models.F('max_retries'),
        created_at__gte=cutoff,
    ).select_related('channel', 'recipient', 'template')

    service = NotificationService()
    retried_count = 0

    for notification in failed_notifications:
        try:
            channel_service = service.get_service(notification.channel.channel_type)
            if channel_service:
                result = channel_service.send(notification)
                if result.success:
                    retried_count += 1
        except Exception as e:
            logger.error(f"Retry failed for notification {notification.id}: {e}")

    logger.info(f"Retried {retried_count} failed notifications")
    return {'retried': retried_count}


@shared_task(queue='notifications')
def send_daily_digest():
    """
    Send daily digest emails to users who have opted in.

    This should be scheduled to run once per day.
    """
    from .models import Notification, NotificationPreference
    from .services import notification_service

    yesterday = timezone.now() - timedelta(days=1)

    # Find users who want daily digests
    preferences = NotificationPreference.objects.filter(
        email_digest_frequency='daily',
        global_unsubscribe=False,
        notifications_enabled=True,
    ).select_related('user')

    sent_count = 0

    for pref in preferences:
        # Get unread notifications from the past 24 hours
        notifications = Notification.objects.filter(
            recipient=pref.user,
            is_read=False,
            created_at__gte=yesterday,
        ).order_by('-created_at')[:20]

        if not notifications.exists():
            continue

        # Build digest content
        notification_list = list(notifications)

        notification_service.send_notification(
            recipient=pref.user,
            notification_type='daily_digest',
            title=f"Your Daily Digest - {len(notification_list)} notifications",
            message=f"You have {len(notification_list)} unread notifications.",
            channels=['email'],
            context_data={
                'notifications': notification_list,
                'notification_count': len(notification_list),
                'period': 'daily',
            },
            priority='low',
        )
        sent_count += 1

    logger.info(f"Sent {sent_count} daily digests")
    return {'sent': sent_count}


@shared_task(queue='notifications')
def send_weekly_digest():
    """
    Send weekly digest emails to users who have opted in.

    This should be scheduled to run once per week.
    """
    from .models import Notification, NotificationPreference
    from .services import notification_service

    last_week = timezone.now() - timedelta(days=7)

    preferences = NotificationPreference.objects.filter(
        email_digest_frequency='weekly',
        global_unsubscribe=False,
        notifications_enabled=True,
    ).select_related('user')

    sent_count = 0

    for pref in preferences:
        # Get notifications from the past week
        notifications = Notification.objects.filter(
            recipient=pref.user,
            created_at__gte=last_week,
        ).order_by('-created_at')[:50]

        if not notifications.exists():
            continue

        notification_list = list(notifications)
        unread_count = sum(1 for n in notification_list if not n.is_read)

        notification_service.send_notification(
            recipient=pref.user,
            notification_type='weekly_digest',
            title=f"Your Weekly Summary - {len(notification_list)} notifications",
            message=f"You received {len(notification_list)} notifications this week, {unread_count} unread.",
            channels=['email'],
            context_data={
                'notifications': notification_list,
                'notification_count': len(notification_list),
                'unread_count': unread_count,
                'period': 'weekly',
                'week_start': last_week.strftime('%B %d'),
                'week_end': timezone.now().strftime('%B %d'),
            },
            priority='low',
        )
        sent_count += 1

    logger.info(f"Sent {sent_count} weekly digests")
    return {'sent': sent_count}


@shared_task(queue='notifications')
def cleanup_old_notifications(days: int = 90, batch_size: int = 1000):
    """
    Clean up old notifications to manage database size.

    Args:
        days: Delete notifications older than this many days
        batch_size: Number of records to delete per batch
    """
    from .models import Notification, NotificationDeliveryLog

    cutoff = timezone.now() - timedelta(days=days)

    # Delete old delivery logs first
    old_logs_deleted = 0
    while True:
        log_ids = list(
            NotificationDeliveryLog.objects.filter(
                notification__created_at__lt=cutoff
            ).values_list('id', flat=True)[:batch_size]
        )
        if not log_ids:
            break
        deleted, _ = NotificationDeliveryLog.objects.filter(id__in=log_ids).delete()
        old_logs_deleted += deleted

    # Delete old notifications (read and dismissed)
    notifications_deleted = 0
    while True:
        notification_ids = list(
            Notification.objects.filter(
                created_at__lt=cutoff,
                is_read=True,
                is_dismissed=True,
            ).values_list('id', flat=True)[:batch_size]
        )
        if not notification_ids:
            break
        deleted, _ = Notification.objects.filter(id__in=notification_ids).delete()
        notifications_deleted += deleted

    logger.info(f"Cleaned up {notifications_deleted} notifications and {old_logs_deleted} delivery logs")
    return {
        'notifications_deleted': notifications_deleted,
        'logs_deleted': old_logs_deleted,
    }


@shared_task(queue='notifications')
def cleanup_expired_notifications():
    """
    Mark expired notifications as dismissed.
    """
    from .models import Notification

    now = timezone.now()

    expired = Notification.objects.filter(
        expires_at__lt=now,
        is_dismissed=False,
    )

    count = expired.update(
        is_dismissed=True,
        dismissed_at=now,
    )

    logger.info(f"Marked {count} expired notifications as dismissed")
    return {'dismissed': count}


@shared_task(queue='notifications')
def send_appointment_reminders():
    """
    Send reminders for upcoming appointments.

    This should be scheduled to run every hour or so.
    """
    from .services import notification_service

    try:
        from appointment.models import Appointment
    except ImportError:
        logger.warning("Appointment app not available")
        return {'sent': 0}

    now = timezone.now()

    # Remind for appointments in the next 24 hours
    reminder_window_start = now
    reminder_window_end = now + timedelta(hours=24)

    appointments = Appointment.objects.filter(
        appointment_datetime__gte=reminder_window_start,
        appointment_datetime__lte=reminder_window_end,
        status='confirmed',
        reminder_sent=False,  # Assuming this field exists
    ).select_related('client', 'service')

    sent_count = 0
    for appointment in appointments:
        try:
            notification_service.send_notification(
                recipient=appointment.client,
                notification_type='appointment_reminder',
                title=f"Reminder: {appointment.service.name}",
                message=f"Your appointment is scheduled for {appointment.appointment_datetime.strftime('%B %d at %I:%M %p')}",
                channels=['email', 'sms', 'push'],
                action_url=f"/appointments/{appointment.id}/",
                context_data={
                    'appointment': appointment,
                    'service_name': appointment.service.name,
                    'appointment_date': appointment.appointment_datetime.strftime('%B %d, %Y'),
                    'appointment_time': appointment.appointment_datetime.strftime('%I:%M %p'),
                },
                priority='high',
            )
            appointment.reminder_sent = True
            appointment.save(update_fields=['reminder_sent'])
            sent_count += 1
        except Exception as e:
            logger.error(f"Failed to send reminder for appointment {appointment.id}: {e}")

    logger.info(f"Sent {sent_count} appointment reminders")
    return {'sent': sent_count}


# Import models here to avoid circular imports
from django.db import models
