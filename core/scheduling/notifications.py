"""
Unified notification system for scheduling.

Handles email, SMS, and in-app notifications for both:
- Recruitment interviews (jobs.Interview)
- Service appointments (interviews.Appointment)

Author: Zumodra Team
Since: 2026-01-17
"""

from datetime import datetime
from typing import List, Dict, Optional, Any

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.translation import gettext as _

# Import notification system if available
try:
    from notifications.models import Notification
    NOTIFICATIONS_AVAILABLE = True
except ImportError:
    NOTIFICATIONS_AVAILABLE = False


class SchedulingNotificationService:
    """
    Service for sending scheduling-related notifications.

    Supports multiple channels: email, SMS, in-app notifications.
    """

    def __init__(self, tenant=None):
        """
        Initialize notification service.

        Args:
            tenant: Optional tenant for multi-tenant context
        """
        self.tenant = tenant

    def send_confirmation_email(
        self,
        recipient_email: str,
        recipient_name: str,
        event_type: str,
        event_title: str,
        scheduled_start: datetime,
        scheduled_end: datetime,
        location: Optional[str] = None,
        meeting_url: Optional[str] = None,
        additional_details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send confirmation email for scheduled event.

        Args:
            recipient_email: Recipient email address
            recipient_name: Recipient's name
            event_type: Type of event ('interview' or 'appointment')
            event_title: Title/subject of the event
            scheduled_start: Start datetime
            scheduled_end: End datetime
            location: Physical location (optional)
            meeting_url: Video meeting URL (optional)
            additional_details: Extra context data

        Returns:
            True if sent successfully
        """
        context = {
            'recipient_name': recipient_name,
            'event_type': event_type,
            'event_title': event_title,
            'scheduled_start': scheduled_start,
            'scheduled_end': scheduled_end,
            'location': location,
            'meeting_url': meeting_url,
            'tenant': self.tenant,
            **(additional_details or {})
        }

        subject = _("Confirmed: %(title)s on %(date)s") % {
            'title': event_title,
            'date': scheduled_start.strftime('%B %d, %Y')
        }

        # Render email templates
        text_content = render_to_string(
            'scheduling/emails/confirmation.txt',
            context
        )
        html_content = render_to_string(
            'scheduling/emails/confirmation.html',
            context
        )

        # Send email
        return self._send_email(
            recipient_email,
            subject,
            text_content,
            html_content
        )

    def send_reminder_email(
        self,
        recipient_email: str,
        recipient_name: str,
        event_type: str,
        event_title: str,
        scheduled_start: datetime,
        scheduled_end: datetime,
        reminder_type: str,  # '1day', '1hour', '15min'
        location: Optional[str] = None,
        meeting_url: Optional[str] = None,
        additional_details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send reminder email for upcoming event.

        Args:
            recipient_email: Recipient email address
            recipient_name: Recipient's name
            event_type: Type of event ('interview' or 'appointment')
            event_title: Title/subject of the event
            scheduled_start: Start datetime
            scheduled_end: End datetime
            reminder_type: Type of reminder ('1day', '1hour', '15min')
            location: Physical location (optional)
            meeting_url: Video meeting URL (optional)
            additional_details: Extra context data

        Returns:
            True if sent successfully
        """
        reminder_labels = {
            '1day': _('Tomorrow'),
            '1hour': _('In 1 hour'),
            '15min': _('In 15 minutes')
        }

        context = {
            'recipient_name': recipient_name,
            'event_type': event_type,
            'event_title': event_title,
            'scheduled_start': scheduled_start,
            'scheduled_end': scheduled_end,
            'reminder_label': reminder_labels.get(reminder_type, ''),
            'location': location,
            'meeting_url': meeting_url,
            'tenant': self.tenant,
            **(additional_details or {})
        }

        subject = _("Reminder: %(title)s %(when)s") % {
            'title': event_title,
            'when': reminder_labels.get(reminder_type, '')
        }

        # Render email templates
        text_content = render_to_string(
            'scheduling/emails/reminder.txt',
            context
        )
        html_content = render_to_string(
            'scheduling/emails/reminder.html',
            context
        )

        # Send email
        return self._send_email(
            recipient_email,
            subject,
            text_content,
            html_content
        )

    def send_cancellation_email(
        self,
        recipient_email: str,
        recipient_name: str,
        event_type: str,
        event_title: str,
        scheduled_start: datetime,
        cancellation_reason: Optional[str] = None,
        cancelled_by_name: Optional[str] = None,
        additional_details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send cancellation notification email.

        Args:
            recipient_email: Recipient email address
            recipient_name: Recipient's name
            event_type: Type of event ('interview' or 'appointment')
            event_title: Title/subject of the event
            scheduled_start: Original start datetime
            cancellation_reason: Reason for cancellation (optional)
            cancelled_by_name: Name of person who cancelled (optional)
            additional_details: Extra context data

        Returns:
            True if sent successfully
        """
        context = {
            'recipient_name': recipient_name,
            'event_type': event_type,
            'event_title': event_title,
            'scheduled_start': scheduled_start,
            'cancellation_reason': cancellation_reason,
            'cancelled_by_name': cancelled_by_name,
            'tenant': self.tenant,
            **(additional_details or {})
        }

        subject = _("Cancelled: %(title)s on %(date)s") % {
            'title': event_title,
            'date': scheduled_start.strftime('%B %d, %Y')
        }

        # Render email templates
        text_content = render_to_string(
            'scheduling/emails/cancellation.txt',
            context
        )
        html_content = render_to_string(
            'scheduling/emails/cancellation.html',
            context
        )

        # Send email
        return self._send_email(
            recipient_email,
            subject,
            text_content,
            html_content
        )

    def send_reschedule_email(
        self,
        recipient_email: str,
        recipient_name: str,
        event_type: str,
        event_title: str,
        old_start: datetime,
        old_end: datetime,
        new_start: datetime,
        new_end: datetime,
        reschedule_reason: Optional[str] = None,
        location: Optional[str] = None,
        meeting_url: Optional[str] = None,
        additional_details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send reschedule notification email.

        Args:
            recipient_email: Recipient email address
            recipient_name: Recipient's name
            event_type: Type of event ('interview' or 'appointment')
            event_title: Title/subject of the event
            old_start: Original start datetime
            old_end: Original end datetime
            new_start: New start datetime
            new_end: New end datetime
            reschedule_reason: Reason for rescheduling (optional)
            location: Physical location (optional)
            meeting_url: Video meeting URL (optional)
            additional_details: Extra context data

        Returns:
            True if sent successfully
        """
        context = {
            'recipient_name': recipient_name,
            'event_type': event_type,
            'event_title': event_title,
            'old_start': old_start,
            'old_end': old_end,
            'new_start': new_start,
            'new_end': new_end,
            'reschedule_reason': reschedule_reason,
            'location': location,
            'meeting_url': meeting_url,
            'tenant': self.tenant,
            **(additional_details or {})
        }

        subject = _("Rescheduled: %(title)s now on %(date)s") % {
            'title': event_title,
            'date': new_start.strftime('%B %d, %Y')
        }

        # Render email templates
        text_content = render_to_string(
            'scheduling/emails/reschedule.txt',
            context
        )
        html_content = render_to_string(
            'scheduling/emails/reschedule.html',
            context
        )

        # Send email
        return self._send_email(
            recipient_email,
            subject,
            text_content,
            html_content
        )

    def send_in_app_notification(
        self,
        recipient_user,
        notification_type: str,
        title: str,
        message: str,
        action_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send in-app notification.

        Args:
            recipient_user: User object to notify
            notification_type: Type of notification
            title: Notification title
            message: Notification message
            action_url: Optional action URL
            metadata: Optional metadata

        Returns:
            True if sent successfully
        """
        if not NOTIFICATIONS_AVAILABLE:
            return False

        try:
            Notification.objects.create(
                recipient=recipient_user,
                notification_type=notification_type,
                title=title,
                message=message,
                action_url=action_url,
                metadata=metadata or {},
                tenant=self.tenant
            )
            return True
        except Exception:
            return False

    def _send_email(
        self,
        recipient: str,
        subject: str,
        text_content: str,
        html_content: str
    ) -> bool:
        """
        Internal method to send email.

        Args:
            recipient: Recipient email address
            subject: Email subject
            text_content: Plain text content
            html_content: HTML content

        Returns:
            True if sent successfully
        """
        try:
            from_email = getattr(
                settings,
                'DEFAULT_FROM_EMAIL',
                'noreply@zumodra.com'
            )

            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=from_email,
                to=[recipient]
            )
            email.attach_alternative(html_content, "text/html")
            email.send()
            return True
        except Exception as e:
            # Log error
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send email to {recipient}: {e}")
            return False


def send_scheduling_confirmation(
    event_type: str,
    event_instance: Any,
    recipients: List[str],
    tenant=None
) -> None:
    """
    Helper function to send confirmation to multiple recipients.

    Args:
        event_type: 'interview' or 'appointment'
        event_instance: Interview or Appointment model instance
        recipients: List of recipient email addresses
        tenant: Optional tenant context
    """
    service = SchedulingNotificationService(tenant=tenant)

    for recipient in recipients:
        service.send_confirmation_email(
            recipient_email=recipient,
            recipient_name="",  # Override in actual usage
            event_type=event_type,
            event_title=getattr(event_instance, 'title', str(event_instance)),
            scheduled_start=event_instance.scheduled_start,
            scheduled_end=event_instance.scheduled_end,
            location=getattr(event_instance, 'location', None),
            meeting_url=getattr(event_instance, 'meeting_url', None)
        )


def send_scheduling_reminder(
    event_type: str,
    event_instance: Any,
    recipients: List[str],
    reminder_type: str,
    tenant=None
) -> None:
    """
    Helper function to send reminders to multiple recipients.

    Args:
        event_type: 'interview' or 'appointment'
        event_instance: Interview or Appointment model instance
        recipients: List of recipient email addresses
        reminder_type: '1day', '1hour', or '15min'
        tenant: Optional tenant context
    """
    service = SchedulingNotificationService(tenant=tenant)

    for recipient in recipients:
        service.send_reminder_email(
            recipient_email=recipient,
            recipient_name="",  # Override in actual usage
            event_type=event_type,
            event_title=getattr(event_instance, 'title', str(event_instance)),
            scheduled_start=event_instance.scheduled_start,
            scheduled_end=event_instance.scheduled_end,
            reminder_type=reminder_type,
            location=getattr(event_instance, 'location', None),
            meeting_url=getattr(event_instance, 'meeting_url', None)
        )
