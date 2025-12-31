"""
Notification Services for Multi-Channel Notification System.

Provides services for sending notifications via email, SMS, push, in-app, Slack, and webhooks.
"""

import logging
import json
import traceback
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass
from datetime import datetime
import uuid as uuid_lib

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils import timezone
from django.contrib.auth import get_user_model

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from .models import (
    Notification,
    NotificationChannel,
    NotificationTemplate,
    NotificationPreference,
    NotificationDeliveryLog,
    ScheduledNotification,
)

logger = logging.getLogger(__name__)
User = get_user_model()


@dataclass
class NotificationResult:
    """Result of a notification send operation."""
    success: bool
    notification_id: Optional[int] = None
    external_id: Optional[str] = None
    error_message: Optional[str] = None
    channel_type: Optional[str] = None


class BaseNotificationService(ABC):
    """Abstract base class for notification services."""

    channel_type: str = None

    def __init__(self, channel: NotificationChannel = None):
        self.channel = channel

    @abstractmethod
    def send(
        self,
        notification: Notification,
        **kwargs
    ) -> NotificationResult:
        """Send a notification. Must be implemented by subclasses."""
        pass

    def create_delivery_log(
        self,
        notification: Notification,
        status: str,
        request_payload: dict = None,
        response_payload: dict = None,
        response_code: int = None,
        error_type: str = None,
        error_message: str = None,
        external_id: str = None,
        started_at: datetime = None,
    ) -> NotificationDeliveryLog:
        """Create a delivery log entry."""
        completed_at = timezone.now()
        duration_ms = None
        if started_at:
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

        return NotificationDeliveryLog.objects.create(
            notification=notification,
            attempt_number=notification.retry_count + 1,
            status=status,
            request_payload=request_payload or {},
            response_payload=response_payload or {},
            response_code=response_code,
            error_type=error_type or '',
            error_message=error_message or '',
            error_traceback=traceback.format_exc() if error_message else '',
            completed_at=completed_at,
            duration_ms=duration_ms,
            external_id=external_id or '',
        )


class EmailNotificationService(BaseNotificationService):
    """Service for sending email notifications."""

    channel_type = 'email'

    def send(
        self,
        notification: Notification,
        **kwargs
    ) -> NotificationResult:
        """Send an email notification."""
        started_at = timezone.now()

        try:
            recipient_email = notification.recipient.email
            if not recipient_email:
                raise ValueError("Recipient has no email address")

            # Build unsubscribe URL
            prefs = NotificationPreference.objects.filter(user=notification.recipient).first()
            unsubscribe_url = ""
            if prefs:
                unsubscribe_url = f"{settings.SITE_URL if hasattr(settings, 'SITE_URL') else ''}/notifications/unsubscribe/{prefs.unsubscribe_token}/"

            # Prepare context for email template
            context = {
                'notification': notification,
                'recipient': notification.recipient,
                'title': notification.title,
                'message': notification.message,
                'action_url': notification.action_url,
                'action_text': notification.action_text,
                'unsubscribe_url': unsubscribe_url,
                **notification.context_data,
            }

            # Use HTML template if available
            html_content = notification.html_message
            if not html_content and notification.template:
                html_content = notification.template.render_html_body(context)

            # If still no HTML content, try to render from a template file
            if not html_content:
                try:
                    html_content = render_to_string(
                        'notifications/email/notification.html',
                        context
                    )
                except Exception:
                    pass

            # Create email
            email = EmailMultiAlternatives(
                subject=notification.title,
                body=notification.message,
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
                to=[recipient_email],
                headers={
                    'X-Notification-ID': str(notification.uuid),
                    'X-Notification-Type': notification.notification_type,
                    'List-Unsubscribe': f'<{unsubscribe_url}>',
                }
            )

            if html_content:
                email.attach_alternative(html_content, 'text/html')

            # Send email
            email.send(fail_silently=False)

            # Log success
            self.create_delivery_log(
                notification=notification,
                status='sent',
                request_payload={'to': recipient_email, 'subject': notification.title},
                response_payload={'status': 'sent'},
                started_at=started_at,
            )

            notification.mark_as_sent()

            return NotificationResult(
                success=True,
                notification_id=notification.id,
                channel_type=self.channel_type,
            )

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Email notification failed: {error_msg}")

            self.create_delivery_log(
                notification=notification,
                status='failed',
                error_type=type(e).__name__,
                error_message=error_msg,
                started_at=started_at,
            )

            notification.mark_as_failed(error_msg)

            return NotificationResult(
                success=False,
                notification_id=notification.id,
                error_message=error_msg,
                channel_type=self.channel_type,
            )


class SMSNotificationService(BaseNotificationService):
    """Service for sending SMS notifications via Twilio."""

    channel_type = 'sms'

    def __init__(self, channel: NotificationChannel = None):
        super().__init__(channel)
        self.account_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', None)
        self.auth_token = getattr(settings, 'TWILIO_AUTH_TOKEN', None)
        self.from_number = getattr(settings, 'TWILIO_FROM_NUMBER', None)

    def send(
        self,
        notification: Notification,
        phone_number: str = None,
        **kwargs
    ) -> NotificationResult:
        """Send an SMS notification via Twilio."""
        started_at = timezone.now()

        try:
            # Check Twilio configuration
            if not all([self.account_sid, self.auth_token, self.from_number]):
                raise ValueError("Twilio is not configured")

            # Get recipient phone number
            prefs = NotificationPreference.objects.filter(user=notification.recipient).first()
            to_number = phone_number or (prefs.phone_number if prefs else None)

            if not to_number:
                raise ValueError("Recipient has no phone number")

            # Import Twilio client
            try:
                from twilio.rest import Client
            except ImportError:
                raise ImportError("Twilio library is not installed. Install with: pip install twilio")

            client = Client(self.account_sid, self.auth_token)

            # Truncate message for SMS (160 chars typical limit)
            sms_message = notification.message[:1600]  # Twilio supports up to 1600 chars

            # Send SMS
            message = client.messages.create(
                body=sms_message,
                from_=self.from_number,
                to=to_number,
            )

            # Log success
            self.create_delivery_log(
                notification=notification,
                status='sent',
                request_payload={'to': to_number, 'body': sms_message[:100]},
                response_payload={'sid': message.sid, 'status': message.status},
                external_id=message.sid,
                started_at=started_at,
            )

            notification.mark_as_sent(external_id=message.sid)

            return NotificationResult(
                success=True,
                notification_id=notification.id,
                external_id=message.sid,
                channel_type=self.channel_type,
            )

        except Exception as e:
            error_msg = str(e)
            logger.error(f"SMS notification failed: {error_msg}")

            self.create_delivery_log(
                notification=notification,
                status='failed',
                error_type=type(e).__name__,
                error_message=error_msg,
                started_at=started_at,
            )

            notification.mark_as_failed(error_msg)

            return NotificationResult(
                success=False,
                notification_id=notification.id,
                error_message=error_msg,
                channel_type=self.channel_type,
            )


class PushNotificationService(BaseNotificationService):
    """Service for sending push notifications via FCM (Firebase Cloud Messaging) and APNS."""

    channel_type = 'push'

    def __init__(self, channel: NotificationChannel = None):
        super().__init__(channel)
        self.fcm_server_key = getattr(settings, 'FCM_SERVER_KEY', None)

    def send(
        self,
        notification: Notification,
        **kwargs
    ) -> NotificationResult:
        """Send a push notification."""
        started_at = timezone.now()

        try:
            prefs = NotificationPreference.objects.filter(user=notification.recipient).first()

            if not prefs:
                raise ValueError("Recipient has no notification preferences")

            # Try FCM first
            if prefs.fcm_token:
                return self._send_fcm(notification, prefs.fcm_token, started_at)

            # Fall back to APNS
            if prefs.apns_token:
                return self._send_apns(notification, prefs.apns_token, started_at)

            raise ValueError("Recipient has no push notification tokens")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Push notification failed: {error_msg}")

            self.create_delivery_log(
                notification=notification,
                status='failed',
                error_type=type(e).__name__,
                error_message=error_msg,
                started_at=started_at,
            )

            notification.mark_as_failed(error_msg)

            return NotificationResult(
                success=False,
                notification_id=notification.id,
                error_message=error_msg,
                channel_type=self.channel_type,
            )

    def _send_fcm(
        self,
        notification: Notification,
        fcm_token: str,
        started_at: datetime,
    ) -> NotificationResult:
        """Send notification via Firebase Cloud Messaging."""
        import requests

        if not self.fcm_server_key:
            raise ValueError("FCM server key is not configured")

        headers = {
            'Authorization': f'key={self.fcm_server_key}',
            'Content-Type': 'application/json',
        }

        payload = {
            'to': fcm_token,
            'notification': {
                'title': notification.title,
                'body': notification.message[:1024],
                'click_action': notification.action_url or '',
            },
            'data': {
                'notification_id': str(notification.uuid),
                'notification_type': notification.notification_type,
                'action_url': notification.action_url or '',
                **notification.context_data,
            },
        }

        response = requests.post(
            'https://fcm.googleapis.com/fcm/send',
            headers=headers,
            json=payload,
            timeout=30,
        )

        response_data = response.json()

        if response.status_code == 200 and response_data.get('success') == 1:
            self.create_delivery_log(
                notification=notification,
                status='sent',
                request_payload=payload,
                response_payload=response_data,
                response_code=response.status_code,
                started_at=started_at,
            )

            notification.mark_as_sent()

            return NotificationResult(
                success=True,
                notification_id=notification.id,
                channel_type=self.channel_type,
            )
        else:
            error_msg = response_data.get('results', [{}])[0].get('error', 'Unknown FCM error')
            raise Exception(error_msg)

    def _send_apns(
        self,
        notification: Notification,
        apns_token: str,
        started_at: datetime,
    ) -> NotificationResult:
        """Send notification via Apple Push Notification Service."""
        # APNS implementation would require more setup (certificates, etc.)
        # This is a placeholder for the actual implementation
        raise NotImplementedError("APNS support requires additional configuration")


class InAppNotificationService(BaseNotificationService):
    """Service for sending real-time in-app notifications via WebSocket."""

    channel_type = 'in_app'

    def send(
        self,
        notification: Notification,
        **kwargs
    ) -> NotificationResult:
        """Send an in-app notification via WebSocket."""
        started_at = timezone.now()

        try:
            channel_layer = get_channel_layer()

            if not channel_layer:
                raise ValueError("Channel layer is not configured")

            # Prepare notification data for WebSocket
            notification_data = {
                'type': 'notification',
                'data': {
                    'id': notification.id,
                    'uuid': str(notification.uuid),
                    'notification_type': notification.notification_type,
                    'title': notification.title,
                    'message': notification.message[:500],
                    'action_url': notification.action_url,
                    'action_text': notification.action_text,
                    'priority': notification.priority,
                    'created_at': notification.created_at.isoformat(),
                    'sender': {
                        'id': notification.sender.id if notification.sender else None,
                        'username': notification.sender.username if notification.sender else None,
                    } if notification.sender else None,
                }
            }

            # Send to user's personal notification channel
            user_group = f"notifications_{notification.recipient.id}"

            async_to_sync(channel_layer.group_send)(
                user_group,
                {
                    'type': 'send_notification',
                    'notification': notification_data,
                }
            )

            # Log success
            self.create_delivery_log(
                notification=notification,
                status='sent',
                request_payload={'group': user_group, 'data': notification_data},
                response_payload={'status': 'sent_to_channel'},
                started_at=started_at,
            )

            notification.mark_as_sent()

            return NotificationResult(
                success=True,
                notification_id=notification.id,
                channel_type=self.channel_type,
            )

        except Exception as e:
            error_msg = str(e)
            logger.error(f"In-app notification failed: {error_msg}")

            self.create_delivery_log(
                notification=notification,
                status='failed',
                error_type=type(e).__name__,
                error_message=error_msg,
                started_at=started_at,
            )

            notification.mark_as_failed(error_msg)

            return NotificationResult(
                success=False,
                notification_id=notification.id,
                error_message=error_msg,
                channel_type=self.channel_type,
            )


class SlackNotificationService(BaseNotificationService):
    """Service for sending notifications via Slack."""

    channel_type = 'slack'

    def __init__(self, channel: NotificationChannel = None):
        super().__init__(channel)
        self.bot_token = getattr(settings, 'SLACK_BOT_TOKEN', None)
        self.webhook_url = getattr(settings, 'SLACK_WEBHOOK_URL', None)

    def send(
        self,
        notification: Notification,
        slack_channel: str = None,
        **kwargs
    ) -> NotificationResult:
        """Send a Slack notification."""
        started_at = timezone.now()

        try:
            import requests

            # Get recipient's Slack user ID
            prefs = NotificationPreference.objects.filter(user=notification.recipient).first()
            slack_user_id = prefs.slack_user_id if prefs else None

            if not slack_user_id and not slack_channel and not self.webhook_url:
                raise ValueError("No Slack destination configured")

            # Build Slack message blocks
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": notification.title[:150],
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": notification.message[:3000]
                    }
                }
            ]

            if notification.action_url:
                blocks.append({
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": notification.action_text or "View",
                                "emoji": True
                            },
                            "url": notification.action_url,
                            "action_id": f"notification_{notification.uuid}"
                        }
                    ]
                })

            # Add context footer
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Notification ID: {notification.uuid}"
                    }
                ]
            })

            # Try direct message via Bot Token first
            if self.bot_token and slack_user_id:
                return self._send_via_api(
                    notification, slack_user_id, blocks, started_at
                )

            # Fall back to webhook
            if self.webhook_url:
                return self._send_via_webhook(
                    notification, blocks, started_at
                )

            raise ValueError("No Slack sending method available")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Slack notification failed: {error_msg}")

            self.create_delivery_log(
                notification=notification,
                status='failed',
                error_type=type(e).__name__,
                error_message=error_msg,
                started_at=started_at,
            )

            notification.mark_as_failed(error_msg)

            return NotificationResult(
                success=False,
                notification_id=notification.id,
                error_message=error_msg,
                channel_type=self.channel_type,
            )

    def _send_via_api(
        self,
        notification: Notification,
        channel: str,
        blocks: list,
        started_at: datetime,
    ) -> NotificationResult:
        """Send notification via Slack Web API."""
        import requests

        headers = {
            'Authorization': f'Bearer {self.bot_token}',
            'Content-Type': 'application/json',
        }

        payload = {
            'channel': channel,
            'text': notification.title,
            'blocks': blocks,
        }

        response = requests.post(
            'https://slack.com/api/chat.postMessage',
            headers=headers,
            json=payload,
            timeout=30,
        )

        response_data = response.json()

        if response_data.get('ok'):
            external_id = response_data.get('ts')

            self.create_delivery_log(
                notification=notification,
                status='sent',
                request_payload=payload,
                response_payload=response_data,
                response_code=response.status_code,
                external_id=external_id,
                started_at=started_at,
            )

            notification.mark_as_sent(external_id=external_id)

            return NotificationResult(
                success=True,
                notification_id=notification.id,
                external_id=external_id,
                channel_type=self.channel_type,
            )
        else:
            raise Exception(response_data.get('error', 'Unknown Slack API error'))

    def _send_via_webhook(
        self,
        notification: Notification,
        blocks: list,
        started_at: datetime,
    ) -> NotificationResult:
        """Send notification via Slack Webhook."""
        import requests

        payload = {
            'text': notification.title,
            'blocks': blocks,
        }

        response = requests.post(
            self.webhook_url,
            json=payload,
            timeout=30,
        )

        if response.status_code == 200:
            self.create_delivery_log(
                notification=notification,
                status='sent',
                request_payload=payload,
                response_payload={'status': 'ok'},
                response_code=response.status_code,
                started_at=started_at,
            )

            notification.mark_as_sent()

            return NotificationResult(
                success=True,
                notification_id=notification.id,
                channel_type=self.channel_type,
            )
        else:
            raise Exception(f"Webhook failed with status {response.status_code}")


class WebhookNotificationService(BaseNotificationService):
    """Service for sending notifications via custom webhooks."""

    channel_type = 'webhook'

    def send(
        self,
        notification: Notification,
        webhook_url: str = None,
        **kwargs
    ) -> NotificationResult:
        """Send a notification via webhook."""
        started_at = timezone.now()

        try:
            import requests

            url = webhook_url or (self.channel.config.get('url') if self.channel else None)

            if not url:
                raise ValueError("Webhook URL is not configured")

            headers = self.channel.config.get('headers', {}) if self.channel else {}
            headers.setdefault('Content-Type', 'application/json')

            payload = {
                'notification_id': str(notification.uuid),
                'notification_type': notification.notification_type,
                'title': notification.title,
                'message': notification.message,
                'action_url': notification.action_url,
                'recipient_id': notification.recipient.id,
                'sender_id': notification.sender.id if notification.sender else None,
                'created_at': notification.created_at.isoformat(),
                'context_data': notification.context_data,
            }

            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=30,
            )

            if response.status_code in [200, 201, 202]:
                try:
                    response_data = response.json()
                except Exception:
                    response_data = {'status': 'ok'}

                self.create_delivery_log(
                    notification=notification,
                    status='sent',
                    request_payload=payload,
                    response_payload=response_data,
                    response_code=response.status_code,
                    started_at=started_at,
                )

                notification.mark_as_sent()

                return NotificationResult(
                    success=True,
                    notification_id=notification.id,
                    channel_type=self.channel_type,
                )
            else:
                raise Exception(f"Webhook failed with status {response.status_code}")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Webhook notification failed: {error_msg}")

            self.create_delivery_log(
                notification=notification,
                status='failed',
                error_type=type(e).__name__,
                error_message=error_msg,
                started_at=started_at,
            )

            notification.mark_as_failed(error_msg)

            return NotificationResult(
                success=False,
                notification_id=notification.id,
                error_message=error_msg,
                channel_type=self.channel_type,
            )


class NotificationService:
    """
    Main notification dispatcher service.
    Handles routing notifications to appropriate channels based on user preferences.
    """

    SERVICE_MAP = {
        'email': EmailNotificationService,
        'sms': SMSNotificationService,
        'push': PushNotificationService,
        'in_app': InAppNotificationService,
        'slack': SlackNotificationService,
        'webhook': WebhookNotificationService,
    }

    def __init__(self):
        self.channel_services: Dict[str, BaseNotificationService] = {}

    def get_service(self, channel_type: str) -> Optional[BaseNotificationService]:
        """Get or create a service instance for a channel type."""
        if channel_type not in self.channel_services:
            service_class = self.SERVICE_MAP.get(channel_type)
            if service_class:
                channel = NotificationChannel.objects.filter(
                    channel_type=channel_type,
                    is_active=True
                ).first()
                self.channel_services[channel_type] = service_class(channel=channel)
        return self.channel_services.get(channel_type)

    def send_notification(
        self,
        recipient: User,
        notification_type: str,
        title: str,
        message: str,
        channels: List[str] = None,
        sender: User = None,
        action_url: str = None,
        action_text: str = None,
        context_data: dict = None,
        content_object: Any = None,
        priority: str = 'normal',
        template_name: str = None,
        batch_id: str = None,
        respect_preferences: bool = True,
        **kwargs
    ) -> List[NotificationResult]:
        """
        Send a notification to a user through multiple channels.

        Args:
            recipient: The user to send the notification to
            notification_type: Type of notification (from NOTIFICATION_TYPES)
            title: Notification title
            message: Notification message
            channels: List of channel types to send through (defaults to all enabled)
            sender: User who triggered the notification (optional)
            action_url: URL to navigate to when notification is clicked
            action_text: Text for the action button
            context_data: Additional context for template rendering
            content_object: Related model instance
            priority: Notification priority (low, normal, high, urgent)
            template_name: Specific template to use (optional)
            batch_id: Batch ID for bulk notifications
            respect_preferences: Whether to check user preferences
            **kwargs: Additional keyword arguments passed to channel services

        Returns:
            List of NotificationResult for each channel
        """
        results = []
        context_data = context_data or {}

        # Get user preferences
        prefs, _ = NotificationPreference.objects.get_or_create(user=recipient)

        # Check global preferences
        if respect_preferences:
            if not prefs.notifications_enabled or prefs.global_unsubscribe:
                logger.info(f"Notifications disabled for user {recipient.id}")
                return results

            if prefs.is_quiet_hours() and priority not in ['high', 'urgent']:
                logger.info(f"Quiet hours active for user {recipient.id}")
                # Could queue for later or skip based on requirements
                pass

        # Determine channels to use
        if channels is None:
            channels = ['in_app', 'email']  # Default channels

        # Get active channel models
        active_channels = NotificationChannel.objects.filter(
            channel_type__in=channels,
            is_active=True
        )

        for channel in active_channels:
            # Check user preference for this channel and type
            if respect_preferences:
                if not prefs.is_type_enabled(notification_type, channel.channel_type):
                    logger.info(
                        f"Channel {channel.channel_type} disabled for {notification_type} "
                        f"for user {recipient.id}"
                    )
                    continue

            # Get template if specified
            template = None
            if template_name:
                template = NotificationTemplate.objects.filter(
                    name=template_name,
                    channel=channel,
                    is_active=True
                ).first()
            else:
                template = NotificationTemplate.objects.filter(
                    template_type=notification_type,
                    channel=channel,
                    language=getattr(recipient, 'language', 'en') or 'en',
                    is_active=True
                ).first()

            # Render content from template if available
            rendered_title = title
            rendered_message = message
            rendered_html = ""

            if template:
                full_context = {
                    'recipient': recipient,
                    'sender': sender,
                    'action_url': action_url,
                    'action_text': action_text,
                    **template.default_context,
                    **context_data,
                }
                rendered_title = template.render_subject(full_context) or title
                rendered_message = template.render_body(full_context) or message
                rendered_html = template.render_html_body(full_context)

            # Create notification record
            notification = Notification.objects.create(
                recipient=recipient,
                sender=sender,
                channel=channel,
                notification_type=notification_type,
                template=template,
                title=rendered_title,
                message=rendered_message,
                html_message=rendered_html,
                action_url=action_url or '',
                action_text=action_text or 'View',
                context_data=context_data,
                priority=priority,
                status='pending',
                batch_id=batch_id,
            )

            # Set content object if provided
            if content_object:
                from django.contrib.contenttypes.models import ContentType
                notification.content_type = ContentType.objects.get_for_model(content_object)
                notification.object_id = content_object.pk
                notification.save(update_fields=['content_type', 'object_id'])

            # Get service and send
            service = self.get_service(channel.channel_type)
            if service:
                result = service.send(notification, **kwargs)
                results.append(result)
            else:
                logger.warning(f"No service found for channel type: {channel.channel_type}")
                notification.mark_as_failed(f"No service for channel: {channel.channel_type}")
                results.append(NotificationResult(
                    success=False,
                    notification_id=notification.id,
                    error_message=f"No service for channel: {channel.channel_type}",
                    channel_type=channel.channel_type,
                ))

        return results

    def send_bulk_notification(
        self,
        recipients: List[User],
        notification_type: str,
        title: str,
        message: str,
        channels: List[str] = None,
        batch_id: str = None,
        **kwargs
    ) -> Dict[int, List[NotificationResult]]:
        """
        Send the same notification to multiple users.

        Args:
            recipients: List of users to send to
            notification_type: Type of notification
            title: Notification title
            message: Notification message
            channels: List of channel types
            batch_id: Batch ID (generated if not provided)
            **kwargs: Additional arguments passed to send_notification

        Returns:
            Dictionary mapping user IDs to their notification results
        """
        if not batch_id:
            batch_id = str(uuid_lib.uuid4())

        results = {}
        for recipient in recipients:
            try:
                user_results = self.send_notification(
                    recipient=recipient,
                    notification_type=notification_type,
                    title=title,
                    message=message,
                    channels=channels,
                    batch_id=batch_id,
                    **kwargs
                )
                results[recipient.id] = user_results
            except Exception as e:
                logger.error(f"Failed to send bulk notification to user {recipient.id}: {e}")
                results[recipient.id] = [NotificationResult(
                    success=False,
                    error_message=str(e),
                )]

        return results

    def get_unread_count(self, user: User) -> int:
        """Get the count of unread notifications for a user."""
        return Notification.objects.filter(
            recipient=user,
            is_read=False,
            is_dismissed=False,
            status__in=['sent', 'delivered'],
        ).count()

    def mark_all_as_read(self, user: User) -> int:
        """Mark all notifications as read for a user."""
        updated = Notification.objects.filter(
            recipient=user,
            is_read=False,
        ).update(
            is_read=True,
            read_at=timezone.now(),
            status='read',
        )
        return updated

    def dismiss_all(self, user: User) -> int:
        """Dismiss all notifications for a user."""
        updated = Notification.objects.filter(
            recipient=user,
            is_dismissed=False,
        ).update(
            is_dismissed=True,
            dismissed_at=timezone.now(),
        )
        return updated


# Singleton instance
notification_service = NotificationService()


def send_notification(
    recipient: User,
    notification_type: str,
    title: str,
    message: str,
    **kwargs
) -> List[NotificationResult]:
    """Convenience function for sending notifications."""
    return notification_service.send_notification(
        recipient=recipient,
        notification_type=notification_type,
        title=title,
        message=message,
        **kwargs
    )
