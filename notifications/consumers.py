"""
WebSocket Consumers for Real-Time Notifications.

Provides WebSocket support for delivering notifications in real-time.
"""

import json
import logging
from typing import Optional
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone

logger = logging.getLogger(__name__)


class NotificationConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for real-time notifications.

    Each user connects to their own notification channel group.
    """

    async def connect(self):
        """Handle WebSocket connection."""
        self.user = self.scope.get('user')

        if not self.user or not self.user.is_authenticated:
            await self.close(code=4001)
            return

        # Create a unique group for this user's notifications
        self.user_group = f"notifications_{self.user.id}"

        # Join the user's notification group
        await self.channel_layer.group_add(
            self.user_group,
            self.channel_name
        )

        await self.accept()

        # Send initial connection confirmation with unread count
        unread_count = await self.get_unread_count()
        await self.send_json({
            'type': 'connection_established',
            'user_id': self.user.id,
            'unread_count': unread_count,
            'timestamp': timezone.now().isoformat(),
        })

        logger.info(f"User {self.user.id} connected to notifications")

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'user_group'):
            await self.channel_layer.group_discard(
                self.user_group,
                self.channel_name
            )
            logger.info(f"User {self.user.id} disconnected from notifications")

    async def receive(self, text_data=None, bytes_data=None):
        """Handle incoming WebSocket messages."""
        if not text_data:
            return

        try:
            data = json.loads(text_data)
            message_type = data.get('type')

            if message_type == 'mark_read':
                await self.handle_mark_read(data)
            elif message_type == 'mark_all_read':
                await self.handle_mark_all_read()
            elif message_type == 'dismiss':
                await self.handle_dismiss(data)
            elif message_type == 'get_unread_count':
                await self.handle_get_unread_count()
            elif message_type == 'get_notifications':
                await self.handle_get_notifications(data)
            elif message_type == 'ping':
                await self.send_json({'type': 'pong'})
            else:
                await self.send_json({
                    'type': 'error',
                    'message': f'Unknown message type: {message_type}'
                })

        except json.JSONDecodeError:
            await self.send_json({
                'type': 'error',
                'message': 'Invalid JSON'
            })
        except Exception as e:
            logger.error(f"Error handling WebSocket message: {e}")
            await self.send_json({
                'type': 'error',
                'message': 'Internal server error'
            })

    async def handle_mark_read(self, data):
        """Mark a notification as read."""
        notification_id = data.get('notification_id')
        if notification_id:
            success = await self.mark_notification_read(notification_id)
            unread_count = await self.get_unread_count()
            await self.send_json({
                'type': 'mark_read_response',
                'notification_id': notification_id,
                'success': success,
                'unread_count': unread_count,
            })

    async def handle_mark_all_read(self):
        """Mark all notifications as read."""
        count = await self.mark_all_read()
        await self.send_json({
            'type': 'mark_all_read_response',
            'success': True,
            'count': count,
            'unread_count': 0,
        })

    async def handle_dismiss(self, data):
        """Dismiss a notification."""
        notification_id = data.get('notification_id')
        if notification_id:
            success = await self.dismiss_notification(notification_id)
            unread_count = await self.get_unread_count()
            await self.send_json({
                'type': 'dismiss_response',
                'notification_id': notification_id,
                'success': success,
                'unread_count': unread_count,
            })

    async def handle_get_unread_count(self):
        """Get current unread count."""
        count = await self.get_unread_count()
        await self.send_json({
            'type': 'unread_count',
            'count': count,
        })

    async def handle_get_notifications(self, data):
        """Get recent notifications."""
        limit = min(data.get('limit', 20), 100)
        offset = data.get('offset', 0)
        unread_only = data.get('unread_only', False)

        notifications = await self.get_notifications(limit, offset, unread_only)
        await self.send_json({
            'type': 'notifications_list',
            'notifications': notifications,
            'limit': limit,
            'offset': offset,
        })

    # ===== Channel layer handlers =====

    async def send_notification(self, event):
        """
        Handle notification sent from channel layer.

        This is called when a notification is sent via the InAppNotificationService.
        """
        notification = event.get('notification', {})

        # Send to WebSocket client
        await self.send_json({
            'type': 'new_notification',
            **notification.get('data', {}),
        })

        # Also send updated unread count
        unread_count = await self.get_unread_count()
        await self.send_json({
            'type': 'unread_count_update',
            'count': unread_count,
        })

    async def notification_read(self, event):
        """Handle notification read event from another client."""
        await self.send_json({
            'type': 'notification_read',
            'notification_id': event.get('notification_id'),
        })

    async def notification_dismissed(self, event):
        """Handle notification dismissed event from another client."""
        await self.send_json({
            'type': 'notification_dismissed',
            'notification_id': event.get('notification_id'),
        })

    async def unread_count_update(self, event):
        """Handle unread count update event."""
        await self.send_json({
            'type': 'unread_count_update',
            'count': event.get('count', 0),
        })

    # ===== Database operations =====

    @database_sync_to_async
    def get_unread_count(self) -> int:
        """Get count of unread notifications."""
        from .models import Notification
        return Notification.objects.filter(
            recipient=self.user,
            is_read=False,
            is_dismissed=False,
        ).count()

    @database_sync_to_async
    def mark_notification_read(self, notification_id: int) -> bool:
        """Mark a specific notification as read."""
        from .models import Notification
        try:
            notification = Notification.objects.get(
                id=notification_id,
                recipient=self.user,
            )
            notification.mark_as_read()
            return True
        except Notification.DoesNotExist:
            return False

    @database_sync_to_async
    def mark_all_read(self) -> int:
        """Mark all notifications as read."""
        from .models import Notification
        return Notification.objects.filter(
            recipient=self.user,
            is_read=False,
        ).update(
            is_read=True,
            read_at=timezone.now(),
            status='read',
        )

    @database_sync_to_async
    def dismiss_notification(self, notification_id: int) -> bool:
        """Dismiss a specific notification."""
        from .models import Notification
        try:
            notification = Notification.objects.get(
                id=notification_id,
                recipient=self.user,
            )
            notification.dismiss()
            return True
        except Notification.DoesNotExist:
            return False

    @database_sync_to_async
    def get_notifications(
        self,
        limit: int = 20,
        offset: int = 0,
        unread_only: bool = False
    ) -> list:
        """Get notifications for the user."""
        from .models import Notification

        queryset = Notification.objects.filter(
            recipient=self.user,
            is_dismissed=False,
        ).select_related('channel', 'sender')

        if unread_only:
            queryset = queryset.filter(is_read=False)

        notifications = queryset.order_by('-created_at')[offset:offset + limit]

        return [
            {
                'id': n.id,
                'uuid': str(n.uuid),
                'notification_type': n.notification_type,
                'title': n.title,
                'message': n.message[:200],  # Truncate for list view
                'action_url': n.action_url,
                'action_text': n.action_text,
                'priority': n.priority,
                'is_read': n.is_read,
                'created_at': n.created_at.isoformat(),
                'sender': {
                    'id': n.sender.id,
                    'username': n.sender.username,
                } if n.sender else None,
                'channel_type': n.channel.channel_type if n.channel else None,
            }
            for n in notifications
        ]

    # ===== Utility methods =====

    async def send_json(self, content: dict):
        """Send JSON data to the WebSocket client."""
        await self.send(text_data=json.dumps(content))


class BroadcastNotificationConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for system-wide broadcast notifications.

    Used for system announcements, maintenance notices, etc.
    """

    BROADCAST_GROUP = 'notifications_broadcast'

    async def connect(self):
        """Handle WebSocket connection."""
        self.user = self.scope.get('user')

        if not self.user or not self.user.is_authenticated:
            await self.close(code=4001)
            return

        # Join the broadcast group
        await self.channel_layer.group_add(
            self.BROADCAST_GROUP,
            self.channel_name
        )

        await self.accept()

        await self.send_json({
            'type': 'connection_established',
            'channel': 'broadcast',
        })

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        await self.channel_layer.group_discard(
            self.BROADCAST_GROUP,
            self.channel_name
        )

    async def receive(self, text_data=None, bytes_data=None):
        """Handle incoming messages (minimal for broadcast channel)."""
        if text_data:
            try:
                data = json.loads(text_data)
                if data.get('type') == 'ping':
                    await self.send_json({'type': 'pong'})
            except json.JSONDecodeError:
                pass

    async def broadcast_notification(self, event):
        """Handle broadcast notification event."""
        await self.send_json({
            'type': 'broadcast',
            'title': event.get('title'),
            'message': event.get('message'),
            'priority': event.get('priority', 'normal'),
            'action_url': event.get('action_url'),
            'notification_type': event.get('notification_type', 'system_maintenance'),
            'timestamp': timezone.now().isoformat(),
        })

    async def send_json(self, content: dict):
        """Send JSON data to the WebSocket client."""
        await self.send(text_data=json.dumps(content))


# Helper function to send broadcast notifications
async def send_broadcast_notification(
    title: str,
    message: str,
    notification_type: str = 'system_maintenance',
    priority: str = 'normal',
    action_url: str = None,
):
    """
    Send a broadcast notification to all connected users.

    Usage:
        from notifications.consumers import send_broadcast_notification
        await send_broadcast_notification(
            title="System Maintenance",
            message="The system will be down for maintenance...",
        )
    """
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    channel_layer = get_channel_layer()

    await channel_layer.group_send(
        BroadcastNotificationConsumer.BROADCAST_GROUP,
        {
            'type': 'broadcast_notification',
            'title': title,
            'message': message,
            'notification_type': notification_type,
            'priority': priority,
            'action_url': action_url,
        }
    )


# Synchronous version for use in regular Django views
def send_broadcast_notification_sync(
    title: str,
    message: str,
    notification_type: str = 'system_maintenance',
    priority: str = 'normal',
    action_url: str = None,
):
    """Synchronous wrapper for send_broadcast_notification."""
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    channel_layer = get_channel_layer()

    async_to_sync(channel_layer.group_send)(
        BroadcastNotificationConsumer.BROADCAST_GROUP,
        {
            'type': 'broadcast_notification',
            'title': title,
            'message': message,
            'notification_type': notification_type,
            'priority': priority,
            'action_url': action_url,
        }
    )
