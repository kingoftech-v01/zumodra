"""
Notifications App for Zumodra.

Multi-channel notification system supporting email, SMS, push notifications,
in-app notifications, Slack, and webhooks.

Features:
- Multi-channel delivery (email, SMS, push, in-app, Slack, webhook)
- Template-based notifications with Django template syntax
- User preferences and quiet hours
- Scheduled and recurring notifications
- Real-time WebSocket notifications
- Delivery tracking and retry logic
- Bulk notification support
- Unsubscribe management

Usage:
    from notifications.services import send_notification

    send_notification(
        recipient=user,
        notification_type='proposal_received',
        title='New Proposal',
        message='You received a new proposal',
        channels=['email', 'in_app'],
        action_url='/proposals/123/',
    )
"""

default_app_config = 'notifications.apps.NotificationsConfig'
