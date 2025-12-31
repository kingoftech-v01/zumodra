"""
WebSocket URL routing for notifications app.
"""

from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    # User-specific notification channel
    re_path(r'ws/notifications/$', consumers.NotificationConsumer.as_asgi()),

    # System-wide broadcast channel
    re_path(r'ws/notifications/broadcast/$', consumers.BroadcastNotificationConsumer.as_asgi()),
]
