"""
WebSocket routing configuration for jobs_public app.

Defines URL patterns for WebSocket connections to receive real-time job updates.

Routing:
    ws://domain/ws/jobs/public/ → PublicJobsConsumer
"""

from django.urls import re_path
from . import consumer

websocket_urlpatterns = [
    re_path(r'ws/jobs/public/$', consumer.PublicJobsConsumer.as_asgi()),
]
