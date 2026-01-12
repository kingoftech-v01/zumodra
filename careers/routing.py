"""
WebSocket routing for careers app.
"""

from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/careers/live/', consumers.CareersLiveUpdateConsumer.as_asgi()),
]
