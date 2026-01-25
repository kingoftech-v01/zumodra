"""
WebSocket URL routing for services_public app.

Defines WebSocket URL patterns for real-time features:
- Service catalog filtering
- Interactive map marker updates
"""

from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/services-catalog/$', consumers.ServiceCatalogConsumer.as_asgi()),
    re_path(r'ws/services-map/$', consumers.ServiceMapConsumer.as_asgi()),
]
