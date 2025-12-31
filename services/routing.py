"""
Services WebSocket Routing - Zumodra Freelance Marketplace

WebSocket URL routing for the services app.
"""

from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/location/$', consumers.LocationConsumer.as_asgi()),
    re_path(r'ws/provider-status/$', consumers.ProviderStatusConsumer.as_asgi()),
]
