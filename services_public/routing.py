"""
Services Public WebSocket Routing

WebSocket URL routing for real-time service catalog features.

URLs:
- ws://<domain>/ws/services-catalog/ → ServiceCatalogConsumer
- ws://<domain>/ws/services-map/ → ServiceMapConsumer
"""

from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    # Real-time catalog filtering
    re_path(
        r'ws/services-catalog/$',
        consumers.ServiceCatalogConsumer.as_asgi(),
        name='ws_services_catalog'
    ),

    # Interactive map updates
    re_path(
        r'ws/services-map/$',
        consumers.ServiceMapConsumer.as_asgi(),
        name='ws_services_map'
    ),
]
