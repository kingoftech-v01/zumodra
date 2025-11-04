"""
ASGI config for zumodra project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.core.asgi import get_asgi_application
import messages_sys.routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'zumodra.settings')

# application = ProtocolTypeRouter({
#     "http": get_asgi_application(),
#     "websocket": AuthMiddlewareStack(
#         URLRouter(
#             messages_sys.routing.websocket_urlpatterns
#         )
#     ),
# })

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            URLRouter(
                your_routing.websocket_urlpatterns + messages_sys.routing.websocket_urlpatterns
            )
        )
    ),
})
