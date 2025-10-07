from django.urls import re_path
from . import consumer

websockets_urlpatterns = [
    re_path(r'ws/chat/(?P<conversation_id>\w+)/$', consumer.ChatConsumer.as_asgi()),
]

websocket_urlpatterns = websockets_urlpatterns