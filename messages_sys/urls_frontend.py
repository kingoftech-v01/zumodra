"""
Messages System Frontend URLs - Real-time messaging with WebSocket support.

This module provides frontend URL routing for the messaging system:
- Main chat view
- Conversation management
- Message operations
"""

from django.urls import path
from .views import chat_view

app_name = 'messages_sys'  # Changed from 'messages' to match API namespace (2026-01-18)

urlpatterns = [
    path('', chat_view, name='index'),
]
