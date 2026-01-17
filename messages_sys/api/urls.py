"""
Messages System API URLs

Routes for conversations, messages, contacts, and user status endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .viewsets import (
    ConversationViewSet,
    MessageViewSet,
    ContactViewSet,
    FriendRequestViewSet,
    BlockListViewSet,
    UserStatusViewSet,
)

app_name = 'messages_sys'

router = DefaultRouter()

# Conversation endpoints
router.register(r'conversations', ConversationViewSet, basename='conversation')

# Message endpoints
router.register(r'messages', MessageViewSet, basename='message')

# Contact management
router.register(r'contacts', ContactViewSet, basename='contact')
router.register(r'friend-requests', FriendRequestViewSet, basename='friend-request')
router.register(r'blocked', BlockListViewSet, basename='blocked')

# User status
router.register(r'status', UserStatusViewSet, basename='user-status')

urlpatterns = [
    path('', include(router.urls)),
]
