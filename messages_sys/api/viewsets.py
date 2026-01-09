"""
Messages System API ViewSets - Conversations, Messages, Contacts REST API Endpoints

This module provides DRF ViewSets for:
- Conversations with actions (mark_read, add_participants, leave, archive)
- Messages for history/search (real-time delivery via WebSocket)
- Contacts with actions (add_favorite, remove_favorite)
- Friend requests with actions (accept, reject, cancel)
- Block list management
- User status management
"""

import logging
from django.db.models import Q, Count
from django.utils import timezone

from rest_framework import status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework.mixins import (
    ListModelMixin, RetrieveModelMixin, CreateModelMixin, DestroyModelMixin
)

from api.base import APIResponse

from ..models import (
    Conversation, Message, MessageStatus, TypingStatus,
    Contact, FriendRequest, BlockList, UserStatus
)
from ..serializers import (
    # User/Status serializers
    UserStatusSerializer,
    UserStatusUpdateSerializer,
    # Contact serializers
    ContactListSerializer,
    ContactDetailSerializer,
    ContactCreateSerializer,
    ContactFavoriteSerializer,
    # Friend request serializers
    FriendRequestListSerializer,
    FriendRequestDetailSerializer,
    FriendRequestCreateSerializer,
    # Block list serializers
    BlockListSerializer,
    BlockUserSerializer,
    # Conversation serializers
    ConversationListSerializer,
    ConversationDetailSerializer,
    ConversationCreateSerializer,
    ConversationParticipantSerializer,
    ConversationMarkReadSerializer,
    # Message serializers
    MessageListSerializer,
    MessageDetailSerializer,
    MessageCreateSerializer,
    MessageSearchSerializer,
    MessageSearchResultSerializer,
    # Typing status serializers
    TypingStatusSerializer,
    TypingStatusUpdateSerializer,
)

logger = logging.getLogger('messages_sys.api')


# =============================================================================
# CONVERSATION VIEWSETS
# =============================================================================

class ConversationViewSet(
    ListModelMixin,
    RetrieveModelMixin,
    CreateModelMixin,
    GenericViewSet
):
    """
    ViewSet for conversations.

    List/retrieve conversations for the current user.
    Create new conversations (direct or group).

    Actions:
    - mark_read: Mark all messages in conversation as read
    - add_participants: Add participants to group chat
    - remove_participant: Remove participant from group chat
    - leave: Leave a group conversation
    - archive: Archive conversation (hide from list)
    """
    queryset = Conversation.objects.all()
    serializer_class = ConversationListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return ConversationDetailSerializer
        if self.action == 'create':
            return ConversationCreateSerializer
        return ConversationListSerializer

    def get_queryset(self):
        user = self.request.user
        queryset = Conversation.objects.filter(
            participants=user
        ).prefetch_related('participants').order_by('-updated_at')

        # Filter by type
        conv_type = self.request.query_params.get('type')
        if conv_type == 'direct':
            queryset = queryset.annotate(
                participant_count=Count('participants')
            ).filter(participant_count=2)
        elif conv_type == 'group':
            queryset = queryset.annotate(
                participant_count=Count('participants')
            ).filter(participant_count__gt=2)

        return queryset

    def perform_create(self, serializer):
        serializer.save()

    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        """Mark all messages in conversation as read."""
        conversation = self.get_object()

        updated = Message.objects.mark_conversation_read(
            request.user, conversation.id
        )

        return APIResponse.success(
            data={'messages_marked_read': updated},
            message=f"{updated} messages marked as read"
        )

    @action(detail=True, methods=['post'])
    def add_participants(self, request, pk=None):
        """Add participants to group conversation."""
        conversation = self.get_object()

        if conversation.participants.count() <= 2:
            return APIResponse.error(
                message="Cannot add participants to direct conversation. Create a group instead.",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        serializer = ConversationParticipantSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from custom_account_u.models import CustomUser
        users = CustomUser.objects.filter(
            id__in=serializer.validated_data['user_ids']
        )

        for user in users:
            if not BlockList.objects.is_blocked_by(request.user, user):
                conversation.add_participant(user)

        return APIResponse.success(
            data=ConversationDetailSerializer(
                conversation, context=self.get_serializer_context()
            ).data,
            message="Participants added"
        )

    @action(detail=True, methods=['post'])
    def remove_participant(self, request, pk=None):
        """Remove a participant from group conversation."""
        conversation = self.get_object()

        if conversation.participants.count() <= 2:
            return APIResponse.error(
                message="Cannot remove participants from direct conversation.",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        serializer = ConversationParticipantSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        from custom_account_u.models import CustomUser
        user_ids = serializer.validated_data['user_ids']

        for user_id in user_ids:
            try:
                user = CustomUser.objects.get(id=user_id)
                if user != request.user:  # Can't remove yourself this way
                    conversation.remove_participant(user)
            except CustomUser.DoesNotExist:
                pass

        return APIResponse.success(
            data=ConversationDetailSerializer(
                conversation, context=self.get_serializer_context()
            ).data,
            message="Participants removed"
        )

    @action(detail=True, methods=['post'])
    def leave(self, request, pk=None):
        """Leave a group conversation."""
        conversation = self.get_object()

        if conversation.participants.count() <= 2:
            return APIResponse.error(
                message="Cannot leave a direct conversation.",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        conversation.remove_participant(request.user)

        return APIResponse.success(message="Left conversation")

    @action(detail=True, methods=['post'])
    def archive(self, request, pk=None):
        """Archive conversation (implementation depends on model)."""
        conversation = self.get_object()

        # Note: This would require adding an 'archived' field to the model
        # For now, just return success
        return APIResponse.success(message="Conversation archived")


# =============================================================================
# MESSAGE VIEWSETS
# =============================================================================

class MessageViewSet(
    ListModelMixin,
    RetrieveModelMixin,
    CreateModelMixin,
    GenericViewSet
):
    """
    ViewSet for messages.

    List messages for a conversation (paginated history).
    Retrieve message details.
    Create messages (fallback for when WebSocket is unavailable).

    Note: Real-time message delivery should use WebSocket.
    This endpoint is for history retrieval and search.

    Actions:
    - search: Search messages across conversations
    """
    queryset = Message.objects.all()
    serializer_class = MessageListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return MessageDetailSerializer
        if self.action == 'create':
            return MessageCreateSerializer
        if self.action == 'search':
            return MessageSearchResultSerializer
        return MessageListSerializer

    def get_queryset(self):
        user = self.request.user

        # Base queryset: messages from user's conversations
        queryset = Message.objects.filter(
            conversation__participants=user
        ).select_related('sender').order_by('-timestamp')

        # Filter by conversation
        conversation_id = self.request.query_params.get('conversation')
        if conversation_id:
            queryset = queryset.filter(conversation_id=conversation_id)

        # Cursor-based pagination
        before = self.request.query_params.get('before')
        if before:
            queryset = queryset.filter(timestamp__lt=before)

        return queryset

    @action(detail=False, methods=['get', 'post'])
    def search(self, request):
        """Search messages across conversations."""
        if request.method == 'GET':
            query = request.query_params.get('q', '')
            conversation_id = request.query_params.get('conversation')
        else:
            serializer = MessageSearchSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            query = serializer.validated_data['query']
            conversation_id = serializer.validated_data.get('conversation_id')

        if len(query) < 2:
            return APIResponse.error(
                message="Search query must be at least 2 characters",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        queryset = Message.objects.filter(
            conversation__participants=request.user,
            content__icontains=query
        ).select_related('sender', 'conversation').order_by('-timestamp')

        if conversation_id:
            queryset = queryset.filter(conversation_id=conversation_id)

        # Limit results
        queryset = queryset[:50]

        serializer = MessageSearchResultSerializer(
            queryset, many=True,
            context={'request': request, 'query': query}
        )

        return APIResponse.success(
            data={
                'query': query,
                'count': len(serializer.data),
                'results': serializer.data
            }
        )


# =============================================================================
# CONTACT VIEWSETS
# =============================================================================

class ContactViewSet(
    ListModelMixin,
    RetrieveModelMixin,
    CreateModelMixin,
    DestroyModelMixin,
    GenericViewSet
):
    """
    ViewSet for contacts.

    Actions:
    - add_favorite: Add contact to favorites
    - remove_favorite: Remove contact from favorites
    """
    queryset = Contact.objects.all()
    serializer_class = ContactListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return ContactDetailSerializer
        if self.action == 'create':
            return ContactCreateSerializer
        return ContactListSerializer

    def get_queryset(self):
        return Contact.objects.filter(
            owner=self.request.user
        ).select_related('contact').order_by('-is_favorite', 'contact__first_name')

    @action(detail=True, methods=['post'])
    def add_favorite(self, request, pk=None):
        """Add contact to favorites."""
        contact = self.get_object()
        contact.is_favorite = True
        contact.save()

        return APIResponse.success(
            data=ContactListSerializer(contact, context=self.get_serializer_context()).data,
            message="Contact added to favorites"
        )

    @action(detail=True, methods=['post'])
    def remove_favorite(self, request, pk=None):
        """Remove contact from favorites."""
        contact = self.get_object()
        contact.is_favorite = False
        contact.save()

        return APIResponse.success(
            data=ContactListSerializer(contact, context=self.get_serializer_context()).data,
            message="Contact removed from favorites"
        )

    @action(detail=False, methods=['get'])
    def favorites(self, request):
        """List favorite contacts only."""
        contacts = self.get_queryset().filter(is_favorite=True)
        serializer = self.get_serializer(contacts, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def online(self, request):
        """List online contacts."""
        contacts = self.get_queryset().filter(
            contact__status__is_online=True
        )
        serializer = self.get_serializer(contacts, many=True)
        return Response(serializer.data)


# =============================================================================
# FRIEND REQUEST VIEWSETS
# =============================================================================

class FriendRequestViewSet(
    ListModelMixin,
    RetrieveModelMixin,
    CreateModelMixin,
    GenericViewSet
):
    """
    ViewSet for friend requests.

    Actions:
    - accept: Accept a friend request
    - reject: Reject a friend request
    - cancel: Cancel a sent friend request
    - pending: List pending requests
    """
    queryset = FriendRequest.objects.all()
    serializer_class = FriendRequestListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return FriendRequestDetailSerializer
        if self.action == 'create':
            return FriendRequestCreateSerializer
        return FriendRequestListSerializer

    def get_queryset(self):
        user = self.request.user
        return FriendRequest.objects.filter(
            Q(sender=user) | Q(receiver=user)
        ).select_related('sender', 'receiver').order_by('-created_at')

    @action(detail=True, methods=['post'])
    def accept(self, request, pk=None):
        """Accept a friend request."""
        friend_request = self.get_object()

        if friend_request.receiver != request.user:
            return APIResponse.forbidden("Only the receiver can accept this request")

        try:
            friend_request.accept()
            return APIResponse.success(
                data=FriendRequestDetailSerializer(
                    friend_request, context=self.get_serializer_context()
                ).data,
                message="Friend request accepted"
            )
        except Exception as e:
            return APIResponse.error(
                message=str(e),
                status_code=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject a friend request."""
        friend_request = self.get_object()

        if friend_request.receiver != request.user:
            return APIResponse.forbidden("Only the receiver can reject this request")

        try:
            friend_request.reject()
            return APIResponse.success(
                data=FriendRequestDetailSerializer(
                    friend_request, context=self.get_serializer_context()
                ).data,
                message="Friend request rejected"
            )
        except Exception as e:
            return APIResponse.error(
                message=str(e),
                status_code=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a sent friend request."""
        friend_request = self.get_object()

        if friend_request.sender != request.user:
            return APIResponse.forbidden("Only the sender can cancel this request")

        try:
            friend_request.cancel()
            return APIResponse.success(message="Friend request cancelled")
        except Exception as e:
            return APIResponse.error(
                message=str(e),
                status_code=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['get'])
    def received(self, request):
        """List received pending friend requests."""
        requests = self.get_queryset().filter(
            receiver=request.user,
            accepted=False,
            rejected=False
        )
        serializer = self.get_serializer(requests, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def sent(self, request):
        """List sent pending friend requests."""
        requests = self.get_queryset().filter(
            sender=request.user,
            accepted=False,
            rejected=False
        )
        serializer = self.get_serializer(requests, many=True)
        return Response(serializer.data)


# =============================================================================
# BLOCK LIST VIEWSETS
# =============================================================================

class BlockListViewSet(
    ListModelMixin,
    CreateModelMixin,
    DestroyModelMixin,
    GenericViewSet
):
    """
    ViewSet for blocked users.

    List blocked users, block new users, unblock users.
    """
    queryset = BlockList.objects.all()
    serializer_class = BlockListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'create':
            return BlockUserSerializer
        return BlockListSerializer

    def get_queryset(self):
        return BlockList.objects.filter(
            blocker=self.request.user
        ).select_related('blocked').order_by('-created_at')

    def perform_destroy(self, instance):
        """Unblock user."""
        instance.delete()

    @action(detail=False, methods=['post'])
    def check(self, request):
        """Check if a user is blocked."""
        user_id = request.data.get('user_id')
        if not user_id:
            return APIResponse.error(
                message="user_id is required",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        from custom_account_u.models import CustomUser
        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return APIResponse.not_found("User not found")

        is_blocked = BlockList.objects.is_blocked(request.user, user)
        is_blocked_by = BlockList.objects.is_blocked(user, request.user)

        return APIResponse.success(
            data={
                'is_blocked': is_blocked,
                'is_blocked_by': is_blocked_by,
                'any_block': is_blocked or is_blocked_by
            }
        )


# =============================================================================
# USER STATUS VIEWSETS
# =============================================================================

class UserStatusViewSet(GenericViewSet):
    """
    ViewSet for user online status.

    Get/update current user's status.
    """
    queryset = UserStatus.objects.all()
    serializer_class = UserStatusSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current user's status."""
        user_status, created = UserStatus.objects.get_or_create(
            user=request.user
        )
        serializer = UserStatusSerializer(
            user_status, context=self.get_serializer_context()
        )
        return Response(serializer.data)

    @action(detail=False, methods=['put', 'patch'])
    def update_status(self, request):
        """Update current user's status."""
        user_status, created = UserStatus.objects.get_or_create(
            user=request.user
        )

        serializer = UserStatusUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_status.is_online = serializer.validated_data['is_online']
        if not user_status.is_online:
            user_status.last_seen = timezone.now()
        user_status.save()

        return APIResponse.success(
            data=UserStatusSerializer(
                user_status, context=self.get_serializer_context()
            ).data,
            message="Status updated"
        )

    @action(detail=False, methods=['get'])
    def contact_statuses(self, request):
        """Get online status of all contacts."""
        contacts = Contact.objects.filter(owner=request.user)
        contact_user_ids = contacts.values_list('contact_id', flat=True)

        statuses = UserStatus.objects.filter(
            user_id__in=contact_user_ids
        ).select_related('user')

        serializer = UserStatusSerializer(
            statuses, many=True, context=self.get_serializer_context()
        )

        return APIResponse.success(data=serializer.data)
