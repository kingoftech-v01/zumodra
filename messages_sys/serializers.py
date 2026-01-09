"""
Messages System API Serializers - Conversations, Messages, Contacts REST API Serializers

This module provides DRF serializers for:
- Conversations (list, detail, create)
- Messages (for history/search - real-time via WebSocket)
- Contacts and friend requests
- Block list management
- User online status
"""

from rest_framework import serializers
from django.utils import timezone
from django.db import transaction
from django.db.models import Q

from .models import (
    Conversation, Message, MessageStatus, TypingStatus,
    Contact, FriendRequest, BlockList, UserStatus
)
from custom_account_u.models import CustomUser


# ==================== USER SERIALIZERS ====================

class UserMinimalSerializer(serializers.ModelSerializer):
    """Minimal user information for nested representations"""
    full_name = serializers.SerializerMethodField()
    avatar_url = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name', 'avatar_url']
        read_only_fields = fields

    def get_full_name(self, obj):
        return obj.get_full_name()

    def get_avatar_url(self, obj):
        if hasattr(obj, 'avatar') and obj.avatar:
            return obj.avatar.url
        return None


class UserStatusSerializer(serializers.ModelSerializer):
    """Serializer for user online status"""
    user = UserMinimalSerializer(read_only=True)
    is_online = serializers.BooleanField()
    last_seen_display = serializers.SerializerMethodField()

    class Meta:
        model = UserStatus
        fields = ['id', 'user', 'is_online', 'last_seen', 'last_seen_display']
        read_only_fields = ['id', 'user', 'last_seen']

    def get_last_seen_display(self, obj):
        if obj.is_online:
            return 'Online'
        if obj.last_seen:
            now = timezone.now()
            delta = now - obj.last_seen
            if delta.total_seconds() < 60:
                return 'Just now'
            elif delta.total_seconds() < 3600:
                minutes = int(delta.total_seconds() / 60)
                return f'{minutes}m ago'
            elif delta.total_seconds() < 86400:
                hours = int(delta.total_seconds() / 3600)
                return f'{hours}h ago'
            else:
                return obj.last_seen.strftime('%b %d')
        return 'Unknown'


class UserStatusUpdateSerializer(serializers.Serializer):
    """Serializer for updating user status"""
    is_online = serializers.BooleanField()


# ==================== CONTACT SERIALIZERS ====================

class ContactListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing contacts"""
    contact = UserMinimalSerializer(read_only=True)
    is_online = serializers.SerializerMethodField()

    class Meta:
        model = Contact
        fields = ['id', 'contact', 'is_favorite', 'is_online', 'created_at']
        read_only_fields = fields

    def get_is_online(self, obj):
        try:
            return obj.contact.status.is_online
        except UserStatus.DoesNotExist:
            return False


class ContactDetailSerializer(serializers.ModelSerializer):
    """Full contact detail serializer"""
    contact = UserMinimalSerializer(read_only=True)
    is_online = serializers.SerializerMethodField()
    last_seen = serializers.SerializerMethodField()
    conversation_id = serializers.SerializerMethodField()

    class Meta:
        model = Contact
        fields = [
            'id', 'contact', 'is_favorite', 'is_online',
            'last_seen', 'conversation_id', 'created_at'
        ]
        read_only_fields = fields

    def get_is_online(self, obj):
        try:
            return obj.contact.status.is_online
        except UserStatus.DoesNotExist:
            return False

    def get_last_seen(self, obj):
        try:
            return obj.contact.status.last_seen
        except UserStatus.DoesNotExist:
            return None

    def get_conversation_id(self, obj):
        """Get the direct conversation ID with this contact"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return None
        try:
            conv, _ = Conversation.objects.get_or_create_direct(
                request.user, obj.contact
            )
            return str(conv.id)
        except Exception:
            return None


class ContactCreateSerializer(serializers.ModelSerializer):
    """Serializer for adding contacts"""
    contact_id = serializers.UUIDField(write_only=True)

    class Meta:
        model = Contact
        fields = ['contact_id', 'is_favorite']

    def validate_contact_id(self, value):
        try:
            user = CustomUser.objects.get(id=value)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")

        request = self.context.get('request')
        if request and user == request.user:
            raise serializers.ValidationError("Cannot add yourself as a contact.")

        if Contact.objects.filter(
            owner=request.user, contact=user
        ).exists():
            raise serializers.ValidationError("Contact already exists.")

        return value

    def create(self, validated_data):
        contact_id = validated_data.pop('contact_id')
        contact = CustomUser.objects.get(id=contact_id)
        validated_data['owner'] = self.context['request'].user
        validated_data['contact'] = contact
        return super().create(validated_data)


class ContactFavoriteSerializer(serializers.Serializer):
    """Serializer for toggling contact favorite status"""
    is_favorite = serializers.BooleanField()


# ==================== FRIEND REQUEST SERIALIZERS ====================

class FriendRequestListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing friend requests"""
    sender = UserMinimalSerializer(read_only=True)
    receiver = UserMinimalSerializer(read_only=True)
    status_display = serializers.SerializerMethodField()

    class Meta:
        model = FriendRequest
        fields = [
            'id', 'sender', 'receiver',
            'accepted', 'rejected', 'status_display',
            'created_at'
        ]
        read_only_fields = fields

    def get_status_display(self, obj):
        if obj.accepted:
            return 'Accepted'
        elif obj.rejected:
            return 'Rejected'
        return 'Pending'


class FriendRequestDetailSerializer(serializers.ModelSerializer):
    """Full friend request detail serializer"""
    sender = UserMinimalSerializer(read_only=True)
    receiver = UserMinimalSerializer(read_only=True)
    status_display = serializers.SerializerMethodField()
    can_accept = serializers.SerializerMethodField()
    can_reject = serializers.SerializerMethodField()
    can_cancel = serializers.SerializerMethodField()

    class Meta:
        model = FriendRequest
        fields = [
            'id', 'sender', 'receiver',
            'accepted', 'rejected', 'status_display',
            'can_accept', 'can_reject', 'can_cancel',
            'created_at'
        ]
        read_only_fields = fields

    def get_status_display(self, obj):
        if obj.accepted:
            return 'Accepted'
        elif obj.rejected:
            return 'Rejected'
        return 'Pending'

    def get_can_accept(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return (
            obj.receiver == request.user and
            not obj.accepted and not obj.rejected
        )

    def get_can_reject(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return (
            obj.receiver == request.user and
            not obj.accepted and not obj.rejected
        )

    def get_can_cancel(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return (
            obj.sender == request.user and
            not obj.accepted and not obj.rejected
        )


class FriendRequestCreateSerializer(serializers.Serializer):
    """Serializer for creating friend requests"""
    receiver_id = serializers.UUIDField()

    def validate_receiver_id(self, value):
        try:
            user = CustomUser.objects.get(id=value)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")

        request = self.context.get('request')
        if request and user == request.user:
            raise serializers.ValidationError("Cannot send request to yourself.")

        # Check if request already exists
        if FriendRequest.objects.filter(
            sender=request.user, receiver=user
        ).exists():
            raise serializers.ValidationError("Friend request already sent.")

        # Check if already contacts
        if Contact.objects.filter(
            owner=request.user, contact=user
        ).exists():
            raise serializers.ValidationError("Already in contacts.")

        # Check if blocked
        if BlockList.objects.is_blocked_by(request.user, user):
            raise serializers.ValidationError("Cannot send request to this user.")

        return value

    def create(self, validated_data):
        receiver = CustomUser.objects.get(id=validated_data['receiver_id'])
        return FriendRequest.objects.create(
            sender=self.context['request'].user,
            receiver=receiver
        )


# ==================== BLOCK LIST SERIALIZERS ====================

class BlockListSerializer(serializers.ModelSerializer):
    """Serializer for blocked users"""
    blocked = UserMinimalSerializer(read_only=True)

    class Meta:
        model = BlockList
        fields = ['id', 'blocked', 'created_at']
        read_only_fields = fields


class BlockUserSerializer(serializers.Serializer):
    """Serializer for blocking a user"""
    user_id = serializers.UUIDField()

    def validate_user_id(self, value):
        try:
            user = CustomUser.objects.get(id=value)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")

        request = self.context.get('request')
        if request and user == request.user:
            raise serializers.ValidationError("Cannot block yourself.")

        if BlockList.objects.filter(
            blocker=request.user, blocked=user
        ).exists():
            raise serializers.ValidationError("User already blocked.")

        return value

    def create(self, validated_data):
        blocked = CustomUser.objects.get(id=validated_data['user_id'])
        return BlockList.objects.create(
            blocker=self.context['request'].user,
            blocked=blocked
        )


# ==================== CONVERSATION SERIALIZERS ====================

class ConversationListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing conversations"""
    participants = UserMinimalSerializer(many=True, read_only=True)
    last_message_preview = serializers.SerializerMethodField()
    unread_count = serializers.SerializerMethodField()
    is_group = serializers.SerializerMethodField()
    other_participant = serializers.SerializerMethodField()

    class Meta:
        model = Conversation
        fields = [
            'id', 'name', 'participants',
            'last_message_text', 'last_message_at', 'last_message_sender_id',
            'last_message_preview', 'unread_count', 'is_group',
            'other_participant', 'updated_at'
        ]
        read_only_fields = fields

    def get_last_message_preview(self, obj):
        if obj.last_message_text:
            return obj.last_message_text[:50] + ('...' if len(obj.last_message_text) > 50 else '')
        return None

    def get_unread_count(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return 0
        return Message.objects.filter(
            conversation=obj,
            is_read=False
        ).exclude(sender=request.user).count()

    def get_is_group(self, obj):
        return obj.participants.count() > 2

    def get_other_participant(self, obj):
        """For direct chats, return the other participant"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return None
        if obj.participants.count() == 2:
            other = obj.participants.exclude(id=request.user.id).first()
            if other:
                return UserMinimalSerializer(other, context=self.context).data
        return None


class ConversationDetailSerializer(serializers.ModelSerializer):
    """Full conversation detail serializer"""
    participants = UserMinimalSerializer(many=True, read_only=True)
    unread_count = serializers.SerializerMethodField()
    is_group = serializers.SerializerMethodField()
    other_participant = serializers.SerializerMethodField()
    can_leave = serializers.SerializerMethodField()
    can_add_participants = serializers.SerializerMethodField()

    class Meta:
        model = Conversation
        fields = [
            'id', 'name', 'participants',
            'last_message_text', 'last_message_at', 'last_message_sender_id',
            'unread_count', 'is_group', 'other_participant',
            'can_leave', 'can_add_participants',
            'created_at', 'updated_at'
        ]
        read_only_fields = fields

    def get_unread_count(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return 0
        return Message.objects.filter(
            conversation=obj,
            is_read=False
        ).exclude(sender=request.user).count()

    def get_is_group(self, obj):
        return obj.participants.count() > 2

    def get_other_participant(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return None
        if obj.participants.count() == 2:
            other = obj.participants.exclude(id=request.user.id).first()
            if other:
                return UserMinimalSerializer(other, context=self.context).data
        return None

    def get_can_leave(self, obj):
        return obj.participants.count() > 2  # Can only leave group chats

    def get_can_add_participants(self, obj):
        return obj.participants.count() > 2  # Can only add to group chats


class ConversationCreateSerializer(serializers.Serializer):
    """Serializer for creating conversations"""
    participant_ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1
    )
    name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    message = serializers.CharField(required=False, allow_blank=True)

    def validate_participant_ids(self, value):
        request = self.context.get('request')
        participants = CustomUser.objects.filter(id__in=value)

        if participants.count() != len(value):
            raise serializers.ValidationError("One or more users not found.")

        # Check if any participant is blocked
        for participant in participants:
            if BlockList.objects.is_blocked_by(request.user, participant):
                raise serializers.ValidationError(
                    f"Cannot create conversation with blocked user."
                )

        return value

    @transaction.atomic
    def create(self, validated_data):
        participant_ids = validated_data['participant_ids']
        name = validated_data.get('name')
        initial_message = validated_data.get('message')
        request = self.context['request']

        participants = list(CustomUser.objects.filter(id__in=participant_ids))

        # For direct conversations (1 other participant), use get_or_create
        if len(participants) == 1:
            conv, created = Conversation.objects.get_or_create_direct(
                request.user, participants[0]
            )
        else:
            # Group conversation
            conv = Conversation.objects.create(name=name)
            conv.participants.add(request.user, *participants)

        # Send initial message if provided
        if initial_message:
            Message.objects.create(
                conversation=conv,
                sender=request.user,
                content=initial_message
            )

        return conv


class ConversationParticipantSerializer(serializers.Serializer):
    """Serializer for adding/removing participants"""
    user_ids = serializers.ListField(child=serializers.UUIDField())

    def validate_user_ids(self, value):
        users = CustomUser.objects.filter(id__in=value)
        if users.count() != len(value):
            raise serializers.ValidationError("One or more users not found.")
        return value


class ConversationMarkReadSerializer(serializers.Serializer):
    """Serializer for marking conversation as read"""
    pass  # No input required


# ==================== MESSAGE SERIALIZERS ====================

class MessageListSerializer(serializers.ModelSerializer):
    """Compact serializer for listing messages (paginated history)"""
    sender = UserMinimalSerializer(read_only=True)
    is_own = serializers.SerializerMethodField()
    has_attachment = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            'id', 'conversation', 'sender',
            'content', 'is_own', 'has_attachment',
            'is_read', 'is_voice', 'timestamp'
        ]
        read_only_fields = fields

    def get_is_own(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return obj.sender_id == request.user.id

    def get_has_attachment(self, obj):
        return bool(obj.file or obj.voice_message)


class MessageDetailSerializer(serializers.ModelSerializer):
    """Full message detail serializer"""
    sender = UserMinimalSerializer(read_only=True)
    is_own = serializers.SerializerMethodField()
    file_url = serializers.SerializerMethodField()
    voice_message_url = serializers.SerializerMethodField()
    read_by = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            'id', 'conversation', 'sender',
            'content', 'file', 'file_url',
            'voice_message', 'voice_message_url',
            'is_voice', 'is_read', 'is_own',
            'read_by', 'timestamp'
        ]
        read_only_fields = fields

    def get_is_own(self, obj):
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        return obj.sender_id == request.user.id

    def get_file_url(self, obj):
        if obj.file:
            return obj.file.url
        return None

    def get_voice_message_url(self, obj):
        if obj.voice_message:
            return obj.voice_message.url
        return None

    def get_read_by(self, obj):
        """Get list of users who have read this message"""
        statuses = obj.statuses.filter(read_at__isnull=False).select_related('user')
        return [
            {
                'user_id': str(status.user_id),
                'read_at': status.read_at
            }
            for status in statuses
        ]


class MessageCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating messages.
    Note: In production, messages should be sent via WebSocket for real-time delivery.
    This endpoint is for fallback/offline scenarios.
    """
    conversation_id = serializers.UUIDField(write_only=True)

    class Meta:
        model = Message
        fields = ['conversation_id', 'content', 'file', 'voice_message', 'is_voice']

    def validate_conversation_id(self, value):
        try:
            conversation = Conversation.objects.get(id=value)
        except Conversation.DoesNotExist:
            raise serializers.ValidationError("Conversation not found.")

        request = self.context.get('request')
        if not conversation.is_participant(request.user):
            raise serializers.ValidationError("You are not a participant.")

        return value

    def validate(self, data):
        # Require either content, file, or voice_message
        if not data.get('content') and not data.get('file') and not data.get('voice_message'):
            raise serializers.ValidationError(
                "Message must have content, file, or voice message."
            )
        return data

    def create(self, validated_data):
        conversation_id = validated_data.pop('conversation_id')
        conversation = Conversation.objects.get(id=conversation_id)
        validated_data['conversation'] = conversation
        validated_data['sender'] = self.context['request'].user
        return super().create(validated_data)


class MessageSearchSerializer(serializers.Serializer):
    """Serializer for searching messages"""
    query = serializers.CharField(min_length=2, max_length=100)
    conversation_id = serializers.UUIDField(required=False)


class MessageSearchResultSerializer(serializers.ModelSerializer):
    """Serializer for message search results"""
    sender = UserMinimalSerializer(read_only=True)
    conversation_name = serializers.SerializerMethodField()
    content_highlight = serializers.SerializerMethodField()

    class Meta:
        model = Message
        fields = [
            'id', 'conversation', 'conversation_name',
            'sender', 'content', 'content_highlight',
            'timestamp'
        ]
        read_only_fields = fields

    def get_conversation_name(self, obj):
        if obj.conversation.name:
            return obj.conversation.name
        # For direct chats, show other participant's name
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            other = obj.conversation.participants.exclude(
                id=request.user.id
            ).first()
            if other:
                return other.get_full_name()
        return 'Chat'

    def get_content_highlight(self, obj):
        """Return content with search term highlighted"""
        query = self.context.get('query', '')
        if query and obj.content:
            # Simple case-insensitive highlight
            import re
            pattern = re.compile(re.escape(query), re.IGNORECASE)
            return pattern.sub(f'<mark>{query}</mark>', obj.content[:200])
        return obj.content[:200] if obj.content else ''


# ==================== TYPING STATUS SERIALIZER ====================

class TypingStatusSerializer(serializers.ModelSerializer):
    """Serializer for typing indicators"""
    user = UserMinimalSerializer(read_only=True)

    class Meta:
        model = TypingStatus
        fields = ['conversation', 'user', 'is_typing', 'updated_at']
        read_only_fields = ['user', 'updated_at']


class TypingStatusUpdateSerializer(serializers.Serializer):
    """Serializer for updating typing status"""
    conversation_id = serializers.UUIDField()
    is_typing = serializers.BooleanField()
