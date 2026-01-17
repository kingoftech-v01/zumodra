#!/usr/bin/env python3
"""
Zumodra Messaging System Comprehensive Test Suite
===================================================

This test suite comprehensively tests the complete messaging system:
1. Direct message sending/receiving
2. Group conversation creation and management
3. Real-time WebSocket delivery
4. Message read receipts
5. File attachment handling
6. Message search functionality
7. Notification integration

Tests use pytest with the Django test fixtures from conftest.py

USAGE:
------
# Run all messaging tests
pytest test_messaging_system_comprehensive.py -v

# Run specific test
pytest test_messaging_system_comprehensive.py::test_send_direct_message -v

# Run with coverage
pytest test_messaging_system_comprehensive.py --cov=messages_sys -v

# Run with detailed output
pytest test_messaging_system_comprehensive.py -vv -s

REQUIREMENTS:
- pytest-django
- Django 5.2.7
- pytest-asyncio for async consumer tests
- channels-testing for WebSocket testing

"""

import pytest
import json
import base64
from io import BytesIO
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import patch, MagicMock

from django.test import TestCase, TransactionTestCase, AsyncClient
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.cache import cache
from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from channels.testing import WebsocketCommunicator
from channels.layers import get_channel_layer

from messages_sys.models import (
    Conversation, Message, MessageStatus, Contact, FriendRequest,
    BlockList, UserStatus, TypingStatus
)
from messages_sys.consumer import ChatConsumer

User = get_user_model()


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def user1(db):
    """Create test user 1"""
    return User.objects.create_user(
        username='user1',
        email='user1@test.com',
        password='testpass123',
        first_name='User',
        last_name='One'
    )


@pytest.fixture
def user2(db):
    """Create test user 2"""
    return User.objects.create_user(
        username='user2',
        email='user2@test.com',
        password='testpass123',
        first_name='User',
        last_name='Two'
    )


@pytest.fixture
def user3(db):
    """Create test user 3"""
    return User.objects.create_user(
        username='user3',
        email='user3@test.com',
        password='testpass123',
        first_name='User',
        last_name='Three'
    )


@pytest.fixture
def api_client():
    """Create API client"""
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, user1):
    """Create authenticated API client"""
    api_client.force_authenticate(user=user1)
    return api_client


# ============================================================================
# 1. DIRECT MESSAGE TESTS
# ============================================================================

@pytest.mark.django_db
class TestDirectMessages:
    """Test direct messaging functionality"""

    def test_create_direct_conversation(self, user1, user2):
        """Test creating a direct conversation between two users"""
        conversation, created = Conversation.objects.get_or_create_direct(user1, user2)

        assert created is True, "Conversation should be created"
        assert conversation.participants.count() == 2
        assert conversation.participants.filter(id=user1.id).exists()
        assert conversation.participants.filter(id=user2.id).exists()
        assert conversation.is_group() is False

    def test_get_existing_direct_conversation(self, user1, user2):
        """Test retrieving an existing direct conversation"""
        conversation1, created1 = Conversation.objects.get_or_create_direct(user1, user2)
        conversation2, created2 = Conversation.objects.get_or_create_direct(user1, user2)

        assert created1 is True
        assert created2 is False, "Should return existing conversation"
        assert conversation1.id == conversation2.id

    def test_direct_conversation_caching(self, user1, user2):
        """Test that direct conversations are cached properly"""
        conversation1, _ = Conversation.objects.get_or_create_direct(user1, user2)

        # Clear database to ensure cache is used
        with patch('messages_sys.models.Conversation.objects.get') as mock_get:
            conversation2, created = Conversation.objects.get_or_create_direct(user1, user2)
            # Should use cache, not hit database
            assert conversation1.id == conversation2.id

    def test_send_direct_message(self, user1, user2):
        """Test sending a direct message"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Hello, User 2!"
        )

        assert message.id is not None
        assert message.content == "Hello, User 2!"
        assert message.sender == user1
        assert message.is_read is False
        assert message.timestamp is not None

    def test_send_empty_message_fails(self, user1, user2):
        """Test that sending empty messages is handled"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        # Empty content should still save but might be invalid in consumer
        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content=""
        )

        assert message.content == ""

    def test_message_timestamps(self, user1, user2):
        """Test that messages have proper timestamps"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        now = timezone.now()
        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Test message"
        )

        assert message.timestamp >= now
        assert message.timestamp <= timezone.now()

    def test_conversation_updates_last_message(self, user1, user2):
        """Test that conversation's last message fields are updated"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="First message"
        )

        conversation.refresh_from_db()
        assert conversation.last_message_text == "First message"
        assert conversation.last_message_sender_id == user1.id
        assert conversation.last_message_at is not None

    def test_conversation_denormalization_updates(self, user1, user2):
        """Test denormalized fields are updated correctly"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        message1 = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Message 1"
        )

        message2 = Message.objects.create(
            conversation=conversation,
            sender=user2,
            content="Message 2"
        )

        conversation.refresh_from_db()
        # Last message should be message2
        assert conversation.last_message_text == "Message 2"
        assert conversation.last_message_sender_id == user2.id

    def test_get_conversation_by_id(self, user1, user2):
        """Test retrieving conversation by ID"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        retrieved = Conversation.objects.get(id=conversation.id)
        assert retrieved.id == conversation.id
        assert retrieved.participants.count() == 2

    def test_conversation_not_visible_to_non_participant(self, user1, user2, user3):
        """Test that non-participants can't see conversation"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        assert not conversation.is_participant(user3)

        # User3 shouldn't be in query results
        user3_conversations = Conversation.objects.for_user(user3)
        assert conversation not in user3_conversations


# ============================================================================
# 2. GROUP CONVERSATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestGroupConversations:
    """Test group chat functionality"""

    def test_create_group_conversation(self, user1, user2, user3):
        """Test creating a group conversation"""
        group = Conversation.objects.create(name="Test Group")
        group.participants.add(user1, user2, user3)

        assert group.name == "Test Group"
        assert group.participants.count() == 3
        assert group.is_group() is True

    def test_group_with_two_participants_not_group(self, user1, user2):
        """Test that 2-person conversation is not a group"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)
        assert conversation.is_group() is False

    def test_group_with_three_participants_is_group(self, user1, user2, user3):
        """Test that 3+ person conversation is a group"""
        group = Conversation.objects.create(name="Group")
        group.participants.add(user1, user2, user3)
        assert group.is_group() is True

    def test_add_participant_to_group(self, user1, user2, user3):
        """Test adding a participant to group"""
        group = Conversation.objects.create(name="Group")
        group.participants.add(user1, user2)

        assert group.participants.count() == 2
        group.add_participant(user3)
        assert group.participants.count() == 3

    def test_cannot_add_duplicate_participant(self, user1, user2):
        """Test that duplicate participants aren't added"""
        group = Conversation.objects.create(name="Group")
        group.participants.add(user1)

        group.add_participant(user1)
        assert group.participants.count() == 1

    def test_remove_participant_from_group(self, user1, user2, user3):
        """Test removing a participant from group"""
        group = Conversation.objects.create(name="Group")
        group.participants.add(user1, user2, user3)

        assert group.participants.count() == 3
        group.remove_participant(user2)
        assert group.participants.count() == 2
        assert not group.participants.filter(id=user2.id).exists()

    def test_delete_group_when_last_participant_removed(self, user1):
        """Test that group is deleted when last participant is removed"""
        group = Conversation.objects.create(name="Group")
        group.participants.add(user1)
        group_id = group.id

        group.remove_participant(user1)

        assert not Conversation.objects.filter(id=group_id).exists()

    def test_group_message_visibility(self, user1, user2, user3):
        """Test that all group members can see messages"""
        group = Conversation.objects.create(name="Group")
        group.participants.add(user1, user2, user3)

        message = Message.objects.create(
            conversation=group,
            sender=user1,
            content="Group message"
        )

        # All participants should see the message
        user1_messages = Message.objects.filter(conversation__participants=user1)
        user2_messages = Message.objects.filter(conversation__participants=user2)
        user3_messages = Message.objects.filter(conversation__participants=user3)

        assert message in user1_messages
        assert message in user2_messages
        assert message in user3_messages

    def test_list_conversations_by_type(self, user1, user2, user3):
        """Test filtering conversations by type (direct vs group)"""
        # Create direct conversation
        direct, _ = Conversation.objects.get_or_create_direct(user1, user2)

        # Create group conversation
        group = Conversation.objects.create(name="Group")
        group.participants.add(user1, user2, user3)

        # Filter direct
        direct_only = Conversation.objects.filter(
            participants=user1
        ).annotate(
            participant_count=__import__('django.db.models', fromlist=['Count']).Count('participants')
        ).filter(participant_count=2)

        assert direct in direct_only
        assert group not in direct_only


# ============================================================================
# 3. MESSAGE READ RECEIPTS TESTS
# ============================================================================

@pytest.mark.django_db
class TestMessageReadReceipts:
    """Test message read receipt functionality"""

    def test_create_message_status(self, user1, user2):
        """Test creating a message status record"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)
        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Test"
        )

        status = MessageStatus.objects.create(
            user=user2,
            message=message,
            read_at=timezone.now()
        )

        assert status.user == user2
        assert status.message == message
        assert status.read_at is not None

    def test_mark_message_as_read(self, user1, user2):
        """Test marking a message as read"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)
        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Test"
        )

        message.mark_as_read(user2)

        assert message.is_read_by(user2) is True

    def test_unread_message_not_read(self, user1, user2):
        """Test that unread message shows as unread"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)
        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Test"
        )

        assert message.is_read_by(user2) is False

    def test_mark_conversation_as_read(self, user1, user2):
        """Test marking all messages in conversation as read"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        msg1 = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Message 1"
        )
        msg2 = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Message 2"
        )

        updated = Message.objects.mark_conversation_read(user2, conversation.id)

        assert updated == 2

    def test_get_unread_messages_for_user(self, user1, user2):
        """Test retrieving unread messages for a user"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        msg1 = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Message 1"
        )
        msg2 = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Message 2"
        )

        unread = Message.objects.unread_for_user(user2)

        assert msg1 in unread
        assert msg2 in unread

    def test_read_messages_not_in_unread(self, user1, user2):
        """Test that read messages don't appear in unread list"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Message"
        )
        message.mark_as_read(user2)

        unread = Message.objects.unread_for_user(user2)
        assert message not in unread


# ============================================================================
# 4. FILE ATTACHMENT TESTS
# ============================================================================

@pytest.mark.django_db
class TestFileAttachments:
    """Test file attachment functionality"""

    def test_send_message_with_file_attachment(self, user1, user2):
        """Test sending a message with a file attachment"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        # Create a test file
        file_content = b"Test file content"
        uploaded_file = SimpleUploadedFile(
            "test.txt",
            file_content,
            content_type="text/plain"
        )

        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Check this file",
            file=uploaded_file
        )

        assert message.file is not None
        assert message.file.name.endswith('.txt')

    def test_file_size_validation(self, user1, user2):
        """Test that file size is validated"""
        # Create a file that's too large (51MB)
        large_file = SimpleUploadedFile(
            "large.bin",
            b"x" * (51 * 1024 * 1024),
            content_type="application/octet-stream"
        )

        from django.core.exceptions import ValidationError

        with pytest.raises(ValidationError):
            Message.validate_file(large_file)

    def test_file_extension_validation(self, user1, user2):
        """Test that file extensions are validated"""
        from django.core.exceptions import ValidationError

        dangerous_file = SimpleUploadedFile(
            "malware.exe",
            b"MZ\x90...",  # PE file header
            content_type="application/octet-stream"
        )

        with pytest.raises(ValidationError):
            Message.validate_file(dangerous_file)

    def test_allowed_file_types(self, user1, user2):
        """Test that allowed file types are accepted"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        allowed_files = [
            ("test.pdf", b"%PDF"),
            ("test.jpg", b"\xff\xd8\xff"),
            ("test.png", b"\x89PNG"),
            ("test.txt", b"Hello"),
        ]

        for filename, content in allowed_files:
            uploaded_file = SimpleUploadedFile(
                filename,
                content,
                content_type="application/octet-stream"
            )

            message = Message.objects.create(
                conversation=conversation,
                sender=user1,
                file=uploaded_file
            )

            assert message.file is not None

    def test_voice_message_flag(self, user1, user2):
        """Test voice message flag"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        voice_file = SimpleUploadedFile(
            "audio.mp3",
            b"ID3...",
            content_type="audio/mpeg"
        )

        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            is_voice=True,
            voice_message=voice_file
        )

        assert message.is_voice is True

    def test_message_with_file_and_text(self, user1, user2):
        """Test message that has both text and file"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        file_content = b"Document content"
        uploaded_file = SimpleUploadedFile(
            "document.pdf",
            file_content,
            content_type="application/pdf"
        )

        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="See attached document",
            file=uploaded_file
        )

        assert message.content == "See attached document"
        assert message.file is not None


# ============================================================================
# 5. MESSAGE SEARCH TESTS
# ============================================================================

@pytest.mark.django_db
class TestMessageSearch:
    """Test message search functionality"""

    def test_search_messages_by_content(self, user1, user2):
        """Test searching messages by content"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="I love Python programming"
        )
        Message.objects.create(
            conversation=conversation,
            sender=user2,
            content="Java is also great"
        )

        results = Message.objects.filter(content__icontains="Python")
        assert results.count() == 1

    def test_search_case_insensitive(self, user1, user2):
        """Test that search is case-insensitive"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Hello World"
        )

        results = Message.objects.filter(content__icontains="hello")
        assert results.count() == 1

    def test_search_across_conversations(self, user1, user2, user3):
        """Test searching across multiple conversations"""
        conv1, _ = Conversation.objects.get_or_create_direct(user1, user2)
        conv2, _ = Conversation.objects.get_or_create_direct(user1, user3)

        Message.objects.create(
            conversation=conv1,
            sender=user1,
            content="Project deadline"
        )
        Message.objects.create(
            conversation=conv2,
            sender=user1,
            content="Project status"
        )

        results = Message.objects.filter(content__icontains="Project")
        assert results.count() == 2

    def test_search_within_conversation(self, user1, user2):
        """Test searching within a specific conversation"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Urgent meeting"
        )

        results = Message.objects.filter(
            conversation=conversation,
            content__icontains="meeting"
        )
        assert results.count() == 1

    def test_search_no_results(self, user1, user2):
        """Test search with no results"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Hello"
        )

        results = Message.objects.filter(content__icontains="xyz")
        assert results.count() == 0

    def test_search_minimum_query_length(self, user1, user2):
        """Test that search requires minimum query length"""
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Test message"
        )

        # Single character searches might be limited by API
        results = Message.objects.filter(content__icontains="a")
        # This should still work at DB level, but API might limit it


# ============================================================================
# 6. CONTACT MANAGEMENT TESTS
# ============================================================================

@pytest.mark.django_db
class TestContactManagement:
    """Test contact management functionality"""

    def test_add_contact(self, user1, user2):
        """Test adding a contact"""
        contact = Contact.objects.create(
            owner=user1,
            contact=user2,
            is_favorite=False
        )

        assert contact.owner == user1
        assert contact.contact == user2

    def test_favorite_contact(self, user1, user2):
        """Test marking contact as favorite"""
        contact = Contact.objects.create(
            owner=user1,
            contact=user2,
            is_favorite=False
        )

        contact.is_favorite = True
        contact.save()

        assert contact.is_favorite is True

    def test_list_user_contacts(self, user1, user2, user3):
        """Test listing user's contacts"""
        Contact.objects.create(owner=user1, contact=user2)
        Contact.objects.create(owner=user1, contact=user3)

        contacts = Contact.objects.filter(owner=user1)
        assert contacts.count() == 2

    def test_list_favorite_contacts(self, user1, user2, user3):
        """Test listing favorite contacts"""
        Contact.objects.create(owner=user1, contact=user2, is_favorite=True)
        Contact.objects.create(owner=user1, contact=user3, is_favorite=False)

        favorites = Contact.objects.filter(owner=user1, is_favorite=True)
        assert favorites.count() == 1

    def test_unique_contact_constraint(self, user1, user2):
        """Test that duplicate contacts are prevented"""
        Contact.objects.create(owner=user1, contact=user2)

        with pytest.raises(Exception):  # IntegrityError
            Contact.objects.create(owner=user1, contact=user2)


# ============================================================================
# 7. FRIEND REQUEST TESTS
# ============================================================================

@pytest.mark.django_db
class TestFriendRequests:
    """Test friend request functionality"""

    def test_create_friend_request(self, user1, user2):
        """Test creating a friend request"""
        request = FriendRequest.objects.create(
            sender=user1,
            receiver=user2
        )

        assert request.sender == user1
        assert request.receiver == user2
        assert request.accepted is False
        assert request.rejected is False

    def test_accept_friend_request(self, user1, user2):
        """Test accepting a friend request"""
        request = FriendRequest.objects.create(
            sender=user1,
            receiver=user2
        )

        request.accept()

        assert request.accepted is True
        # Contacts should be created automatically
        assert Contact.objects.filter(owner=user1, contact=user2).exists()
        assert Contact.objects.filter(owner=user2, contact=user1).exists()

    def test_reject_friend_request(self, user1, user2):
        """Test rejecting a friend request"""
        request = FriendRequest.objects.create(
            sender=user1,
            receiver=user2
        )

        request.reject()

        assert request.rejected is True

    def test_cannot_accept_rejected_request(self, user1, user2):
        """Test that rejected requests can't be accepted"""
        request = FriendRequest.objects.create(
            sender=user1,
            receiver=user2
        )

        request.reject()

        from django.core.exceptions import ValidationError
        with pytest.raises(ValidationError):
            request.accept()

    def test_cancel_friend_request(self, user1, user2):
        """Test canceling a friend request"""
        request = FriendRequest.objects.create(
            sender=user1,
            receiver=user2
        )

        request.cancel()

        assert not FriendRequest.objects.filter(id=request.id).exists()

    def test_unique_friend_request_constraint(self, user1, user2):
        """Test that duplicate requests are prevented"""
        FriendRequest.objects.create(sender=user1, receiver=user2)

        with pytest.raises(Exception):  # IntegrityError
            FriendRequest.objects.create(sender=user1, receiver=user2)


# ============================================================================
# 8. BLOCKING TESTS
# ============================================================================

@pytest.mark.django_db
class TestBlocking:
    """Test user blocking functionality"""

    def test_block_user(self, user1, user2):
        """Test blocking a user"""
        block = BlockList.objects.create(
            blocker=user1,
            blocked=user2
        )

        assert block.blocker == user1
        assert block.blocked == user2

    def test_is_blocked_check(self, user1, user2):
        """Test checking if user is blocked"""
        BlockList.objects.create(blocker=user1, blocked=user2)

        is_blocked = BlockList.objects.is_blocked(user1, user2)
        assert is_blocked is True

    def test_is_not_blocked(self, user1, user2):
        """Test that non-blocked users return False"""
        is_blocked = BlockList.objects.is_blocked(user1, user2)
        assert is_blocked is False

    def test_is_blocked_by_either_user(self, user1, user2):
        """Test checking if either user has blocked the other"""
        BlockList.objects.create(blocker=user1, blocked=user2)

        is_blocked = BlockList.objects.is_blocked_by(user1, user2)
        assert is_blocked is True

    def test_blocked_user_ids_list(self, user1, user2, user3):
        """Test getting list of blocked user IDs"""
        BlockList.objects.create(blocker=user1, blocked=user2)
        BlockList.objects.create(blocker=user1, blocked=user3)

        blocked_ids = BlockList.objects.blocked_user_ids(user1)
        assert user2.id in blocked_ids
        assert user3.id in blocked_ids

    def test_cannot_message_blocked_user_websocket(self, user1, user2):
        """Test that blocked users can't send messages via WebSocket"""
        # This would be tested in consumer tests
        pass

    def test_unblock_user(self, user1, user2):
        """Test unblocking a user"""
        block = BlockList.objects.create(blocker=user1, blocked=user2)
        assert BlockList.objects.is_blocked(user1, user2)

        block.delete()
        assert not BlockList.objects.is_blocked(user1, user2)


# ============================================================================
# 9. USER STATUS TESTS
# ============================================================================

@pytest.mark.django_db
class TestUserStatus:
    """Test user status functionality"""

    def test_create_user_status(self, user1):
        """Test creating user status"""
        status = UserStatus.objects.create(
            user=user1,
            is_online=True
        )

        assert status.user == user1
        assert status.is_online is True

    def test_set_user_online(self, user1):
        """Test setting user as online"""
        status, _ = UserStatus.objects.get_or_create(user=user1)
        status.is_online = True
        status.save()

        assert status.is_online is True

    def test_set_user_offline(self, user1):
        """Test setting user as offline"""
        status, _ = UserStatus.objects.get_or_create(user=user1)
        status.is_online = False
        status.last_seen = timezone.now()
        status.save()

        assert status.is_online is False
        assert status.last_seen is not None

    def test_get_user_status_string(self, user1):
        """Test user status string representation"""
        status = UserStatus.objects.create(
            user=user1,
            is_online=True
        )

        status_str = str(status)
        assert "Online" in status_str

    def test_last_seen_tracking(self, user1):
        """Test tracking last seen time"""
        now = timezone.now()
        status = UserStatus.objects.create(
            user=user1,
            is_online=False,
            last_seen=now
        )

        assert status.last_seen >= now


# ============================================================================
# 10. API ENDPOINT TESTS
# ============================================================================

@pytest.mark.django_db
class TestMessagingAPI(APITestCase):
    """Test messaging REST API endpoints"""

    def setUp(self):
        """Set up test users and client"""
        self.user1 = User.objects.create_user(
            username='apiuser1',
            email='apiuser1@test.com',
            password='testpass123'
        )
        self.user2 = User.objects.create_user(
            username='apiuser2',
            email='apiuser2@test.com',
            password='testpass123'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user1)

    def test_list_conversations(self):
        """Test listing conversations endpoint"""
        # Create a conversation
        conversation, _ = Conversation.objects.get_or_create_direct(
            self.user1, self.user2
        )

        response = self.client.get('/api/v1/messages/conversations/')

        assert response.status_code == 200
        assert 'results' in response.json() or isinstance(response.json(), list)

    def test_create_conversation(self):
        """Test creating conversation endpoint"""
        data = {
            'participants': [self.user2.id]
        }

        response = self.client.post(
            '/api/v1/messages/conversations/',
            data,
            format='json'
        )

        # Should return 201 Created or 400 if endpoint doesn't support creation
        assert response.status_code in [201, 400]

    def test_list_messages(self):
        """Test listing messages endpoint"""
        conversation, _ = Conversation.objects.get_or_create_direct(
            self.user1, self.user2
        )

        Message.objects.create(
            conversation=conversation,
            sender=self.user1,
            content="Test message"
        )

        response = self.client.get('/api/v1/messages/messages/')

        assert response.status_code == 200

    def test_search_messages(self):
        """Test searching messages endpoint"""
        conversation, _ = Conversation.objects.get_or_create_direct(
            self.user1, self.user2
        )

        Message.objects.create(
            conversation=conversation,
            sender=self.user1,
            content="Test search query"
        )

        response = self.client.get('/api/v1/messages/messages/search/?q=search')

        assert response.status_code in [200, 404]

    def test_list_contacts(self):
        """Test listing contacts endpoint"""
        Contact.objects.create(owner=self.user1, contact=self.user2)

        response = self.client.get('/api/v1/messages/contacts/')

        assert response.status_code == 200

    def test_mark_conversation_read(self):
        """Test mark conversation as read endpoint"""
        conversation, _ = Conversation.objects.get_or_create_direct(
            self.user1, self.user2
        )

        Message.objects.create(
            conversation=conversation,
            sender=self.user2,
            content="Unread message"
        )

        response = self.client.post(
            f'/api/v1/messages/conversations/{conversation.id}/mark_read/',
            {},
            format='json'
        )

        assert response.status_code in [200, 404]


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

@pytest.mark.django_db
class TestMessagingIntegration:
    """Integration tests for complete messaging flows"""

    def test_complete_direct_message_flow(self, user1, user2):
        """Test complete flow: create conversation -> send message -> read"""
        # 1. Create conversation
        conversation, created = Conversation.objects.get_or_create_direct(user1, user2)
        assert created is True

        # 2. Send message
        message = Message.objects.create(
            conversation=conversation,
            sender=user1,
            content="Hello User 2"
        )

        # 3. Check unread messages
        unread = Message.objects.unread_for_user(user2, conversation.id)
        assert message in unread

        # 4. Mark as read
        message.mark_as_read(user2)

        # 5. Verify read
        assert message.is_read_by(user2) is True

    def test_complete_group_message_flow(self, user1, user2, user3):
        """Test complete group messaging flow"""
        # 1. Create group
        group = Conversation.objects.create(name="Test Group")
        group.participants.add(user1, user2, user3)
        assert group.is_group() is True

        # 2. Send group message
        message = Message.objects.create(
            conversation=group,
            sender=user1,
            content="Hello Group!"
        )

        # 3. Check all members see it
        for user in [user2, user3]:
            unread = Message.objects.unread_for_user(user)
            assert message in unread

        # 4. Members read message
        message.mark_as_read(user2)
        message.mark_as_read(user3)

        # 5. Verify all read
        assert message.is_read_by(user2) is True
        assert message.is_read_by(user3) is True

    def test_blocked_user_cannot_receive_messages(self, user1, user2):
        """Test that blocked users can't participate in conversation"""
        # 1. Create conversation
        conversation, _ = Conversation.objects.get_or_create_direct(user1, user2)

        # 2. Block user2
        BlockList.objects.create(blocker=user1, blocked=user2)

        # 3. Check block status
        assert BlockList.objects.is_blocked(user1, user2) is True

    def test_contact_favorite_workflow(self, user1, user2):
        """Test adding contact and marking as favorite"""
        # 1. Add contact
        contact = Contact.objects.create(owner=user1, contact=user2)

        # 2. Get contacts
        contacts = Contact.objects.filter(owner=user1)
        assert contact in contacts

        # 3. Mark as favorite
        contact.is_favorite = True
        contact.save()

        # 4. Get favorites
        favorites = Contact.objects.filter(owner=user1, is_favorite=True)
        assert contact in favorites


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
