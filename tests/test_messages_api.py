"""
Tests for Messages System API.

This module tests the messages API endpoints including:
- Conversations
- Messages
- Contacts
- Friend requests
- Block list
- User status
"""

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from messages_sys.models import (
    Conversation, Message, Contact, FriendRequest,
    BlockList, UserStatus
)


@pytest.fixture
def api_client():
    """Return API client."""
    return APIClient()


@pytest.fixture
def authenticated_client(api_client, user_factory):
    """Return authenticated API client."""
    user = user_factory()
    api_client.force_authenticate(user=user)
    return api_client, user


@pytest.fixture
def two_users(db, user_factory):
    """Create two users for messaging tests."""
    return user_factory(), user_factory()


@pytest.fixture
def conversation(db, two_users):
    """Create test conversation."""
    user1, user2 = two_users
    conv = Conversation.objects.create()
    conv.participants.add(user1, user2)
    return conv


@pytest.fixture
def message(db, conversation, two_users):
    """Create test message."""
    user1, user2 = two_users
    return Message.objects.create(
        conversation=conversation,
        sender=user1,
        content='Hello, this is a test message!'
    )


@pytest.fixture
def contact(db, two_users):
    """Create test contact."""
    user1, user2 = two_users
    return Contact.objects.create(
        owner=user1,
        contact=user2,
        is_favorite=False
    )


@pytest.fixture
def friend_request(db, two_users):
    """Create test friend request."""
    user1, user2 = two_users
    return FriendRequest.objects.create(
        sender=user1,
        receiver=user2
    )


@pytest.fixture
def block_entry(db, two_users):
    """Create test block entry."""
    user1, user2 = two_users
    return BlockList.objects.create(
        blocker=user1,
        blocked=user2
    )


@pytest.fixture
def user_status(db, user_factory):
    """Create test user status."""
    user = user_factory()
    return UserStatus.objects.create(
        user=user,
        is_online=True
    )


# =============================================================================
# CONVERSATION TESTS
# =============================================================================

class TestConversationViewSet:
    """Tests for ConversationViewSet."""

    @pytest.mark.django_db
    def test_list_conversations(self, api_client, conversation, two_users):
        """Test listing conversations."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:conversation-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 1

    @pytest.mark.django_db
    def test_list_conversations_unauthenticated(self, api_client):
        """Test conversations require authentication."""
        url = reverse('api_v1:messages:conversation-list')
        response = api_client.get(url)

        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]

    @pytest.mark.django_db
    def test_retrieve_conversation(self, api_client, conversation, two_users):
        """Test retrieving a conversation."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:conversation-detail', args=[conversation.id])
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_create_conversation(self, api_client, two_users):
        """Test creating a conversation."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:conversation-list')
        response = api_client.post(url, {
            'participant_ids': [user2.id]
        }, format='json')

        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK]

    @pytest.mark.django_db
    def test_mark_read(self, api_client, conversation, message, two_users):
        """Test marking conversation as read."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user2)

        url = reverse('api_v1:messages:conversation-mark-read', args=[conversation.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_leave_group_conversation(self, api_client, user_factory):
        """Test leaving a group conversation."""
        users = [user_factory() for _ in range(4)]
        conv = Conversation.objects.create()
        for user in users:
            conv.participants.add(user)

        api_client.force_authenticate(user=users[0])

        url = reverse('api_v1:messages:conversation-leave', args=[conv.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_200_OK
        assert users[0] not in conv.participants.all()

    @pytest.mark.django_db
    def test_cannot_leave_direct_conversation(self, api_client, conversation, two_users):
        """Test cannot leave a direct (2-person) conversation."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:conversation-leave', args=[conversation.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_400_BAD_REQUEST


# =============================================================================
# MESSAGE TESTS
# =============================================================================

class TestMessageViewSet:
    """Tests for MessageViewSet."""

    @pytest.mark.django_db
    def test_list_messages(self, api_client, conversation, message, two_users):
        """Test listing messages."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:message-list')
        response = api_client.get(url, {'conversation': conversation.id})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_retrieve_message(self, api_client, message, two_users):
        """Test retrieving a message."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:message-detail', args=[message.id])
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_create_message(self, api_client, conversation, two_users):
        """Test creating a message."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:message-list')
        response = api_client.post(url, {
            'conversation': conversation.id,
            'content': 'Test message content'
        })

        assert response.status_code == status.HTTP_201_CREATED

    @pytest.mark.django_db
    def test_search_messages(self, api_client, conversation, message, two_users):
        """Test searching messages."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:message-search')
        response = api_client.get(url, {'q': 'test message'})

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_search_messages_post(self, api_client, conversation, message, two_users):
        """Test searching messages with POST."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:message-search')
        response = api_client.post(url, {
            'query': 'test message'
        })

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_search_requires_min_length(self, api_client, two_users):
        """Test search requires minimum query length."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:message-search')
        response = api_client.get(url, {'q': 'a'})

        assert response.status_code == status.HTTP_400_BAD_REQUEST


# =============================================================================
# CONTACT TESTS
# =============================================================================

class TestContactViewSet:
    """Tests for ContactViewSet."""

    @pytest.mark.django_db
    def test_list_contacts(self, api_client, contact, two_users):
        """Test listing contacts."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:contact-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 1

    @pytest.mark.django_db
    def test_add_favorite(self, api_client, contact, two_users):
        """Test adding contact to favorites."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:contact-add-favorite', args=[contact.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_200_OK
        contact.refresh_from_db()
        assert contact.is_favorite is True

    @pytest.mark.django_db
    def test_remove_favorite(self, api_client, contact, two_users):
        """Test removing contact from favorites."""
        user1, user2 = two_users
        contact.is_favorite = True
        contact.save()
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:contact-remove-favorite', args=[contact.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_200_OK
        contact.refresh_from_db()
        assert contact.is_favorite is False

    @pytest.mark.django_db
    def test_list_favorites(self, api_client, contact, two_users):
        """Test listing favorite contacts."""
        user1, user2 = two_users
        contact.is_favorite = True
        contact.save()
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:contact-favorites')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 1

    @pytest.mark.django_db
    def test_delete_contact(self, api_client, contact, two_users):
        """Test deleting a contact."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)
        contact_id = contact.id

        url = reverse('api_v1:messages:contact-detail', args=[contact_id])
        response = api_client.delete(url)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Contact.objects.filter(id=contact_id).exists()


# =============================================================================
# FRIEND REQUEST TESTS
# =============================================================================

class TestFriendRequestViewSet:
    """Tests for FriendRequestViewSet."""

    @pytest.mark.django_db
    def test_list_friend_requests(self, api_client, friend_request, two_users):
        """Test listing friend requests."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:friend-request-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_send_friend_request(self, api_client, user_factory):
        """Test sending a friend request."""
        sender = user_factory()
        receiver = user_factory()
        api_client.force_authenticate(user=sender)

        url = reverse('api_v1:messages:friend-request-list')
        response = api_client.post(url, {
            'receiver_id': receiver.id
        })

        assert response.status_code == status.HTTP_201_CREATED

    @pytest.mark.django_db
    def test_accept_friend_request(self, api_client, friend_request, two_users):
        """Test accepting a friend request."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user2)  # receiver

        url = reverse('api_v1:messages:friend-request-accept', args=[friend_request.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_200_OK
        friend_request.refresh_from_db()
        assert friend_request.accepted is True

    @pytest.mark.django_db
    def test_reject_friend_request(self, api_client, friend_request, two_users):
        """Test rejecting a friend request."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user2)  # receiver

        url = reverse('api_v1:messages:friend-request-reject', args=[friend_request.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_200_OK
        friend_request.refresh_from_db()
        assert friend_request.rejected is True

    @pytest.mark.django_db
    def test_cancel_friend_request(self, api_client, friend_request, two_users):
        """Test cancelling a friend request."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)  # sender

        url = reverse('api_v1:messages:friend-request-cancel', args=[friend_request.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_only_receiver_can_accept(self, api_client, friend_request, two_users):
        """Test only receiver can accept friend request."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)  # sender, not receiver

        url = reverse('api_v1:messages:friend-request-accept', args=[friend_request.id])
        response = api_client.post(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_list_received_requests(self, api_client, friend_request, two_users):
        """Test listing received friend requests."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user2)

        url = reverse('api_v1:messages:friend-request-received')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_list_sent_requests(self, api_client, friend_request, two_users):
        """Test listing sent friend requests."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:friend-request-sent')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK


# =============================================================================
# BLOCK LIST TESTS
# =============================================================================

class TestBlockListViewSet:
    """Tests for BlockListViewSet."""

    @pytest.mark.django_db
    def test_list_blocked_users(self, api_client, block_entry, two_users):
        """Test listing blocked users."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:block-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 1

    @pytest.mark.django_db
    def test_block_user(self, api_client, user_factory):
        """Test blocking a user."""
        blocker = user_factory()
        blocked = user_factory()
        api_client.force_authenticate(user=blocker)

        url = reverse('api_v1:messages:block-list')
        response = api_client.post(url, {
            'user_id': blocked.id
        })

        assert response.status_code == status.HTTP_201_CREATED

    @pytest.mark.django_db
    def test_unblock_user(self, api_client, block_entry, two_users):
        """Test unblocking a user."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)
        block_id = block_entry.id

        url = reverse('api_v1:messages:block-detail', args=[block_id])
        response = api_client.delete(url)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not BlockList.objects.filter(id=block_id).exists()

    @pytest.mark.django_db
    def test_check_blocked(self, api_client, block_entry, two_users):
        """Test checking if a user is blocked."""
        user1, user2 = two_users
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:block-check')
        response = api_client.post(url, {
            'user_id': user2.id
        })

        assert response.status_code == status.HTTP_200_OK
        assert response.data.get('data', {}).get('is_blocked') is True


# =============================================================================
# USER STATUS TESTS
# =============================================================================

class TestUserStatusViewSet:
    """Tests for UserStatusViewSet."""

    @pytest.mark.django_db
    def test_get_my_status(self, authenticated_client):
        """Test getting current user's status."""
        client, user = authenticated_client

        url = reverse('api_v1:messages:user-status-me')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_update_status(self, authenticated_client):
        """Test updating user status."""
        client, user = authenticated_client
        UserStatus.objects.create(user=user, is_online=False)

        url = reverse('api_v1:messages:user-status-update-status')
        response = client.put(url, {
            'is_online': True
        })

        assert response.status_code == status.HTTP_200_OK
        user_status = UserStatus.objects.get(user=user)
        assert user_status.is_online is True

    @pytest.mark.django_db
    def test_get_contact_statuses(self, api_client, contact, two_users):
        """Test getting contact statuses."""
        user1, user2 = two_users
        UserStatus.objects.create(user=user2, is_online=True)
        api_client.force_authenticate(user=user1)

        url = reverse('api_v1:messages:user-status-contact-statuses')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_200_OK
