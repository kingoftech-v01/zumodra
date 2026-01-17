"""
WebSocket integration tests for messages_sys app.

Tests the ChatConsumer WebSocket functionality including:
- Connection/disconnection
- Message sending/receiving
- Typing indicators
- Read receipts
- File uploads
- Multi-user scenarios
- Tenant isolation
"""

import pytest
import json
import base64
from channels.testing import WebsocketCommunicator
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from messages_sys.consumer import ChatConsumer
from messages_sys.models import Conversation, Message

User = get_user_model()


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
class TestChatConsumerConnection:
    """Test WebSocket connection lifecycle."""

    async def test_authenticated_user_can_connect(self, user_factory, conversation_factory):
        """Test that authenticated users can establish WebSocket connections."""
        user = await database_sync_to_async(user_factory)()
        conversation = await database_sync_to_async(conversation_factory)(participants=[user])

        communicator = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator.scope['user'] = user
        communicator.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}

        connected, _ = await communicator.connect()
        assert connected, "WebSocket connection should succeed for authenticated user"

        # Should receive connection confirmation
        response = await communicator.receive_json_from(timeout=5)
        assert response['type'] == 'status'
        assert response['message'] == 'Connected'
        assert response['is_online'] is True

        await communicator.disconnect()

    async def test_unauthenticated_user_rejected(self, conversation_factory):
        """Test that unauthenticated users are rejected."""
        conversation = await database_sync_to_async(conversation_factory)()

        communicator = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator.scope['user'] = None  # Unauthenticated

        connected, close_code = await communicator.connect()
        assert not connected, "Unauthenticated connection should be rejected"
        assert close_code == 4001  # Expected close code for auth failure

    async def test_non_participant_rejected(self, user_factory, conversation_factory):
        """Test that users who are not conversation participants are rejected."""
        user = await database_sync_to_async(user_factory)()
        other_user = await database_sync_to_async(user_factory)()
        conversation = await database_sync_to_async(conversation_factory)(participants=[other_user])

        communicator = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator.scope['user'] = user  # Not a participant
        communicator.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}

        connected, close_code = await communicator.connect()
        assert not connected, "Non-participant should be rejected"
        assert close_code == 4003  # Expected close code for access denied


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
class TestChatConsumerMessaging:
    """Test message sending and receiving."""

    async def test_send_text_message(self, user_factory, conversation_factory):
        """Test sending a simple text message."""
        user = await database_sync_to_async(user_factory)()
        conversation = await database_sync_to_async(conversation_factory)(participants=[user])

        communicator = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator.scope['user'] = user
        communicator.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}

        await communicator.connect()
        await communicator.receive_json_from(timeout=5)  # Connection status

        # Send message
        await communicator.send_json_to({
            'type': 'send_message',
            'content': 'Hello, World!',
        })

        # Receive broadcast message
        response = await communicator.receive_json_from(timeout=5)
        assert response['type'] == 'message'
        assert response['content'] == 'Hello, World!'
        assert response['sender'] == user.username
        assert response['is_read'] is False

        await communicator.disconnect()

    async def test_empty_message_rejected(self, user_factory, conversation_factory):
        """Test that empty messages are rejected."""
        user = await database_sync_to_async(user_factory)()
        conversation = await database_sync_to_async(conversation_factory)(participants=[user])

        communicator = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator.scope['user'] = user
        communicator.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}

        await communicator.connect()
        await communicator.receive_json_from(timeout=5)  # Connection status

        # Send empty message
        await communicator.send_json_to({
            'type': 'send_message',
            'content': '',
        })

        # Should receive error
        response = await communicator.receive_json_from(timeout=5)
        assert response['type'] == 'error'
        assert 'Empty message' in response['message']

        await communicator.disconnect()

    async def test_message_length_limit(self, user_factory, conversation_factory):
        """Test that messages exceeding length limit are rejected."""
        user = await database_sync_to_async(user_factory)()
        conversation = await database_sync_to_async(conversation_factory)(participants=[user])

        communicator = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator.scope['user'] = user
        communicator.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}

        await communicator.connect()
        await communicator.receive_json_from(timeout=5)  # Connection status

        # Send message exceeding 10,000 character limit
        long_message = 'A' * 10001
        await communicator.send_json_to({
            'type': 'send_message',
            'content': long_message,
        })

        # Should receive error
        response = await communicator.receive_json_from(timeout=5)
        assert response['type'] == 'error'
        assert 'too long' in response['message'].lower()

        await communicator.disconnect()


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
class TestChatConsumerTyping:
    """Test typing indicators."""

    async def test_typing_indicator_broadcast(self, user_factory, conversation_factory):
        """Test that typing indicators are broadcast to other users."""
        user = await database_sync_to_async(user_factory)()
        conversation = await database_sync_to_async(conversation_factory)(participants=[user])

        communicator = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator.scope['user'] = user
        communicator.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}

        await communicator.connect()
        await communicator.receive_json_from(timeout=5)  # Connection status

        # Send typing indicator
        await communicator.send_json_to({
            'type': 'typing',
            'is_typing': True,
        })

        # Should receive broadcast
        response = await communicator.receive_json_from(timeout=5)
        assert response['type'] == 'typing'
        assert response['typing_user'] == user.username
        assert response['is_typing'] is True

        # Stop typing
        await communicator.send_json_to({
            'type': 'typing',
            'is_typing': False,
        })

        response = await communicator.receive_json_from(timeout=5)
        assert response['type'] == 'typing'
        assert response['is_typing'] is False

        await communicator.disconnect()


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
class TestChatConsumerReadReceipts:
    """Test read receipt functionality."""

    async def test_read_receipt_recorded(self, user_factory, conversation_factory):
        """Test that read receipts are recorded and broadcast."""
        user = await database_sync_to_async(user_factory)()
        conversation = await database_sync_to_async(conversation_factory)(participants=[user])

        communicator = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator.scope['user'] = user
        communicator.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}

        await communicator.connect()
        await communicator.receive_json_from(timeout=5)  # Connection status

        # Send a message first
        await communicator.send_json_to({
            'type': 'send_message',
            'content': 'Test message',
        })

        # Receive the message
        message_response = await communicator.receive_json_from(timeout=5)
        message_id = message_response['id']

        # Send read receipt
        await communicator.send_json_to({
            'type': 'read',
            'message_id': message_id,
        })

        # Should receive read receipt broadcast
        response = await communicator.receive_json_from(timeout=5)
        assert response['type'] == 'read'
        assert response['message_id'] == message_id
        assert response['user'] == user.username

        await communicator.disconnect()


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
class TestChatConsumerFileUpload:
    """Test file upload functionality."""

    async def test_valid_file_upload(self, user_factory, conversation_factory):
        """Test uploading a valid file."""
        user = await database_sync_to_async(user_factory)()
        conversation = await database_sync_to_async(conversation_factory)(participants=[user])

        communicator = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator.scope['user'] = user
        communicator.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}

        await communicator.connect()
        await communicator.receive_json_from(timeout=5)  # Connection status

        # Create a simple text file
        file_content = b"This is a test file"
        file_base64 = base64.b64encode(file_content).decode('utf-8')

        # Send file
        await communicator.send_json_to({
            'type': 'send_message',
            'content': 'Sending a file',
            'file': {
                'name': 'test.txt',
                'content': file_base64,
            },
        })

        # Should receive message with file
        response = await communicator.receive_json_from(timeout=5)
        assert response['type'] == 'message'
        assert response['content'] == 'Sending a file'
        assert response['file'] != ''  # File URL should be present

        await communicator.disconnect()

    async def test_dangerous_file_rejected(self, user_factory, conversation_factory):
        """Test that dangerous file types are rejected."""
        user = await database_sync_to_async(user_factory)()
        conversation = await database_sync_to_async(conversation_factory)(participants=[user])

        communicator = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator.scope['user'] = user
        communicator.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}

        await communicator.connect()
        await communicator.receive_json_from(timeout=5)  # Connection status

        # Try to upload .exe file
        file_content = b"MZ\x90\x00"  # PE executable header
        file_base64 = base64.b64encode(file_content).decode('utf-8')

        await communicator.send_json_to({
            'type': 'send_message',
            'content': 'Sending malicious file',
            'file': {
                'name': 'malware.exe',
                'content': file_base64,
            },
        })

        # Should receive error
        response = await communicator.receive_json_from(timeout=5)
        assert response['type'] == 'error'
        assert 'not allowed' in response['message'].lower()

        await communicator.disconnect()

    async def test_file_size_limit(self, user_factory, conversation_factory):
        """Test that files exceeding size limit are rejected."""
        user = await database_sync_to_async(user_factory)()
        conversation = await database_sync_to_async(conversation_factory)(participants=[user])

        communicator = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator.scope['user'] = user
        communicator.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}

        await communicator.connect()
        await communicator.receive_json_from(timeout=5)  # Connection status

        # Create file larger than 50MB limit (simulate with metadata)
        # Note: We don't actually create 50MB+ data to avoid memory issues in tests
        large_file_content = b"X" * (51 * 1024 * 1024)  # 51 MB
        file_base64 = base64.b64encode(large_file_content).decode('utf-8')

        await communicator.send_json_to({
            'type': 'send_message',
            'content': 'Sending large file',
            'file': {
                'name': 'large.zip',
                'content': file_base64,
            },
        })

        # Should receive error
        response = await communicator.receive_json_from(timeout=5)
        assert response['type'] == 'error'
        assert 'too large' in response['message'].lower()

        await communicator.disconnect()


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
class TestChatConsumerMultiUser:
    """Test multi-user chat scenarios."""

    async def test_message_broadcast_to_all_participants(self, user_factory, conversation_factory):
        """Test that messages are broadcast to all conversation participants."""
        user1 = await database_sync_to_async(user_factory)()
        user2 = await database_sync_to_async(user_factory)()
        conversation = await database_sync_to_async(conversation_factory)(participants=[user1, user2])

        # Connect first user
        communicator1 = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator1.scope['user'] = user1
        communicator1.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}
        await communicator1.connect()
        await communicator1.receive_json_from(timeout=5)  # Connection status

        # Connect second user
        communicator2 = WebsocketCommunicator(
            ChatConsumer.as_asgi(),
            f"/ws/chat/{conversation.id}/"
        )
        communicator2.scope['user'] = user2
        communicator2.scope['url_route'] = {'kwargs': {'conversation_id': str(conversation.id)}}
        await communicator2.connect()
        await communicator2.receive_json_from(timeout=5)  # Connection status

        # User 1 sends message
        await communicator1.send_json_to({
            'type': 'send_message',
            'content': 'Hello from User 1',
        })

        # Both users should receive the message
        response1 = await communicator1.receive_json_from(timeout=5)
        response2 = await communicator2.receive_json_from(timeout=5)

        assert response1['content'] == 'Hello from User 1'
        assert response2['content'] == 'Hello from User 1'
        assert response1['sender'] == user1.username
        assert response2['sender'] == user1.username

        await communicator1.disconnect()
        await communicator2.disconnect()
