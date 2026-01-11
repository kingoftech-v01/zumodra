# Messages System App

## Overview

Real-time messaging system using Django Channels and WebSockets for instant communication between users.

## Key Features

- **Real-Time Chat**: WebSocket-based instant messaging
- **Typing Indicators**: Live typing status
- **Read Receipts**: Message read tracking
- **File Sharing**: Attachment support
- **Conversation Threading**: Organized conversations
- **Online Status**: User presence indicators

## Architecture

### Technology Stack
- **Django Channels**: WebSocket support
- **Redis**: Channel layer backend
- **Daphne**: ASGI server

### WebSocket Flow
```
Client WebSocket → Daphne → Channels → Redis → Consumer → Database
```

## Models

| Model | Description |
|-------|-------------|
| **Conversation** | Chat conversations |
| **Message** | Individual messages |
| **Participant** | Conversation participants |
| **Attachment** | Message attachments |
| **ReadReceipt** | Message read status |

## Consumers

Located in `messages_sys/consumers.py`:

- `ChatConsumer`: Main WebSocket consumer
- `TypingConsumer`: Typing indicator consumer
- `PresenceConsumer`: Online status consumer

## Views

- `ConversationListView` - List conversations
- `ConversationDetailView` - Chat interface
- `MessageSendView` - Send message (HTMX fallback)
- `AttachmentUploadView` - File upload

## URL Structure

```python
# WebSocket
ws/chat/<conversation_id>/
ws/typing/<conversation_id>/
ws/presence/

# HTTP
frontend:messages:conversation_list
frontend:messages:conversation_detail (pk)
frontend:messages:send_message
```

## Integration Points

- **Accounts**: User profiles and status
- **Services**: Contract messaging
- **ATS**: Recruiter-candidate chat
- **Notifications**: Message notifications

## Future Improvements

### High Priority

1. **Group Chats**: Multi-participant conversations
2. **Message Search**: Full-text search in conversations
3. **Voice Messages**: Audio message support
4. **Video Calls**: Integrated video calling
5. **Message Reactions**: Emoji reactions

### Medium Priority

6. **Message Threading**: Reply threads
7. **Message Editing**: Edit sent messages
8. **Message Pinning**: Pin important messages
9. **Auto-Delete**: Disappearing messages
10. **Message Translation**: Auto-translate languages

## Security

- User authentication required
- Conversation access control
- Message encryption in transit (TLS)
- Attachment virus scanning
- Rate limiting on WebSocket

## Performance

- Redis for channel layer
- Message pagination
- Connection pooling
- Async message processing
- CDN for attachments

## Testing

```
tests/
├── test_chat_consumer.py
├── test_messages.py
├── test_conversations.py
└── test_websocket_auth.py
```

---

**Status:** Production
