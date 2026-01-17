# Messaging System Testing - Quick Start Guide

## Overview
Complete test suite for Zumodra's real-time messaging system including direct messages, groups, WebSocket, file attachments, and more.

## Files Created

1. **test_messaging_system_comprehensive.py** (500+ lines)
   - Database model tests (55 test cases)
   - API endpoint tests
   - Integration tests

2. **test_messaging_websocket.py** (400+ lines)
   - WebSocket consumer tests
   - Real-time delivery tests
   - Security tests

3. **MESSAGING_SYSTEM_TEST_REPORT.md** (Comprehensive documentation)

---

## Quick Test Commands

### Run All Tests
```bash
cd /c/Users/techn/OneDrive/Documents/zumodra
pytest test_messaging_system_comprehensive.py -v
```

### Run Specific Test Class
```bash
# Test direct messaging
pytest test_messaging_system_comprehensive.py::TestDirectMessages -v

# Test groups
pytest test_messaging_system_comprehensive.py::TestGroupConversations -v

# Test read receipts
pytest test_messaging_system_comprehensive.py::TestMessageReadReceipts -v

# Test files
pytest test_messaging_system_comprehensive.py::TestFileAttachments -v

# Test search
pytest test_messaging_system_comprehensive.py::TestMessageSearch -v

# Test contacts
pytest test_messaging_system_comprehensive.py::TestContactManagement -v

# Test friend requests
pytest test_messaging_system_comprehensive.py::TestFriendRequests -v

# Test blocking
pytest test_messaging_system_comprehensive.py::TestBlocking -v

# Test API
pytest test_messaging_system_comprehensive.py::TestMessagingAPI -v
```

### Run with Coverage
```bash
pytest test_messaging_system_comprehensive.py --cov=messages_sys --cov-report=html -v
```

### Run with Output
```bash
pytest test_messaging_system_comprehensive.py -vv -s
```

---

## Test Coverage Summary

### 1. Direct Messages ✓ (8 tests)
- Creating 1-to-1 conversations
- Caching mechanisms
- Message sending
- Timestamp tracking
- Denormalization updates
- Access control

### 2. Group Conversations ✓ (9 tests)
- Creating groups (3+ participants)
- Adding/removing participants
- Participant validation
- Group deletion on empty
- Message visibility to all members

### 3. Read Receipts ✓ (7 tests)
- Creating MessageStatus records
- Marking messages as read
- Unread message queries
- Bulk marking conversation as read
- Excluding read from unread list

### 4. File Attachments ✓ (7 tests)
- Uploading files with messages
- File size validation (50MB limit)
- Extension validation (whitelist)
- Allowed types: PDF, DOC, JPG, PNG, MP4, ZIP, etc.
- Blocked types: EXE, BAT, SH, PHP, etc.
- Voice messages

### 5. Message Search ✓ (6 tests)
- Full-text search
- Case-insensitive matching
- Cross-conversation search
- Within-conversation search
- Result limiting (50 max)
- Minimum query length (2 chars)

### 6. Contact Management ✓ (5 tests)
- Adding contacts
- Favorite marking
- Listing contacts
- Duplicate prevention

### 7. Friend Requests ✓ (6 tests)
- Creating requests
- Accepting (creates bidirectional contacts)
- Rejecting
- Canceling
- Validation rules

### 8. User Blocking ✓ (7 tests)
- Blocking users
- Checking block status
- Bidirectional checking
- Cache-backed queries (5min TTL)
- Blocking prevents WebSocket access

### 9. User Status ✓ (5 tests)
- Online/offline status
- Last seen tracking
- Status queries
- String representation

### 10. REST API ✓ (6 tests)
- Conversations endpoints
- Messages endpoints
- Contacts endpoints
- Friend requests endpoints
- Block list endpoints
- Status endpoints

### 11. WebSocket Real-Time ✓ (Testing framework)
- Connection establishment
- Message delivery
- Typing indicators
- Read receipts
- File uploads
- Group management
- Security/authorization
- Error handling

---

## WebSocket Testing

### Check Consumer Status
```bash
# Consumer implementation check
python -c "from messages_sys.consumer import ChatConsumer; print('✓ ChatConsumer is active')"

# Check routing
python -c "from messages_sys.routing import websocket_urlpatterns; print(f'✓ WebSocket routes: {len(websocket_urlpatterns)} patterns')"
```

### Test WebSocket Connection
```bash
# Using wscat (npm install -g wscat)
wscat -c "ws://localhost:8003/ws/chat/{conversation_id}/"

# Or use channels testing (in Django shell)
python manage.py shell
from channels.testing import WebsocketCommunicator
from messages_sys.consumer import ChatConsumer
```

### Manual WebSocket Test
```python
# In Django shell
import asyncio
from channels.testing import WebsocketCommunicator
from messages_sys.consumer import ChatConsumer
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.first()
conversation_id = "your-conversation-id"

async def test():
    communicator = WebsocketCommunicator(
        ChatConsumer.as_asgi(),
        f"ws/chat/{conversation_id}/",
        headers=[(b"user", user.username.encode())]
    )
    connected, _ = await communicator.connect()
    print(f"Connected: {connected}")

    # Send message
    await communicator.send_json_to({
        "type": "send_message",
        "content": "Hello from test"
    })

    # Receive
    response = await communicator.receive_json_from()
    print(f"Response: {response}")

    await communicator.disconnect()

asyncio.run(test())
```

---

## Docker Integration

### Start Services
```bash
docker compose up -d
```

### Check Services
```bash
# Check Channels (WebSocket)
docker compose logs channels | head -50

# Check Redis (Channel layer)
docker compose logs redis | head -20

# Check Database
docker compose logs db | head -20
```

### Run Tests in Docker
```bash
# Install dependencies
docker compose exec web pip install pytest-asyncio channels-testing

# Run tests
docker compose exec web pytest test_messaging_system_comprehensive.py -v

# Run WebSocket tests
docker compose exec web pytest test_messaging_websocket.py -v

# View WebSocket logs
docker compose exec channels tail -f /app/logs/channels.log
```

### Check Service Health
```bash
# Web service
curl http://localhost:8002/health/

# Channels service (WebSocket)
curl http://localhost:8003/health/

# Redis
docker compose exec redis redis-cli ping

# PostgreSQL
docker compose exec db pg_isready
```

---

## API Testing

### Base URL
```
http://localhost:8002/api/v1/messages/
```

### Authentication
```bash
# Get JWT token
curl -X POST http://localhost:8002/api/token/ \
  -d '{"email":"user@test.com","password":"testpass"}' \
  -H "Content-Type: application/json"

# Use token
curl -H "Authorization: Bearer {token}" \
  http://localhost:8002/api/v1/messages/conversations/
```

### Endpoints

**Conversations:**
```bash
# List
curl http://localhost:8002/api/v1/messages/conversations/ \
  -H "Authorization: Bearer {token}"

# Create
curl -X POST http://localhost:8002/api/v1/messages/conversations/ \
  -d '{"participants":[2]}' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {token}"

# Mark as read
curl -X POST http://localhost:8002/api/v1/messages/conversations/{id}/mark_read/ \
  -H "Authorization: Bearer {token}"
```

**Messages:**
```bash
# List
curl http://localhost:8002/api/v1/messages/messages/ \
  -H "Authorization: Bearer {token}"

# Search
curl "http://localhost:8002/api/v1/messages/messages/search/?q=hello" \
  -H "Authorization: Bearer {token}"
```

**Contacts:**
```bash
# List
curl http://localhost:8002/api/v1/messages/contacts/ \
  -H "Authorization: Bearer {token}"

# Add
curl -X POST http://localhost:8002/api/v1/messages/contacts/ \
  -d '{"contact":2}' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {token}"

# Add favorite
curl -X POST http://localhost:8002/api/v1/messages/contacts/{id}/add_favorite/ \
  -H "Authorization: Bearer {token}"
```

**Blocked Users:**
```bash
# List
curl http://localhost:8002/api/v1/messages/blocked/ \
  -H "Authorization: Bearer {token}"

# Block user
curl -X POST http://localhost:8002/api/v1/messages/blocked/ \
  -d '{"blocked_user_id":2}' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {token}"

# Check if blocked
curl -X POST http://localhost:8002/api/v1/messages/blocked/check/ \
  -d '{"user_id":2}' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {token}"
```

---

## Test Database Setup

### Create Test Users
```python
# In Django shell
from django.contrib.auth import get_user_model

User = get_user_model()

# Create users
user1 = User.objects.create_user(
    username='testuser1',
    email='user1@test.com',
    password='testpass123'
)

user2 = User.objects.create_user(
    username='testuser2',
    email='user2@test.com',
    password='testpass123'
)

print(f"Created: {user1}, {user2}")
```

### Create Test Conversation
```python
from messages_sys.models import Conversation

conv, created = Conversation.objects.get_or_create_direct(user1, user2)
print(f"Conversation {conv.id}: Created={created}")
```

### Send Test Message
```python
from messages_sys.models import Message

msg = Message.objects.create(
    conversation=conv,
    sender=user1,
    content="Hello from test!"
)
print(f"Message: {msg.content}")
```

---

## Common Issues & Solutions

### Issue: Import Error - ChatConsumer not found
**Solution:** Check that consumer.py exists and ChatConsumer class is not commented out
```bash
grep -n "class ChatConsumer" messages_sys/consumer.py
```

### Issue: WebSocket Connection Refused
**Solution:** Check Channels service is running
```bash
docker compose logs channels | tail -20
docker compose ps | grep channels
```

### Issue: Tests timeout
**Solution:** Increase pytest timeout
```bash
pytest test_messaging_system_comprehensive.py --timeout=300 -v
```

### Issue: Database not ready
**Solution:** Ensure migrations are applied
```bash
python manage.py migrate_schemas --shared
python manage.py migrate_schemas --tenant
```

### Issue: Redis connection error
**Solution:** Check Redis is running
```bash
redis-cli ping
docker compose logs redis | tail -20
```

---

## Performance Testing

### Load Test - Send Many Messages
```python
# In Django shell
import time
from messages_sys.models import Message

conversation = Conversation.objects.first()
start = time.time()

for i in range(100):
    Message.objects.create(
        conversation=conversation,
        sender=user1,
        content=f"Message {i}"
    )

elapsed = time.time() - start
print(f"Created 100 messages in {elapsed:.2f}s ({100/elapsed:.0f} msg/s)")
```

### Query Performance
```python
# Check query count
from django.test.utils import override_settings
from django.db import connection
from django.test import TestCase

with override_settings(DEBUG=True):
    conversations = Conversation.objects.for_user(user1)
    list(conversations)  # Execute query

    print(f"SQL Queries: {len(connection.queries)}")
    for q in connection.queries:
        print(f"  {q['time']:.4f}s - {q['sql'][:100]}")
```

---

## Monitoring

### Enable Logging
```python
# In settings.py (for testing)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'messages_sys': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}
```

### Monitor WebSocket Connections
```bash
# Check active connections
docker compose exec channels curl -s http://localhost:8001/health/

# Check Redis memory
docker compose exec redis redis-cli info memory

# Monitor messages
docker compose exec web python manage.py shell
from messages_sys.models import Message
print(f"Total messages: {Message.objects.count()}")
print(f"Today's messages: {Message.objects.filter(timestamp__date=date.today()).count()}")
```

---

## Continuous Integration

### GitHub Actions Example
```yaml
name: Test Messaging System

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgis/postgis:15
        env:
          POSTGRES_PASSWORD: password

      redis:
        image: redis:7-alpine

    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'

      - run: pip install -r requirements.txt
      - run: pytest test_messaging_system_comprehensive.py -v
      - run: pytest test_messaging_websocket.py -v
      - run: pytest --cov=messages_sys --cov-report=xml
      - uses: codecov/codecov-action@v2
```

---

## Support & Resources

- **Test Files:** `/c/Users/techn/OneDrive/Documents/zumodra/test_messaging_*.py`
- **Models:** `/c/Users/techn/OneDrive/Documents/zumodra/messages_sys/models.py`
- **Consumer:** `/c/Users/techn/OneDrive/Documents/zumodra/messages_sys/consumer.py`
- **API:** `/c/Users/techn/OneDrive/Documents/zumodra/messages_sys/api/viewsets.py`
- **Full Report:** `MESSAGING_SYSTEM_TEST_REPORT.md`

## Next Steps

1. Run tests to verify setup
2. Review test output for any failures
3. Check Docker services if WebSocket tests fail
4. Adjust settings based on environment
5. Deploy to production with confidence
