# Notification Testing - Technical Reference & Troubleshooting

## Table of Contents

1. [Notification System Architecture](#architecture)
2. [Database Models](#database-models)
3. [Service Layer](#service-layer)
4. [Celery Tasks](#celery-tasks)
5. [API Endpoints](#api-endpoints)
6. [Common Issues & Solutions](#common-issues)
7. [Performance Tuning](#performance-tuning)
8. [Monitoring & Debugging](#monitoring--debugging)

---

## Architecture

### Notification Flow Diagram

```
User Action (e.g., job application)
    ↓
Signal Trigger (notifications.signals)
    ↓
notification_service.send_notification()
    ↓
Celery Task: send_notification_task()
    ↓
├─→ EmailNotificationService (SMTP → MailHog)
├─→ InAppNotificationService (Database)
├─→ PushNotificationService (FCM/APNs)
└─→ SMSNotificationService (Twilio/etc)
    ↓
NotificationDeliveryLog (created for each attempt)
    ↓
Retry mechanism (if failed, exponential backoff)
```

### Component Responsibilities

| Component | Responsibility |
|-----------|-----------------|
| **Models** | Store notifications, preferences, delivery logs |
| **Services** | Handle sending logic for each channel |
| **Tasks** | Async processing via Celery |
| **Signals** | Trigger notifications on events |
| **Views/API** | Expose notification endpoints |
| **Preferences** | User-configurable notification settings |

---

## Database Models

### NotificationChannel

Store available notification channels and their configuration.

```python
class NotificationChannel(models.Model):
    name = models.CharField(max_length=50, unique=True)
    channel_type = models.CharField(
        max_length=20,
        choices=[
            ('email', 'Email'),
            ('sms', 'SMS'),
            ('push', 'Push Notification'),
            ('in_app', 'In-App Notification'),
            ('slack', 'Slack'),
            ('webhook', 'Webhook'),
        ]
    )
    is_active = models.BooleanField(default=True)
    rate_limit_per_hour = models.PositiveIntegerField(default=100)
    config = models.JSONField(default=dict)  # Channel-specific config
```

**Example Config:**

```json
{
    "email": {
        "smtp_host": "mailhog",
        "smtp_port": 1025,
        "from_email": "noreply@zumodra.com"
    },
    "push": {
        "fcm_api_key": "xxx",
        "ios_team_id": "xxx"
    }
}
```

### NotificationTemplate

Reusable templates for different notification types.

```python
class NotificationTemplate(models.Model):
    name = models.CharField(max_length=100, unique=True)
    template_type = models.CharField(max_length=50, choices=TEMPLATE_TYPES)
    subject = models.CharField(max_length=255)
    text_body = models.TextField()
    html_body = models.TextField()
    description = models.TextField()
    variables = models.JSONField(default=list)  # Required template variables
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

### Notification

Main notification model storing individual notifications.

```python
class Notification(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    recipient = models.ForeignKey(User, on_delete=models.CASCADE)
    sender = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='sent_notifications'
    )
    notification_type = models.CharField(max_length=100)
    title = models.CharField(max_length=255)
    message = models.TextField()
    html_message = models.TextField(blank=True)
    channels = models.JSONField(default=list)  # ["email", "in_app", "push"]
    priority = models.CharField(
        max_length=20,
        choices=[('low', 'Low'), ('normal', 'Normal'), ('high', 'High')],
        default='normal'
    )
    action_url = models.URLField(blank=True)
    action_text = models.CharField(max_length=100, blank=True, default='View')
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)
    template = models.ForeignKey(NotificationTemplate, null=True, blank=True)
    context_data = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Retry tracking
    retry_count = models.PositiveIntegerField(default=0)
    max_retries = models.PositiveIntegerField(default=3)
    last_retry_at = models.DateTimeField(null=True, blank=True)
    next_retry_at = models.DateTimeField(null=True, blank=True)
```

### NotificationDeliveryLog

Tracks every delivery attempt with details.

```python
class NotificationDeliveryLog(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('failed', 'Failed'),
        ('bounced', 'Bounced'),
        ('opened', 'Opened'),
        ('clicked', 'Clicked'),
    ]

    notification = models.ForeignKey(Notification, on_delete=models.CASCADE)
    attempt_number = models.PositiveIntegerField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    request_payload = models.JSONField()
    response_payload = models.JSONField()
    response_code = models.PositiveIntegerField(null=True)
    error_type = models.CharField(max_length=255, blank=True)
    error_message = models.TextField(blank=True)
    error_traceback = models.TextField(blank=True)
    external_id = models.CharField(max_length=255, blank=True)
    completed_at = models.DateTimeField()
    duration_ms = models.PositiveIntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
```

### NotificationPreference

User notification preferences.

```python
class NotificationPreference(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_enabled = models.BooleanField(default=True)
    in_app_enabled = models.BooleanField(default=True)
    push_enabled = models.BooleanField(default=False)
    sms_enabled = models.BooleanField(default=False)
    batch_digest_frequency = models.CharField(
        max_length=20,
        choices=[
            ('immediate', 'Immediate'),
            ('hourly', 'Hourly'),
            ('daily', 'Daily'),
            ('weekly', 'Weekly'),
        ],
        default='daily'
    )
    quiet_hours_start = models.TimeField(default='22:00')
    quiet_hours_end = models.TimeField(default='08:00')

    # Complex settings
    channel_settings = models.JSONField(default=dict)
    notification_type_settings = models.JSONField(default=dict)
    unsubscribe_token = models.CharField(max_length=100, unique=True)
    unsubscribed_types = models.JSONField(default=list)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
```

---

## Service Layer

### NotificationService (Base)

Abstract base class for all notification services.

```python
class BaseNotificationService(ABC):
    """Abstract base for notification services."""

    channel_type: str = None

    def __init__(self, channel: NotificationChannel = None):
        self.channel = channel

    @abstractmethod
    def send(self, notification: Notification, **kwargs) -> NotificationResult:
        """Send notification. Must be implemented by subclasses."""
        pass

    def create_delivery_log(self, notification, status, **kwargs):
        """Create delivery log entry."""
        # Implementation...
```

### EmailNotificationService

Handles email delivery via SMTP.

```python
class EmailNotificationService(BaseNotificationService):
    """Service for sending email notifications."""

    channel_type = 'email'

    def send(self, notification: Notification, **kwargs) -> NotificationResult:
        """
        Send email notification.

        Steps:
        1. Get recipient email
        2. Build unsubscribe URL
        3. Render HTML from template
        4. Create EmailMultiAlternatives
        5. Send via SMTP
        6. Log delivery result
        7. Retry on failure
        """
        # Implementation...
```

**Configuration:**

```python
# settings.py
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'mailhog'  # Docker service name
EMAIL_PORT = 1025
EMAIL_HOST_USER = ''
EMAIL_HOST_PASSWORD = ''
EMAIL_USE_TLS = False
DEFAULT_FROM_EMAIL = 'noreply@zumodra.com'
```

### InAppNotificationService

Stores notifications in database.

```python
class InAppNotificationService(BaseNotificationService):
    """Service for in-app notifications."""

    channel_type = 'in_app'

    def send(self, notification: Notification, **kwargs) -> NotificationResult:
        """
        Store in-app notification.

        Steps:
        1. Ensure notification object exists
        2. Create delivery log with 'sent' status
        3. Return success
        """
        # Implementation...
```

### PushNotificationService

Sends push notifications to devices.

```python
class PushNotificationService(BaseNotificationService):
    """Service for push notifications."""

    channel_type = 'push'

    def send(self, notification: Notification, **kwargs) -> NotificationResult:
        """
        Send push notification to device tokens.

        Steps:
        1. Get user's device tokens
        2. Build push payload
        3. Send via FCM/APNs
        4. Log delivery with external ID
        5. Handle failures (invalid tokens, etc.)
        """
        # Implementation...
```

### Singleton Pattern

```python
class NotificationServiceFactory:
    """Factory for notification services."""

    _services = {}

    @classmethod
    def get_service(cls, channel_type: str) -> BaseNotificationService:
        """Get service instance for channel type."""
        if channel_type not in cls._services:
            channel = NotificationChannel.objects.get(channel_type=channel_type)
            if channel_type == 'email':
                cls._services[channel_type] = EmailNotificationService(channel)
            elif channel_type == 'in_app':
                cls._services[channel_type] = InAppNotificationService(channel)
            # ... etc
        return cls._services[channel_type]
```

---

## Celery Tasks

### send_notification_task

Main async task for sending notifications.

```python
@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,
    queue='notifications'
)
def send_notification_task(self, recipient_id, notification_type, **kwargs):
    """
    Send notification asynchronously.

    Retries:
    - First: 60 seconds
    - Second: 300 seconds (5 minutes)
    - Third: 900 seconds (15 minutes)
    """
    # Implementation...
```

### Task Queue Configuration

```python
# settings.py
CELERY_BROKER_URL = 'amqp://zumodra:password@rabbitmq:5672/zumodra'
CELERY_RESULT_BACKEND = 'redis://redis:6379/1'
CELERY_TASK_ROUTES = {
    'notifications.tasks.*': {'queue': 'notifications'},
}
CELERY_TASK_RATE_LIMIT = '1000/m'  # Max tasks per minute
```

### Task Monitoring

```bash
# List active tasks
docker compose exec celery-worker celery -A zumodra inspect active

# Get task stats
docker compose exec celery-worker celery -A zumodra inspect stats

# Purge failed tasks
docker compose exec celery-worker celery -A zumodra purge

# Monitor in real-time
docker compose exec celery-worker celery -A zumodra events
```

---

## API Endpoints

### List Notifications

```
GET /api/v1/notifications/list/
Authorization: Bearer {token}

Response:
{
    "count": 42,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": "uuid-123",
            "recipient": "user@example.com",
            "notification_type": "application_received",
            "title": "New Application",
            "message": "You have a new job application",
            "is_read": false,
            "created_at": "2026-01-16T10:30:00Z"
        }
    ]
}
```

### Get Notification Detail

```
GET /api/v1/notifications/{id}/
Authorization: Bearer {token}

Response:
{
    "id": "uuid-123",
    "recipient": "user@example.com",
    "notification_type": "application_received",
    "title": "New Application",
    "message": "You have a new job application",
    "html_message": "<p>You have a new job application</p>",
    "channels": ["email", "in_app"],
    "priority": "high",
    "action_url": "https://zumodra.com/applications/123",
    "action_text": "View Application",
    "is_read": false,
    "read_at": null,
    "created_at": "2026-01-16T10:30:00Z"
}
```

### Mark as Read

```
PATCH /api/v1/notifications/{id}/mark-read/
Authorization: Bearer {token}

Response:
{
    "id": "uuid-123",
    "is_read": true,
    "read_at": "2026-01-16T10:35:00Z"
}
```

### Get Unread Count

```
GET /api/v1/notifications/unread-count/
Authorization: Bearer {token}

Response:
{
    "unread_count": 5
}
```

### Get Preferences

```
GET /api/v1/notifications/preferences/
Authorization: Bearer {token}

Response:
{
    "id": 1,
    "user": 1,
    "email_enabled": true,
    "in_app_enabled": true,
    "push_enabled": false,
    "sms_enabled": false,
    "batch_digest_frequency": "daily"
}
```

### Update Preferences

```
PUT /api/v1/notifications/preferences/
Authorization: Bearer {token}

Request:
{
    "email_enabled": true,
    "in_app_enabled": true,
    "push_enabled": true,
    "sms_enabled": false,
    "batch_digest_frequency": "daily"
}

Response:
{
    "id": 1,
    "email_enabled": true,
    "in_app_enabled": true,
    "push_enabled": true,
    "sms_enabled": false,
    "batch_digest_frequency": "daily"
}
```

---

## Common Issues & Solutions

### Issue 1: Emails Not Received

**Symptoms:** Test emails not appearing in MailHog

**Causes:**
1. MailHog service not running
2. Django EMAIL_BACKEND configured incorrectly
3. SMTP credentials wrong
4. Notification channel disabled

**Solutions:**

```bash
# 1. Check MailHog is running
docker compose ps mailhog

# 2. Check Django config
docker compose exec web python -c "
from django.conf import settings
print(f'Backend: {settings.EMAIL_BACKEND}')
print(f'Host: {settings.EMAIL_HOST}')
print(f'Port: {settings.EMAIL_PORT}')
"

# 3. Test SMTP connection
docker compose exec web python << 'EOF'
import smtplib
try:
    server = smtplib.SMTP('mailhog', 1025)
    server.quit()
    print("SMTP connection successful")
except Exception as e:
    print(f"SMTP error: {e}")
EOF

# 4. Check notification channel
docker compose exec web python << 'EOF'
from notifications.models import NotificationChannel
channel = NotificationChannel.objects.filter(channel_type='email').first()
print(f"Email channel active: {channel.is_active if channel else 'NOT FOUND'}")
EOF
```

### Issue 2: In-App Notifications Not Showing

**Symptoms:** Notifications created but not visible in UI

**Causes:**
1. Notification not marked as "in_app" channel
2. Database query incorrect
3. Frontend not fetching notifications

**Solutions:**

```bash
# 1. Verify notification in database
docker compose exec web python << 'EOF'
from notifications.models import Notification
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.first()
notifs = Notification.objects.filter(recipient=user)
for n in notifs:
    print(f"ID: {n.id}, Type: {n.notification_type}")
    print(f"Channels: {n.channels}")
    print(f"Created: {n.created_at}")
EOF

# 2. Check if "in_app" is in channels
docker compose exec web python << 'EOF'
from notifications.models import Notification
notif = Notification.objects.first()
if notif:
    print(f"Channels: {notif.channels}")
    print(f"Has in_app: {'in_app' in notif.channels}")
EOF
```

### Issue 3: Celery Tasks Not Executing

**Symptoms:** Tasks queued but not processed

**Causes:**
1. Celery worker not running
2. RabbitMQ not accessible
3. Task queue misconfigured

**Solutions:**

```bash
# 1. Check Celery worker is running
docker compose ps celery-worker

# 2. Check RabbitMQ connection
docker compose exec celery-worker celery -A zumodra inspect ping

# 3. View active tasks
docker compose exec celery-worker celery -A zumodra inspect active

# 4. Check task queue
docker compose exec celery-worker celery -A zumodra inspect active_queues

# 5. View Celery logs
docker compose logs -f celery-worker
```

### Issue 4: Rate Limiting Blocking Notifications

**Symptoms:** Notifications fail with rate limit error

**Causes:**
1. Too many notifications sent to same user
2. Channel rate limit exceeded
3. Global rate limiting active

**Solutions:**

```bash
# Check rate limits
docker compose exec web python << 'EOF'
from notifications.models import NotificationChannel
for channel in NotificationChannel.objects.all():
    print(f"{channel.name}: {channel.rate_limit_per_hour} per hour")
EOF

# Update rate limit
docker compose exec web python << 'EOF'
from notifications.models import NotificationChannel
channel = NotificationChannel.objects.get(channel_type='email')
channel.rate_limit_per_hour = 200  # Increase limit
channel.save()
EOF
```

### Issue 5: Delivery Logs Not Created

**Symptoms:** No delivery logs for sent notifications

**Causes:**
1. Service not creating logs
2. Batch notification mode enabled
3. Async task not completing

**Solutions:**

```bash
# Check for delivery logs
docker compose exec web python << 'EOF'
from notifications.models import NotificationDeliveryLog
logs = NotificationDeliveryLog.objects.all().order_by('-created_at')[:10]
for log in logs:
    print(f"Status: {log.status}, Code: {log.response_code}, Error: {log.error_message}")
EOF

# Force synchronous sending for testing
docker compose exec web python << 'EOF'
from django.test.utils import override_settings
with override_settings(CELERY_TASK_ALWAYS_EAGER=True):
    # Send notification - will execute immediately
    pass
EOF
```

---

## Performance Tuning

### Database Optimization

```sql
-- Add indexes for common queries
CREATE INDEX idx_notification_recipient_created
ON notifications_notification(recipient_id, created_at DESC);

CREATE INDEX idx_notification_is_read
ON notifications_notification(recipient_id, is_read);

CREATE INDEX idx_notificationdeliverylog_notification
ON notifications_notificationdeliverylog(notification_id);

CREATE INDEX idx_notificationdeliverylog_status
ON notifications_notificationdeliverylog(status);
```

### Celery Optimization

```python
# settings.py

# Task optimization
CELERY_TASK_COMPRESSION = 'gzip'
CELERY_RESULT_COMPRESSION = 'gzip'

# Worker settings
CELERYD_POOL = 'prefork'
CELERYD_CONCURRENCY = 4
CELERYD_PREFETCH_MULTIPLIER = 4

# Task scheduling
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes
CELERY_TASK_SOFT_TIME_LIMIT = 25 * 60  # 25 minutes

# Batching
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_ALWAYS_EAGER = False  # True only in tests
```

### Query Optimization

```python
# Use select_related for foreign keys
notifications = Notification.objects.select_related(
    'recipient',
    'sender',
    'template'
).all()

# Use prefetch_related for reverse relations
users = User.objects.prefetch_related(
    'notifications'
).all()
```

---

## Monitoring & Debugging

### Django Debug Toolbar

```python
# settings.py
INSTALLED_APPS += ['debug_toolbar']
MIDDLEWARE += ['debug_toolbar.middleware.DebugToolbarMiddleware']
INTERNAL_IPS = ['127.0.0.1']
```

### Query Monitoring

```bash
# Log all database queries
docker compose exec web python << 'EOF'
from django.db import connection
from django.test.utils import CaptureQueriesContext

with CaptureQueriesContext(connection) as context:
    # Your code here
    pass

print(f"Queries: {len(context.captured_queries)}")
for i, query in enumerate(context.captured_queries, 1):
    print(f"{i}. {query['sql']}")
EOF
```

### Email Delivery Monitoring

```bash
# Watch MailHog for incoming emails
watch -n 1 'curl -s http://localhost:8025/api/messages | jq ".total"'

# Get detailed email info
curl -s http://localhost:8025/api/messages | jq '.items[0]'
```

### Celery Task Monitoring

```bash
# Real-time task monitoring
docker compose exec celery-worker celery -A zumodra events

# Get task statistics
docker compose exec celery-worker celery -A zumodra inspect stats

# View task history
docker compose logs --tail=100 celery-worker | grep "tasks"
```

---

## Testing Utilities

### Create Test User with Notifications

```python
from django.contrib.auth import get_user_model
from notifications.models import Notification, NotificationPreference

User = get_user_model()

# Create user
user = User.objects.create_user(
    username='testuser@example.com',
    email='testuser@example.com',
    password='testpass123'
)

# Create preferences
prefs, _ = NotificationPreference.objects.get_or_create(
    user=user,
    defaults={'email_enabled': True}
)

# Send test notification
from notifications.services import notification_service
results = notification_service.send_notification(
    recipient=user,
    notification_type='test',
    title='Test Notification',
    message='This is a test',
    channels=['email', 'in_app']
)

print(f"Results: {results}")
```

### Bulk Testing

```python
# Create 100 test notifications
from django.contrib.auth import get_user_model
from notifications.models import Notification

User = get_user_model()
user = User.objects.first()

notifications = [
    Notification(
        recipient=user,
        notification_type='bulk_test',
        title=f'Test {i}',
        message=f'Message {i}',
        channels=['in_app'],
    )
    for i in range(100)
]

Notification.objects.bulk_create(notifications)
print("Created 100 test notifications")
```

---

**Last Updated:** 2026-01-16
**Version:** 1.0
