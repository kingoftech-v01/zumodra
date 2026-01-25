# Comprehensive Notification Delivery System Testing Guide

## Overview

This guide covers testing all notification delivery channels and features of the Zumodra platform:

1. Email notification sending
2. In-app notification display
3. Push notification delivery
4. SMS notification sending (if configured)
5. Notification preferences management
6. Notification batching/digests
7. Unread notification tracking

## Prerequisites

### Docker Services Required

The following services must be running:

- **PostgreSQL**: `zumodra_db` (port 5434)
- **Redis**: `zumodra_redis` (port 6380)
- **RabbitMQ**: `zumodra_rabbitmq` (ports 5673, 15673)
- **Django Web**: `zumodra_web` (port 8002)
- **Celery Worker**: `zumodra_celery-worker`
- **Celery Beat**: `zumodra_celery-beat`
- **Channels**: `zumodra_channels` (port 8003)
- **MailHog**: `zumodra_mailhog` (ports 1026, 8026)

### Startup Commands

```bash
# Start all services
docker compose up -d

# Verify all services are healthy
docker compose ps

# Check logs for any issues
docker compose logs -f web

# Wait for migrations to complete (first startup can take 5+ minutes)
docker compose logs web | grep "Migrations applied"
```

## Testing Sections

### 1. EMAIL NOTIFICATION TESTING

Email notifications are sent through SMTP and captured by MailHog for testing.

#### Setup

```bash
# Verify MailHog is running
docker compose ps mailhog

# Access MailHog UI
# Browser: http://localhost:8026
# API: http://localhost:8025/api
```

#### Manual Tests

**Test 1.1: Email Notification Sending**

```python
# Via Django shell
docker compose exec web python manage.py shell

from django.contrib.auth import get_user_model
from notifications.services import notification_service

User = get_user_model()
user = User.objects.first()

# Send test email
results = notification_service.send_notification(
    recipient=user,
    notification_type="test_email",
    title="Test Email Notification",
    message="This is a test email notification.",
    channels=["email"],
    priority="high",
)

print(f"Results: {results}")
```

Check MailHog at http://localhost:8026 to verify email was received.

**Test 1.2: Email with Template**

```python
from notifications.models import NotificationTemplate, Notification

# Create template
template = NotificationTemplate.objects.create(
    name="welcome",
    template_type="application_received",
    subject="Welcome to Zumodra",
    text_body="Hello {{ recipient.first_name }}, welcome!",
    html_body="<h1>Welcome {{ recipient.first_name }}!</h1>",
)

# Send with template
notification = Notification.objects.create(
    recipient=user,
    notification_type="welcome",
    title="Welcome",
    message="Welcome to our platform",
    template=template,
    channels=["email"],
)
```

#### Automated Tests

```bash
# Run email notification tests
docker compose exec web pytest test_notifications_comprehensive.py::TestNotificationsComprehensive::test_01_email_notifications -v

# Run all tests with verbose output
docker compose exec web pytest test_notifications_comprehensive.py -v
```

#### Validation Checklist

- [ ] Email received in MailHog
- [ ] Subject line is correct
- [ ] Recipient email is correct
- [ ] HTML rendering is correct
- [ ] Template variables are rendered properly
- [ ] Unsubscribe link is present
- [ ] Delivery log is created with status "sent"
- [ ] Response code is 200

### 2. IN-APP NOTIFICATION TESTING

In-app notifications are stored in the database and displayed in the UI.

#### Manual Tests

**Test 2.1: Create In-App Notification**

```python
from notifications.models import Notification

notification = Notification.objects.create(
    recipient=user,
    notification_type="in_app_test",
    title="In-App Test Notification",
    message="This is an in-app notification.",
    channels=["in_app"],
    priority="normal",
)

print(f"Notification ID: {notification.id}")
print(f"Is Read: {notification.is_read}")
print(f"Created: {notification.created_at}")
```

**Test 2.2: Retrieve and Display Notifications**

```python
# Get unread notifications for user
unread_notifs = Notification.objects.filter(
    recipient=user,
    is_read=False,
).order_by('-created_at')

for notif in unread_notifs:
    print(f"[{notif.notification_type}] {notif.title}")
    print(f"  Message: {notif.message}")
    print(f"  Created: {notif.created_at}")
```

**Test 2.3: Unread Notification Tracking**

```python
# Mark notification as read
notification.is_read = True
notification.read_at = timezone.now()
notification.save()

# Query read vs unread
total = Notification.objects.filter(recipient=user).count()
unread = Notification.objects.filter(recipient=user, is_read=False).count()
read = total - unread

print(f"Total: {total}, Unread: {unread}, Read: {read}")
```

#### API Testing

```bash
# Get user's notifications
curl -X GET http://localhost:8002/api/v1/notifications/list/ \
  -H "Authorization: Bearer YOUR_TOKEN"

# Mark notification as read
curl -X PATCH http://localhost:8002/api/v1/notifications/{id}/mark-read/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Validation Checklist

- [ ] In-app notification created in database
- [ ] Notification displays in UI
- [ ] Unread count is correct
- [ ] Mark as read functionality works
- [ ] Notifications are ordered by recency
- [ ] Old notifications can be archived
- [ ] Notification detail view works

### 3. PUSH NOTIFICATION TESTING

Push notifications are sent to device tokens registered by users.

#### Prerequisites

- Device token registration mechanism must be implemented
- Push notification service (FCM, APNs, etc.) must be configured

#### Manual Tests

**Test 3.1: Create Push Notification**

```python
notification = Notification.objects.create(
    recipient=user,
    notification_type="push_test",
    title="Push Test",
    message="This is a push notification.",
    channels=["push"],
    priority="high",
)

# Check delivery logs
from notifications.models import NotificationDeliveryLog
logs = NotificationDeliveryLog.objects.filter(notification=notification)
for log in logs:
    print(f"Status: {log.status}, Code: {log.response_code}")
```

#### Validation Checklist

- [ ] Push notification created
- [ ] Device tokens are stored securely
- [ ] Push payload is properly formatted
- [ ] Delivery log is created
- [ ] Retry mechanism works for failed deliveries
- [ ] Expired tokens are cleaned up

### 4. SMS NOTIFICATION TESTING

SMS notifications are sent via SMS provider (Twilio, etc.).

#### Prerequisites

- SMS provider must be configured
- User phone numbers must be validated
- SMS credits/quota must be available

#### Manual Tests

**Test 4.1: Check SMS Configuration**

```python
from notifications.models import NotificationChannel

sms_channel = NotificationChannel.objects.filter(
    channel_type="sms",
    is_active=True
).first()

if sms_channel:
    print(f"SMS Channel Config: {sms_channel.config}")
else:
    print("SMS channel not configured")
```

**Test 4.2: Send SMS Notification**

```python
# Only if SMS is configured and user has phone
if user.phone_number:
    notification = Notification.objects.create(
        recipient=user,
        notification_type="sms_test",
        title="SMS Test",
        message="Test SMS notification",
        channels=["sms"],
        priority="normal",
    )
```

#### Validation Checklist

- [ ] SMS channel is active
- [ ] User has verified phone number
- [ ] SMS credentials are configured
- [ ] SMS sent successfully
- [ ] Delivery confirmation received
- [ ] Cost is logged
- [ ] Retry mechanism works

### 5. NOTIFICATION PREFERENCES TESTING

Users can customize their notification preferences by channel and type.

#### Manual Tests

**Test 5.1: Create Notification Preferences**

```python
from notifications.models import NotificationPreference

prefs, created = NotificationPreference.objects.get_or_create(
    user=user,
    defaults={
        "email_enabled": True,
        "in_app_enabled": True,
        "push_enabled": True,
        "sms_enabled": False,
        "batch_digest_frequency": "daily",
    }
)

print(f"Preferences: {prefs}")
```

**Test 5.2: Per-Channel Preferences**

```python
# Set channel-specific preferences
prefs.channel_settings = {
    "email": {
        "enabled": True,
        "quiet_hours_start": "22:00",
        "quiet_hours_end": "08:00",
        "digest_enabled": True,
    },
    "in_app": {
        "enabled": True,
        "sound": True,
        "badge_count": True,
    },
    "push": {
        "enabled": False,
    },
}
prefs.save()
```

**Test 5.3: Notification Type Preferences**

```python
# Set type-specific preferences
prefs.notification_type_settings = {
    "application_received": {
        "enabled": True,
        "channels": ["email", "in_app", "push"],
    },
    "interview_scheduled": {
        "enabled": True,
        "channels": ["email", "push"],
    },
    "marketing_email": {
        "enabled": False,
        "channels": [],
    },
}
prefs.save()
```

#### API Testing

```bash
# Get user preferences
curl -X GET http://localhost:8002/api/v1/notifications/preferences/ \
  -H "Authorization: Bearer YOUR_TOKEN"

# Update preferences
curl -X PUT http://localhost:8002/api/v1/notifications/preferences/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email_enabled": true,
    "in_app_enabled": true,
    "push_enabled": false
  }'
```

#### Validation Checklist

- [ ] Preferences are saved correctly
- [ ] Channels can be enabled/disabled independently
- [ ] Notification types can be customized
- [ ] Quiet hours are respected
- [ ] Preferences persist across sessions
- [ ] Default preferences are applied for new users

### 6. NOTIFICATION BATCHING AND DIGESTS

Notifications can be batched and sent as digests based on user preferences.

#### Manual Tests

**Test 6.1: Create Batch Notifications**

```python
# Create multiple notifications at once
for i in range(5):
    Notification.objects.create(
        recipient=user,
        notification_type="batch_test",
        title=f"Batch Notification {i+1}",
        message=f"Message {i+1}",
        channels=["email"],
    )

# Query batch
batch = Notification.objects.filter(
    recipient=user,
    notification_type="batch_test"
).order_by('created_at')

print(f"Batch size: {batch.count()}")
```

**Test 6.2: Digest Frequency**

```python
from notifications.models import NotificationPreference

prefs, _ = NotificationPreference.objects.get_or_create(user=user)

# Test different frequencies
for frequency in ["immediate", "hourly", "daily", "weekly"]:
    prefs.batch_digest_frequency = frequency
    prefs.save()
    print(f"Set digest frequency to: {frequency}")
```

**Test 6.3: Digest Email Generation**

```bash
# Trigger digest email task
docker compose exec celery-worker celery -A zumodra inspect active

# Check for batch notification tasks
docker compose exec web python manage.py shell << 'EOF'
from notifications.tasks import process_notification_digest
# This would be called by Celery Beat on schedule
EOF
```

#### Validation Checklist

- [ ] Multiple notifications are batched
- [ ] Digest frequency is configurable
- [ ] Digest emails are generated correctly
- [ ] Digest template renders properly
- [ ] Digest sent at configured time
- [ ] User can still get immediate notifications if needed
- [ ] Digest format is readable

### 7. UNREAD NOTIFICATION TRACKING

System tracks which notifications have been read by users.

#### Manual Tests

**Test 7.1: Unread Status Tracking**

```python
# Create unread notification
notif = Notification.objects.create(
    recipient=user,
    notification_type="unread_test",
    title="Unread Test",
    message="Test",
    channels=["in_app"],
    is_read=False,
)

# Verify unread
assert not notif.is_read
print(f"Notification is unread: {not notif.is_read}")

# Mark as read
notif.is_read = True
notif.read_at = timezone.now()
notif.save()

# Verify read
notif.refresh_from_db()
assert notif.is_read
print(f"Notification is read: {notif.is_read}")
```

**Test 7.2: Unread Count**

```python
unread_count = Notification.objects.filter(
    recipient=user,
    is_read=False,
).count()

print(f"Unread notifications: {unread_count}")
```

**Test 7.3: Bulk Mark as Read**

```python
# Mark all notifications as read
Notification.objects.filter(
    recipient=user,
    is_read=False,
).update(is_read=True, read_at=timezone.now())

# Verify all are read
remaining_unread = Notification.objects.filter(
    recipient=user,
    is_read=False,
).count()

print(f"Remaining unread: {remaining_unread}")
```

#### API Testing

```bash
# Get unread count
curl -X GET http://localhost:8002/api/v1/notifications/unread-count/ \
  -H "Authorization: Bearer YOUR_TOKEN"

# Mark all as read
curl -X POST http://localhost:8002/api/v1/notifications/mark-all-read/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Validation Checklist

- [ ] Unread notifications tracked correctly
- [ ] Read status persists
- [ ] Read timestamp is recorded
- [ ] Unread count API endpoint works
- [ ] Bulk mark as read works
- [ ] UI shows unread indicator
- [ ] Badge count updates

## Running Automated Tests

### Execute Full Test Suite

```bash
# Run all notification tests
docker compose exec web pytest test_notifications_comprehensive.py -v

# Run with coverage
docker compose exec web pytest test_notifications_comprehensive.py --cov=notifications

# Run specific test
docker compose exec web pytest test_notifications_comprehensive.py::TestNotificationsComprehensive::test_01_email_notifications -v
```

### View Test Report

Test reports are saved to: `tests_comprehensive/reports/`

```bash
# View generated report
cat tests_comprehensive/reports/NOTIFICATION_SYSTEM_TEST_REPORT.md
```

## MailHog Email Verification

### Access MailHog UI

Browser: http://localhost:8026

### Check Email via API

```bash
# Get all emails
curl http://localhost:8025/api/messages

# Get specific email (replace ID)
curl http://localhost:8025/api/messages/{id}

# Delete all emails
curl -X DELETE http://localhost:8025/api/messages
```

### Expected Email Fields

```json
{
  "ID": "msg_12345",
  "From": "noreply@zumodra.com",
  "To": ["user@example.com"],
  "Subject": "Notification Title",
  "Created": "2024-01-16T12:00:00Z",
  "MIME": {
    "Parts": [
      {
        "Headers": {
          "Content-Type": ["text/plain"],
          "Content-Transfer-Encoding": ["7bit"]
        },
        "Body": "Email body text"
      }
    ]
  }
}
```

## Troubleshooting

### Email Not Received

```bash
# Check MailHog is running
docker compose ps mailhog

# View MailHog logs
docker compose logs mailhog

# Verify Django email backend is configured
docker compose exec web python -c "from django.conf import settings; print(settings.EMAIL_BACKEND)"

# Test SMTP connection
docker compose exec web python << 'EOF'
from django.core.mail import send_mail
send_mail(
    'Test Subject',
    'Test Message',
    'from@example.com',
    ['to@example.com'],
)
print("Email sent!")
EOF
```

### In-App Notifications Not Showing

```bash
# Check notifications in database
docker compose exec web python manage.py shell << 'EOF'
from notifications.models import Notification
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.first()
notifs = Notification.objects.filter(recipient=user)
print(f"Total notifications: {notifs.count()}")
for n in notifs:
    print(f"- {n.title} (read: {n.is_read})")
EOF
```

### Celery Tasks Not Executing

```bash
# Check Celery worker status
docker compose exec celery-worker celery -A zumodra inspect active

# View Celery logs
docker compose logs -f celery-worker

# Check RabbitMQ connection
docker compose exec rabbitmq rabbitmq-diagnostics -q ping
```

### Rate Limiting Issues

```bash
# Check notification delivery logs
docker compose exec web python manage.py shell << 'EOF'
from notifications.models import NotificationDeliveryLog
logs = NotificationDeliveryLog.objects.order_by('-created_at')[:10]
for log in logs:
    print(f"{log.status} - {log.response_code} - {log.error_message}")
EOF
```

## Performance Considerations

### Optimal Settings

- Email batch size: 50-100 per batch
- Push notification batch: 1000+ (async)
- Digest frequency: Daily (most common)
- Retry attempts: 3-5
- Retry backoff: Exponential (60s, 300s, 900s)

### Monitoring

```bash
# Check database query count
docker compose exec web python manage.py shell << 'EOF'
from django.db import connection
from django.test.utils import CaptureQueriesContext

with CaptureQueriesContext(connection) as ctx:
    # Test code here
    pass

print(f"Query count: {len(ctx.captured_queries)}")
for query in ctx.captured_queries:
    print(f"- {query['sql']}")
EOF
```

## Next Steps

After completing all tests:

1. Review the generated test report
2. Fix any identified issues
3. Update documentation as needed
4. Deploy to staging environment
5. Perform end-to-end user testing

## References

- Notification Models: `/c/Users/techn/OneDrive/Documents/zumodra/notifications/models.py`
- Notification Services: `/c/Users/techn/OneDrive/Documents/zumodra/notifications/services.py`
- Notification Tasks: `/c/Users/techn/OneDrive/Documents/zumodra/notifications/tasks.py`
- MailHog Docs: https://github.com/mailhog/MailHog
- Django Email: https://docs.djangoproject.com/en/stable/topics/email/
