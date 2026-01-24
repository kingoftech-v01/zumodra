# Comprehensive Email System Integration Test Guide

## Overview

This guide covers testing the complete email system integration for the Zumodra SaaS platform. The email system includes:

1. **Transactional Email Sending** - Direct email sending for key events
2. **Email Template Rendering** - Dynamic email template rendering with context
3. **Email Queue Processing** - Celery-based async email processing
4. **Bounce and Complaint Handling** - Handling email delivery failures and complaints
5. **Email Tracking** - Open and click tracking for emails
6. **Unsubscribe Management** - User preference management and unsubscribe links
7. **Email Logs and Audit Trail** - Complete logging and audit trail of all email activity
8. **Multi-tenant Isolation** - Email isolation between tenants

## System Architecture

### Email Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Email System                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐      ┌──────────────────┐            │
│  │ Notification     │      │ Email Provider   │            │
│  │ Service          │──────│ Integration      │            │
│  └──────────────────┘      │ (Gmail, SMTP)    │            │
│         │                  └──────────────────┘            │
│         │                           │                       │
│         ▼                           ▼                       │
│  ┌──────────────────┐      ┌──────────────────┐            │
│  │ Celery Tasks     │      │ Email Backend    │            │
│  │ (Async Queue)    │      │ (Django)         │            │
│  └──────────────────┘      └──────────────────┘            │
│         │                           │                       │
│         └───────────┬───────────────┘                       │
│                     ▼                                       │
│          ┌────────────────────┐                            │
│          │  MailHog or SMTP   │                            │
│          │  Server            │                            │
│          └────────────────────┘                            │
│                     │                                       │
│         ┌───────────┴───────────┐                          │
│         ▼                       ▼                          │
│  ┌────────────────┐    ┌─────────────────┐               │
│  │ User Inbox     │    │ Tracking/Logs   │               │
│  └────────────────┘    └─────────────────┘               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

### Services Required

1. **Django Web Server** (Port 8002)
   - `docker-compose up -d web`

2. **PostgreSQL Database** (Port 5434)
   - Required for storing notification models
   - `docker-compose up -d db`

3. **Redis** (Port 6380)
   - Required for Celery message broker
   - `docker-compose up -d redis`

4. **RabbitMQ** (Port 5673) - Optional
   - Alternative message broker for Celery

5. **MailHog** (Port 8026)
   - Email testing interface
   - `docker-compose up -d mailhog`
   - UI: http://localhost:8026

6. **Celery Worker** (Background Tasks)
   - Required for async email processing
   - `docker-compose up -d celery`

7. **Celery Beat** (Scheduled Tasks)
   - For scheduled emails
   - `docker-compose up -d celery-beat`

### Starting All Services

```bash
# Start all required services
docker-compose up -d web db redis mailhog celery celery-beat

# Verify services are running
docker-compose ps

# Check specific service logs
docker-compose logs -f web          # Django logs
docker-compose logs -f celery       # Celery worker logs
docker-compose logs -f mailhog      # MailHog logs
```

### Environment Configuration

Ensure `.env` is properly configured:

```bash
# Email Backend
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=mailhog
EMAIL_PORT=1025
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=
EMAIL_USE_TLS=False
DEFAULT_FROM_EMAIL=noreply@zumodra.local

# Celery Configuration
CELERY_BROKER_URL=redis://redis:6380/0
CELERY_RESULT_BACKEND=redis://redis:6380/0

# MailHog Configuration
MAILHOG_HOST=mailhog
MAILHOG_PORT=1025
MAILHOG_UI_PORT=8026
```

## Test Execution

### 1. Run All Tests (Automated)

```bash
# Run the comprehensive test suite
python tests_comprehensive/email_system_test_simple.py

# Run with Django ORM tests (requires Django setup)
python manage.py test notifications.tests.test_notifications -v 2

# Run pytest tests
pytest notifications/tests/ -v --tb=short
```

### 2. Run Individual Test Modules

#### Test Transactional Email Sending

```python
# Direct Django test
python manage.py shell << EOF
from django.core.mail import send_mail

result = send_mail(
    subject='Test Email',
    message='This is a test',
    from_email='noreply@zumodra.local',
    recipient_list=['test@example.com'],
)
print(f"Email sent: {result}")
EOF
```

#### Test Email Template Rendering

```python
python manage.py shell << EOF
from notifications.models import NotificationTemplate

# Get a template
template = NotificationTemplate.objects.filter(is_active=True).first()
if template:
    print(f"Template: {template.name}")
    print(f"Subject: {template.subject}")
    print(f"Body: {template.body_text[:100]}...")

    # Test rendering with context
    context = {'user_name': 'John Doe'}
    rendered = template.subject.format(**context)
    print(f"Rendered: {rendered}")
EOF
```

#### Test Celery Task Processing

```python
python manage.py shell << EOF
from notifications.tasks import send_email_notification
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.first()

# Queue email task
task = send_email_notification.delay(
    user_id=user.id,
    title='Test Email',
    message='This is a test email',
)
print(f"Task ID: {task.id}")
print(f"Task Status: {task.status}")
EOF
```

#### Test Bounce Handling

```python
python manage.py shell << EOF
from notifications.models import NotificationDeliveryLog, Notification
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.first()

# Create notification
notif = Notification.objects.create(
    user=user,
    title='Test Bounce',
    message='Testing bounce handling',
)

# Log bounce
log = NotificationDeliveryLog.objects.create(
    notification=notif,
    status='bounced',
    error_type='permanent_bounce',
    error_message='Invalid email address',
)

print(f"Bounce logged: {log.id}")
print(f"Error type: {log.error_type}")
EOF
```

#### Test Email Tracking

```python
python manage.py shell << EOF
from notifications.models import NotificationDeliveryLog, Notification
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.first()

# Create notification with tracking
notif = Notification.objects.create(
    user=user,
    title='Tracking Test',
    message='Testing email tracking',
)

# Create delivery log with tracking data
log = NotificationDeliveryLog.objects.create(
    notification=notif,
    status='delivered',
    response_payload={
        'tracking_pixel': '/tracking/pixel/abc123',
        'click_tracking': True,
    }
)

print(f"Tracking ID: {log.id}")
print(f"Tracking enabled: {log.response_payload.get('click_tracking')}")
EOF
```

#### Test Unsubscribe Management

```python
python manage.py shell << EOF
from notifications.models import NotificationPreference
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.first()

# Get user preferences
prefs, created = NotificationPreference.objects.get_or_create(user=user)

print(f"Original marketing emails: {prefs.marketing_emails}")

# Unsubscribe from marketing emails
prefs.marketing_emails = False
prefs.save()

print(f"After unsubscribe: {prefs.marketing_emails}")

# Check unsubscribe status
if not prefs.marketing_emails:
    print("✓ Unsubscribe successful")
EOF
```

#### Test Email Logs and Audit Trail

```python
python manage.py shell << EOF
from notifications.models import NotificationDeliveryLog
from django.db.models import Count

# Get email statistics
logs = NotificationDeliveryLog.objects.all()
stats = logs.values('status').annotate(count=Count('id'))

print("Email Delivery Statistics:")
for stat in stats:
    print(f"  {stat['status']}: {stat['count']}")

# Get recent logs
recent = logs.order_by('-completed_at')[:5]
print("\nRecent email deliveries:")
for log in recent:
    print(f"  - {log.notification.title}: {log.status}")
EOF
```

### 3. MailHog Testing

#### Access MailHog UI

```bash
# Open MailHog interface
open http://localhost:8026/

# Or use curl to interact with API
curl http://localhost:8026/api/v2/messages
```

#### Check Sent Emails

```bash
# Get all messages
curl http://localhost:8026/api/v2/messages | jq '.'

# Get message count
curl http://localhost:8026/api/v2/messages | jq '.total'

# Get first message details
curl http://localhost:8026/api/v2/messages | jq '.items[0]'
```

#### Clear MailHog Messages

```bash
# Delete all messages
curl -X DELETE http://localhost:8026/api/v1/messages

# Verify cleared
curl http://localhost:8026/api/v2/messages
```

### 4. Manual Testing Checklist

#### Send Test Email

```bash
# Create test user and send email via Django admin
python manage.py shell << EOF
from django.core.mail import send_mail
from django.contrib.auth import get_user_model

User = get_user_model()
user, _ = User.objects.get_or_create(
    username='emailtest',
    defaults={'email': 'test@zumodra.local'}
)

send_mail(
    subject='Zumodra Email Test',
    message='This is a test email from Zumodra',
    from_email='noreply@zumodra.local',
    recipient_list=[user.email],
)
print(f"Email sent to {user.email}")
EOF
```

#### Verify Email in MailHog

1. Open http://localhost:8026
2. Check for email from noreply@zumodra.local
3. Click on email to view content
4. Verify subject, body, and headers

## Test Scenarios

### Scenario 1: Complete Email Workflow

1. **Send Email**
   - Create notification
   - Queue Celery task
   - Email processed by worker

2. **Track Delivery**
   - Check MailHog
   - Verify delivery log in database
   - Check notification status

3. **Monitor Tracking**
   - Check tracking pixel URL
   - Simulate click event
   - Verify tracking data recorded

4. **Handle Bounce**
   - Simulate bounce response
   - Update delivery log status
   - Record bounce type

### Scenario 2: Multi-tenant Email Isolation

1. Create emails for multiple tenants
2. Verify email isolation
3. Check that users only see their emails

### Scenario 3: Scheduled Email Workflow

1. Create scheduled notification
2. Verify scheduled time
3. Wait for Celery Beat trigger
4. Confirm delivery

### Scenario 4: Bulk Email Campaign

1. Create multiple notifications
2. Queue as batch
3. Monitor processing
4. Verify all delivered

## Test Results Location

All test reports are saved to:

```
tests_comprehensive/reports/
├── email_test_report_*.json          # Detailed test results
├── mailhog_messages_*.json           # MailHog message dump
├── python_test_output_*.txt          # Python test output
└── email_test_summary_*.txt          # Summary report
```

## Performance Metrics to Monitor

1. **Email Sending Speed**
   - Time from trigger to queuing: < 100ms
   - Time from queue to delivery: < 1s
   - Batch processing rate: 100+ emails/second

2. **Success Rate**
   - Target: > 99% for valid addresses
   - Bounce rate tracking
   - Retry success rate

3. **Resource Usage**
   - Celery worker memory
   - Database query performance
   - Redis connection pool

## Common Issues and Solutions

### Issue 1: MailHog Not Accessible

**Problem:** `MailHog error: HTTPConnectionPool(host='localhost', port=8026)`

**Solution:**
```bash
# Check if MailHog is running
docker-compose ps mailhog

# Start MailHog
docker-compose up -d mailhog

# Check logs
docker-compose logs mailhog
```

### Issue 2: Emails Not Being Sent

**Problem:** Notifications created but no emails arrive

**Solution:**
```bash
# Check Celery worker is running
docker-compose ps celery

# Check Celery logs
docker-compose logs -f celery

# Check Django logs
docker-compose logs -f web

# Verify EMAIL_BACKEND setting
python manage.py shell -c "from django.conf import settings; print(settings.EMAIL_BACKEND)"
```

### Issue 3: Database Errors

**Problem:** Notification model errors

**Solution:**
```bash
# Run migrations
python manage.py migrate

# Check migration status
python manage.py showmigrations notifications

# Create missing tables
python manage.py migrate notifications --run-syncdb
```

### Issue 4: Template Rendering Fails

**Problem:** Email templates not found or rendering fails

**Solution:**
```bash
# Check templates exist
python manage.py shell -c "from notifications.models import NotificationTemplate; print(NotificationTemplate.objects.count())"

# Create default templates
python manage.py shell << EOF
from notifications.models import NotificationTemplate

templates = [
    {
        'code': 'welcome_email',
        'name': 'Welcome Email',
        'subject': 'Welcome to Zumodra, {{ user_name }}!',
        'body_text': 'Welcome to the Zumodra platform.',
        'body_html': '<h1>Welcome</h1><p>Welcome to Zumodra!</p>',
    }
]

for t in templates:
    NotificationTemplate.objects.get_or_create(
        code=t['code'],
        defaults=t
    )
EOF
```

## Debugging Commands

### Check Email Configuration

```bash
python manage.py shell << EOF
from django.conf import settings

print("Email Configuration:")
print(f"  EMAIL_BACKEND: {settings.EMAIL_BACKEND}")
print(f"  EMAIL_HOST: {settings.EMAIL_HOST}")
print(f"  EMAIL_PORT: {settings.EMAIL_PORT}")
print(f"  EMAIL_USE_TLS: {settings.EMAIL_USE_TLS}")
print(f"  DEFAULT_FROM_EMAIL: {settings.DEFAULT_FROM_EMAIL}")
EOF
```

### List Notifications

```bash
python manage.py shell << EOF
from notifications.models import Notification

for n in Notification.objects.all()[:5]:
    print(f"- {n.title}: {n.status}")
EOF
```

### Check Delivery Logs

```bash
python manage.py shell << EOF
from notifications.models import NotificationDeliveryLog

for log in NotificationDeliveryLog.objects.all()[:5]:
    print(f"- {log.notification.title}: {log.status} ({log.completed_at})")
EOF
```

### Monitor Celery Tasks

```bash
# Check Celery worker status
celery -A zumodra inspect active

# List pending tasks
celery -A zumodra inspect pending

# Check task statistics
celery -A zumodra inspect stats

# Monitor in real-time
watch -n 1 'celery -A zumodra inspect active'
```

## Test Files Location

- Main test file: `/tests_comprehensive/test_email_system_integration.py`
- Simple test file: `/tests_comprehensive/email_system_test_simple.py`
- Test runner script: `/tests_comprehensive/run_email_tests.sh`
- Reports directory: `/tests_comprehensive/reports/`

## Next Steps

1. Run tests with proper Docker setup
2. Review test reports for failures
3. Address any identified issues
4. Monitor email delivery metrics
5. Implement email provider integrations (Gmail, SendGrid, etc.)
6. Set up production SMTP or email service

## References

- Django Email: https://docs.djangoproject.com/en/5.0/topics/email/
- Celery Tasks: https://docs.celery.io/en/stable/
- MailHog API: https://mailhog.github.io/APIv2/
- Email Standards: https://tools.ietf.org/html/rfc5322

## Support

For issues or questions:

1. Check test reports in `tests_comprehensive/reports/`
2. Review Django logs
3. Check Celery worker status
4. Verify MailHog connectivity
5. Review email models in `notifications/models.py`
