# Notification System Testing - Complete Setup & Execution Guide

## Project: Zumodra Multi-Tenant SaaS Platform
## Date: 2026-01-16
## Focus: Comprehensive Notification Delivery System Testing

---

## Executive Summary

This document provides a complete guide to test the Zumodra notification delivery system, which supports:

- **Email Notifications** - Via SMTP with MailHog testing
- **In-App Notifications** - Database-stored, UI-displayed
- **Push Notifications** - Device token-based delivery
- **SMS Notifications** - Via SMS provider (if configured)
- **Notification Preferences** - User-customizable by channel and type
- **Batching & Digests** - Scheduled digest notifications
- **Unread Tracking** - Read/unread status management

---

## Quick Start

### 1. Start Docker Environment

```bash
cd /c/Users/techn/OneDrive/Documents/zumodra

# Start all services
docker compose up -d

# Wait for services to be healthy (usually 2-5 minutes)
docker compose ps
```

### 2. Run Tests

```bash
# Run full notification test suite
cd tests_comprehensive
./run_notification_tests.sh --full

# Or run specific test category
./run_notification_tests.sh --email
./run_notification_tests.sh --inapp
./run_notification_tests.sh --preferences
```

### 3. View Results

- Test Output: `tests_comprehensive/reports/test_output_*.log`
- Email Verification: http://localhost:8026 (MailHog UI)
- API Emails: http://localhost:8025/api/messages

---

## File Structure

```
zumodra/
├── test_notifications_comprehensive.py          # Main test suite
├── tests_comprehensive/
│   ├── reports/                                 # Test reports directory
│   │   ├── test_output_*.log                   # Test execution logs
│   │   ├── mailhog_emails_*.json               # Captured emails
│   │   ├── NOTIFICATION_SYSTEM_TEST_REPORT.md  # Generated report
│   │   ├── coverage_html/                      # Coverage reports
│   │   └── test_report_*.html                  # HTML reports
│   ├── run_notification_tests.sh                # Test execution script
│   ├── NOTIFICATION_TESTING_GUIDE.md            # Detailed testing guide
│   └── NOTIFICATION_TESTING_SETUP.md            # This file
├── notifications/
│   ├── models.py                               # Notification models
│   ├── services.py                             # Notification services
│   ├── tasks.py                                # Celery async tasks
│   ├── forms.py                                # Preference forms
│   ├── views.py                                # API endpoints
│   ├── serializers.py                          # DRF serializers
│   └── tests/
│       └── test_notifications.py               # Unit tests
└── docker-compose.yml                          # Docker configuration
```

---

## Test Coverage

### 1. Email Notification Tests (test_01_email_notifications)

**What's Tested:**
- Email notification creation
- SMTP delivery via MailHog
- Template rendering with context variables
- Unsubscribe link generation
- Delivery logging

**Expected Results:**
- Email appears in MailHog UI (http://localhost:8026)
- Delivery log created with status "sent"
- Response code 200

**Manual Verification:**

```python
# In Django shell
from django.contrib.auth import get_user_model
from notifications.services import notification_service

User = get_user_model()
user = User.objects.first()

# Send email
results = notification_service.send_notification(
    recipient=user,
    notification_type="test_email",
    title="Test Email",
    message="This is a test.",
    channels=["email"],
)

# Check MailHog
import requests
emails = requests.get("http://localhost:8025/api/messages").json()
print(f"Emails in MailHog: {emails['total']}")
```

### 2. In-App Notification Tests (test_02_in_app_notifications)

**What's Tested:**
- In-app notification creation
- Database storage
- Unread status tracking
- Read/unread status updates
- Notification retrieval

**Expected Results:**
- Notification stored in database
- is_read field toggles correctly
- read_at timestamp recorded
- Notifications retrieved correctly via query

**Database Query:**

```sql
SELECT * FROM notifications_notification
WHERE recipient_id = <user_id>
ORDER BY created_at DESC;
```

### 3. Notification Preferences Tests (test_03_notification_preferences)

**What's Tested:**
- Preference creation for users
- Per-channel enablement (email, in-app, push, SMS)
- Per-notification-type preferences
- Quiet hours configuration
- Digest frequency settings

**Expected Results:**
- NotificationPreference record created
- Channel settings JSON stored correctly
- Type-specific settings accessible
- Preferences persist across sessions

**Configuration Example:**

```python
{
    "channel_settings": {
        "email": {
            "enabled": true,
            "quiet_hours": "22:00-08:00",
            "digest_enabled": true
        },
        "in_app": {
            "enabled": true,
            "sound": true
        }
    },
    "notification_type_settings": {
        "application_received": {
            "enabled": true,
            "channels": ["email", "in_app"]
        }
    }
}
```

### 4. Notification Batching Tests (test_04_notification_batching)

**What's Tested:**
- Batch notification creation
- Digest frequency configuration
- Scheduled digest processing
- Digest email generation

**Expected Results:**
- Multiple notifications created and grouped
- Digest frequency settings saved
- Digest emails generated at scheduled times

### 5. Delivery Logging Tests (test_05_delivery_logging)

**What's Tested:**
- Delivery log creation for each notification
- Request/response payload logging
- Error tracking and retry logic
- Duration measurement
- Status tracking (sent, failed, retry)

**Expected Results:**
- NotificationDeliveryLog record created per send attempt
- Response code and status recorded
- Error messages captured for failed sends

### 6. Push Notification Tests (test_06_push_notifications)

**What's Tested:**
- Push notification creation
- Device token management
- Push payload formatting
- Delivery confirmation

**Expected Results:**
- Notification created with "push" channel
- Device token validation
- Payload formatting verified

### 7. SMS Notification Tests (test_07_sms_notifications)

**What's Tested:**
- SMS notification creation (if configured)
- Phone number validation
- SMS provider integration
- Delivery tracking

**Expected Results:**
- SMS notification created if channel enabled
- Phone number validated
- Delivery log created

### 8. Channel Configuration Tests (test_08_channel_configuration)

**What's Tested:**
- Channel activation/deactivation
- Rate limiting configuration
- Channel-specific settings
- Channel availability status

**Expected Results:**
- Channels can be toggled on/off
- Rate limits applied
- Settings persisted

---

## Running Tests

### Full Test Suite

```bash
cd /c/Users/techn/OneDrive/Documents/zumodra/tests_comprehensive

# With full output
./run_notification_tests.sh --full

# With coverage analysis
./run_notification_tests.sh --full --coverage

# With HTML report generation
./run_notification_tests.sh --full --report
```

### Individual Test Categories

```bash
# Email tests only
./run_notification_tests.sh --email

# In-app tests only
./run_notification_tests.sh --inapp

# Preferences tests only
./run_notification_tests.sh --preferences

# Batching tests only
./run_notification_tests.sh --batching
```

### Using pytest directly

```bash
# From project root
docker compose exec web pytest test_notifications_comprehensive.py -v

# Specific test
docker compose exec web pytest \
  test_notifications_comprehensive.py::TestNotificationsComprehensive::test_01_email_notifications \
  -v

# With coverage
docker compose exec web pytest \
  test_notifications_comprehensive.py \
  --cov=notifications \
  --cov-report=html
```

---

## Verification Checklist

### Pre-Test Requirements

- [ ] Docker services are running (`docker compose ps`)
- [ ] Database migrations completed (`docker compose logs web | grep "Migrations"`)
- [ ] MailHog is accessible (http://localhost:8026)
- [ ] Redis is responding (`docker compose exec redis redis-cli ping`)
- [ ] RabbitMQ is accessible (http://localhost:15673)

### Email Notifications

- [ ] Email received in MailHog
- [ ] Subject line correct
- [ ] Recipient email correct
- [ ] HTML rendering correct
- [ ] Template variables rendered
- [ ] Unsubscribe link present
- [ ] Delivery log created
- [ ] Response code 200

### In-App Notifications

- [ ] Notification created in database
- [ ] Notification displays in UI
- [ ] Unread count correct
- [ ] Mark as read works
- [ ] Read timestamp recorded
- [ ] Notifications ordered by recency

### Preferences

- [ ] Preferences created for user
- [ ] Per-channel settings saved
- [ ] Notification type settings saved
- [ ] Quiet hours respected
- [ ] Digest frequency configurable

### Batching

- [ ] Multiple notifications batched
- [ ] Digest frequency configurable
- [ ] Digest emails generated
- [ ] Digest template renders

### Delivery Logs

- [ ] Logs created for each send
- [ ] Request/response payloads recorded
- [ ] Error messages captured
- [ ] Duration measured
- [ ] Status tracking works

---

## Viewing Test Results

### Test Output Log

```bash
# View latest test output
tail -f tests_comprehensive/reports/test_output_*.log

# Search for failures
grep -i "fail\|error" tests_comprehensive/reports/test_output_*.log
```

### MailHog Emails

```bash
# Get all emails via API
curl http://localhost:8025/api/messages

# Get specific email count
curl http://localhost:8025/api/messages | jq '.total'

# Get email details (replace ID)
curl http://localhost:8025/api/messages/1 | jq .
```

### Database Verification

```bash
# Connect to database
docker compose exec db psql -U postgres -d zumodra

# Check notifications
SELECT COUNT(*) FROM notifications_notification;
SELECT * FROM notifications_notification WHERE recipient_id = 1;

# Check delivery logs
SELECT * FROM notifications_notificationdeliverylog
ORDER BY created_at DESC LIMIT 10;

# Check preferences
SELECT * FROM notifications_notificationpreference;
```

### Celery Tasks

```bash
# Check active tasks
docker compose exec celery-worker celery -A zumodra inspect active

# Check task stats
docker compose exec celery-worker celery -A zumodra inspect stats

# View Celery logs
docker compose logs -f celery-worker
```

---

## Troubleshooting

### Services Not Starting

```bash
# Check Docker logs
docker compose logs web
docker compose logs celery-worker

# Restart services
docker compose down
docker compose up -d
```

### Email Not Received

```bash
# Check Django email backend
docker compose exec web python -c "from django.conf import settings; print(settings.EMAIL_BACKEND)"

# Check MailHog logs
docker compose logs mailhog

# Test SMTP manually
docker compose exec web python << 'EOF'
from django.core.mail import send_mail
send_mail('Test', 'Test', 'from@test.com', ['to@test.com'])
EOF
```

### In-App Notifications Not Showing

```bash
# Check database
docker compose exec db psql -U postgres -d zumodra << 'EOF'
SELECT * FROM notifications_notification;
EOF

# Check notification service
docker compose exec web python manage.py shell << 'EOF'
from notifications.models import Notification
print(f"Total notifications: {Notification.objects.count()}")
EOF
```

### Celery Tasks Not Executing

```bash
# Check RabbitMQ
docker compose logs rabbitmq

# Check Celery connection
docker compose exec celery-worker celery -A zumodra inspect ping

# View task queue
docker compose exec celery-worker celery -A zumodra inspect active_queues
```

### Rate Limiting Issues

```bash
# Check channel config
docker compose exec web python manage.py shell << 'EOF'
from notifications.models import NotificationChannel
for ch in NotificationChannel.objects.all():
    print(f"{ch.name}: {ch.rate_limit_per_hour}/hour")
EOF
```

---

## Performance Considerations

### Optimal Configuration

```python
# Email batch size
NOTIFICATION_EMAIL_BATCH_SIZE = 50

# Push notification concurrency
NOTIFICATION_PUSH_CONCURRENCY = 10

# Celery task timeout
NOTIFICATION_TASK_TIMEOUT = 300

# Retry settings
NOTIFICATION_MAX_RETRIES = 3
NOTIFICATION_RETRY_BACKOFF = True
NOTIFICATION_RETRY_BACKOFF_MAX = 600
```

### Load Testing

For load testing, adjust these parameters:

```python
# Create bulk notifications
for i in range(1000):
    Notification.objects.create(
        recipient=user,
        notification_type="load_test",
        title=f"Notification {i}",
        message=f"Message {i}",
        channels=["email"],
    )

# Monitor with
docker compose exec celery-worker celery -A zumodra inspect active
```

---

## Next Steps After Testing

1. **Review Results**
   - Check all test reports in `tests_comprehensive/reports/`
   - Review any failures or warnings
   - Note performance metrics

2. **Fix Issues**
   - Address any failed tests
   - Update configuration if needed
   - Re-run tests to verify fixes

3. **Document Findings**
   - Update issue tracker
   - Document any discovered limitations
   - Create deployment notes

4. **Staging Deployment**
   - Deploy to staging environment
   - Run end-to-end user testing
   - Monitor logs for errors

5. **Production Readiness**
   - Set up monitoring/alerting
   - Configure backup email service
   - Plan incident response

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `test_notifications_comprehensive.py` | Main test suite with all test classes |
| `notifications/models.py` | Notification models and database schema |
| `notifications/services.py` | Notification delivery services |
| `notifications/tasks.py` | Celery async tasks |
| `notifications/views.py` | API endpoints |
| `notifications/serializers.py` | DRF serializers |
| `docker-compose.yml` | Docker service configuration |

---

## Support & Documentation

### Internal Docs

- Notification Architecture: `notifications/README.md`
- Model Documentation: Model docstrings in `notifications/models.py`
- Service Documentation: Docstrings in `notifications/services.py`
- API Docs: `/api/docs/` endpoint (Swagger)

### External Resources

- Django Email: https://docs.djangoproject.com/en/5.0/topics/email/
- Celery Tasks: https://docs.celery.io/en/stable/
- MailHog: https://github.com/mailhog/MailHog
- DRF: https://www.django-rest-framework.org/

---

## Test Summary Statistics

**Total Test Cases:** 8 main categories
**Email Tests:** 2
**In-App Tests:** 3
**Preference Tests:** 3
**Batching Tests:** 2
**Delivery Logging Tests:** 2
**Push Tests:** 2
**SMS Tests:** 1
**Channel Tests:** 2

**Estimated Runtime:** 5-10 minutes (full suite)
**Report Location:** `tests_comprehensive/reports/`
**MailHog Verification:** http://localhost:8026

---

## Contact & Issues

For issues or questions about the notification system:

1. Check the `NOTIFICATION_TESTING_GUIDE.md` for detailed instructions
2. Review test output in `tests_comprehensive/reports/`
3. Check database directly for data verification
4. Monitor Celery and service logs

---

**Generated:** 2026-01-16
**Last Updated:** 2026-01-16
**Version:** 1.0
