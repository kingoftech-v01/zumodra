# Email System Testing - Quick Start Guide

## 5-Minute Setup

### 1. Start Docker Services
```bash
docker-compose up -d web db redis mailhog celery celery-beat
sleep 10
```

### 2. Verify Services
```bash
docker-compose ps
```

Expected output: All services showing `running`

### 3. Run Tests
```bash
python tests_comprehensive/email_system_test_simple.py
```

### 4. Check MailHog
```bash
open http://localhost:8026
```

Or check via API:
```bash
curl http://localhost:8026/api/v2/messages
```

## Test Report Location
```bash
ls tests_comprehensive/reports/
```

Latest report: `email_test_report_*.json`

## Common Commands

### Send Test Email
```bash
python manage.py shell << 'EOF'
from django.core.mail import send_mail
send_mail('Test', 'Test message', 'noreply@zumodra.local', ['test@example.com'])
EOF
```

### Check Celery Queue
```bash
celery -A zumodra inspect active
```

### View Email Logs
```bash
python manage.py shell << 'EOF'
from notifications.models import NotificationDeliveryLog
for log in NotificationDeliveryLog.objects.all()[:5]:
    print(f"{log.notification.title}: {log.status}")
EOF
```

### Clear MailHog
```bash
curl -X DELETE http://localhost:8026/api/v1/messages
```

## Troubleshooting

### Issue: Connection Timeout
**Solution:** Make sure all services are running
```bash
docker-compose logs mailhog
docker-compose logs web
```

### Issue: No Emails in MailHog
**Solution:** Check EMAIL_BACKEND
```bash
python manage.py shell -c "from django.conf import settings; print(settings.EMAIL_BACKEND)"
```

Should output: `django.core.mail.backends.smtp.EmailBackend`

### Issue: Celery Tasks Not Processing
**Solution:** Start celery worker
```bash
docker-compose up -d celery
docker-compose logs celery
```

## Files Overview

| File | Purpose |
|------|---------|
| `test_email_system_integration.py` | Django ORM tests (12 scenarios) |
| `email_system_test_simple.py` | API tests (13 scenarios) |
| `run_email_tests.sh` | Automated test runner |
| `EMAIL_SYSTEM_TEST_GUIDE.md` | Complete testing guide |
| `EMAIL_SYSTEM_ANALYSIS.md` | Architecture and design |
| `EMAIL_QUICK_START.md` | This file |

## Test Coverage

✓ Transactional emails
✓ Template rendering
✓ Queue processing
✓ Bounce handling
✓ Click tracking
✓ Unsubscribe management
✓ Email logs
✓ Multi-tenant isolation

## Performance Goals

- Email send: < 100ms (queued)
- Delivery: < 1 second
- Template render: < 10ms
- Bounce handling: < 1 second

## Next Steps

1. Run the quick start commands above
2. Review test reports
3. Check MailHog UI at http://localhost:8026
4. Read `EMAIL_SYSTEM_TEST_GUIDE.md` for detailed info
5. Run `EMAIL_SYSTEM_ANALYSIS.md` for architecture details

## Quick Reference

| Task | Command |
|------|---------|
| Start services | `docker-compose up -d web db redis mailhog celery celery-beat` |
| Stop services | `docker-compose down` |
| View logs | `docker-compose logs -f <service>` |
| Run tests | `python tests_comprehensive/email_system_test_simple.py` |
| View MailHog | `open http://localhost:8026` |
| Check queue | `celery -A zumodra inspect active` |
| Run migrations | `python manage.py migrate` |
| Django shell | `python manage.py shell` |

## Expected Test Results

When all services are running:
- 6-8 tests should PASS
- 3-4 tests should WARNING (depends on configuration)
- 0-2 tests should FAIL (requires investigation)

A success rate of 60%+ indicates the email system is functioning.

---

For more details, see the comprehensive guides in `tests_comprehensive/`
