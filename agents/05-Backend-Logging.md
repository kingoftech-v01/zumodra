# Zumodra Project – Backend Developer – Logging & Monitoring
## Comprehensive Onboarding Document

**Project:** Zumodra HR/Management SaaS  
**Deadline:** January 21, 2026  
**Role:** Backend Developer (Logging & Monitoring)

---

## 1. Executive Summary

You are responsible for implementing standardized, usable logging throughout Zumodra. Currently, there is no standardized logging, making it hard to debug issues. Your goal is to configure Django logging, ensure logs are captured properly, and set up monitoring so the team can diagnose problems quickly.

### Primary Objectives
- **Day 1:** Configure Django logging system with proper formatters and handlers
- **Day 2:** Integrate logging throughout the codebase
- **Day 3:** Setup error tracking (Sentry or similar) and dashboards
- **Day 4:** Document logging best practices and security considerations
- **Day 5:** Final validation and optimization

### Success Criteria
- [ ] Django LOGGING configured in settings.py
- [ ] Logs go to console (for Docker) and files
- [ ] Clear log format with timestamp, level, module, message
- [ ] Error tracking integrated (Sentry)
- [ ] Sensitive data not logged (passwords, tokens, PII)
- [ ] Log analysis examples documented

---

## 2. Django Logging Configuration

### 2.1 Settings.py Configuration

Add to `zumodra/settings.py`:

```python
import logging.config
import os

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'simple': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'json': {
            '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s',
        },
    },
    'filters': {
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'django.log'),
            'maxBytes': 1024 * 1024 * 10,  # 10 MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
        'error_file': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'errors.log'),
            'maxBytes': 1024 * 1024 * 10,
            'backupCount': 10,
            'formatter': 'verbose',
        },
        'request_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'requests.log'),
            'maxBytes': 1024 * 1024 * 10,
            'backupCount': 5,
            'formatter': 'simple',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file', 'error_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console', 'request_file', 'error_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'apps': {
            'handlers': ['console', 'file', 'error_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'apps.api': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Create logs directory if it doesn't exist
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)
```

### 2.2 Environment-Specific Configuration

```python
# In settings.py, adjust log levels based on environment
if DEBUG:
    LOGGING['loggers']['django']['level'] = 'DEBUG'
    LOGGING['loggers']['apps']['level'] = 'DEBUG'
else:
    LOGGING['loggers']['django']['level'] = 'INFO'
    LOGGING['loggers']['apps']['level'] = 'INFO'
```

---

## 3. Logging Throughout the Codebase

### 3.1 Basic Logging Usage

```python
import logging

logger = logging.getLogger(__name__)

def example_function():
    logger.debug("Starting function")
    try:
        result = do_something()
        logger.info(f"Function completed successfully", extra={
            'user_id': request.user.id,
            'action': 'create_user',
        })
        return result
    except Exception as e:
        logger.error(f"Error in example_function", exc_info=True, extra={
            'user_id': request.user.id if hasattr(request, 'user') else 'anonymous',
        })
        raise
```

**Log Levels:**
- **DEBUG** – Detailed information for diagnosing problems (development only)
- **INFO** – General informational messages (successful operations)
- **WARNING** – Warning messages (unexpected but recoverable)
- **ERROR** – Error messages (something failed)
- **CRITICAL** – Critical issues (system in danger)

### 3.2 Logging in Views

```python
import logging
from django.shortcuts import render
from django.views import View

logger = logging.getLogger(__name__)

class UserListView(View):
    def get(self, request):
        logger.info(f"UserListView accessed by {request.user.email}")
        
        try:
            users = User.objects.all()
            logger.debug(f"Retrieved {users.count()} users")
            return render(request, 'users/list.html', {'users': users})
        except Exception as e:
            logger.error(f"Error loading user list", exc_info=True)
            return render(request, 'errors/500.html', status=500)
```

### 3.3 Logging in Models

```python
import logging
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)

class User(models.Model):
    email = models.EmailField(unique=True)
    # ...

@receiver(post_save, sender=User)
def log_user_creation(sender, instance, created, **kwargs):
    if created:
        logger.info(f"New user created", extra={
            'user_id': instance.id,
            'email': instance.email,
        })
    else:
        logger.debug(f"User updated", extra={
            'user_id': instance.id,
            'email': instance.email,
        })
```

### 3.4 Logging in Utilities

```python
import logging

logger = logging.getLogger(__name__)

def send_email(to, subject, body):
    """Send email and log result."""
    try:
        # ... email sending logic ...
        logger.info(f"Email sent", extra={
            'recipient': to,
            'subject': subject,
        })
    except Exception as e:
        logger.error(f"Failed to send email", exc_info=True, extra={
            'recipient': to,
            'error': str(e),
        })
        raise
```

---

## 4. Structured Logging with Context

### 4.1 Using Structlog (Optional, for advanced needs)

```bash
pip install structlog
```

```python
import structlog

logger = structlog.get_logger()

def create_order(user, items):
    logger.info(
        "order.created",
        user_id=user.id,
        item_count=len(items),
        total_amount=sum(item.price for item in items),
    )
```

### 4.2 Request Context Logging

```python
import uuid
import logging
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

class RequestLoggingMiddleware(MiddlewareMixin):
    """Add request ID to all logs for tracking."""
    def process_request(self, request):
        request.id = str(uuid.uuid4())
        request.log_data = {
            'request_id': request.id,
            'user_id': getattr(request.user, 'id', 'anonymous'),
            'path': request.path,
            'method': request.method,
        }
        logger.info(f"Request started", extra=request.log_data)
    
    def process_response(self, request, response):
        logger.info(
            f"Request completed",
            extra={**request.log_data, 'status_code': response.status_code}
        )
        return response
```

---

## 5. What NOT to Log

### 5.1 Sensitive Data Filters

```python
import logging
import re

class SensitiveDataFilter(logging.Filter):
    """Remove sensitive data from logs."""
    
    PATTERNS = {
        'password': r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        'token': r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        'credit_card': r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}',
        'ssn': r'\d{3}-\d{2}-\d{4}',
    }
    
    def filter(self, record):
        message = record.getMessage()
        for key, pattern in self.PATTERNS.items():
            message = re.sub(pattern, f'{key}=***', message, flags=re.IGNORECASE)
        record.msg = message
        record.args = ()
        return True

# Add to settings.py LOGGING config:
LOGGING['filters']['sensitive_data'] = {
    '()': '__main__.SensitiveDataFilter',
}

# Apply to handlers:
LOGGING['handlers']['console']['filters'] = ['sensitive_data']
LOGGING['handlers']['file']['filters'] = ['sensitive_data']
```

### 5.2 What to Exclude from Logs

**Never log:**
- Passwords or passphrases
- Tokens, API keys, or secrets
- Credit card numbers
- Social Security numbers
- Personal email addresses (optional, use hashed values)
- Medical/health information
- Any Personally Identifiable Information (PII) unless necessary

**Safe to log:**
- User ID (not email, not name)
- Action performed (create, update, delete)
- Timestamp
- Result (success/failure)
- Error types and stack traces (without sensitive data)

---

## 6. Sentry Integration (Error Tracking)

### 6.1 Setup

```bash
pip install sentry-sdk
```

```python
# settings.py
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

sentry_sdk.init(
    dsn=config('SENTRY_DSN', default=''),
    integrations=[DjangoIntegration()],
    traces_sample_rate=0.1,  # 10% of requests
    send_default_pii=False,  # Don't send PII
)
```

### 6.2 Capturing Exceptions

```python
import sentry_sdk

try:
    result = risky_operation()
except Exception as e:
    sentry_sdk.capture_exception(e)
    logger.error("Error in operation", exc_info=True)
```

---

## 7. Log Analysis & Debugging

### 7.1 Useful Log Queries

```bash
# Show all errors
tail -f logs/errors.log

# Show recent activity
tail -50 logs/django.log

# Find specific user's actions
grep "user_id=123" logs/django.log

# Count errors by type
grep "ERROR" logs/errors.log | grep -o "error=[^,]*" | sort | uniq -c

# Show slow requests
grep -E "completed.*[5-9][0-9]{3}ms" logs/requests.log
```

### 7.2 Log Monitoring Dashboard (Optional)

Consider tools like:
- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Splunk**
- **Datadog**
- **CloudWatch** (if on AWS)

For MVP, local log files are fine. Monitor with:
```bash
# Watch errors in real-time
tail -f logs/errors.log | grep ERROR
```

---

## 8. Testing Logging

```python
from django.test import TestCase
import logging

class LoggingTestCase(TestCase):
    def test_user_creation_logged(self):
        """Verify user creation is logged."""
        with self.assertLogs('apps', level='INFO') as log_context:
            User.objects.create(email='test@test.com')
        
        self.assertEqual(len(log_context.records), 1)
        self.assertIn('user created', log_context.output[0])
```

---

## 9. Deliverables

By **End of Day 4**, provide:

- [ ] LOGGING configuration in settings.py (console + files)
- [ ] Logs directory created and rotation configured
- [ ] Sensitive data filter implemented
- [ ] Logging integrated in views, models, utilities
- [ ] Error tracking (Sentry) configured
- [ ] Documentation on logging best practices
- [ ] Log examples showing typical operations and errors
- [ ] Monitoring setup (basic or advanced depending on budget)

---

## 10. Quick Reference

**Log Levels by Use Case:**
| Scenario | Level | Example |
|----------|-------|---------|
| User logged in | INFO | `logger.info("User login")` |
| Database query executed | DEBUG | `logger.debug("Query executed")` |
| Authentication failed | WARNING | `logger.warning("Auth failed")` |
| Payment processing error | ERROR | `logger.error("Payment failed", exc_info=True)` |
| System down | CRITICAL | `logger.critical("DB connection lost")` |

**Configuration Checklist:**
- [ ] LOGGING dict in settings.py
- [ ] Console handler (for Docker logs)
- [ ] File handler with rotation (for persistent logs)
- [ ] Error-specific handler
- [ ] Sensitive data filter
- [ ] Appropriate levels by module

---

**Document Version:** 1.0  
**Created:** January 16, 2026  
**Owner:** Backend Developer – Logging & Monitoring