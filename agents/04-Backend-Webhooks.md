# Zumodra Project – Backend Developer – Webhooks
## Comprehensive Onboarding Document

**Project:** Zumodra HR/Management SaaS  
**Deadline:** January 21, 2026  
**Role:** Backend Developer (Webhooks)

---

## 1. Executive Summary

You are responsible for implementing and stabilizing webhook functionality. Webhooks allow Zumodra to receive events from external services (payment providers, HR systems, notification services) and trigger internal actions. Your goal is to identify all webhook types, implement them with proper validation and idempotency, and ensure they're production-ready by Day 4.

### Primary Objectives
- **Day 1–2:** Identify all webhook types, define specifications, document expected payloads
- **Day 3:** Implement webhook receivers with signature validation and idempotency
- **Day 4:** Add logging, monitoring, and test coverage
- **Day 5:** Final testing and documentation

### Success Criteria
- [ ] All webhook types identified and documented
- [ ] Webhook endpoints validate requests (signature, timestamp)
- [ ] Idempotency handled (no duplicate processing)
- [ ] Detailed logging of all webhook calls
- [ ] Test suite with happy path + error cases
- [ ] Admin interface to view webhook logs

---

## 2. Webhook Types & Specifications

### 2.1 Common Webhook Types (Identify which ones Zumodra uses)

Typical webhook sources:
1. **Payment Provider** (Stripe, PayPal, etc.) – Payment events, refunds
2. **Email Service** (Sendgrid, Mailgun) – Delivery status, bounces
3. **HR System** (Gusto, BambooHR) – Employee updates, payroll events
4. **Notification Service** – Webhook events for alerting
5. **Internal Events** – App-generated webhooks for external integrations

**Identify Your Webhooks:**

Create a file `docs/WEBHOOKS.md`:

```markdown
# Zumodra Webhooks Specification

## Identified Webhooks

### 1. Payment Webhook (Stripe)
- **Source:** Stripe
- **Trigger:** Payment succeeded, failed, refunded
- **URL:** POST /webhooks/stripe/
- **Signature Method:** HMAC-SHA256
- **Expected Events:** charge.succeeded, charge.failed, charge.refunded
- **Sample Payload:**
```json
{
  "id": "evt_...",
  "type": "charge.succeeded",
  "created": 1234567890,
  "data": {
    "object": {
      "id": "ch_...",
      "amount": 5000,
      "currency": "usd",
      "customer": "cus_...",
      "status": "succeeded"
    }
  }
}
```

### 2. Email Delivery Webhook (Sendgrid)
- **Source:** Sendgrid
- **Trigger:** Email delivered, bounced, opened, clicked
- **URL:** POST /webhooks/sendgrid/
- **Signature Method:** Signature header verification
- **Expected Events:** delivered, bounce, open, click
- **Sample Payload:**
```json
[
  {
    "email": "user@example.com",
    "timestamp": 1234567890,
    "event": "delivered",
    "messageId": "...",
    "sg_message_id": "..."
  }
]
```

### 3. Employee Update Webhook (BambooHR)
- **Source:** BambooHR
- **Trigger:** Employee created, updated, terminated
- **URL:** POST /webhooks/bamboohr/
- **Signature Method:** Basic Auth or API key
- **Expected Events:** employeeUpdated, employeeDeleted
- **Sample Payload:**
```json
{
  "eventId": "...",
  "eventTime": "2026-01-16T10:00:00Z",
  "eventType": "employeeUpdated",
  "employee": {
    "id": 123,
    "firstName": "John",
    "lastName": "Doe",
    "status": "Active"
  }
}
```

[... more webhook types ...]
```

---

## 3. Webhook Implementation

### 3.1 Standard Webhook Receiver Pattern

```python
import hmac
import hashlib
import json
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from apps.webhooks.models import WebhookLog
import logging

logger = logging.getLogger(__name__)

def verify_stripe_signature(request, secret):
    """Verify Stripe webhook signature."""
    signature = request.META.get('HTTP_STRIPE_SIGNATURE', '')
    payload = request.body
    
    # Extract timestamp and signature from header
    parts = {item.split('=')[0]: item.split('=')[1] for item in signature.split(',')}
    timestamp = parts.get('t')
    received_sig = parts.get('v1')
    
    # Compute expected signature
    signed_content = f'{timestamp}.{payload.decode()}'
    expected_sig = hmac.new(
        secret.encode(),
        signed_content.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_sig, received_sig)

@require_http_methods(["POST"])
@csrf_exempt  # Webhooks can't include CSRF tokens
def stripe_webhook(request):
    """Handle Stripe webhook events."""
    secret = settings.STRIPE_WEBHOOK_SECRET
    
    # Verify signature
    if not verify_stripe_signature(request, secret):
        logger.warning("Invalid Stripe webhook signature")
        return JsonResponse({'error': 'Invalid signature'}, status=403)
    
    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        logger.error("Invalid JSON in Stripe webhook")
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    # Log webhook call
    webhook_log = WebhookLog.objects.create(
        source='stripe',
        event_type=payload.get('type'),
        payload=payload,
        status='received'
    )
    
    try:
        # Process based on event type
        event_type = payload.get('type')
        
        if event_type == 'charge.succeeded':
            process_payment_succeeded(payload)
        elif event_type == 'charge.failed':
            process_payment_failed(payload)
        elif event_type == 'charge.refunded':
            process_refund(payload)
        else:
            logger.info(f"Unhandled event type: {event_type}")
        
        webhook_log.status = 'processed'
        webhook_log.save()
        
        return JsonResponse({'status': 'received'}, status=200)
    
    except Exception as e:
        logger.exception(f"Error processing Stripe webhook: {e}")
        webhook_log.status = 'failed'
        webhook_log.error_message = str(e)
        webhook_log.save()
        return JsonResponse({'error': 'Processing failed'}, status=500)

def process_payment_succeeded(payload):
    """Handle successful payment."""
    charge_id = payload['data']['object']['id']
    customer_id = payload['data']['object']['customer']
    amount = payload['data']['object']['amount']
    
    # Check for duplicate (idempotency)
    from apps.payments.models import Payment
    if Payment.objects.filter(stripe_charge_id=charge_id).exists():
        logger.info(f"Duplicate payment webhook: {charge_id}")
        return
    
    # Create payment record
    payment = Payment.objects.create(
        stripe_charge_id=charge_id,
        amount=amount / 100,  # Convert from cents
        status='completed'
    )
    
    # Trigger any side effects (email, update account, etc.)
    payment.send_confirmation_email()
    logger.info(f"Payment processed: {charge_id}")
```

### 3.2 Webhook Models

```python
from django.db import models

class WebhookLog(models.Model):
    """Log of all incoming webhooks."""
    SOURCE_CHOICES = [
        ('stripe', 'Stripe'),
        ('sendgrid', 'Sendgrid'),
        ('bamboohr', 'BambooHR'),
    ]
    
    STATUS_CHOICES = [
        ('received', 'Received'),
        ('processed', 'Processed'),
        ('failed', 'Failed'),
        ('ignored', 'Ignored'),
    ]
    
    source = models.CharField(max_length=50, choices=SOURCE_CHOICES)
    event_type = models.CharField(max_length=100)
    payload = models.JSONField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='received')
    error_message = models.TextField(blank=True)
    received_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-received_at']
        indexes = [
            models.Index(fields=['source', 'event_type']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"{self.source} – {self.event_type} ({self.status})"

class WebhookDelivery(models.Model):
    """Track webhook deliveries to external services (if Zumodra sends webhooks)."""
    url = models.URLField()
    event_type = models.CharField(max_length=100)
    payload = models.JSONField()
    status_code = models.IntegerField(null=True, blank=True)
    attempts = models.IntegerField(default=1)
    next_retry = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
```

### 3.3 URL Configuration

```python
# apps/webhooks/urls.py
from django.urls import path
from . import views

app_name = 'webhooks'

urlpatterns = [
    path('stripe/', views.stripe_webhook, name='stripe'),
    path('sendgrid/', views.sendgrid_webhook, name='sendgrid'),
    path('bamboohr/', views.bamboohr_webhook, name='bamboohr'),
]

# Include in root urls.py:
# path('webhooks/', include('apps.webhooks.urls')),
```

---

## 4. Idempotency & Reliability

### 4.1 Preventing Duplicate Processing

Webhooks may be called multiple times for the same event. Implement idempotency:

```python
def process_with_idempotency(source, event_id, event_type, handler_func):
    """
    Process webhook event only once.
    
    Args:
        source: Webhook source (e.g., 'stripe')
        event_id: Unique event ID from source
        event_type: Type of event
        handler_func: Function to call to process event
    """
    from apps.webhooks.models import ProcessedEvent
    
    # Check if already processed
    processed = ProcessedEvent.objects.filter(
        source=source,
        event_id=event_id
    ).exists()
    
    if processed:
        logger.info(f"Duplicate event: {source} – {event_id}")
        return {'status': 'already_processed'}
    
    try:
        result = handler_func()
        
        # Mark as processed
        ProcessedEvent.objects.create(
            source=source,
            event_id=event_id,
            event_type=event_type
        )
        
        return result
    except Exception as e:
        logger.exception(f"Error processing event {event_id}: {e}")
        raise
```

### 4.2 Retry Logic

```python
from celery import shared_task
from django.utils import timezone
from datetime import timedelta

@shared_task
def retry_failed_webhooks():
    """Retry failed webhook deliveries."""
    failed = WebhookLog.objects.filter(
        status='failed',
        next_retry__lte=timezone.now()
    )[:10]  # Retry 10 at a time
    
    for log in failed:
        try:
            # Reprocess the webhook
            process_webhook(log.source, log.payload)
            log.status = 'processed'
        except Exception as e:
            log.attempts += 1
            # Exponential backoff: 5 min, 30 min, 2 hours, etc.
            delay = timedelta(minutes=5 * (2 ** log.attempts))
            log.next_retry = timezone.now() + delay
        
        log.save()

# Schedule in Celery Beat:
# 'retry-webhooks': {
#     'task': 'apps.webhooks.tasks.retry_failed_webhooks',
#     'schedule': crontab(minute='*/15'),  # Every 15 minutes
# }
```

---

## 5. Testing Webhooks

### 5.1 Unit Tests

```python
from django.test import TestCase, Client
from django.test.utils import override_settings
import json
import hmac
import hashlib

@override_settings(STRIPE_WEBHOOK_SECRET='test_secret')
class StripeWebhookTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.secret = 'test_secret'
    
    def test_invalid_signature(self):
        """Webhook with invalid signature should be rejected."""
        payload = json.dumps({'type': 'charge.succeeded'})
        response = self.client.post(
            '/webhooks/stripe/',
            data=payload,
            content_type='application/json',
            HTTP_STRIPE_SIGNATURE='t=12345,v1=invalid'
        )
        self.assertEqual(response.status_code, 403)
    
    def test_valid_signature(self):
        """Webhook with valid signature should be processed."""
        timestamp = '1234567890'
        payload = json.dumps({
            'type': 'charge.succeeded',
            'data': {
                'object': {
                    'id': 'ch_test',
                    'amount': 5000,
                    'customer': 'cus_test'
                }
            }
        })
        
        signed_content = f'{timestamp}.{payload}'
        signature = hmac.new(
            self.secret.encode(),
            signed_content.encode(),
            hashlib.sha256
        ).hexdigest()
        
        response = self.client.post(
            '/webhooks/stripe/',
            data=payload,
            content_type='application/json',
            HTTP_STRIPE_SIGNATURE=f't={timestamp},v1={signature}'
        )
        self.assertEqual(response.status_code, 200)
        
        # Verify webhook log was created
        from apps.webhooks.models import WebhookLog
        log = WebhookLog.objects.latest('id')
        self.assertEqual(log.source, 'stripe')
        self.assertEqual(log.status, 'processed')
    
    def test_duplicate_webhook(self):
        """Duplicate webhook should not be processed twice."""
        # [First call]
        # [Second call with same event]
        # Verify only one payment record created
```

### 5.2 Manual Testing with curl

```bash
# Test Stripe webhook locally
# First, get Stripe CLI or use RequestBin to generate signature

TIMESTAMP=$(date +%s)
PAYLOAD='{"type":"charge.succeeded","data":{"object":{"id":"ch_test","amount":5000}}}'
SIGNED_CONTENT="$TIMESTAMP.$PAYLOAD"
SIGNATURE=$(echo -n "$SIGNED_CONTENT" | openssl dgst -sha256 -hmac "test_secret" | cut -d' ' -f2)

curl -X POST http://localhost:8000/webhooks/stripe/ \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: t=$TIMESTAMP,v1=$SIGNATURE" \
  -d "$PAYLOAD"
```

---

## 6. Monitoring & Logging

### 6.1 Webhook Admin Interface

```python
from django.contrib import admin
from .models import WebhookLog

@admin.register(WebhookLog)
class WebhookLogAdmin(admin.ModelAdmin):
    list_display = ['source', 'event_type', 'status', 'received_at']
    list_filter = ['source', 'status', 'received_at']
    search_fields = ['event_type']
    readonly_fields = ['payload', 'received_at']
    
    def has_add_permission(self, request):
        return False  # Don't allow manual webhook creation
    
    def has_delete_permission(self, request, obj=None):
        return False  # Preserve webhook history
```

### 6.2 Logging Best Practices

```python
import logging
logger = logging.getLogger(__name__)

# Log at appropriate levels
logger.debug("Webhook received", extra={'event_id': event_id})
logger.info("Webhook processed successfully", extra={'event_id': event_id})
logger.warning("Webhook validation failed", extra={'reason': 'invalid_signature'})
logger.error("Error processing webhook", exc_info=True)

# Exclude sensitive data from logs
def safe_log_payload(payload):
    """Remove sensitive data before logging."""
    safe = payload.copy()
    safe.pop('credit_card', None)
    safe.pop('password', None)
    return safe
```

---

## 7. Deliverables

By **End of Day 4**, provide:

- [ ] Comprehensive webhook specification (`docs/WEBHOOKS.md`)
- [ ] All webhook receivers implemented and tested
- [ ] Signature validation working for all sources
- [ ] Idempotency handling in place
- [ ] Webhook logging and admin interface
- [ ] Retry logic for failed deliveries
- [ ] Test coverage 80%+
- [ ] curl/Postman examples for manual testing

---

## 8. Quick Reference

**Webhook Security Checklist:**
- [ ] Validate signature on every webhook
- [ ] Check timestamp to prevent replay attacks
- [ ] Log all webhook calls (for audit trail)
- [ ] Handle timeouts gracefully
- [ ] Implement idempotency (don't process duplicates)
- [ ] Respond quickly (webhook providers timeout after 5–30 seconds)
- [ ] Retry failed deliveries with exponential backoff
- [ ] Never log sensitive data (credit cards, passwords)

---

**Document Version:** 1.0  
**Created:** January 16, 2026  
**Owner:** Backend Developer – Webhooks