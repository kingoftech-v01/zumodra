# Webhook Review Day 2 - Findings and Fixes

**Date:** 2026-01-16
**Review Status:** Complete
**Critical Issues Found:** 5
**Warnings:** 3
**Recommendations:** 4

---

## Executive Summary

The webhook system implements both incoming (from 3rd parties) and outgoing (to subscribers) webhook flows with good overall structure. However, several critical security and idempotency issues require immediate attention:

1. **Critical: Silent Signature Verification Failure** - Missing secret key returns True instead of False
2. **Critical: Missing Event ID Validation** - Idempotency checks fail silently when event_id is empty
3. **Critical: Incomplete HelloSign Verification** - Returns True without actual validation
4. **Critical: Timestamp Validation Logic Errors** - Slack/Zoom use tolerance check that could be bypassed
5. **High: Duplicate Event Detection Race Condition** - Non-atomic check-then-process

---

## Files Reviewed

```
/root/zumodra/integrations/webhooks.py          (648 lines)
/root/zumodra/integrations/webhook_signals.py   (615 lines)
/root/zumodra/integrations/outbound_webhooks.py (728 lines)
/root/zumodra/integrations/models.py            (958 lines)
/root/zumodra/integrations/tasks.py             (479 lines)
```

---

## Section 1: Incoming Webhook Receiver (`webhooks.py`)

### 1.1 WebhookValidator Class - CRITICAL ISSUES

#### Issue #1: Silent Verification Bypass (Line 59-60)
**Severity:** CRITICAL - Security Vulnerability

```python
if not self.secret_key:
    return True  # No secret configured, skip validation
```

**Problem:**
- When `secret_key` is not configured, the validator returns `True`, bypassing all signature checks
- This is dangerous because a misconfigured integration could accept ANY webhook payload
- No logging or warning that signature validation was skipped

**Impact:**
- Malicious actors could send unverified webhooks if secret is missing
- Difficult to debug configuration issues

**Fix Required:**
```python
if not self.secret_key:
    logger.error(f"No secret key configured for webhook endpoint {self.endpoint.id}")
    return False  # Reject webhooks without signature verification capability
```

---

#### Issue #2: HelloSign Verification Returns True (Line 412)
**Severity:** CRITICAL - No Validation

```python
elif provider == 'hellosign':
    # HelloSign uses event_hash in payload for verification
    # The secret is used to compute the hash
    return True  # Simplified - implement full verification
```

**Problem:**
- HelloSign webhooks are NOT actually verified; the code just returns True
- This is a TODO comment that was never implemented
- No actual signature validation occurs for HelloSign

**Impact:**
- Unverified HelloSign webhooks accepted
- Could lead to spoofed signature completion events

**Fix Required:**
Implement actual HelloSign signature verification:
```python
elif provider == 'hellosign':
    # HelloSign sends event_hash in the payload
    # Verify by computing HMAC-SHA256(payload, secret) and comparing with event_hash
    event_hash = payload.get('event', {}).get('event_hash', '')
    if not event_hash:
        return False

    # Reconstruct payload exactly as HelloSign signs it
    import json
    signed_payload = json.dumps(payload['event'], separators=(',', ':'))
    expected = hmac.new(
        self.secret_key.encode(),
        signed_payload.encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, event_hash)
```

---

#### Issue #3: Timestamp Validation Vulnerability (Lines 393-394, 613-614, 636-637)
**Severity:** MEDIUM - Potential Replay Attack Vector

**Stripe signature verification (Line 393-394):**
```python
if abs(int(timestamp) - int(time.time())) > 300:
    return False
```

**Issue:** The check passes if timestamp is within 5 minutes (300 seconds). However:
1. `time.time()` returns float but only the integer part is compared
2. If the server clock is slightly off, valid requests might be rejected
3. No compensation for timezone differences

**Slack verification (Lines 612-614):**
```python
if abs(int(time.time()) - int(timestamp)) > 300:
    return False
```

**Same issue:** Integer truncation and no timezone compensation

**Zoom verification (Lines 369-370):**
```python
timestamp = request.headers.get('x-zm-request-timestamp', '')
message = f"v0:{timestamp}:{payload.decode()}"
```

**Issue:** If timestamp header is missing or malformed, the signature can be computed with an empty string and might still validate

**Fix Required:**
```python
# For all providers with timestamp validation
try:
    request_timestamp = int(float(timestamp))
except (ValueError, TypeError):
    logger.warning(f"Invalid timestamp in request: {timestamp}")
    return False

current_time = int(time.time())
time_diff = abs(current_time - request_timestamp)

# Log near-expiry requests
if time_diff > 250:  # Warn at 250 seconds
    logger.warning(f"Webhook timestamp {time_diff}s old for {provider}")

if time_diff > 300:
    logger.error(f"Webhook timestamp validation failed for {provider}: {time_diff}s")
    return False
```

---

### 1.2 IncomingWebhookView - CRITICAL IDEMPOTENCY ISSUES

#### Issue #4: Race Condition in Duplicate Detection (Lines 183-189)
**Severity:** CRITICAL - Data Consistency

```python
# Check for duplicates
if delivery.is_duplicate():
    logger.info(f"Duplicate webhook event: {event_id}")
    delivery.status = 'delivered'
    delivery.status_message = 'Duplicate event - already processed'
    delivery.processed_at = timezone.now()
    delivery.save()
    return JsonResponse({'status': 'duplicate'}, status=200)
```

**Problem:**
- `is_duplicate()` check and subsequent processing are NOT atomic
- Two identical webhook payloads could be received simultaneously
- Both threads could pass the duplicate check before either saves
- Both could process the same event, causing duplicate side effects

**Code in models.py (Line 846-854):**
```python
def is_duplicate(self):
    """Check if this event has already been processed."""
    if not self.event_id:
        return False
    return WebhookDelivery.objects.filter(
        endpoint=self.endpoint,
        event_id=self.event_id,
        status=self.Status.DELIVERED
    ).exclude(pk=self.pk).exists()
```

**Additional Problem:** If event_id is empty, `is_duplicate()` returns False immediately, so no deduplication occurs

**Impact:**
- Duplicate processing of webhooks can cause double-counting
- Background checks marked as completed twice
- Financial transactions duplicated
- Job applicant statuses updated twice

**Fix Required:**
Implement database-level uniqueness constraint and use atomic operations.

---

#### Issue #5: Missing Event ID Handling (Lines 165-166, 294-317)
**Severity:** HIGH - Idempotency Failure

```python
# Get event ID for deduplication
event_id = self._extract_event_id(provider, request, payload)
```

**Problem in extraction logic (Lines 311-317):**
```python
# Default patterns
return (
    payload.get('event_id') or
    payload.get('id') or
    payload.get('uuid') or
    ''  # Returns empty string if all fail
)
```

**Issues:**
- Many webhooks return empty string for event_id
- When event_id is empty, `is_duplicate()` returns False (line 848)
- No warning when event_id cannot be extracted
- No fallback mechanism (e.g., hash of payload)

**Providers with unreliable event_id:**
- Hellosign: Uses `event_hash` but code only stores in event_id (line 306)
- Checkr/Sterling: Uses `id` but nested in different locations per provider
- Generic providers: Fallback is empty string

**Impact:**
- No deduplication for providers without standard event_id
- Duplicate webhook processing not detected
- Race conditions become more severe

**Fix Required:**
```python
def _extract_event_id(self, provider: str, request, payload: Dict) -> str:
    """Extract event ID for deduplication, with fallback to payload hash."""
    event_id = self._extract_event_id_impl(provider, request, payload)

    # If no event_id found, generate deterministic hash of payload
    if not event_id:
        import hashlib
        payload_str = json.dumps(payload, sort_keys=True, default=str)
        event_id = f"hash_{hashlib.sha256(payload_str.encode()).hexdigest()[:16]}"
        logger.warning(f"No native event_id for {provider}, using payload hash: {event_id}")

    return event_id
```

---

### 1.3 Signature Extraction and Verification

#### Issue #6: Case-Sensitive Header Lookup with Fallback (Lines 73-84)
**Severity:** LOW - Edge Case

```python
signature = None
for header in signature_headers:
    if header in headers:
        signature = headers[header]
        break

if not signature:
    # Check case-insensitive
    headers_lower = {k.lower(): v for k, v in headers.items()}
```

**Problem:** This is inefficient. HTTP headers are case-insensitive per spec, but Django's request.headers already handles this.

**Better approach:**
```python
signature = None
for header in signature_headers:
    # Django request.headers is case-insensitive
    signature = request.headers.get(header)
    if signature:
        break
```

---

### 1.4 Provider-Specific Verification Issues

#### Slack Verification (Lines 356-365)
**Status:** Correct implementation ✓
- Uses v0 prefix correctly
- Combines timestamp + body properly
- Uses hmac.compare_digest

#### Stripe Verification (Lines 378-396)
**Status:** Has issues
- Timestamp parsing is correct
- But: no validation that all required parts (t, v1) exist
- Should check `len(parts) >= 2`

**Fix:**
```python
elif provider == 'stripe':
    try:
        parts = dict(p.split('=', 1) for p in signature.split(','))
        if 'v1' not in parts or 't' not in parts:
            logger.warning("Stripe signature missing required parts (t, v1)")
            return False

        timestamp = int(parts['t'])
        sig_v1 = parts['v1']
        # ... rest of verification
    except (ValueError, KeyError) as e:
        logger.error(f"Stripe signature parsing failed: {e}")
        return False
```

---

## Section 2: Outbound Webhook System (`outbound_webhooks.py`)

### 2.1 OutboundWebhook Model - GOOD

**Strengths:**
- ✓ Secret key auto-generated if missing (line 143-144)
- ✓ Status tracking (ACTIVE/SUSPENDED)
- ✓ Consecutive failure counter
- ✓ Auto-suspension after 10 consecutive failures
- ✓ Statistics tracking (total_sent, total_successful, total_failed)

**Issues:**
- The suspension logic (line 197-198) is good but no notification to tenant admin
- No rate limiting on webhook delivery attempts

---

### 2.2 OutboundWebhookDelivery Model - GOOD

**Strengths:**
- ✓ Comprehensive status tracking (PENDING, SENDING, DELIVERED, FAILED, RETRYING)
- ✓ Exponential backoff with calculated next_retry_at
- ✓ Response tracking (status_code, body, response_time_ms)
- ✓ Max retries configurable (default 5)

**Issues:**
- No prevention of duplicate deliveries if database errors occur
- No circuit breaker pattern for repeatedly failing webhooks
- Retry count incremented before save (line 294), could lose count on crash

---

### 2.3 send_webhook_sync Function - ISSUES

**Strengths:**
- ✓ Comprehensive error handling
- ✓ Timeout protection (30 seconds)
- ✓ Response time tracking
- ✓ Response body truncation (10000 chars)
- ✓ Proper use of hmac.compare_digest

**Issues:**

#### Issue #7: No Payload Serialization Error Handling (Line 503)
```python
payload_json = json.dumps(payload, default=str)
```

**Problem:** If payload contains objects that can't be serialized even with `default=str`, this fails silently with `default=str` fallback. Better to be explicit.

#### Issue #8: Missing Content-Length Header (Lines 509-517)
```python
headers = {
    'Content-Type': 'application/json',
    'X-Webhook-Signature': f"sha256={signature}",
    'X-Webhook-Event': f"{delivery.app_name}.{delivery.event_type}",
    'X-Webhook-ID': str(delivery.id),
    'X-Webhook-Timestamp': str(int(time.time())),
    'User-Agent': 'Zumodra-Webhook/1.0',
}
```

**Missing:** Content-Length header. Some servers/clients expect it. `requests` library should add it automatically, but explicit is better.

---

## Section 3: Webhook Signals (`webhook_signals.py`)

### 3.1 Signal Connection - GOOD

**Overview:**
- Comprehensive coverage of 9 apps (tenants, accounts, ats, hr_core, services, finance, appointment, messages_sys, notifications, blog, newsletter)
- Proper use of `@receiver` decorators
- Good error handling for missing imports

**Issues:**

#### Issue #9: Silent Failures During Setup (Lines 92-94, 141-142)
```python
except Exception as e:
    # During initial setup, tables might not exist yet - this is expected
    # Log as warning instead of error to avoid false alarms
    logger.warning(f"Failed to dispatch webhook {app_name}.{event_type} (expected during setup): {e}")
```

**Problem:** This is too permissive. It silently ignores real errors:
- Table doesn't exist (expected during migration)
- OutboundWebhook model import failed (error)
- Tenant doesn't exist (error)
- Database connection timeout (error)

**Better approach:**
```python
except ImportError as e:
    # Expected during setup - table might not exist yet
    logger.debug(f"Skipping webhook - likely during setup: {e}")
except Exception as e:
    # Real error - should not be silently logged as warning
    logger.error(f"Failed to dispatch webhook {app_name}.{event_type}: {e}", exc_info=True)
    # Still don't crash the signal, but log properly
```

---

### 3.2 Tenant Webhook Handler (Lines 101-162)

**Status:** Good with minor issues

**Issues:**
- Tenant webhooks use `instance.id` as event_id (line 136), but should use UUID for consistency
- Missing tenant_deleted signal cleanup of webhook subscriptions

---

### 3.3 Event Extraction Functions - ISSUES

#### Issue #10: Serialize Instance Uses Type Checking (Lines 41-62)
```python
def serialize_instance(instance, fields: list = None) -> Dict[str, Any]:
    """Serialize a model instance to a dictionary."""
    data = {
        'id': str(instance.pk) if instance.pk else None,
    }

    # Add common fields
    for field in ['uuid', 'name', 'title', 'email', 'status', 'created_at', 'updated_at']:
        if hasattr(instance, field):
            val = getattr(instance, field)
            if val is not None:
                data[field] = str(val) if not isinstance(val, (str, int, float, bool, type(None))) else val
```

**Problem:**
- Naive type checking converts datetime to string manually
- Should use `default=str` in json.dumps instead
- Doesn't handle UUID objects properly
- Truncates useful type information

---

## Section 4: Models and Database

### 4.1 WebhookDelivery Model (models.py Lines 733-884)

**Strengths:**
- ✓ UUID primary key
- ✓ Comprehensive status tracking
- ✓ Event deduplication support
- ✓ Request metadata (IP, user_agent)
- ✓ Audit logging connected

**Critical Issues:**

#### Issue #11: No Unique Constraint on event_id (Line 761-765)
```python
event_id = models.CharField(
    max_length=255,
    blank=True,
    help_text=_('External event ID for deduplication')
)
```

**Problem:**
- No `unique_together` constraint on (endpoint, event_id)
- `is_duplicate()` method uses `.exists()` but doesn't prevent concurrent inserts
- Race condition: two requests pass check simultaneously, both insert

**Fix Required:**
Add database constraint:
```python
class Meta:
    verbose_name = _('Webhook Delivery')
    verbose_name_plural = _('Webhook Deliveries')
    ordering = ['-received_at']
    indexes = [
        models.Index(fields=['endpoint', '-received_at']),
        models.Index(fields=['endpoint', 'status']),
        models.Index(fields=['event_id']),
    ]
    # Add this constraint:
    constraints = [
        models.UniqueConstraint(
            fields=['endpoint', 'event_id'],
            condition=Q(event_id__isnull=False) & Q(event_id__exact=''),
            name='unique_webhook_event_id_per_endpoint'
        )
    ]
```

**Note:** The constraint above won't work for empty strings. Better approach:
```python
constraints = [
    models.UniqueConstraint(
        fields=['endpoint', 'event_id'],
        name='unique_webhook_delivery_per_endpoint',
        condition=~Q(event_id='')
    )
]
```

---

### 4.2 OutboundWebhook Model (outbound_webhooks.py Lines 39-204)

**Status:** Good

**Minor Issue:** No circuit breaker implementation. After 10 failures, webhook is suspended but can be manually re-enabled. Should implement circuit breaker pattern.

---

## Section 5: Webhook Signal Connections

### 5.1 Coverage Analysis

**Connected apps (✓):**
- tenants (3 signals)
- accounts (4 signals)
- ats (6 signals)
- hr_core (3 signals)
- services (6 signals)
- finance (3 signals)
- appointment (1 signal)
- messages_sys (2 signals)
- notifications (1 signal)
- blog (3 signals)
- newsletter (3 signals)

**Not connected (app exists but no webhooks):**
- dashboard (no webhooks needed?)
- documents (if exists)
- compliance (if exists)

**Well-structured:** All use proper `@receiver` decorators and error handling

---

## Section 6: Task Queue Integration

### 6.1 Webhook Retry Task (tasks.py Lines 176-209)

**Issue:** Imports `retry_webhook_delivery` from models which doesn't exist

```python
from .webhooks import process_webhook_delivery
```

**Problem:** This should be from `.models` for incoming webhooks, but the code is correct - it's in webhooks.py

---

### 6.2 Outbound Webhook Delivery Task (tasks.py Lines 410-439)

**Status:** Good

**Minor Issue:** No deduplication protection if Celery crashes during task processing

---

## Section 7: Critical Path Issues Summary

| # | Issue | Severity | Location | Impact |
|---|-------|----------|----------|--------|
| 1 | Silent signature bypass (no secret key) | CRITICAL | webhooks.py:59-60 | Unverified webhooks accepted |
| 2 | HelloSign no actual verification | CRITICAL | webhooks.py:412 | Spoofed events accepted |
| 3 | Timestamp validation has edge cases | MEDIUM | webhooks.py:393,613,369 | Potential replay attacks |
| 4 | Duplicate detection race condition | CRITICAL | webhooks.py:183-189 | Duplicate processing |
| 5 | Missing event_id detection | HIGH | webhooks.py:311-317 | No deduplication for many events |
| 6 | Signal setup fails silently | MEDIUM | webhook_signals.py:92-94 | Webhooks not dispatched silently |
| 7 | No unique constraint on event_id | CRITICAL | models.py:761-765 | Race condition at DB level |
| 8 | JSON serialization not robust | LOW | outbound_webhooks.py:503 | Could fail on complex objects |
| 9 | Provider-specific verification gaps | HIGH | webhooks.py:378-408 | Missing validation for some providers |
| 10 | Type checking in serialization | LOW | webhook_signals.py:41-62 | Poor data representation |
| 11 | No circuit breaker for webhooks | MEDIUM | outbound_webhooks.py:196-198 | Webhook thrashing |

---

## Recommendations

### Immediate Actions (Critical)

1. **Fix signature verification to reject when secret key missing**
   - File: `integrations/webhooks.py` line 59-60
   - Change return True to return False
   - Add error logging

2. **Implement HelloSign signature verification**
   - File: `integrations/webhooks.py` line 412
   - Add actual HMAC verification logic
   - Test with HelloSign sandbox

3. **Add unique constraint on webhook delivery**
   - File: `integrations/models.py` WebhookDelivery meta
   - Add UniqueConstraint on (endpoint, event_id) with condition
   - Create migration for existing data

4. **Implement atomic duplicate detection**
   - File: `integrations/webhooks.py` IncomingWebhookView.post()
   - Use database-level uniqueness or select_for_update()
   - Wrap in transaction

### Short-term Actions (High Priority)

5. **Add fallback event_id generation**
   - File: `integrations/webhooks.py` _extract_event_id()
   - Generate hash of payload if native event_id missing
   - Log warning for operators

6. **Improve timestamp validation**
   - File: `integrations/webhooks.py` _verify_signature()
   - Add proper error handling for malformed timestamps
   - Validate required fields exist before using them

7. **Audit logging for signature failures**
   - Add debug logging when signatures fail
   - Include provider, event_type, and error reason
   - Create admin dashboard view for failed webhooks

8. **Test coverage for webhook system**
   - Add pytest tests for signature verification
   - Add tests for duplicate detection
   - Add tests for provider-specific event extraction

### Medium-term Improvements

9. **Implement circuit breaker pattern**
   - Prevent webhook thrashing
   - Implement half-open state for recovery testing
   - Add metrics/monitoring

10. **Add webhook replay simulation**
    - Test system behavior with duplicate events
    - Verify idempotency of downstream operations
    - Document requirements for consuming systems

11. **Enhanced error handling in signal dispatch**
    - Distinguish between setup errors and runtime errors
    - Add monitoring/alerting for webhook dispatch failures
    - Create remediation procedures

12. **Add request signing validation test suite**
    - Unit tests for each provider's signature verification
    - Test with real provider test webhooks
    - Validate against provider documentation

---

## Testing Recommendations

### Unit Tests

```python
# Test signature verification
def test_signature_verification_requires_secret_key():
    """Signature should be rejected if secret key missing"""
    endpoint = WebhookEndpoint(secret_key='')
    validator = WebhookValidator(endpoint)
    assert validator.validate_signature(b'payload', {}) == False

# Test event deduplication
def test_duplicate_webhook_not_processed():
    """Identical webhook events should be processed only once"""
    # Send webhook 1
    response1 = client.post('/webhook/', payload, event_id='abc123')
    assert response1.status_code == 200

    # Send same webhook 2
    response2 = client.post('/webhook/', payload, event_id='abc123')
    assert response2.status_code == 200
    assert response2.json()['status'] == 'duplicate'

    # Verify only one side effect occurred
    assert MyModel.objects.count() == 1

# Test concurrent duplicate handling
def test_concurrent_duplicate_webhooks():
    """Concurrent identical webhooks should handle gracefully"""
    from concurrent.futures import ThreadPoolExecutor

    def send_webhook():
        return client.post('/webhook/', payload, event_id='abc123')

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(send_webhook, range(5)))

    # All should complete, but only one should succeed
    assert sum(1 for r in results if r.status_code == 200) == 5
    # But side effect should occur once
    assert MyModel.objects.count() == 1
```

### Integration Tests

1. Test with real Stripe webhook samples
2. Test with real Slack webhook samples
3. Test with background check provider webhooks
4. Test signature validation against provider specifications
5. Test race conditions with concurrent requests

### Load Testing

1. Send 1000 webhooks/second and verify all processed
2. Send duplicate events and verify deduplication works
3. Verify retry mechanism under high failure rate
4. Monitor database lock contention

---

## Security Checklist

- [ ] All webhook signatures validated before processing
- [ ] Timestamp validation prevents replay attacks
- [ ] Duplicate detection prevents double processing
- [ ] Race conditions prevented at database level
- [ ] Sensitive data (API keys, secrets) not logged
- [ ] SSRF protection on webhook URLs (outbound)
- [ ] Rate limiting on webhook processing
- [ ] Audit trail of all webhook processing
- [ ] Circuit breaker prevents cascade failures
- [ ] Provider credentials securely encrypted

---

## Migration Path

```bash
# 1. Create backup
pg_dump zumodra > backup_$(date +%Y%m%d_%H%M%S).sql

# 2. Create migration for unique constraint
python manage.py makemigrations integrations --name add_webhook_delivery_unique_constraint

# 3. Review migration for NULL handling
# Migration should include data cleanup:
# - Find duplicates and keep only DELIVERED status
# - Or mark non-DELIVERED as EXPIRED

# 4. Apply migration with data migration
python manage.py migrate

# 5. Deploy code fixes
git commit -m "fix: webhook security and idempotency issues"
git push

# 6. Run tests
pytest tests/integrations/test_webhooks.py -v

# 7. Monitor logs for errors
tail -f /var/log/zumodra/app.log
```

---

## References

- OWASP Webhook Security: https://owasp.org/www-community/Webhook
- RFC 9421 - HTTP Message Signatures: https://datatracker.ietf.org/doc/html/rfc9421
- Stripe Webhook Security: https://stripe.com/docs/webhooks/signatures
- GitHub Webhook Security: https://docs.github.com/en/developers/webhooks-and-events/webhooks/securing-your-webhooks

---

**Review Completed By:** Claude Code
**Review Date:** 2026-01-16
**Next Review:** After implementing critical fixes
