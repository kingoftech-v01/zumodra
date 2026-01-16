# Webhook Security Fixes - Summary

**Date:** 2026-01-16
**Status:** Implementation Complete
**Files Modified:** 4
**Files Created:** 3

---

## Changes Made

### 1. Critical Security Fix: Signature Verification (`webhooks.py`)

**Location:** `integrations/webhooks.py:59-61`

**Before:**
```python
if not self.secret_key:
    return True  # No secret configured, skip validation
```

**After:**
```python
if not self.secret_key:
    logger.error(f"No secret key configured for webhook endpoint {self.endpoint.id} - rejecting webhook")
    return False  # Reject webhooks without signature verification capability
```

**Impact:**
- ✅ Webhooks are now rejected when secret key is missing
- ✅ Clear error logging for operators
- ✅ Prevents unverified webhook processing

---

### 2. Critical Fix: HelloSign Signature Verification (`webhooks.py`)

**Location:** `integrations/webhooks.py:410-432`

**Before:**
```python
elif provider == 'hellosign':
    # HelloSign uses event_hash in payload for verification
    # The secret is used to compute the hash
    return True  # Simplified - implement full verification
```

**After:**
```python
elif provider == 'hellosign':
    # HelloSign uses event_hash in payload for verification
    event_hash = payload.get('event', {}).get('event_hash', '')
    if not event_hash:
        logger.warning("HelloSign webhook missing event_hash in payload")
        return False

    # HelloSign signs the event object as JSON string
    event_data = payload.get('event', {})
    import json
    signed_payload = json.dumps(event_data, separators=(',', ':'), sort_keys=False)

    expected = hmac.new(
        secret.encode(),
        signed_payload.encode(),
        hashlib.sha256
    ).hexdigest()

    result = hmac.compare_digest(expected, event_hash)
    if not result:
        logger.warning(f"HelloSign signature verification failed...")
    return result
```

**Impact:**
- ✅ HelloSign webhooks now actually validated
- ✅ Prevents spoofed signature events
- ✅ Proper error logging

---

### 3. Enhanced: Event ID Extraction with Fallback Hash (`webhooks.py`)

**Location:** `integrations/webhooks.py:295-330`

**Before:**
```python
def _extract_event_id(self, provider: str, request, payload: Dict) -> str:
    """Extract event ID for deduplication."""
    # ... provider-specific extraction ...
    return (
        payload.get('event_id') or
        payload.get('id') or
        payload.get('uuid') or
        ''  # Returns empty string if all fail
    )
```

**After:**
```python
def _extract_event_id(self, provider: str, request, payload: Dict) -> str:
    """Extract event ID for deduplication, with fallback to payload hash."""
    event_id = ''
    # ... provider-specific extraction ...

    # If no event_id found, generate deterministic hash of payload for deduplication
    if not event_id:
        payload_str = json.dumps(payload, sort_keys=True, default=str)
        payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()[:16]
        event_id = f"hash_{payload_hash}"
        logger.warning(f"No native event_id for {provider}, using payload hash: {event_id}")

    return event_id
```

**Impact:**
- ✅ No more empty event_id values
- ✅ Deterministic hash-based deduplication fallback
- ✅ All webhooks now have deduplication capability
- ✅ Operators warned when native event_id missing

---

### 4. Enhanced: Stripe Signature Validation (`webhooks.py`)

**Location:** `integrations/webhooks.py:391-428`

**Improvements:**
- ✅ Validates required parts (t and v1) exist
- ✅ Proper timestamp parsing with error handling
- ✅ Explicit integer validation before comparison
- ✅ Better error logging
- ✅ Graceful exception handling

**Key Changes:**
```python
# Validate required parts exist
if 'v1' not in parts or 't' not in parts:
    logger.warning("Stripe signature missing required parts (t and/or v1)")
    return False

# Validate timestamp
try:
    request_timestamp = int(timestamp)
except (ValueError, TypeError):
    logger.warning(f"Invalid Stripe timestamp: {timestamp}")
    return False

# Check tolerance
current_time = int(time.time())
time_diff = abs(current_time - request_timestamp)
if time_diff > 300:
    logger.warning(f"Stripe webhook timestamp out of range: {time_diff} seconds old")
    return False
```

---

### 5. Improved: Webhook Signal Error Handling (`webhook_signals.py`)

**Location:** `integrations/webhook_signals.py:83-97`

**Before:**
```python
except Exception as e:
    # During initial setup, tables might not exist yet - this is expected
    # Log as warning instead of error to avoid false alarms
    logger.warning(f"Failed to dispatch webhook {app_name}.{event_type} (expected during setup): {e}")
```

**After:**
```python
except ImportError as e:
    # Expected during initial setup - tables might not exist yet
    logger.debug(f"Skipping webhook dispatch during setup (ImportError): {e}")
except Exception as e:
    # Real errors should be logged as errors, not warnings
    logger.error(f"Failed to dispatch webhook {app_name}.{event_type}: {e}", exc_info=True)
    # Note: We still don't crash the signal to avoid blocking model saves
```

**Impact:**
- ✅ Distinguishes between setup errors and runtime errors
- ✅ Real errors properly logged as errors, not warnings
- ✅ Better visibility into webhook system health

---

### 6. Database Constraint: Unique Event ID (`models.py`)

**Location:** `integrations/models.py:761-831`

**Changes:**
1. Added `db_index=True` to `event_id` field
2. Added UniqueConstraint to Meta class

```python
event_id = models.CharField(
    max_length=255,
    blank=True,
    db_index=True,  # Added
    help_text=_('External event ID for deduplication')
)

class Meta:
    # ... existing meta options ...
    constraints = [
        models.UniqueConstraint(
            fields=['endpoint', 'event_id'],
            condition=~models.Q(event_id=''),
            name='unique_webhook_delivery_per_endpoint'
        ),
    ]
```

**Impact:**
- ✅ Database-level enforcement of deduplication
- ✅ Prevents race condition concurrent duplicates
- ✅ Better query performance with index
- ✅ Empty event_id allowed for fallback hashes

---

### 7. Migration: Database Constraint

**Location:** `integrations/migrations/0002_webhook_delivery_unique_constraint.py`

**Contents:**
```python
class Migration(migrations.Migration):
    dependencies = [
        ('integrations', '0001_initial'),
    ]

    operations = [
        migrations.AddConstraint(
            model_name='webhookdelivery',
            constraint=models.UniqueConstraint(
                condition=~Q(('event_id', '')),
                fields=('endpoint', 'event_id'),
                name='unique_webhook_delivery_per_endpoint'
            ),
        ),
        migrations.AlterField(
            model_name='webhookdelivery',
            name='event_id',
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text='External event ID for deduplication',
                max_length=255
            ),
        ),
    ]
```

**Impact:**
- ✅ Safe migration path for constraint addition
- ✅ Maintains backward compatibility
- ✅ Handles existing data appropriately

---

### 8. Test Suite: Webhook Security

**Location:** `tests/integrations/test_webhook_security.py`

**Test Coverage:**
- ✅ 10+ security and idempotency tests
- ✅ Signature verification tests
- ✅ Event ID extraction tests
- ✅ Duplicate event detection tests
- ✅ Provider-specific verification tests
- ✅ Signal error handling tests

**Usage:**
```bash
# Run all webhook security tests
pytest tests/integrations/test_webhook_security.py -v

# Run specific test class
pytest tests/integrations/test_webhook_security.py::TestWebhookSignatureVerification -v

# Run with markers
pytest tests/integrations/test_webhook_security.py -m security -v
```

---

## Security Improvements Summary

| Issue | Before | After | Status |
|-------|--------|-------|--------|
| Missing secret key handling | Accept (CRITICAL BUG) | Reject | ✅ FIXED |
| HelloSign verification | No validation (TODO) | Actual HMAC check | ✅ FIXED |
| Event ID extraction | Empty string fallback | Deterministic hash | ✅ FIXED |
| Race condition duplicates | Possible | Prevented by DB constraint | ✅ FIXED |
| Stripe timestamp validation | Basic check | Robust with error handling | ✅ ENHANCED |
| Signal error handling | Permissive logging | Proper error levels | ✅ IMPROVED |
| Event deduplication | Query-based only | Query + DB constraint | ✅ ENHANCED |

---

## Deployment Instructions

### Step 1: Code Deployment
```bash
# Backup current code
git stash

# Pull updated code
git fetch origin
git checkout origin/main

# Or apply patches if on branch
git apply webhook_fixes.patch
```

### Step 2: Database Migration
```bash
# Test migration locally first
python manage.py migrate --plan

# Apply migration
python manage.py migrate integrations

# Verify migration success
python manage.py showmigrations integrations
```

### Step 3: Test Deployment
```bash
# Run webhook security tests
pytest tests/integrations/test_webhook_security.py -v

# Run full integration test suite
pytest tests/integrations/ -v

# Monitor logs
tail -f /var/log/zumodra/app.log
```

### Step 4: Verify in Production
```bash
# Check webhook endpoint functionality
curl -X POST http://localhost:8002/api/integrations/webhooks/stripe/test/ \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: test" \
  -d '{"type":"charge.completed"}'

# Should return 401 (invalid signature) or 404 (endpoint not found), not 200
```

---

## Monitoring and Validation

### Logs to Watch
```bash
# Monitor webhook signature failures
tail -f /var/log/zumodra/app.log | grep "signature\|Signature"

# Monitor duplicate detection
tail -f /var/log/zumodra/app.log | grep "duplicate\|Duplicate"

# Monitor event ID generation
tail -f /var/log/zumodra/app.log | grep "payload hash\|using payload"
```

### Database Validation
```sql
-- Check constraint exists
SELECT constraint_name
FROM information_schema.table_constraints
WHERE table_name='integrations_webhookdelivery'
AND constraint_type='UNIQUE';

-- Find any constraint violations (should be empty)
SELECT endpoint_id, event_id, COUNT(*) as count
FROM integrations_webhookdelivery
WHERE event_id != ''
GROUP BY endpoint_id, event_id
HAVING count > 1;
```

### Query Performance
```sql
-- Check index on event_id
EXPLAIN ANALYZE
SELECT * FROM integrations_webhookdelivery
WHERE event_id = 'evt_12345' AND endpoint_id = 1;
-- Should show index usage
```

---

## Rollback Plan

If issues occur:

```bash
# Rollback migration
python manage.py migrate integrations 0001_initial

# Revert code changes
git revert <commit_hash>

# Restart services
systemctl restart zumodra-web zumodra-celery
```

---

## Security Checklist

After deployment, verify:

- [ ] All webhook signatures validated before processing
- [ ] Missing secret keys cause rejection, not bypass
- [ ] HelloSign webhooks are cryptographically verified
- [ ] No webhook processed twice (race condition prevented)
- [ ] Error logs show proper levels (debug/error, not warning)
- [ ] Database constraint prevents duplicate entries
- [ ] Event ID extraction uses fallback hash
- [ ] Stripe timestamp validation is robust
- [ ] All tests pass
- [ ] No production errors in logs

---

## References

- **Review Document:** `/docs/WEBHOOK_REVIEW_DAY2.md`
- **Test Suite:** `/tests/integrations/test_webhook_security.py`
- **Files Modified:**
  - `integrations/webhooks.py`
  - `integrations/webhook_signals.py`
  - `integrations/models.py`
  - `integrations/migrations/0002_webhook_delivery_unique_constraint.py`

---

**Implementation Complete:** 2026-01-16
**Ready for Review:** Yes
**Ready for Production:** After testing and review
