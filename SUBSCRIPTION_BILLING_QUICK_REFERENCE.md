# Subscription & Billing Workflow - Quick Reference Guide

**Last Updated**: 2026-01-16

---

## Test Results At A Glance

```
TEST 1: Plan Selection & Upgrade/Downgrade        ⚠ PARTIAL (Code commented out)
TEST 2: Stripe Payment Integration                ⚠ NEEDS FIXES (3 issues)
TEST 3: Invoice Generation                        ✓ WORKING WELL
TEST 4: Payment History Tracking                  ✓ FULLY WORKING
TEST 5: Subscription Renewal                      ✗ NOT IMPLEMENTED
TEST 6: Cancellation Workflow                     ✓ FULLY WORKING
TEST 7: Webhook Processing                        ✗ CRITICAL ISSUES (3 problems)

STATUS: 3 Working, 2 Partial, 2 Critical Failures
```

---

## Critical Issues (MUST FIX)

### Issue 1: Webhooks Not Processed
- **File**: `integrations/webhooks.py`
- **Problem**: Events logged but never acted upon
- **Impact**: Stripe changes don't sync to database
- **Fix**: Implement event handlers (SUBSCRIPTION_BILLING_FIXES.md - FIX 2)

### Issue 2: Weak Webhook Signature
- **File**: `integrations/webhooks.py`
- **Problem**: Missing timestamp validation, wrong header parsing
- **Impact**: Security vulnerability, unauthorized webhooks possible
- **Fix**: Use Stripe-specific signature validation (SUBSCRIPTION_BILLING_FIXES.md - FIX 1)

### Issue 3: No Renewal Automation
- **File**: `finance/models.py`, `finance/views.py`
- **Problem**: Subscriptions don't auto-renew
- **Impact**: Lost revenue, business-breaking bug
- **Fix**: Implement renewal scheduler (SUBSCRIPTION_BILLING_FIXES.md - FIX 3, 4, 5)

### Issue 4: Upgrade/Downgrade Disabled
- **File**: `finance/api/viewsets.py`
- **Problem**: Core code is commented out
- **Impact**: Users cannot change plans
- **Fix**: Uncomment and implement pro-rata logic (SUBSCRIPTION_BILLING_FIXES.md - FIX 6)

### Issue 5: No Payment Retry
- **File**: `finance/tasks.py`
- **Problem**: Failed payments not retried
- **Impact**: Legitimate payments fail, users unaware
- **Fix**: Implement retry scheduler with backoff

---

## Files to Review

### Critical Priority
- `integrations/webhooks.py` - Weak signature validation, no event processing
- `finance/api/viewsets.py` - Commented code for upgrades
- `finance/tasks.py` - No renewal or retry tasks
- `finance/models.py` - Missing SubscriptionRenewal model

### High Priority
- `finance/views.py` - Missing idempotency, weak error handling
- `integrations/models.py` - WebhookEndpoint structure

### Medium Priority
- `finance/serializers.py` - Payment serialization
- `finance/admin.py` - Admin interface

---

## Key Models

### Working Models ✓
```python
- SubscriptionPlan (price, interval, Stripe IDs)
- PaymentTransaction (amount, status, Stripe ID)
- Invoice (amount_due, paid_at, status)
- UserSubscription (period tracking, status)
- StripeWebhookEvent (event logging)
```

### Missing Models ❌
```python
- SubscriptionRenewal (renewal tracking, retry logic)
- PaymentMethod (saved cards for future use)
- InvoiceLineItem (detailed charges)
```

---

## Celery Tasks Status

### Implemented ✓
- None currently active

### Needed ❌
- `process_subscription_renewals` - Run hourly
- `retry_failed_renewals` - Run every 6 hours
- `sync_stripe_subscriptions` - Run daily
- `send_renewal_reminders` - Run daily
- `send_invoice_email` - On-demand
- `send_payment_failed_notification` - On-demand

---

## Test Coverage

### Tests Created
1. `test_subscription_billing_workflow.py` - Full integration tests
2. `test_billing_workflow_direct.py` - Direct ORM tests

### Test Scenarios
- Plan listing and details
- Plan upgrade/downgrade
- Payment transaction creation
- Invoice generation and payment
- Payment history filtering
- Subscription renewal simulation
- Cancellation workflow
- Webhook event logging

---

## API Endpoints Status

### Working ✓
- `POST /api/v1/finance/subscription/` - Create subscription
- `GET /api/v1/finance/payments/` - List payments
- `POST /api/v1/finance/subscription/cancel/` - Cancel subscription
- `POST /api/v1/finance/subscription/reactivate/` - Reactivate

### Broken ❌
- `POST /api/v1/finance/subscription/upgrade/` - Code commented
- `POST /api/v1/finance/subscription/downgrade/` - Code commented

### Missing ❌
- Webhook endpoint for event processing
- Payment method CRUD endpoints
- Renewal status endpoints

---

## Stripe Integration Checklist

- [ ] Secret key configured in `.env`
- [ ] Public key configured in `.env`
- [ ] Webhook secret configured in `.env`
- [ ] Plans created in Stripe dashboard
- [ ] Plan IDs stored in database
- [ ] Webhook endpoint created in Stripe
- [ ] Test payment method saved
- [ ] Signature validation working
- [ ] Event handlers implemented
- [ ] Renewal scheduler running

---

## Quick Fix Priority

### Day 1 (4-6 hours)
1. Fix webhook signature validation
2. Implement basic event handlers
3. Mark webhooks as processed

### Day 2 (4-6 hours)
4. Implement renewal scheduler
5. Create renewal tasks
6. Test renewal flow

### Day 3 (2-4 hours)
7. Uncomment upgrade/downgrade code
8. Add pro-rata calculations
9. Test plan changes

### Day 4 (2-3 hours)
10. Add payment retry logic
11. Implement daily Stripe sync
12. Test error scenarios

---

## Testing Commands

### Run subscription tests
```bash
docker compose exec web pytest finance/tests/ -v
```

### Test webhook signature
```bash
# Manual test with curl
curl -X POST http://localhost:8002/api/webhooks/stripe/ \
  -H "Stripe-Signature: t=123456,v1=abcdef" \
  -d '{"id":"evt_123","type":"charge.succeeded"}'
```

### Check Celery tasks
```bash
docker compose exec web celery -A zumodra inspect active
```

### View webhook logs
```bash
docker compose logs integrations | grep webhook
```

---

## Security Reminders

- ✓ Validate payment amounts server-side
- ✓ Use constant-time signature comparison
- ✓ Validate webhook timestamp (within 5 minutes)
- ✓ Rate limit payment endpoints
- ✓ Log all financial transactions
- ✓ Sanitize error messages (don't expose Stripe details)
- ✓ Use HMAC-SHA256 for webhook signatures
- ✓ Atomic webhook deduplication

---

## Monitoring & Alerts

### Metrics to Track
- Successful payments per day
- Failed payment rate
- Subscription renewal rate
- Webhook delivery rate
- Average webhook latency
- Stripe sync discrepancies

### Alerts to Configure
- Failed renewals > 5% of total
- Webhook processing latency > 10s
- Stripe sync out of sync > 1 hour
- Payment failure rate > 3%

---

## Documentation References

### Full Documentation
1. `SUBSCRIPTION_BILLING_WORKFLOW_TEST_REPORT.md` - Detailed findings
2. `SUBSCRIPTION_BILLING_FIXES.md` - Code implementations
3. `TESTING_SUMMARY_SUBSCRIPTION_BILLING.md` - Complete summary

### Related Files
- `finance/models.py` - Data models
- `finance/views.py` - View implementations
- `finance/api/viewsets.py` - API endpoints
- `integrations/webhooks.py` - Webhook handling
- `integrations/webhook_signals.py` - Signal handlers

---

## Common Issues & Solutions

### Issue: Payment shows in Stripe but not in database
**Cause**: Webhook not processed
**Solution**: Implement event handlers

### Issue: Subscription doesn't renew
**Cause**: No renewal scheduler
**Solution**: Implement Celery tasks

### Issue: Users can't change plans
**Cause**: Upgrade/downgrade code commented out
**Solution**: Uncomment and test

### Issue: Duplicate payment attempts
**Cause**: Missing idempotency key
**Solution**: Add idempotency_key to checkout session

### Issue: Webhook processing fails silently
**Cause**: Events logged but not processed
**Solution**: Implement event handler functions

---

## Rollout Plan

### Phase 1: Security Fixes (1-2 days)
- [ ] Fix webhook signature validation
- [ ] Implement atomic deduplication
- [ ] Add timestamp validation

### Phase 2: Core Functionality (3-4 days)
- [ ] Implement event handlers
- [ ] Add renewal scheduler
- [ ] Implement payment retry

### Phase 3: Feature Completion (2-3 days)
- [ ] Complete upgrade/downgrade
- [ ] Add payment method management
- [ ] Implement daily sync

### Phase 4: Testing & QA (3-4 days)
- [ ] End-to-end testing
- [ ] Load testing
- [ ] Security audit

### Estimated Total: 1-2 weeks to production-ready

---

## Key Contacts

### If Issues Found:
1. Check: SUBSCRIPTION_BILLING_WORKFLOW_TEST_REPORT.md
2. Review: SUBSCRIPTION_BILLING_FIXES.md
3. Implement: Code from SUBSCRIPTION_BILLING_FIXES.md
4. Test: Using provided test scripts
5. Document: Any additional issues

---

## Success Criteria

✓ All 7 test areas working
✓ No critical security issues
✓ Webhooks processing reliably
✓ Renewals automating correctly
✓ Upgrades/downgrades working
✓ All error cases handled
✓ 95%+ successful payment rate
✓ <1% duplicate transaction rate

---

**Last Tested**: 2026-01-16
**Status**: Ready for fixes
**Next Review**: After implementation
