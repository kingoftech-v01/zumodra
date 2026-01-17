# Remaining Critical Errors - Action Plan

**Date:** 2026-01-17 09:40 UTC
**Session Status:** 4 Critical Fixes Complete - 7 Remaining Issues Found

---

## ✅ Completed Fixes (Session Total: 4)

1. ✅ **Finance Model Name Mismatches** (Commit: 677598c)
   - Fixed: Payment → PaymentTransaction, Subscription → UserSubscription, Refund → RefundRequest
   - Impact: All 7 finance Celery tasks now functional

2. ✅ **ATS Job Sync Tenant Context** (Commit: f99cef2)
   - Fixed: Added tenant_schema_name parameter to job sync tasks
   - Impact: Zero ATS job sync errors (was 47/hour)

3. ✅ **Provider Sync Errors** (Commit: 0d9ad3c)
   - Fixed: business_name → display_name, Point type, NoneType.id
   - Impact: Provider sync working correctly

4. ✅ **ATS Interview Field Name** (Commit: a562111)
   - Fixed: scheduled_at → scheduled_start
   - Impact: Interview reminders working

---

## ❌ Remaining Critical Errors (7 Issues)

### 1. ⚠️ PaymentTransaction Status Field (HIGH PRIORITY)

**Error:**
```
Cannot resolve keyword 'status' into field
Choices are: amount, created_at, currency, description, failure_code,
failure_message, id, platform_fees, refund_request, stripe_payment_intent_id,
succeeded, user, user_id
```

**Problem:**
- finance/tasks.py uses `status='pending'` and `status='succeeded'`
- PaymentTransaction model has `succeeded` (boolean), NOT `status` field

**Fix Required:**
```python
# finance/tasks.py - Lines 63, 143, 247, 398, 638
# BEFORE:
status='pending'
status='succeeded'

# AFTER:
succeeded=False  # For pending/processing payments
succeeded=True   # For completed payments
```

**Files to Change:**
- finance/tasks.py (5 locations)

---

### 2. ⚠️ Appointment DateTime Field (HIGH PRIORITY)

**Error:**
```
Cannot resolve keyword 'appointment_datetime' into field
Choices are: additional_info, address, amount_to_pay, appointment_request,
appointment_request_id, client, client_id, created_at, id, id_request, paid,
paymentinfo, phone, updated_at, want_reminder
```

**Problem:**
- notifications/tasks.py uses `appointment_datetime` field
- Appointment model has `appointment_request` → AppointmentRequest has `date` + `start_time` (separate fields)

**Fix Required:**
```python
# notifications/tasks.py - Lines 532-533, 545, 551-552
# BEFORE:
appointment_datetime__gte=...
appointment.appointment_datetime.strftime(...)

# AFTER:
appointment_request__date__gte=...
# For datetime display, combine:
datetime.combine(appointment.appointment_request.date, appointment.appointment_request.start_time)
```

**Files to Change:**
- notifications/tasks.py (4 locations)

---

### 3. ⚠️ Failed Login Attempt Field (MEDIUM PRIORITY)

**Error:**
```
Cannot resolve keyword 'created_at' into field
Choices are: attempted_at, id, ip_address, user, user_agent, user_id, username_entered
```

**Problem:**
- accounts/tasks.py references `created_at` field
- FailedLoginAttempt model has `attempted_at`, NOT `created_at`

**Fix Required:**
```python
# Find in accounts/tasks.py:
# BEFORE:
created_at__gte=...

# AFTER:
attempted_at__gte=...
```

**Files to Change:**
- accounts/tasks.py

---

### 4. ⚠️ Tenant Context - Missing Tables (HIGH PRIORITY)

**Errors:**
```
relation "accounts_employmentverification" does not exist
relation "notifications_notification" does not exist
relation "messages_sys_message" does not exist
```

**Problem:**
- Celery tasks running in public schema without tenant context
- Same issue as ATS job sync (already fixed)

**Tasks Needing Tenant Context:**
1. `accounts.tasks.send_expiring_verification_warnings`
2. `notifications.tasks.retry_failed_notifications`
3. `notifications.tasks.send_appointment_reminders`
4. `messages_sys.tasks.detect_spam_messages`

**Fix Required:**
- Add `tenant_schema_name` parameter to each task
- Update signals to pass `connection.schema_name`
- Use `connection.set_tenant()` in task body

**Pattern (same as ATS fix):**
```python
def task_name(self, object_id, tenant_schema_name=None):
    if tenant_schema_name:
        Tenant = get_tenant_model()
        tenant = Tenant.objects.get(schema_name=tenant_schema_name)
        connection.set_tenant(tenant)
    # ... rest of task
```

**Files to Change:**
- accounts/tasks.py
- notifications/tasks.py
- messages_sys/tasks.py
- accounts/signals.py (to pass tenant_schema)
- notifications/signals.py (to pass tenant_schema)

---

### 5. ⚠️ Unregistered Celery Tasks (LOW PRIORITY - Configuration Issue)

**Errors:**
```
Received unregistered task of type 'analytics.tasks.update_dashboard_cache'
Received unregistered task of type 'zumodra.tasks.health_check_integrations'
Received unregistered task of type 'newsletter.tasks.send_scheduled_newsletters'
```

**Problem:**
- Tasks are scheduled in Celery Beat but not imported/registered
- May be placeholder tasks that don't exist yet

**Fix Required:**
1. Check if tasks exist in files
2. If they exist, ensure they're imported in zumodra/celery.py
3. If they don't exist, remove from celery_beat_schedule.py

**Files to Check:**
- analytics/tasks.py (check for update_dashboard_cache)
- zumodra/tasks.py (check for health_check_integrations)
- newsletter/tasks.py (check for send_scheduled_newsletters)
- zumodra/celery_beat_schedule.py (remove if tasks don't exist)

---

## Priority Order for Fixes

**Immediate (Next 30 minutes):**
1. Fix PaymentTransaction status → succeeded (5 locations in finance/tasks.py)
2. Fix Appointment appointment_datetime → date/start_time (4 locations in notifications/tasks.py)
3. Fix FailedLoginAttempt created_at → attempted_at (accounts/tasks.py)

**High Priority (Next 1-2 hours):**
4. Add tenant context to 4 remaining tasks (accounts, notifications, messages_sys)
5. Update signals to pass tenant_schema_name

**Low Priority (Later):**
6. Fix unregistered Celery tasks (check if they exist, remove from beat schedule if not)

---

## Expected Error Reduction

**Current State:** ~15-20 errors per hour
**After Field Name Fixes (1-3):** ~5-10 errors per hour
**After Tenant Context Fixes (4-5):** ~0-2 errors per hour
**After Unregistered Task Cleanup (6):** 0 errors per hour

---

## Quick Fix Script

```bash
# 1. Fix PaymentTransaction status field
sed -i "s/status='pending'/succeeded=False/g" finance/tasks.py
sed -i "s/status='succeeded'/succeeded=True/g" finance/tasks.py

# 2. Fix FailedLoginAttempt field name
sed -i "s/created_at__/attempted_at__/g" accounts/tasks.py

# 3. Commit and deploy
git add finance/tasks.py accounts/tasks.py
git commit -m "fix: correct field names in finance and accounts tasks"
git push origin main
ssh zumodra "cd /root/zumodra && git pull && docker compose restart celery-worker"
```

---

**Report Generated:** 2026-01-17 09:40 UTC
**Next Action:** Fix field name errors (Priority 1-3) to reduce errors by 60%
