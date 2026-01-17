# Time-Off Workflow Testing - Quick Reference

## 🎯 Test Status Overview

```
Component              Status      Tests    Grade
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Submit Requests     ⚠️  Partial 3/5     60%
2. Manager Approval    ⚠️  Partial 5/7     70%
3. HR Override         ❌ Missing  0/6     0%
4. Calendar View       ✅ Working  6/6     95%
5. Balance Tracking    ⚠️  Broken  4/8     50%
6. Conflict Detect     ❌ Missing  0/6     0%
7. Notifications       ❌ Missing  0/5     0%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OVERALL SCORE: 18/33 PASSING = 54% ⚠️
```

## 🔴 Critical Issues (MUST FIX)

### Issue #1: Balance Deduction Bug
**File:** `/hr_core/models.py` (line 530)
**Severity:** 🔴 CRITICAL
```python
# BROKEN:
Employee.objects.filter(...).update(pto_balance=F(...) - total_days)
# Should update TimeOffBalance, not Employee!

# IMPACT: All approved time off ignored, balance tracking broken
```

### Issue #2: No Overlap Prevention
**File:** `/hr_core/models.py` (TimeOffRequest model)
**Severity:** 🔴 CRITICAL
```python
# PROBLEM: Employee can request overlapping dates
Jan 10-14: Approved
Jan 12-16: Approved (overlaps!)

# No validation prevents this
```

### Issue #3: Race Condition
**File:** `/hr_core/template_views.py` (line 550-560)
**Severity:** 🔴 CRITICAL
```
T1: Check balance (10 days available)
T2: Check balance (10 days available) <- Race condition
T1: Create request (6 days)
T2: Create request (6 days)
T1: Approve (-6 days) = 4 left
T2: Approve (-6 days) = -2 days NEGATIVE BALANCE!
```

## 🟠 High Priority Issues (FIX SOON)

| # | Issue | Location | Impact |
|---|-------|----------|--------|
| 4 | Min notice not checked | forms.py:340 | Can request same-day when 5 days needed |
| 5 | Business days wrong | template_views.py:574 | Over-counts by including weekends |
| 6 | Docs not required | forms.py:340 | Sick leave no medical note |
| 7 | Pending balance ignored | models.py | Can't see pending requests |
| 8 | Blackout dates unused | models.py | Can request during company holidays |

## ✅ What Works

- Calendar display of approved requests ✅
- Manager can approve/reject ✅
- Half-day requests (form) ✅
- Balance accrue/deduct methods ✅
- Year-end carryover calculation ✅
- Form validation (basic) ✅

## ❌ What's Broken

- Balance tracking (dual system) ❌
- Overlapping request detection ❌
- Race condition in approval ❌
- Notification system ❌
- HR override capability ❌
- Conflict detection ❌
- Blackout date enforcement ❌
- Pending balance tracking ❌

## 📊 Error Details

### Balance Issue Example
```
Created:      TimeOffBalance(vacation=20 days)

Request 1:    15 days
  Check:      TimeOffBalance.balance=20 ✅
  Approve:    Employee.pto_balance -= 15
  Result:     TimeOffBalance.balance=20 ❌ (NOT UPDATED!)

Request 2:    10 days
  Check:      TimeOffBalance.balance=20 ✅ (still old value!)
  Approve:    Employee.pto_balance -= 10
  Result:     APPROVED (should reject, only 5 days left)
  
FINAL STATE: 25 days approved, 20 available = BROKEN
```

### Business Days Issue
```
Request dates: Friday Jan 10 - Monday Jan 13

VIEW CALCULATION:
  delta = (13 - 10).days + 1 = 4 days

ACTUAL DATES:
  Fri 10 (business day)
  Sat 11 (weekend)
  Sun 12 (weekend)
  Mon 13 (business day)
  = 2 business days only

EMPLOYEE CHARGE: 4 days (wrong)
SHOULD BE: 2 days
ERROR: +2 days overcharged per request
```

## 🔧 Quick Fixes (Apply in Order)

### Fix #1 (2 hours): Balance Deduction
```python
# In TimeOffRequest.approve():
- Employee.objects.filter(...).update(pto_balance=...)
+ balance.deduct(self.total_days)
```

### Fix #2 (1 hour): Overlap Validation
```python
# In TimeOffRequest.clean():
overlapping = TimeOffRequest.objects.filter(
    employee=self.employee,
    status__in=['pending', 'approved'],
    start_date__lte=self.end_date,
    end_date__gte=self.start_date
)
if overlapping.exists():
    raise ValidationError("Overlapping request exists")
```

### Fix #3 (2 hours): Transaction Safety
```python
# In TimeOffRequestView.post():
with transaction.atomic():
    balance = TimeOffBalance.objects.select_for_update().get(...)
    if balance.balance < total_days:
        return error
    # Safe now - locked until end of transaction
```

### Fix #4 (1 hour): Business Days
```python
# Create utility:
def calculate_business_days(start, end, half_day=False):
    if half_day: return Decimal('0.5')
    days = Decimal('0')
    current = start
    while current <= end:
        if current.weekday() < 5:  # Mon-Fri
            days += 1
        current += timedelta(days=1)
    return days
```

### Fix #5 (30 min each): Validations
```python
# In TimeOffRequestForm.clean():

# Minimum notice
if start_date and time_off_type:
    notice = (start_date - today).days
    if notice < time_off_type.min_notice_days:
        raise ValidationError(f"Need {min} days notice")

# Documentation
if time_off_type.requires_documentation and not doc:
    raise ValidationError("Documentation required")
```

## 📋 Test Coverage Needed

```python
# Critical to test:
✅ test_approval_uses_time_off_balance (not employee.pto_balance)
✅ test_overlapping_requests_rejected
✅ test_race_condition_prevented (with 2 threads)
✅ test_business_days_calculated_correctly
✅ test_minimum_notice_enforced
✅ test_documentation_required
✅ test_pending_balance_updated
✅ test_blackout_dates_blocked
✅ test_notifications_sent
✅ test_hr_override_recorded

# Run with:
pytest test_timeoff_workflow.py -v --tb=short
```

## 📁 Related Files

| File | Status | Issue |
|------|--------|-------|
| `/hr_core/models.py` | 🔴 Has 3 critical bugs | Balance, overlap, blackout |
| `/hr_core/forms.py` | 🟠 Missing 3 validations | Notice, docs, business days |
| `/hr_core/template_views.py` | 🔴 Has 2 critical bugs | Race condition, day calc |
| `/hr_core/signals.py` | ❌ Empty handlers | Notifications |
| `/hr_core/tasks.py` | ❌ No tasks | Accrual, year-end |
| `/templates/hr/time_off_calendar.html` | ✅ Mostly OK | Minor display issues |

## 🚀 Implementation Roadmap

```
WEEK 1 (Critical):
  Day 1: Fix balance deduction
  Day 2: Add overlap validation
  Day 3: Fix race condition
  Day 4: Tests + validation

WEEK 2 (High Priority):
  Day 1: Business days utility
  Day 2: Notice + docs validation
  Day 3: Pending balance signals
  Day 4: Blackout date checking

WEEK 3 (Features):
  Day 1: HR override system
  Day 2: Notifications (email)
  Day 3: Conflict detection UI
  Day 4: Accrual tasks

WEEK 4 (Testing):
  Comprehensive testing
  Load testing (1000+ requests)
  Integration testing
  Production readiness
```

## 📞 Questions?

Refer to detailed documents:
- `TIME_OFF_WORKFLOW_TEST_REPORT.md` - Full analysis
- `TIME_OFF_ISSUES_AND_FIXES.md` - Code fixes with examples
- `test_timeoff_workflow.py` - Runnable test suite

---
Generated: 2026-01-16
