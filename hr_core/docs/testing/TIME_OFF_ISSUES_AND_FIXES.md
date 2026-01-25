# Time-Off Workflow - Issues and Recommended Fixes

**Report Date:** 2026-01-16
**Priority:** Critical - 3 blocking issues, 5 high-priority data issues

---

## CRITICAL ISSUE #1: Balance Deduction Uses Wrong Field

**Location:** `/hr_core/models.py` lines 520-540 (TimeOffRequest.approve method)

### Problem

The approval method deducts balance from `Employee.pto_balance` but the request system checks against `TimeOffBalance.balance`. This creates a fatal inconsistency:

```python
# View checks this:
balance = TimeOffBalance.objects.get(
    employee=employee,
    time_off_type=time_off_type,
    year=timezone.now().year
)
if balance.balance < total_days:
    return HttpResponse('Insufficient balance', status=400)

# But approval updates this:
Employee.objects.filter(id=employee.id).update(
    pto_balance=F('pto_balance') - self.total_days
)

# Result: TimeOffBalance is never updated!
```

### Impact

- Vacation, Sick Leave, Personal Leave balances are never decremented
- Reports show incorrect available time off
- Employees can request far more time than available
- Second request approved with balance from first

### Example Scenario

```
Employee: John Doe
Vacation Balance: 20 days

Request 1: 15 days (Jan 10-24)
  - Check: TimeOffBalance.balance = 20 >= 15 ✅
  - Deduct: Employee.pto_balance -= 15
  - Result: TimeOffBalance.balance = 20 (unchanged!)

Request 2: 10 days (Feb 5-14)
  - Check: TimeOffBalance.balance = 20 >= 10 ✅ (still has old value)
  - Deduct: Employee.pto_balance -= 10
  - Result: TimeOffBalance.balance = 20 (unchanged!)

Employee has now been approved for 25 days but balance says 20
```

### Recommended Fix

```python
# File: /hr_core/models.py

def approve(self, approver):
    """Approve the request with atomic transaction and balance validation."""
    from django.db import transaction
    from django.db.models import F

    with transaction.atomic():
        employee = Employee.objects.select_for_update().get(id=self.employee_id)

        if self.time_off_type.is_accrued:
            # Check if sufficient balance exists
            try:
                balance = TimeOffBalance.objects.select_for_update().get(
                    employee=employee,
                    time_off_type=self.time_off_type,
                    year=timezone.now().year
                )
                if balance.balance < self.total_days:
                    raise ValidationError(
                        f'Insufficient {self.time_off_type.name} balance. '
                        f'Available: {balance.balance}, Requested: {self.total_days}'
                    )

                # Deduct from TimeOffBalance (not Employee.pto_balance)
                balance.deduct(self.total_days)

            except TimeOffBalance.DoesNotExist:
                raise ValidationError(
                    f'No balance record found for {self.time_off_type.name}'
                )

        # Update request status
        self.status = self.RequestStatus.APPROVED
        self.approver = approver
        self.approved_at = timezone.now()
        self.save()
```

### Verification

```python
# Test the fix:
@pytest.mark.django_db
def test_approval_updates_correct_balance():
    request1 = TimeOffRequest.objects.create(
        employee=employee,
        time_off_type=vacation,
        start_date=date(2026, 1, 10),
        end_date=date(2026, 1, 24),
        total_days=Decimal('15'),
        status='pending'
    )

    request1.approve(approver)

    # Check TimeOffBalance is updated
    balance = TimeOffBalance.objects.get(
        employee=employee,
        time_off_type=vacation,
        year=2026
    )
    assert balance.balance == Decimal('5')  # 20 - 15
    assert balance.used_this_year == Decimal('15')
```

---

## CRITICAL ISSUE #2: Overlapping Requests Not Prevented

**Location:** `/hr_core/models.py` (TimeOffRequest model) and `/hr_core/template_views.py` (TimeOffRequestView.post)

### Problem

No validation prevents an employee from submitting overlapping time-off requests:

```python
# Employee can do this:
Request 1: Jan 10-14 (5 days)
Request 2: Jan 12-16 (5 days)  # Overlaps with Request 1
Request 3: Jan 13-17 (5 days)  # Overlaps with both

# All three requests can be created and approved
```

### Impact

- Manager sees conflicting requests, must manually identify and handle
- Potential for double-booking of time off
- Calendar shows overlapping events, visually confusing
- Can approve total > employee's actual days available

### Recommended Fix - Add Model Validation

```python
# File: /hr_core/models.py

from django.core.exceptions import ValidationError

class TimeOffRequest(TenantAwareModel):
    # ... existing fields ...

    def clean(self):
        """Validate no overlapping requests and blackout dates."""
        super().clean()

        if not self.start_date or not self.end_date:
            return

        # Check for overlapping requests
        overlapping = TimeOffRequest.objects.filter(
            employee=self.employee,
            status__in=[
                self.RequestStatus.PENDING,
                self.RequestStatus.APPROVED,
            ],
            start_date__lte=self.end_date,
            end_date__gte=self.start_date
        ).exclude(pk=self.pk)

        if overlapping.exists():
            conflicts = overlapping.values_list('start_date', 'end_date')
            raise ValidationError({
                'start_date': ValidationError(
                    f'These dates overlap with existing requests: {conflicts}',
                    code='overlapping_dates'
                )
            })

        # Check minimum notice period
        days_notice = (self.start_date - timezone.now().date()).days
        if days_notice < self.time_off_type.min_notice_days:
            raise ValidationError({
                'start_date': ValidationError(
                    f'Minimum {self.time_off_type.min_notice_days} days notice required. '
                    f'Only {days_notice} days provided.',
                    code='insufficient_notice'
                )
            })

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)
```

### Update Form to Call Full Clean

```python
# File: /hr_core/forms.py

class TimeOffRequestForm(forms.ModelForm):

    def save(self, commit=True):
        instance = super().save(commit=False)
        # This ensures model clean() is called
        instance.full_clean()
        if commit:
            instance.save()
        return instance
```

### Update View to Handle Validation Errors

```python
# File: /hr_core/template_views.py

def post(self, request):
    tenant = self.get_tenant()
    if not tenant:
        return HttpResponse(status=403)

    try:
        employee = Employee.objects.get(user=request.user)
    except Employee.DoesNotExist:
        return HttpResponse('No employee record', status=400)

    time_off_type_id = request.POST.get('time_off_type')
    start_date = request.POST.get('start_date')
    end_date = request.POST.get('end_date')
    reason = request.POST.get('reason', '')
    is_half_day = request.POST.get('is_half_day') == 'true'
    half_day_period = request.POST.get('half_day_period', '')

    if not all([time_off_type_id, start_date, end_date]):
        return HttpResponse('Missing required fields', status=400)

    time_off_type = get_object_or_404(TimeOffType, pk=time_off_type_id)

    from django.utils.dateparse import parse_date
    start = parse_date(start_date)
    end = parse_date(end_date)

    if start > end:
        return HttpResponse('End date must be after start date', status=400)

    # Calculate total days (business days only)
    if is_half_day:
        total_days = Decimal('0.5')
    else:
        total_days = Decimal('0')
        current = start
        while current <= end:
            if current.weekday() < 5:  # Monday to Friday
                total_days += 1
            current += timedelta(days=1)

    # Check balance if accrued
    if time_off_type.is_accrued:
        try:
            balance = TimeOffBalance.objects.get(
                employee=employee,
                time_off_type=time_off_type,
                year=timezone.now().year
            )
            if balance.balance < total_days:
                return HttpResponse(
                    json.dumps({'error': f'Insufficient {time_off_type.name} balance'}),
                    status=400,
                    content_type='application/json'
                )
        except TimeOffBalance.DoesNotExist:
            pass

    # Create request (model.save() will call full_clean())
    try:
        time_off_request = TimeOffRequest.objects.create(
            employee=employee,
            time_off_type=time_off_type,
            start_date=start,
            end_date=end,
            is_half_day=is_half_day,
            half_day_period=half_day_period,
            total_days=total_days,
            reason=reason,
            status='pending',
        )
    except ValidationError as e:
        return HttpResponse(
            json.dumps({'errors': e.message_dict}),
            status=400,
            content_type='application/json'
        )

    if request.headers.get('HX-Request'):
        response = render(request, 'hr/partials/_time_off_request_success.html', {
            'request': time_off_request
        })
        response['HX-Trigger'] = 'timeOffRequestCreated'
        return response

    messages.success(request, 'Time-off request submitted successfully!')
    return redirect('hr:my-time-off')
```

---

## CRITICAL ISSUE #3: Race Condition in Balance Checking

**Location:** `/hr_core/template_views.py` lines 546-610 (TimeOffRequestView.post)

### Problem

Balance is checked and then request created in separate database operations without locking:

```
Timeline of Race Condition:
T1: Thread A checks balance (15 days available)
T2: Thread B checks balance (15 days available)
T3: Thread A creates 10-day request
T4: Thread B creates 10-day request
T5: Both approved, total = 20 days > 15 available
```

### Scenario

```
Vacation balance: 10 days

Request 1: 6 days
  Thread 1 checks: 10 >= 6 ✅
  [Thread 2 runs here]
  Thread 1 creates request
  Thread 1 approves: -6 days

Request 2: 6 days (overlapping dates from other thread)
  Thread 2 checks: 10 >= 6 ✅
  Thread 2 creates request
  Thread 2 approves: -6 days

Result: Balance = -2 days (Both requests approved!)
```

### Recommended Fix

```python
# File: /hr_core/template_views.py

from django.db import transaction
from django.db.models import F

class TimeOffRequestView(LoginRequiredMixin, TenantViewMixin, View):

    def post(self, request):
        tenant = self.get_tenant()
        if not tenant:
            return HttpResponse(status=403)

        try:
            employee = Employee.objects.get(user=request.user)
        except Employee.DoesNotExist:
            return HttpResponse('No employee record', status=400)

        time_off_type_id = request.POST.get('time_off_type')
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')

        # ... date parsing and validation ...

        # Use atomic transaction with locks
        try:
            with transaction.atomic():
                # Lock the employee's balance record
                balance = TimeOffBalance.objects.select_for_update().get(
                    employee=employee,
                    time_off_type=time_off_type,
                    year=timezone.now().year
                )

                # Check balance while locked
                if balance.balance < total_days:
                    return HttpResponse(
                        json.dumps({
                            'error': 'Insufficient balance',
                            'available': str(balance.balance),
                            'requested': str(total_days)
                        }),
                        status=400,
                        content_type='application/json'
                    )

                # Create request while locked (atomic)
                time_off_request = TimeOffRequest.objects.create(
                    employee=employee,
                    time_off_type=time_off_type,
                    start_date=start,
                    end_date=end,
                    is_half_day=is_half_day,
                    half_day_period=half_day_period,
                    total_days=total_days,
                    reason=reason,
                    status='pending',
                )

        except TimeOffBalance.DoesNotExist:
            return HttpResponse(
                json.dumps({'error': 'No balance record found'}),
                status=400,
                content_type='application/json'
            )
        except ValidationError as e:
            return HttpResponse(
                json.dumps({'errors': e.message_dict}),
                status=400,
                content_type='application/json'
            )

        # Success response
        if request.headers.get('HX-Request'):
            response = render(request, 'hr/partials/_time_off_request_success.html', {
                'request': time_off_request
            })
            response['HX-Trigger'] = 'timeOffRequestCreated'
            return response

        messages.success(request, 'Time-off request submitted successfully!')
        return redirect('hr:my-time-off')
```

---

## HIGH PRIORITY ISSUE #1: Minimum Notice Period Not Enforced

**Location:** `/hr_core/forms.py` lines 291-380 (TimeOffRequestForm)

### Problem

TimeOffType has `min_notice_days` field but form validation ignores it:

```python
class TimeOffType(TenantAwareModel):
    min_notice_days = models.PositiveIntegerField(default=0)
    # This field exists but is never used!
```

### Example Failure

```
Sick Leave: requires 0 days notice (should be immediate)
Vacation: requires 5 days notice (minimum)

Employee requests vacation starting tomorrow
Expected: Rejected - only 1 day notice
Actual: Accepted - no validation
```

### Recommended Fix

```python
# File: /hr_core/forms.py

class TimeOffRequestForm(forms.ModelForm):

    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        time_off_type = cleaned_data.get('time_off_type')

        if start_date and time_off_type:
            days_notice = (start_date - timezone.now().date()).days

            if days_notice < time_off_type.min_notice_days:
                raise ValidationError({
                    'start_date': ValidationError(
                        f'{time_off_type.name} requires {time_off_type.min_notice_days} '
                        f'days notice. You provided {days_notice} days.',
                        code='insufficient_notice'
                    )
                })

        return cleaned_data
```

---

## HIGH PRIORITY ISSUE #2: Business Days Not Calculated Correctly

**Location:** `/hr_core/template_views.py` lines 574-582 (TimeOffRequestView.post)

### Problem

Day calculation includes weekends:

```python
# Current logic:
total_days = Decimal('0')
current = start
while current <= end:
    if current.weekday() < 5:  # Monday=0 to Friday=4
        total_days += 1
    current += timedelta(days=1)

# Example:
start_date = Friday 2026-02-13
end_date = Monday 2026-02-16
# Dates: Fri 13, Sat 14, Sun 15, Mon 16
# Weekdays: 13, 16 = 2 days ✅ (Correct)

# But form calculation (lines 351-353):
delta = (end_date - start_date).days + 1
# = (16-13).days + 1 = 4 days ❌ (Includes weekends)
```

### Scenario

```
Request vacation from Friday Jan 10 to Monday Jan 13
Expected: 2 business days (Friday and Monday)
Actual: 4 days (includes weekend)

Employee's 20-day balance becomes 16 after approval
Should be 18
```

### Recommended Fix

Create utility function:

```python
# File: /hr_core/utils.py

from datetime import timedelta
from decimal import Decimal
from django.utils import timezone

def calculate_business_days(start_date, end_date, is_half_day=False):
    """Calculate business days between two dates (inclusive).

    Args:
        start_date: datetime.date
        end_date: datetime.date
        is_half_day: bool, if True returns 0.5

    Returns:
        Decimal: number of business days
    """
    if is_half_day:
        return Decimal('0.5')

    business_days = Decimal('0')
    current = start_date

    while current <= end_date:
        # Monday=0, Friday=4
        if current.weekday() < 5:
            business_days += 1
        current += timedelta(days=1)

    return business_days


def calculate_business_days_excluding_holidays(start_date, end_date,
                                               excluded_dates=None, is_half_day=False):
    """Calculate business days excluding holidays and weekends.

    Args:
        start_date: datetime.date
        end_date: datetime.date
        excluded_dates: list of datetime.date (holidays)
        is_half_day: bool

    Returns:
        Decimal: number of business days
    """
    if is_half_day:
        return Decimal('0.5')

    excluded_dates = excluded_dates or []
    business_days = Decimal('0')
    current = start_date

    while current <= end_date:
        if current.weekday() < 5 and current not in excluded_dates:
            business_days += 1
        current += timedelta(days=1)

    return business_days
```

Update form:

```python
# File: /hr_core/forms.py

from .utils import calculate_business_days

class TimeOffRequestForm(forms.ModelForm):

    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        is_half_day = cleaned_data.get('is_half_day')

        if start_date and end_date:
            if end_date < start_date:
                raise ValidationError({
                    'end_date': _('End date cannot be before start date.')
                })

            if start_date < timezone.now().date():
                raise ValidationError({
                    'start_date': _('Cannot request time off for past dates.')
                })

            # Use business day calculation
            cleaned_data['total_days'] = calculate_business_days(
                start_date, end_date, is_half_day
            )

        return cleaned_data
```

---

## HIGH PRIORITY ISSUE #3: Documentation Requirements Not Enforced

**Location:** `/hr_core/forms.py` (TimeOffRequestForm)

### Problem

TimeOffType.requires_documentation flag is never checked:

```python
sick_leave = TimeOffType.objects.create(
    name='Sick Leave',
    requires_documentation=True,  # Requires medical note
    ...
)

# But form allows submission without document
```

### Recommended Fix

```python
# File: /hr_core/forms.py

class TimeOffRequestForm(forms.ModelForm):

    def clean(self):
        cleaned_data = super().clean()
        time_off_type = cleaned_data.get('time_off_type')
        supporting_document = cleaned_data.get('supporting_document')

        if time_off_type and time_off_type.requires_documentation:
            if not supporting_document:
                raise ValidationError({
                    'supporting_document': ValidationError(
                        f'{time_off_type.name} requires supporting documentation.',
                        code='documentation_required'
                    )
                })

        return cleaned_data
```

---

## HIGH PRIORITY ISSUE #4: Pending Balance Never Updated

**Location:** `/hr_core/models.py` (TimeOffBalance model) and signals

### Problem

TimeOffBalance.pending field exists but is never incremented:

```python
class TimeOffBalance(models.Model):
    pending = DecimalField(
        max_digits=6,
        decimal_places=2,
        default=Decimal('0.00'),
        help_text=_('Amount in pending requests')
    )
    # Used for: showing available balance = balance - pending
    # But: never updated when requests created/approved!
```

### Impact

- Employees can request more time than available by looking at balance
- If balance = 10 and 5 days pending, they see 10 not 5 available
- No way to see pending requests affecting available balance

### Recommended Fix

```python
# File: /hr_core/signals.py

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import TimeOffRequest, TimeOffBalance

@receiver(post_save, sender=TimeOffRequest)
def update_pending_balance_on_request_change(sender, instance, created, **kwargs):
    """Update pending balance when request status changes."""

    # Only process if time_off_type is accrued
    if not instance.time_off_type.is_accrued:
        return

    try:
        balance = TimeOffBalance.objects.get(
            employee=instance.employee,
            time_off_type=instance.time_off_type,
            year=timezone.now().year
        )
    except TimeOffBalance.DoesNotExist:
        return

    # Recalculate pending from all pending requests
    pending_requests = TimeOffRequest.objects.filter(
        employee=instance.employee,
        time_off_type=instance.time_off_type,
        status=TimeOffRequest.RequestStatus.PENDING,
        start_date__year=timezone.now().year
    ).aggregate(
        total=models.Sum('total_days'),
    )

    balance.pending = pending_requests['total'] or Decimal('0.00')
    balance.save()


@receiver(post_save, sender=TimeOffRequest)
def update_pending_balance_on_approval(sender, instance, created, **kwargs):
    """Move days from pending to used_this_year when approved."""

    if not instance.time_off_type.is_accrued:
        return

    if instance.status != TimeOffRequest.RequestStatus.APPROVED:
        return

    try:
        balance = TimeOffBalance.objects.get(
            employee=instance.employee,
            time_off_type=instance.time_off_type,
            year=timezone.now().year
        )
    except TimeOffBalance.DoesNotExist:
        return

    # Recalculate pending
    pending_requests = TimeOffRequest.objects.filter(
        employee=instance.employee,
        time_off_type=instance.time_off_type,
        status=TimeOffRequest.RequestStatus.PENDING,
        start_date__year=timezone.now().year
    ).aggregate(
        total=models.Sum('total_days'),
    )

    balance.pending = pending_requests['total'] or Decimal('0.00')
    balance.save()
```

---

## HIGH PRIORITY ISSUE #5: No Blackout Date Enforcement

**Location:** `/hr_core/models.py` (TimeOffBlackoutDate exists but unused)

### Problem

Model exists but validation never checks it:

```python
class TimeOffBlackoutDate(models.Model):
    name = CharField(max_length=200)
    start_date = DateField()
    end_date = DateField()
    applies_to_all = BooleanField(default=True)
    restriction_type = CharField(
        choices=[('blocked', ...), ('restricted', ...), ('limited', ...)]
    )
    # But no code checks this during request validation!
```

### Recommended Fix

```python
# File: /hr_core/models.py

class TimeOffRequest(TenantAwareModel):

    def check_blackout_dates(self):
        """Check if request overlaps with blackout periods."""
        from configurations.models import Department

        # Find applicable blackout dates
        query = TimeOffBlackoutDate.objects.filter(
            start_date__lte=self.end_date,
            end_date__gte=self.start_date,
            is_active=True
        )

        # Filter by scope
        applicable_blackouts = query.filter(
            Q(applies_to_all=True) |
            Q(departments=self.employee.department)
        ).distinct()

        if not applicable_blackouts.exists():
            return None

        # Get most restrictive type
        for blackout in applicable_blackouts.order_by('restriction_type'):
            return {
                'name': blackout.name,
                'restriction_type': blackout.restriction_type,
                'dates': (blackout.start_date, blackout.end_date),
            }

        return None

    def clean(self):
        super().clean()

        if not self.start_date or not self.end_date:
            return

        # Check blackout dates
        blackout = self.check_blackout_dates()
        if blackout:
            msg = f"Cannot request time off during {blackout['name']}. "
            if blackout['restriction_type'] == 'blocked':
                msg += "This period is completely blocked."
                raise ValidationError({'start_date': msg})
            elif blackout['restriction_type'] == 'restricted':
                msg += "Requires HR approval."
                # Don't block, just flag for approval
```

---

## SUMMARY OF ALL FIXES

| Issue | File | Lines | Severity | Fix Type |
|-------|------|-------|----------|----------|
| Balance deduction | models.py | 520-540 | CRITICAL | Update approve() method |
| Overlapping requests | models.py | - | CRITICAL | Add clean() validation |
| Race condition | template_views.py | 546-610 | CRITICAL | Use transaction.atomic() + select_for_update() |
| Minimum notice | forms.py | 340-370 | HIGH | Add clean() validation |
| Business days | template_views.py | 574-582 | HIGH | Create utility function |
| Documentation required | forms.py | 340-370 | HIGH | Add clean() validation |
| Pending balance | models.py | 1280-1290 | HIGH | Add signal handler |
| Blackout dates | models.py | - | HIGH | Add check_blackout_dates() + clean() |

---

**Total Issues Found:** 8 (3 Critical, 5 High Priority)
**Estimated Fix Time:** 6-8 hours
**Testing Required:** 30+ test cases
