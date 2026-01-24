# Core Scheduling Module

## Overview

The `core/scheduling/` module provides shared functionality for both recruitment interviews ([jobs/Interview](../../jobs/models.py)) and service appointments ([interviews/Appointment](../../interviews/models.py)). Instead of duplicating scheduling logic across both systems, this module centralizes common behavior into reusable mixins, utilities, and services.

**Created:** 2026-01-17
**Purpose:** Unify scheduling functionality while maintaining separation between ATS recruitment and service appointment contexts

## Architecture Decision

### Why Separate Instead of Merge?

The two interview systems serve fundamentally different business purposes:

| Aspect | jobs.Interview (ATS) | interviews.Appointment (Services) |
|--------|---------------------|----------------------------------|
| **Context** | Recruitment (candidate → job → hire) | Service booking (client → service → provider) |
| **Participants** | Multiple interviewers, candidate, organizer | Client, staff member |
| **Features** | Feedback, templates, interview types, slots | Payment, refunds, service-specific logic |
| **Related Models** | Application, JobPosting, Offer | Service, StaffMember, Payment |
| **Workflow** | Interview → Feedback → Offer → Employee | Booking → Payment → Service Delivery |

**Decision:** Keep systems separate but share common scheduling infrastructure via this module.

## Module Structure

```
core/scheduling/
├── __init__.py               # Public API exports
├── mixins.py                 # Django model mixins
├── utils.py                  # Timezone, validation, slot utilities
├── notifications.py          # Unified notification service
├── calendar_integration.py   # Google/Outlook/iCal integration
└── README.md                 # This file
```

## Mixins

### SchedulableMixin

Provides scheduling fields and methods for any model that represents a scheduled event.

**Fields:**
- `scheduled_start` (DateTimeField)
- `scheduled_end` (DateTimeField)
- `timezone` (CharField)
- `actual_start` (DateTimeField, optional)
- `actual_end` (DateTimeField, optional)

**Methods:**
- `scheduled_duration` - Calculate scheduled duration
- `actual_duration` - Calculate actual duration
- `is_upcoming()` - Check if event is in future
- `is_past()` - Check if event is in past
- `is_in_progress()` - Check if event is happening now
- `time_until_start()` - Time remaining until start
- `convert_to_timezone(target_tz)` - Convert times to different timezone

**Usage:**

```python
from core.scheduling import SchedulableMixin

class Interview(SchedulableMixin, models.Model):
    # Your model fields
    pass

# In code
interview.is_upcoming()  # True/False
interview.scheduled_duration  # timedelta
```

### CancellableMixin

Provides cancellation tracking for events.

**Fields:**
- `cancelled_at` (DateTimeField, nullable)
- `cancelled_by` (ForeignKey to User, nullable)
- `cancellation_reason` (TextField)

**Methods:**
- `is_cancelled` - Check if cancelled
- `cancel(user, reason)` - Cancel the event
- `can_be_cancelled()` - Check if cancellation is allowed

**Usage:**

```python
from core.scheduling import CancellableMixin

class Interview(CancellableMixin, models.Model):
    pass

# Cancel event
interview.cancel(user=request.user, reason="Candidate unavailable")
```

### ReschedulableMixin

Provides reschedule tracking and limits.

**Fields:**
- `reschedule_count` (PositiveIntegerField)
- `reschedule_limit` (PositiveIntegerField, nullable)
- `last_rescheduled_at` (DateTimeField, nullable)

**Methods:**
- `can_be_rescheduled()` - Check if reschedule is allowed
- `increment_reschedule_count()` - Increment counter
- `remaining_reschedules` - Get remaining reschedules

**Usage:**

```python
from core.scheduling import ReschedulableMixin

class Appointment(ReschedulableMixin, models.Model):
    pass

# Check reschedule limit
if appointment.can_be_rescheduled():
    # Perform reschedule
    appointment.increment_reschedule_count()
```

### ReminderMixin

Provides reminder tracking for scheduled events.

**Fields:**
- `reminder_sent_1day` (BooleanField)
- `reminder_sent_1hour` (BooleanField)
- `reminder_sent_15min` (BooleanField)
- `reminder_enabled` (BooleanField)

**Methods:**
- `should_send_1day_reminder(scheduled_time)` - Check if 1-day reminder should be sent
- `should_send_1hour_reminder(scheduled_time)` - Check if 1-hour reminder should be sent
- `should_send_15min_reminder(scheduled_time)` - Check if 15-min reminder should be sent
- `mark_reminder_sent(reminder_type)` - Mark reminder as sent
- `reset_reminders()` - Reset all reminder flags

**Usage:**

```python
from core.scheduling import ReminderMixin

class Interview(ReminderMixin, models.Model):
    pass

# In Celery task
for interview in Interview.objects.filter(reminder_enabled=True):
    if interview.should_send_1day_reminder(interview.scheduled_start):
        send_reminder(interview)
        interview.mark_reminder_sent('1day')
```

## Utilities

### Validation

```python
from core.scheduling import validate_time_slot

# Validate time slot
validate_time_slot(
    start_time=datetime(2026, 1, 20, 14, 0),
    end_time=datetime(2026, 1, 20, 15, 0),
    min_duration=timedelta(minutes=30),
    max_duration=timedelta(hours=2)
)
```

### Conflict Detection

```python
from core.scheduling import check_slot_conflict

# Check for conflicts
existing_slots = [
    (datetime(2026, 1, 20, 10, 0), datetime(2026, 1, 20, 11, 0)),
    (datetime(2026, 1, 20, 14, 0), datetime(2026, 1, 20, 15, 0)),
]

has_conflict = check_slot_conflict(
    start_time=datetime(2026, 1, 20, 10, 30),
    end_time=datetime(2026, 1, 20, 11, 30),
    existing_slots=existing_slots,
    buffer_time=timedelta(minutes=15)
)
```

### Timezone Conversion

```python
from core.scheduling import convert_timezone

# Convert between timezones
ny_time = convert_timezone(
    dt=datetime(2026, 1, 20, 14, 0),
    from_tz='America/Toronto',
    to_tz='America/New_York'
)
```

### Calendar Formatting

```python
from core.scheduling import format_datetime_for_calendar

# Format for iCalendar
ical_format = format_datetime_for_calendar(
    dt=datetime(2026, 1, 20, 14, 0),
    tz='America/Toronto'
)
# Returns: "2026-01-20T14:00:00-05:00"
```

### Next Available Slot

```python
from core.scheduling import get_next_available_slot
from datetime import time

# Find next available slot
next_slot = get_next_available_slot(
    start_date=date(2026, 1, 20),
    working_hours=[(time(9, 0), time(17, 0))],
    duration=timedelta(hours=1),
    existing_bookings=existing_slots,
    buffer_time=timedelta(minutes=15),
    days_ahead=30,
    tz='America/Toronto'
)
```

## Notification Service

### SchedulingNotificationService

Unified notification service for both interview types.

**Features:**
- Email notifications (confirmation, reminder, cancellation, reschedule)
- In-app notifications (if notifications app is available)
- Template-based emails
- Multi-tenant support

**Usage:**

```python
from core.scheduling.notifications import SchedulingNotificationService

service = SchedulingNotificationService(tenant=current_tenant)

# Send confirmation
service.send_confirmation_email(
    recipient_email="candidate@example.com",
    recipient_name="John Doe",
    event_type="interview",
    event_title="Technical Interview - Software Engineer",
    scheduled_start=interview.scheduled_start,
    scheduled_end=interview.scheduled_end,
    meeting_url="https://zoom.us/j/123456789"
)

# Send reminder
service.send_reminder_email(
    recipient_email="candidate@example.com",
    recipient_name="John Doe",
    event_type="interview",
    event_title="Technical Interview - Software Engineer",
    scheduled_start=interview.scheduled_start,
    scheduled_end=interview.scheduled_end,
    reminder_type="1hour",  # '1day', '1hour', '15min'
    meeting_url="https://zoom.us/j/123456789"
)
```

### Helper Functions

```python
from core.scheduling.notifications import (
    send_scheduling_confirmation,
    send_scheduling_reminder
)

# Send to multiple recipients
send_scheduling_confirmation(
    event_type="interview",
    event_instance=interview,
    recipients=["candidate@example.com", "interviewer@company.com"],
    tenant=current_tenant
)

send_scheduling_reminder(
    event_type="appointment",
    event_instance=appointment,
    recipients=["client@example.com"],
    reminder_type="1day",
    tenant=current_tenant
)
```

## Calendar Integration

### Generate Calendar Links

```python
from core.scheduling.calendar_integration import generate_calendar_links

event_data = {
    'title': 'Technical Interview - Software Engineer',
    'description': 'Technical interview for senior developer role',
    'start': datetime(2026, 1, 20, 14, 0, tzinfo=pytz.timezone('America/Toronto')),
    'end': datetime(2026, 1, 20, 15, 0, tzinfo=pytz.timezone('America/Toronto')),
    'location': 'Virtual',
    'meeting_url': 'https://zoom.us/j/123456789',
    'organizer_email': 'hr@company.com',
    'organizer_name': 'HR Team',
    'attendees': ['candidate@example.com', 'interviewer@company.com'],
    'timezone': 'America/Toronto'
}

links = generate_calendar_links(event_data)
# Returns:
# {
#     'google': 'https://calendar.google.com/calendar/render?...',
#     'outlook': 'https://outlook.live.com/calendar/0/deeplink/compose?...',
#     'ics': '<iCalendar format string>'
# }
```

### Generate iCalendar File

```python
from core.scheduling.calendar_integration import CalendarEventGenerator

generator = CalendarEventGenerator(event_data)

# Get .ics file
ics_file = generator.generate_ics_file()

# Attach to email response
response = HttpResponse(ics_file.read(), content_type='text/calendar')
response['Content-Disposition'] = 'attachment; filename="interview.ics"'
return response
```

### Sync with External Calendars

```python
from core.scheduling.calendar_integration import CalendarSync

# Google Calendar
google_sync = CalendarSync(
    provider='google',
    credentials={
        'access_token': 'ya29.a0AfH6...',
        'refresh_token': '1//0gQ...',
        'client_id': 'your-client-id',
        'client_secret': 'your-client-secret'
    }
)

event_id = google_sync.create_event(event_data)

# Microsoft Outlook
outlook_sync = CalendarSync(
    provider='outlook',
    credentials={
        'access_token': 'EwBgA...'
    }
)

event_id = outlook_sync.create_event(event_data)
```

## Integration Examples

### ATS Interview (jobs/Interview)

```python
from django.db import models
from core.scheduling import (
    SchedulableMixin,
    CancellableMixin,
    ReschedulableMixin,
    ReminderMixin
)

class Interview(
    SchedulableMixin,
    CancellableMixin,
    ReschedulableMixin,
    ReminderMixin,
    models.Model
):
    application = models.ForeignKey('Application', on_delete=models.CASCADE)
    interview_type = models.CharField(max_length=35)
    title = models.CharField(max_length=200)
    # ... other ATS-specific fields
```

### Service Appointment (interviews/Appointment)

```python
from django.db import models
from core.scheduling import (
    SchedulableMixin,
    CancellableMixin,
    ReschedulableMixin,
    ReminderMixin
)

class Appointment(
    SchedulableMixin,
    CancellableMixin,
    ReschedulableMixin,
    ReminderMixin,
    models.Model
):
    client = models.ForeignKey(User, on_delete=models.SET_NULL)
    service = models.ForeignKey('Service', on_delete=models.CASCADE)
    paid = models.BooleanField(default=False)
    # ... other service-specific fields
```

## Celery Tasks

### Reminder Tasks

```python
from celery import shared_task
from core.scheduling.notifications import send_scheduling_reminder

@shared_task
def send_interview_reminders():
    """Send reminders for upcoming interviews."""
    from jobs.models import Interview

    for interview in Interview.objects.filter(reminder_enabled=True):
        if interview.should_send_1day_reminder(interview.scheduled_start):
            send_scheduling_reminder(
                event_type='interview',
                event_instance=interview,
                recipients=[interview.application.candidate.email],
                reminder_type='1day'
            )
            interview.mark_reminder_sent('1day')

@shared_task
def send_appointment_reminders():
    """Send reminders for upcoming appointments."""
    from interviews.models import Appointment

    for appointment in Appointment.objects.filter(want_reminder=True):
        if appointment.should_send_1day_reminder(appointment.scheduled_start):
            send_scheduling_reminder(
                event_type='appointment',
                event_instance=appointment,
                recipients=[appointment.client.email],
                reminder_type='1day'
            )
            appointment.mark_reminder_sent('1day')
```

## Testing

### Test Mixins

```python
from django.test import TestCase
from core.scheduling import SchedulableMixin

class SchedulableMixinTest(TestCase):
    def test_scheduled_duration(self):
        interview = Interview.objects.create(
            scheduled_start=datetime(2026, 1, 20, 14, 0),
            scheduled_end=datetime(2026, 1, 20, 15, 0)
        )
        self.assertEqual(interview.scheduled_duration, timedelta(hours=1))

    def test_is_upcoming(self):
        future_interview = Interview.objects.create(
            scheduled_start=timezone.now() + timedelta(days=1),
            scheduled_end=timezone.now() + timedelta(days=1, hours=1)
        )
        self.assertTrue(future_interview.is_upcoming())
```

## Dependencies

- `django>=5.2.7`
- `pytz` - Timezone support
- `icalendar` - iCalendar format generation
- `googleapiclient` (optional) - Google Calendar API
- `requests` (optional) - Microsoft Graph API

## Future Enhancements

- [ ] Add WebSocket support for real-time scheduling updates
- [ ] Implement automated conflict resolution
- [ ] Add recurring event support
- [ ] Integrate with Zoom API for auto-generated meeting links
- [ ] Support for custom reminder schedules
- [ ] Multi-language email templates
- [ ] SMS notifications via Twilio
- [ ] Calendar availability blocking

## Contributing

When adding features to this module:

1. Keep it generic - must work for both ATS and service appointments
2. Follow existing patterns in mixins
3. Add comprehensive docstrings
4. Write unit tests
5. Update this README
6. Ensure timezone-aware datetime handling
7. Support multi-tenant context

## Support

For questions or issues:
- Check code examples in this README
- Review mixin docstrings in `mixins.py`
- See integration examples in `jobs/models.py` and `interviews/models.py`
- Consult main [CLAUDE.md](../../CLAUDE.md) for project guidelines

---

**Last Updated:** January 2026
**Status:** Production-ready
