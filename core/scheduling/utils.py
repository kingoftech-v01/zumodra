"""
Shared utilities for scheduling functionality.

Provides timezone handling, validation, and datetime manipulation
for both recruitment interviews and service appointments.

Author: Zumodra Team
Since: 2026-01-17
"""

from datetime import datetime, timedelta, time, date
from typing import Optional, List, Tuple

import pytz
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


def validate_time_slot(
    start_time: datetime,
    end_time: datetime,
    min_duration: Optional[timedelta] = None,
    max_duration: Optional[timedelta] = None
) -> None:
    """
    Validate a time slot.

    Args:
        start_time: Slot start time
        end_time: Slot end time
        min_duration: Optional minimum duration
        max_duration: Optional maximum duration

    Raises:
        ValidationError: If validation fails
    """
    # Start must be before end
    if start_time >= end_time:
        raise ValidationError(_("Start time must be before end time"))

    # Calculate duration
    duration = end_time - start_time

    # Check minimum duration
    if min_duration and duration < min_duration:
        raise ValidationError(
            _("Duration must be at least %(min)s") % {'min': min_duration}
        )

    # Check maximum duration
    if max_duration and duration > max_duration:
        raise ValidationError(
            _("Duration cannot exceed %(max)s") % {'max': max_duration}
        )

    # Slot must not be in the past
    if start_time < timezone.now():
        raise ValidationError(_("Cannot schedule in the past"))


def check_slot_conflict(
    start_time: datetime,
    end_time: datetime,
    existing_slots: List[Tuple[datetime, datetime]],
    buffer_time: Optional[timedelta] = None
) -> bool:
    """
    Check if a time slot conflicts with existing slots.

    Args:
        start_time: New slot start time
        end_time: New slot end time
        existing_slots: List of (start, end) tuples for existing slots
        buffer_time: Optional buffer time between slots

    Returns:
        True if there's a conflict, False otherwise
    """
    buffer = buffer_time or timedelta(0)

    for existing_start, existing_end in existing_slots:
        # Add buffer to existing slot
        buffered_start = existing_start - buffer
        buffered_end = existing_end + buffer

        # Check for overlap
        if (start_time < buffered_end) and (end_time > buffered_start):
            return True

    return False


def calculate_duration(start: datetime, end: datetime) -> timedelta:
    """
    Calculate duration between two datetimes.

    Args:
        start: Start datetime
        end: End datetime

    Returns:
        Duration as timedelta
    """
    return end - start


def convert_timezone(
    dt: datetime,
    from_tz: str,
    to_tz: str
) -> datetime:
    """
    Convert datetime from one timezone to another.

    Args:
        dt: Datetime to convert
        from_tz: Source timezone string (e.g., 'America/Toronto')
        to_tz: Target timezone string (e.g., 'America/New_York')

    Returns:
        Converted datetime
    """
    source_timezone = pytz.timezone(from_tz)
    target_timezone = pytz.timezone(to_tz)

    # If datetime is naive, localize it
    if dt.tzinfo is None:
        dt_localized = source_timezone.localize(dt)
    else:
        dt_localized = dt.astimezone(source_timezone)

    # Convert to target timezone
    return dt_localized.astimezone(target_timezone)


def format_datetime_for_calendar(
    dt: datetime,
    tz: Optional[str] = None
) -> str:
    """
    Format datetime for calendar integration (iCalendar format).

    Args:
        dt: Datetime to format
        tz: Optional timezone string

    Returns:
        Formatted datetime string (ISO 8601)

    Example:
        "2026-01-17T14:30:00-05:00"
    """
    if tz:
        target_tz = pytz.timezone(tz)
        dt_converted = dt.astimezone(target_tz)
    else:
        dt_converted = dt

    return dt_converted.isoformat()


def get_next_available_slot(
    start_date: date,
    working_hours: List[Tuple[time, time]],
    duration: timedelta,
    existing_bookings: List[Tuple[datetime, datetime]],
    buffer_time: Optional[timedelta] = None,
    days_ahead: int = 30,
    tz: str = 'America/Toronto'
) -> Optional[datetime]:
    """
    Find the next available time slot.

    Args:
        start_date: Date to start searching from
        working_hours: List of (start_time, end_time) tuples for each day
        duration: Required duration for the slot
        existing_bookings: List of (start, end) tuples for booked slots
        buffer_time: Optional buffer between slots
        days_ahead: Maximum days to search ahead
        tz: Timezone string

    Returns:
        Next available slot start time or None if not found
    """
    current_tz = pytz.timezone(tz)
    buffer = buffer_time or timedelta(0)

    for day_offset in range(days_ahead):
        check_date = start_date + timedelta(days=day_offset)

        for start_time, end_time in working_hours:
            # Create datetime for this slot
            slot_start = current_tz.localize(
                datetime.combine(check_date, start_time)
            )
            slot_end = current_tz.localize(
                datetime.combine(check_date, end_time)
            )

            # Check if duration fits in working hours
            if (slot_end - slot_start) < duration:
                continue

            # Try to find available slot within working hours
            current_time = slot_start
            while (current_time + duration) <= slot_end:
                candidate_end = current_time + duration

                # Check for conflicts
                if not check_slot_conflict(
                    current_time,
                    candidate_end,
                    existing_bookings,
                    buffer
                ):
                    # Found available slot
                    return current_time

                # Move to next 15-minute interval
                current_time += timedelta(minutes=15)

    return None


def get_business_days_between(
    start_date: date,
    end_date: date,
    exclude_weekends: bool = True
) -> int:
    """
    Calculate number of business days between two dates.

    Args:
        start_date: Start date
        end_date: End date
        exclude_weekends: Whether to exclude Saturday and Sunday

    Returns:
        Number of business days
    """
    if start_date > end_date:
        return 0

    days = 0
    current = start_date

    while current <= end_date:
        if not exclude_weekends or current.weekday() < 5:  # Monday = 0, Friday = 4
            days += 1
        current += timedelta(days=1)

    return days


def generate_time_slots(
    start_time: time,
    end_time: time,
    slot_duration: timedelta,
    date_obj: date,
    tz: str = 'America/Toronto'
) -> List[Tuple[datetime, datetime]]:
    """
    Generate list of time slots for a given day.

    Args:
        start_time: Working hours start time
        end_time: Working hours end time
        slot_duration: Duration of each slot
        date_obj: Date to generate slots for
        tz: Timezone string

    Returns:
        List of (start_datetime, end_datetime) tuples
    """
    current_tz = pytz.timezone(tz)
    slots = []

    # Create datetime for start
    current = current_tz.localize(
        datetime.combine(date_obj, start_time)
    )
    end_dt = current_tz.localize(
        datetime.combine(date_obj, end_time)
    )

    # Generate slots
    while (current + slot_duration) <= end_dt:
        slot_end = current + slot_duration
        slots.append((current, slot_end))
        current = slot_end

    return slots


def is_within_business_hours(
    dt: datetime,
    start_time: time,
    end_time: time
) -> bool:
    """
    Check if a datetime falls within business hours.

    Args:
        dt: Datetime to check
        start_time: Business hours start time
        end_time: Business hours end time

    Returns:
        True if within business hours
    """
    time_only = dt.time()
    return start_time <= time_only <= end_time


def calculate_end_time(
    start_time: datetime,
    duration: timedelta
) -> datetime:
    """
    Calculate end time given start time and duration.

    Args:
        start_time: Start datetime
        duration: Duration as timedelta

    Returns:
        End datetime
    """
    return start_time + duration


def parse_duration_string(duration_str: str) -> timedelta:
    """
    Parse duration string to timedelta.

    Supports formats like:
    - "30m" or "30 minutes"
    - "1h" or "1 hour"
    - "1h30m" or "1 hour 30 minutes"
    - "2.5h"

    Args:
        duration_str: Duration string

    Returns:
        Parsed timedelta

    Raises:
        ValueError: If format is invalid
    """
    duration_str = duration_str.lower().strip()

    # Handle decimal hours (e.g., "2.5h")
    if 'h' in duration_str and '.' in duration_str:
        hours = float(duration_str.replace('h', '').strip())
        return timedelta(hours=hours)

    # Parse hours and minutes
    hours = 0
    minutes = 0

    if 'h' in duration_str:
        parts = duration_str.split('h')
        hours = int(parts[0].strip())
        if len(parts) > 1 and parts[1].strip():
            duration_str = parts[1]

    if 'm' in duration_str:
        minutes = int(duration_str.replace('m', '').strip())

    if hours == 0 and minutes == 0:
        raise ValueError(f"Invalid duration string: {duration_str}")

    return timedelta(hours=hours, minutes=minutes)
