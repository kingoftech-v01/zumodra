"""
Tests for scheduling utilities.

Author: Zumodra Team
Since: 2026-01-17
"""

from datetime import datetime, timedelta, time, date
import pytest
import pytz
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from core.scheduling.utils import (
    validate_time_slot,
    check_slot_conflict,
    calculate_duration,
    convert_timezone,
    format_datetime_for_calendar,
    get_business_days_between,
    generate_time_slots,
    is_within_business_hours,
    calculate_end_time,
    parse_duration_string,
)


class TestValidateTimeSlot(TestCase):
    """Tests for validate_time_slot function."""

    def test_valid_time_slot(self):
        """Test validation of valid time slot."""
        start = timezone.now() + timedelta(hours=1)
        end = start + timedelta(hours=1)

        # Should not raise
        validate_time_slot(start, end)

    def test_start_after_end_raises_error(self):
        """Test that start after end raises ValidationError."""
        start = timezone.now() + timedelta(hours=2)
        end = start - timedelta(hours=1)

        with self.assertRaises(ValidationError):
            validate_time_slot(start, end)

    def test_past_time_raises_error(self):
        """Test that past time raises ValidationError."""
        start = timezone.now() - timedelta(hours=2)
        end = start + timedelta(hours=1)

        with self.assertRaises(ValidationError):
            validate_time_slot(start, end)

    def test_min_duration_validation(self):
        """Test minimum duration validation."""
        start = timezone.now() + timedelta(hours=1)
        end = start + timedelta(minutes=15)

        with self.assertRaises(ValidationError):
            validate_time_slot(start, end, min_duration=timedelta(minutes=30))

    def test_max_duration_validation(self):
        """Test maximum duration validation."""
        start = timezone.now() + timedelta(hours=1)
        end = start + timedelta(hours=3)

        with self.assertRaises(ValidationError):
            validate_time_slot(start, end, max_duration=timedelta(hours=2))


class TestCheckSlotConflict(TestCase):
    """Tests for check_slot_conflict function."""

    def setUp(self):
        """Set up test data."""
        base = timezone.now() + timedelta(days=1)
        self.existing_slots = [
            (base.replace(hour=10, minute=0), base.replace(hour=11, minute=0)),
            (base.replace(hour=14, minute=0), base.replace(hour=15, minute=0)),
        ]

    def test_no_conflict(self):
        """Test slot with no conflict."""
        base = timezone.now() + timedelta(days=1)
        start = base.replace(hour=12, minute=0)
        end = base.replace(hour=13, minute=0)

        conflict = check_slot_conflict(start, end, self.existing_slots)
        self.assertFalse(conflict)

    def test_exact_overlap(self):
        """Test slot with exact overlap."""
        base = timezone.now() + timedelta(days=1)
        start = base.replace(hour=10, minute=0)
        end = base.replace(hour=11, minute=0)

        conflict = check_slot_conflict(start, end, self.existing_slots)
        self.assertTrue(conflict)

    def test_partial_overlap(self):
        """Test slot with partial overlap."""
        base = timezone.now() + timedelta(days=1)
        start = base.replace(hour=10, minute=30)
        end = base.replace(hour=11, minute=30)

        conflict = check_slot_conflict(start, end, self.existing_slots)
        self.assertTrue(conflict)

    def test_buffer_time(self):
        """Test conflict detection with buffer time."""
        base = timezone.now() + timedelta(days=1)
        start = base.replace(hour=11, minute=0)
        end = base.replace(hour=12, minute=0)

        # Without buffer - no conflict
        conflict = check_slot_conflict(start, end, self.existing_slots)
        self.assertFalse(conflict)

        # With 15min buffer - conflict (11:00 is within 15min of 11:00)
        conflict = check_slot_conflict(
            start, end, self.existing_slots,
            buffer_time=timedelta(minutes=15)
        )
        self.assertTrue(conflict)


class TestCalculateDuration(TestCase):
    """Tests for calculate_duration function."""

    def test_duration_calculation(self):
        """Test duration calculation."""
        start = datetime(2026, 1, 20, 10, 0)
        end = datetime(2026, 1, 20, 11, 30)

        duration = calculate_duration(start, end)
        self.assertEqual(duration, timedelta(hours=1, minutes=30))


class TestConvertTimezone(TestCase):
    """Tests for convert_timezone function."""

    def test_timezone_conversion(self):
        """Test converting between timezones."""
        # 2:00 PM Toronto = 2:00 PM New York (same time zone in winter)
        dt = datetime(2026, 1, 20, 14, 0)
        converted = convert_timezone(dt, 'America/Toronto', 'America/New_York')

        self.assertEqual(converted.hour, 14)

    def test_timezone_conversion_different_offset(self):
        """Test conversion with different UTC offsets."""
        # 2:00 PM Toronto = 11:00 AM Los Angeles (3 hours difference)
        dt = datetime(2026, 1, 20, 14, 0)
        converted = convert_timezone(dt, 'America/Toronto', 'America/Los_Angeles')

        self.assertEqual(converted.hour, 11)


class TestFormatDatetimeForCalendar(TestCase):
    """Tests for format_datetime_for_calendar function."""

    def test_format_with_timezone(self):
        """Test formatting with timezone."""
        dt = datetime(2026, 1, 20, 14, 0, tzinfo=pytz.UTC)
        formatted = format_datetime_for_calendar(dt, 'America/Toronto')

        # Should be in ISO 8601 format
        self.assertIn('2026-01-20', formatted)
        self.assertIn('T', formatted)


class TestGetBusinessDaysBetween(TestCase):
    """Tests for get_business_days_between function."""

    def test_weekdays_only(self):
        """Test counting weekdays only."""
        # Jan 20-24, 2026 (Monday to Friday)
        start = date(2026, 1, 20)
        end = date(2026, 1, 24)

        days = get_business_days_between(start, end, exclude_weekends=True)
        self.assertEqual(days, 5)

    def test_including_weekend(self):
        """Test counting including weekend."""
        # Jan 20-24, 2026 (Monday to Friday)
        start = date(2026, 1, 20)
        end = date(2026, 1, 24)

        days = get_business_days_between(start, end, exclude_weekends=False)
        self.assertEqual(days, 5)

    def test_with_weekend(self):
        """Test counting over a weekend."""
        # Jan 20-26, 2026 (Monday to Sunday)
        start = date(2026, 1, 20)
        end = date(2026, 1, 26)

        days = get_business_days_between(start, end, exclude_weekends=True)
        # Mon, Tue, Wed, Thu, Fri = 5 days (excludes Sat, Sun)
        self.assertEqual(days, 5)


class TestGenerateTimeSlots(TestCase):
    """Tests for generate_time_slots function."""

    def test_generate_hourly_slots(self):
        """Test generating hourly time slots."""
        slots = generate_time_slots(
            start_time=time(9, 0),
            end_time=time(17, 0),
            slot_duration=timedelta(hours=1),
            date_obj=date(2026, 1, 20),
            tz='America/Toronto'
        )

        # 9am-5pm with 1-hour slots = 8 slots
        self.assertEqual(len(slots), 8)

        # First slot should start at 9am
        first_start, first_end = slots[0]
        self.assertEqual(first_start.hour, 9)
        self.assertEqual(first_end.hour, 10)

    def test_generate_30min_slots(self):
        """Test generating 30-minute slots."""
        slots = generate_time_slots(
            start_time=time(9, 0),
            end_time=time(12, 0),
            slot_duration=timedelta(minutes=30),
            date_obj=date(2026, 1, 20),
            tz='America/Toronto'
        )

        # 9am-12pm with 30-min slots = 6 slots
        self.assertEqual(len(slots), 6)


class TestIsWithinBusinessHours(TestCase):
    """Tests for is_within_business_hours function."""

    def test_within_hours(self):
        """Test datetime within business hours."""
        dt = datetime(2026, 1, 20, 14, 0)
        result = is_within_business_hours(dt, time(9, 0), time(17, 0))
        self.assertTrue(result)

    def test_before_hours(self):
        """Test datetime before business hours."""
        dt = datetime(2026, 1, 20, 8, 0)
        result = is_within_business_hours(dt, time(9, 0), time(17, 0))
        self.assertFalse(result)

    def test_after_hours(self):
        """Test datetime after business hours."""
        dt = datetime(2026, 1, 20, 18, 0)
        result = is_within_business_hours(dt, time(9, 0), time(17, 0))
        self.assertFalse(result)


class TestCalculateEndTime(TestCase):
    """Tests for calculate_end_time function."""

    def test_calculate_end_time(self):
        """Test calculating end time."""
        start = datetime(2026, 1, 20, 14, 0)
        duration = timedelta(hours=1, minutes=30)

        end = calculate_end_time(start, duration)
        self.assertEqual(end, datetime(2026, 1, 20, 15, 30))


class TestParseDurationString(TestCase):
    """Tests for parse_duration_string function."""

    def test_parse_minutes(self):
        """Test parsing minutes."""
        duration = parse_duration_string("30m")
        self.assertEqual(duration, timedelta(minutes=30))

        duration = parse_duration_string("30 minutes")
        self.assertEqual(duration, timedelta(minutes=30))

    def test_parse_hours(self):
        """Test parsing hours."""
        duration = parse_duration_string("2h")
        self.assertEqual(duration, timedelta(hours=2))

        duration = parse_duration_string("2 hour")
        self.assertEqual(duration, timedelta(hours=2))

    def test_parse_decimal_hours(self):
        """Test parsing decimal hours."""
        duration = parse_duration_string("2.5h")
        self.assertEqual(duration, timedelta(hours=2, minutes=30))

    def test_parse_hours_and_minutes(self):
        """Test parsing hours and minutes together."""
        duration = parse_duration_string("1h30m")
        self.assertEqual(duration, timedelta(hours=1, minutes=30))

    def test_invalid_format(self):
        """Test invalid format raises ValueError."""
        with self.assertRaises(ValueError):
            parse_duration_string("invalid")
