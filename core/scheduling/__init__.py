"""
Core scheduling module for unified interview and appointment scheduling.

This module provides shared functionality for both:
- jobs.Interview (recruitment ATS interviews)
- interviews.Appointment (service appointment scheduling)

Author: Zumodra Team
Since: 2026-01-17
"""

from .mixins import (
    SchedulableMixin,
    CancellableMixin,
    ReschedulableMixin,
    ReminderMixin,
)
from .utils import (
    validate_time_slot,
    check_slot_conflict,
    calculate_duration,
    convert_timezone,
    format_datetime_for_calendar,
)

__all__ = [
    # Mixins
    'SchedulableMixin',
    'CancellableMixin',
    'ReschedulableMixin',
    'ReminderMixin',
    # Utils
    'validate_time_slot',
    'check_slot_conflict',
    'calculate_duration',
    'convert_timezone',
    'format_datetime_for_calendar',
]
