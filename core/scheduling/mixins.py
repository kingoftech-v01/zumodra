"""
Shared mixins for scheduling functionality.

These mixins provide common behavior for both recruitment interviews
(jobs.Interview) and service appointments (interviews.Appointment).

Author: Zumodra Team
Since: 2026-01-17
"""

from datetime import datetime, timedelta
from typing import Optional

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class SchedulableMixin(models.Model):
    """
    Mixin for schedulable entities (interviews, appointments).

    Provides common fields and methods for scheduling start/end times,
    timezone handling, and duration calculation.
    """

    scheduled_start = models.DateTimeField(
        verbose_name=_("Scheduled Start"),
        help_text=_("The scheduled start date and time"),
        db_index=True  # Index for querying upcoming/past items
    )
    scheduled_end = models.DateTimeField(
        verbose_name=_("Scheduled End"),
        help_text=_("The scheduled end date and time")
    )
    timezone = models.CharField(
        max_length=50,
        default='America/Toronto',
        verbose_name=_("Timezone"),
        help_text=_("Timezone for the scheduled times")
    )
    actual_start = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Actual Start"),
        help_text=_("The actual start time (if different from scheduled)")
    )
    actual_end = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Actual End"),
        help_text=_("The actual end time (if different from scheduled)")
    )

    class Meta:
        abstract = True

    def clean(self):
        """Validate scheduling fields."""
        super().clean()

        # Ensure start is before end
        if self.scheduled_start and self.scheduled_end:
            if self.scheduled_start >= self.scheduled_end:
                raise ValidationError({
                    'scheduled_end': _("End time must be after start time")
                })

        # Validate actual times if provided
        if self.actual_start and self.actual_end:
            if self.actual_start >= self.actual_end:
                raise ValidationError({
                    'actual_end': _("Actual end time must be after actual start time")
                })

    @property
    def scheduled_duration(self) -> timedelta:
        """Calculate scheduled duration."""
        if self.scheduled_start and self.scheduled_end:
            return self.scheduled_end - self.scheduled_start
        return timedelta(0)

    @property
    def actual_duration(self) -> Optional[timedelta]:
        """Calculate actual duration if both times are set."""
        if self.actual_start and self.actual_end:
            return self.actual_end - self.actual_start
        return None

    def is_upcoming(self) -> bool:
        """Check if the scheduled item is in the future."""
        return self.scheduled_start > timezone.now()

    def is_past(self) -> bool:
        """Check if the scheduled item is in the past."""
        return self.scheduled_end < timezone.now()

    def is_in_progress(self) -> bool:
        """Check if the scheduled item is currently happening."""
        now = timezone.now()
        return self.scheduled_start <= now <= self.scheduled_end

    def time_until_start(self) -> Optional[timedelta]:
        """Calculate time remaining until start."""
        if self.is_upcoming():
            return self.scheduled_start - timezone.now()
        return None

    def convert_to_timezone(self, target_timezone: str) -> dict:
        """
        Convert scheduled times to target timezone.

        Args:
            target_timezone: Target timezone string (e.g., 'America/New_York')

        Returns:
            dict with 'start' and 'end' in target timezone
        """
        import pytz

        source_tz = pytz.timezone(self.timezone)
        target_tz = pytz.timezone(target_timezone)

        # Localize to source timezone
        start_localized = source_tz.localize(self.scheduled_start.replace(tzinfo=None))
        end_localized = source_tz.localize(self.scheduled_end.replace(tzinfo=None))

        # Convert to target timezone
        start_converted = start_localized.astimezone(target_tz)
        end_converted = end_localized.astimezone(target_tz)

        return {
            'start': start_converted,
            'end': end_converted,
            'timezone': target_timezone
        }


class CancellableMixin(models.Model):
    """
    Mixin for cancellable entities.

    Provides fields and methods for tracking cancellations with
    timestamps, reasons, and the user who cancelled.
    """

    cancelled_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Cancelled At"),
        help_text=_("Timestamp when the item was cancelled")
    )
    cancelled_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(app_label)s_%(class)s_cancelled',
        verbose_name=_("Cancelled By"),
        help_text=_("User who cancelled the item")
    )
    cancellation_reason = models.TextField(
        blank=True,
        verbose_name=_("Cancellation Reason"),
        help_text=_("Reason provided for cancellation")
    )

    class Meta:
        abstract = True

    @property
    def is_cancelled(self) -> bool:
        """Check if the item has been cancelled."""
        return self.cancelled_at is not None

    def cancel(self, user: 'settings.AUTH_USER_MODEL', reason: str = '') -> None:
        """
        Cancel the item.

        Args:
            user: User performing the cancellation
            reason: Optional reason for cancellation
        """
        self.cancelled_at = timezone.now()
        self.cancelled_by = user
        self.cancellation_reason = reason
        self.save(update_fields=['cancelled_at', 'cancelled_by', 'cancellation_reason'])

    def can_be_cancelled(self) -> bool:
        """
        Check if the item can be cancelled.

        Override this method in subclasses to add custom logic.
        By default, only non-cancelled items can be cancelled.
        """
        return not self.is_cancelled


class ReschedulableMixin(models.Model):
    """
    Mixin for reschedulable entities.

    Provides fields and methods for tracking reschedule attempts
    and enforcing reschedule limits.
    """

    reschedule_count = models.PositiveIntegerField(
        default=0,
        verbose_name=_("Reschedule Count"),
        help_text=_("Number of times this item has been rescheduled")
    )
    reschedule_limit = models.PositiveIntegerField(
        null=True,
        blank=True,
        verbose_name=_("Reschedule Limit"),
        help_text=_("Maximum number of allowed reschedules (null = unlimited)")
    )
    last_rescheduled_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Last Rescheduled At"),
        help_text=_("Timestamp of the most recent reschedule")
    )

    class Meta:
        abstract = True

    def can_be_rescheduled(self) -> bool:
        """
        Check if the item can be rescheduled.

        Returns:
            True if reschedule is allowed, False otherwise
        """
        # No limit set = unlimited reschedules
        if self.reschedule_limit is None:
            return True

        # Check if under the limit
        return self.reschedule_count < self.reschedule_limit

    def increment_reschedule_count(self) -> None:
        """Increment the reschedule counter and update timestamp."""
        self.reschedule_count += 1
        self.last_rescheduled_at = timezone.now()
        self.save(update_fields=['reschedule_count', 'last_rescheduled_at'])

    @property
    def remaining_reschedules(self) -> Optional[int]:
        """
        Get number of remaining reschedules.

        Returns:
            Remaining reschedules or None if unlimited
        """
        if self.reschedule_limit is None:
            return None
        return max(0, self.reschedule_limit - self.reschedule_count)


class ReminderMixin(models.Model):
    """
    Mixin for entities that send reminders.

    Tracks multiple reminder levels (1 day, 1 hour, 15 minutes)
    commonly used in scheduling systems.
    """

    reminder_sent_1day = models.BooleanField(
        default=False,
        verbose_name=_("1-Day Reminder Sent"),
        help_text=_("Whether 1-day advance reminder was sent")
    )
    reminder_sent_1hour = models.BooleanField(
        default=False,
        verbose_name=_("1-Hour Reminder Sent"),
        help_text=_("Whether 1-hour advance reminder was sent")
    )
    reminder_sent_15min = models.BooleanField(
        default=False,
        verbose_name=_("15-Minute Reminder Sent"),
        help_text=_("Whether 15-minute advance reminder was sent")
    )
    reminder_enabled = models.BooleanField(
        default=True,
        verbose_name=_("Reminders Enabled"),
        help_text=_("Whether automatic reminders should be sent")
    )

    class Meta:
        abstract = True

    def should_send_1day_reminder(self, scheduled_time: datetime) -> bool:
        """
        Check if 1-day reminder should be sent.

        Args:
            scheduled_time: The scheduled datetime

        Returns:
            True if reminder should be sent now
        """
        if not self.reminder_enabled or self.reminder_sent_1day:
            return False

        now = timezone.now()
        time_until = scheduled_time - now

        # Send if between 24h and 23h before event
        return timedelta(hours=23) <= time_until <= timedelta(hours=24)

    def should_send_1hour_reminder(self, scheduled_time: datetime) -> bool:
        """
        Check if 1-hour reminder should be sent.

        Args:
            scheduled_time: The scheduled datetime

        Returns:
            True if reminder should be sent now
        """
        if not self.reminder_enabled or self.reminder_sent_1hour:
            return False

        now = timezone.now()
        time_until = scheduled_time - now

        # Send if between 1h and 55min before event
        return timedelta(minutes=55) <= time_until <= timedelta(hours=1)

    def should_send_15min_reminder(self, scheduled_time: datetime) -> bool:
        """
        Check if 15-minute reminder should be sent.

        Args:
            scheduled_time: The scheduled datetime

        Returns:
            True if reminder should be sent now
        """
        if not self.reminder_enabled or self.reminder_sent_15min:
            return False

        now = timezone.now()
        time_until = scheduled_time - now

        # Send if between 15min and 10min before event
        return timedelta(minutes=10) <= time_until <= timedelta(minutes=15)

    def mark_reminder_sent(self, reminder_type: str) -> None:
        """
        Mark a specific reminder as sent.

        Args:
            reminder_type: One of '1day', '1hour', '15min'
        """
        field_map = {
            '1day': 'reminder_sent_1day',
            '1hour': 'reminder_sent_1hour',
            '15min': 'reminder_sent_15min',
        }

        field_name = field_map.get(reminder_type)
        if field_name:
            setattr(self, field_name, True)
            self.save(update_fields=[field_name])

    def reset_reminders(self) -> None:
        """Reset all reminder flags (useful after rescheduling)."""
        self.reminder_sent_1day = False
        self.reminder_sent_1hour = False
        self.reminder_sent_15min = False
        self.save(update_fields=[
            'reminder_sent_1day',
            'reminder_sent_1hour',
            'reminder_sent_15min'
        ])
