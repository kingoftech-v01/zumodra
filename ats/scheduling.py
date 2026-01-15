"""
ATS Interview Scheduling System

This module provides comprehensive interview scheduling functionality:
- InterviewSlot: Availability management for interviewers
- CalendarIntegration: Base class with Google/Outlook adapters
- Timezone-aware scheduling with candidate timezone support
- Interview panel coordination
- Automated reminder scheduling
- Reschedule/cancel workflows with notifications
- Video meeting link generation

All classes are tenant-aware and follow Zumodra's multi-tenant architecture.
"""

import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, date, time
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.conf import settings


# =============================================================================
# TIMEZONE VALIDATION UTILITIES
# =============================================================================

# Common valid timezones for quick validation
COMMON_TIMEZONES = frozenset([
    'UTC', 'America/New_York', 'America/Los_Angeles', 'America/Chicago',
    'America/Toronto', 'America/Vancouver', 'America/Montreal',
    'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Amsterdam',
    'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Singapore', 'Asia/Dubai',
    'Australia/Sydney', 'Australia/Melbourne', 'Pacific/Auckland',
])


def validate_timezone(tz: str) -> bool:
    """
    Validate that a timezone string is a valid IANA timezone.

    Args:
        tz: Timezone string to validate (e.g., 'America/Toronto', 'UTC')

    Returns:
        True if the timezone is valid, False otherwise

    Example:
        >>> validate_timezone('America/Toronto')
        True
        >>> validate_timezone('Invalid/Timezone')
        False
        >>> validate_timezone('')
        False
    """
    if not tz or not isinstance(tz, str):
        return False

    # Quick check for common timezones
    if tz in COMMON_TIMEZONES:
        return True

    # Try to instantiate ZoneInfo to validate
    try:
        ZoneInfo(tz)
        return True
    except (ZoneInfoNotFoundError, KeyError, ValueError):
        return False


def get_safe_timezone(tz: str, default: str = 'UTC') -> ZoneInfo:
    """
    Get a ZoneInfo object, falling back to default if invalid.

    Args:
        tz: Timezone string to convert
        default: Default timezone if tz is invalid

    Returns:
        ZoneInfo object for the timezone

    Raises:
        ValueError: If both tz and default are invalid

    Example:
        >>> get_safe_timezone('America/Toronto')
        ZoneInfo(key='America/Toronto')
        >>> get_safe_timezone('Invalid/Zone')
        ZoneInfo(key='UTC')
    """
    if validate_timezone(tz):
        return ZoneInfo(tz)

    logger.warning(f"Invalid timezone '{tz}', falling back to '{default}'")

    if validate_timezone(default):
        return ZoneInfo(default)

    raise ValueError(f"Both timezone '{tz}' and default '{default}' are invalid")
from django.db import models, transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from core.db.models import TenantAwareModel
from core.db.managers import TenantAwareManager
from ats.models import InterviewSlot

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class CalendarProvider(str, Enum):
    """Supported calendar providers."""
    GOOGLE = 'google'
    OUTLOOK = 'outlook'
    APPLE = 'apple'
    CALDAV = 'caldav'


class MeetingProvider(str, Enum):
    """Supported video meeting providers."""
    ZOOM = 'zoom'
    TEAMS = 'teams'
    GOOGLE_MEET = 'google_meet'
    WEBEX = 'webex'
    JITSI = 'jitsi'
    CUSTOM = 'custom'


class SlotStatus(str, Enum):
    """Interview slot status."""
    AVAILABLE = 'available'
    TENTATIVE = 'tentative'
    BOOKED = 'booked'
    BLOCKED = 'blocked'
    CANCELLED = 'cancelled'


class ReminderType(str, Enum):
    """Types of interview reminders."""
    ONE_DAY = '1_day'
    ONE_HOUR = '1_hour'
    FIFTEEN_MIN = '15_min'
    CUSTOM = 'custom'


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class TimeSlot:
    """Represents a time slot for scheduling."""
    start: datetime
    end: datetime
    timezone: str = 'UTC'

    @property
    def duration_minutes(self) -> int:
        """Return duration in minutes."""
        return int((self.end - self.start).total_seconds() / 60)

    def overlaps(self, other: 'TimeSlot') -> bool:
        """Check if this slot overlaps with another."""
        return self.start < other.end and other.start < self.end

    def to_timezone(self, tz: str) -> 'TimeSlot':
        """
        Convert to a different timezone.

        Args:
            tz: Target timezone string (e.g., 'America/Toronto')

        Returns:
            New TimeSlot with times converted to the target timezone

        Raises:
            ValueError: If timezone is invalid
        """
        if not validate_timezone(tz):
            raise ValueError(f"Invalid timezone: {tz}")

        target_tz = ZoneInfo(tz)
        return TimeSlot(
            start=self.start.astimezone(target_tz),
            end=self.end.astimezone(target_tz),
            timezone=tz
        )


@dataclass
class AvailabilitySlot:
    """Represents an interviewer's availability slot."""
    interviewer_id: str
    interviewer_name: str
    slot: TimeSlot
    status: SlotStatus = SlotStatus.AVAILABLE
    notes: str = ''


@dataclass
class CommonAvailability:
    """Common availability across multiple interviewers."""
    slot: TimeSlot
    available_interviewers: List[str]
    total_interviewers: int
    coverage_percentage: float


@dataclass
class MeetingDetails:
    """Video meeting details."""
    provider: MeetingProvider
    meeting_url: str
    meeting_id: str = ''
    password: str = ''
    dial_in_numbers: List[str] = field(default_factory=list)
    host_key: str = ''
    additional_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SchedulingResult:
    """Result of a scheduling operation."""
    success: bool
    interview_id: Optional[str] = None
    message: str = ''
    meeting_details: Optional[MeetingDetails] = None
    calendar_event_id: Optional[str] = None
    conflicts: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# =============================================================================
# INTERVIEWER AVAILABILITY MODEL
# =============================================================================

class InterviewerAvailability(TenantAwareModel):
    """
    Weekly recurring availability patterns for interviewers.

    Defines standard working hours for each day of the week.
    """

    interviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='availability_patterns'
    )
    day_of_week = models.PositiveSmallIntegerField(
        choices=[
            (0, _('Monday')),
            (1, _('Tuesday')),
            (2, _('Wednesday')),
            (3, _('Thursday')),
            (4, _('Friday')),
            (5, _('Saturday')),
            (6, _('Sunday')),
        ]
    )
    start_time = models.TimeField()
    end_time = models.TimeField()
    timezone = models.CharField(max_length=50, default='America/Toronto')
    is_active = models.BooleanField(default=True)

    # Interview preferences
    preferred_interview_types = models.JSONField(
        default=list,
        blank=True
    )
    max_interviews = models.PositiveIntegerField(default=4)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Interviewer Availability')
        verbose_name_plural = _('Interviewer Availabilities')
        ordering = ['day_of_week', 'start_time']
        constraints = [
            models.UniqueConstraint(
                fields=['tenant', 'interviewer', 'day_of_week', 'start_time'],
                name='ats_intervieweravailability_unique'
            )
        ]

    def __str__(self):
        return f"{self.interviewer.get_full_name()} - {self.get_day_of_week_display()}"


# =============================================================================
# AVAILABILITY EXCEPTION MODEL
# =============================================================================

class AvailabilityException(TenantAwareModel):
    """
    Exceptions to regular availability (vacation, blocked times, etc.).
    """

    interviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='availability_exceptions'
    )
    exception_date = models.DateField()
    start_time = models.TimeField(null=True, blank=True)
    end_time = models.TimeField(null=True, blank=True)
    is_all_day = models.BooleanField(default=True)
    reason = models.CharField(max_length=200, blank=True)
    exception_type = models.CharField(
        max_length=20,
        choices=[
            ('vacation', _('Vacation')),
            ('blocked', _('Blocked')),
            ('sick', _('Sick Leave')),
            ('meeting', _('Other Meeting')),
            ('holiday', _('Holiday')),
        ],
        default='blocked'
    )

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Availability Exception')
        verbose_name_plural = _('Availability Exceptions')
        ordering = ['exception_date', 'start_time']

    def __str__(self):
        return f"{self.interviewer.get_full_name()} - {self.exception_date}"


# =============================================================================
# INTERVIEW REMINDER MODEL
# =============================================================================

class InterviewReminder(TenantAwareModel):
    """
    Scheduled reminders for interviews.
    """

    interview = models.ForeignKey(
        'ats.Interview',
        on_delete=models.CASCADE,
        related_name='reminders'
    )
    reminder_type = models.CharField(
        max_length=20,
        choices=[(r.value, r.name.replace('_', ' ').title()) for r in ReminderType]
    )
    scheduled_at = models.DateTimeField()
    sent_at = models.DateTimeField(null=True, blank=True)
    recipient_type = models.CharField(
        max_length=20,
        choices=[
            ('candidate', _('Candidate')),
            ('interviewer', _('Interviewer')),
            ('all', _('All Participants')),
        ]
    )
    recipient_email = models.EmailField(blank=True)
    is_sent = models.BooleanField(default=False)
    send_sms = models.BooleanField(default=False)
    error_message = models.TextField(blank=True)

    objects = TenantAwareManager()

    class Meta:
        verbose_name = _('Interview Reminder')
        verbose_name_plural = _('Interview Reminders')
        ordering = ['scheduled_at']

    def __str__(self):
        return f"Reminder for {self.interview} at {self.scheduled_at}"

    def mark_sent(self):
        """Mark reminder as sent."""
        self.is_sent = True
        self.sent_at = timezone.now()
        self.save(update_fields=['is_sent', 'sent_at', 'updated_at'])


# =============================================================================
# CALENDAR INTEGRATION BASE CLASS
# =============================================================================

class CalendarIntegration(ABC):
    """
    Abstract base class for calendar integrations.

    Provides a common interface for interacting with different
    calendar providers (Google, Outlook, etc.).
    """

    def __init__(self, credentials: Dict[str, Any]):
        """
        Initialize calendar integration.

        Args:
            credentials: Provider-specific credentials
        """
        self.credentials = credentials
        self._client = None

    @abstractmethod
    def authenticate(self) -> bool:
        """
        Authenticate with the calendar provider.

        Returns:
            True if authentication successful
        """
        pass

    @abstractmethod
    def create_event(
        self,
        title: str,
        start: datetime,
        end: datetime,
        attendees: List[str],
        description: str = '',
        location: str = '',
        meeting_url: str = ''
    ) -> Optional[str]:
        """
        Create a calendar event.

        Args:
            title: Event title
            start: Start datetime
            end: End datetime
            attendees: List of attendee emails
            description: Event description
            location: Physical or virtual location
            meeting_url: Video meeting URL

        Returns:
            Event ID if created successfully
        """
        pass

    @abstractmethod
    def update_event(
        self,
        event_id: str,
        title: str = None,
        start: datetime = None,
        end: datetime = None,
        attendees: List[str] = None,
        description: str = None
    ) -> bool:
        """
        Update an existing calendar event.

        Returns:
            True if update successful
        """
        pass

    @abstractmethod
    def delete_event(self, event_id: str) -> bool:
        """
        Delete a calendar event.

        Returns:
            True if deletion successful
        """
        pass

    @abstractmethod
    def get_free_busy(
        self,
        emails: List[str],
        start: datetime,
        end: datetime
    ) -> Dict[str, List[TimeSlot]]:
        """
        Get free/busy information for users.

        Args:
            emails: List of user emails
            start: Start of time range
            end: End of time range

        Returns:
            Dict mapping email to list of busy TimeSlots
        """
        pass

    def find_common_availability(
        self,
        emails: List[str],
        start: datetime,
        end: datetime,
        duration_minutes: int = 60
    ) -> List[TimeSlot]:
        """
        Find common available time slots.

        Args:
            emails: List of participant emails
            start: Start of search range
            end: End of search range
            duration_minutes: Required duration

        Returns:
            List of available TimeSlots
        """
        busy_times = self.get_free_busy(emails, start, end)
        available_slots = []

        current = start
        while current + timedelta(minutes=duration_minutes) <= end:
            slot = TimeSlot(
                start=current,
                end=current + timedelta(minutes=duration_minutes)
            )

            # Check if slot conflicts with any busy time
            is_available = True
            for email, busy_slots in busy_times.items():
                for busy in busy_slots:
                    if slot.overlaps(busy):
                        is_available = False
                        break
                if not is_available:
                    break

            if is_available:
                available_slots.append(slot)

            current += timedelta(minutes=30)  # 30-minute increments

        return available_slots


# =============================================================================
# GOOGLE CALENDAR ADAPTER
# =============================================================================

class GoogleCalendarAdapter(CalendarIntegration):
    """
    Google Calendar integration adapter.
    """

    def authenticate(self) -> bool:
        """Authenticate with Google Calendar API."""
        try:
            # In production, this would use google-auth and googleapiclient
            # For now, we'll simulate authentication
            logger.info("Google Calendar authentication initiated")
            return True
        except Exception as e:
            logger.error(f"Google Calendar authentication failed: {e}")
            return False

    def create_event(
        self,
        title: str,
        start: datetime,
        end: datetime,
        attendees: List[str],
        description: str = '',
        location: str = '',
        meeting_url: str = ''
    ) -> Optional[str]:
        """Create a Google Calendar event."""
        try:
            # Build event body
            event_body = {
                'summary': title,
                'description': description,
                'location': location or meeting_url,
                'start': {
                    'dateTime': start.isoformat(),
                    'timeZone': str(start.tzinfo) if start.tzinfo else 'UTC',
                },
                'end': {
                    'dateTime': end.isoformat(),
                    'timeZone': str(end.tzinfo) if end.tzinfo else 'UTC',
                },
                'attendees': [{'email': email} for email in attendees],
                'conferenceData': {
                    'entryPoints': [
                        {
                            'entryPointType': 'video',
                            'uri': meeting_url,
                        }
                    ] if meeting_url else []
                },
                'reminders': {
                    'useDefault': False,
                    'overrides': [
                        {'method': 'email', 'minutes': 24 * 60},
                        {'method': 'popup', 'minutes': 60},
                    ],
                },
            }

            # In production, call Google Calendar API
            # event = service.events().insert(...).execute()
            event_id = f"gcal_{uuid.uuid4().hex[:12]}"

            logger.info(f"Created Google Calendar event: {event_id}")
            return event_id

        except Exception as e:
            logger.error(f"Failed to create Google Calendar event: {e}")
            return None

    def update_event(
        self,
        event_id: str,
        title: str = None,
        start: datetime = None,
        end: datetime = None,
        attendees: List[str] = None,
        description: str = None
    ) -> bool:
        """Update a Google Calendar event."""
        try:
            # Build update body with only provided fields
            update_body = {}
            if title:
                update_body['summary'] = title
            if description:
                update_body['description'] = description
            if start:
                update_body['start'] = {
                    'dateTime': start.isoformat(),
                    'timeZone': str(start.tzinfo) if start.tzinfo else 'UTC',
                }
            if end:
                update_body['end'] = {
                    'dateTime': end.isoformat(),
                    'timeZone': str(end.tzinfo) if end.tzinfo else 'UTC',
                }
            if attendees:
                update_body['attendees'] = [{'email': email} for email in attendees]

            # In production, call Google Calendar API
            # service.events().patch(eventId=event_id, body=update_body).execute()

            logger.info(f"Updated Google Calendar event: {event_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to update Google Calendar event: {e}")
            return False

    def delete_event(self, event_id: str) -> bool:
        """Delete a Google Calendar event."""
        try:
            # In production, call Google Calendar API
            # service.events().delete(eventId=event_id).execute()

            logger.info(f"Deleted Google Calendar event: {event_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete Google Calendar event: {e}")
            return False

    def get_free_busy(
        self,
        emails: List[str],
        start: datetime,
        end: datetime
    ) -> Dict[str, List[TimeSlot]]:
        """Get free/busy information from Google Calendar."""
        try:
            # In production, call Google Calendar API freebusy query
            # result = service.freebusy().query(body={...}).execute()

            # For now, return empty (all free)
            return {email: [] for email in emails}

        except Exception as e:
            logger.error(f"Failed to get free/busy from Google Calendar: {e}")
            return {email: [] for email in emails}


# =============================================================================
# OUTLOOK CALENDAR ADAPTER
# =============================================================================

class OutlookCalendarAdapter(CalendarIntegration):
    """
    Microsoft Outlook/365 Calendar integration adapter.
    """

    def authenticate(self) -> bool:
        """Authenticate with Microsoft Graph API."""
        try:
            # In production, this would use msal library
            logger.info("Outlook Calendar authentication initiated")
            return True
        except Exception as e:
            logger.error(f"Outlook Calendar authentication failed: {e}")
            return False

    def create_event(
        self,
        title: str,
        start: datetime,
        end: datetime,
        attendees: List[str],
        description: str = '',
        location: str = '',
        meeting_url: str = ''
    ) -> Optional[str]:
        """Create an Outlook Calendar event."""
        try:
            # Build event body for Microsoft Graph API
            event_body = {
                'subject': title,
                'body': {
                    'contentType': 'HTML',
                    'content': description,
                },
                'start': {
                    'dateTime': start.isoformat(),
                    'timeZone': str(start.tzinfo) if start.tzinfo else 'UTC',
                },
                'end': {
                    'dateTime': end.isoformat(),
                    'timeZone': str(end.tzinfo) if end.tzinfo else 'UTC',
                },
                'location': {
                    'displayName': location or meeting_url,
                },
                'attendees': [
                    {
                        'emailAddress': {'address': email},
                        'type': 'required'
                    }
                    for email in attendees
                ],
                'isOnlineMeeting': bool(meeting_url),
            }

            # In production, call Microsoft Graph API
            # response = graph_client.post('/me/events', json=event_body)
            event_id = f"outlook_{uuid.uuid4().hex[:12]}"

            logger.info(f"Created Outlook Calendar event: {event_id}")
            return event_id

        except Exception as e:
            logger.error(f"Failed to create Outlook Calendar event: {e}")
            return None

    def update_event(
        self,
        event_id: str,
        title: str = None,
        start: datetime = None,
        end: datetime = None,
        attendees: List[str] = None,
        description: str = None
    ) -> bool:
        """Update an Outlook Calendar event."""
        try:
            update_body = {}
            if title:
                update_body['subject'] = title
            if description:
                update_body['body'] = {'contentType': 'HTML', 'content': description}
            if start:
                update_body['start'] = {
                    'dateTime': start.isoformat(),
                    'timeZone': str(start.tzinfo) if start.tzinfo else 'UTC',
                }
            if end:
                update_body['end'] = {
                    'dateTime': end.isoformat(),
                    'timeZone': str(end.tzinfo) if end.tzinfo else 'UTC',
                }
            if attendees:
                update_body['attendees'] = [
                    {'emailAddress': {'address': email}, 'type': 'required'}
                    for email in attendees
                ]

            # In production, call Microsoft Graph API
            logger.info(f"Updated Outlook Calendar event: {event_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to update Outlook Calendar event: {e}")
            return False

    def delete_event(self, event_id: str) -> bool:
        """Delete an Outlook Calendar event."""
        try:
            # In production, call Microsoft Graph API
            logger.info(f"Deleted Outlook Calendar event: {event_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete Outlook Calendar event: {e}")
            return False

    def get_free_busy(
        self,
        emails: List[str],
        start: datetime,
        end: datetime
    ) -> Dict[str, List[TimeSlot]]:
        """Get free/busy information from Outlook Calendar."""
        try:
            # In production, call Microsoft Graph API
            return {email: [] for email in emails}

        except Exception as e:
            logger.error(f"Failed to get free/busy from Outlook Calendar: {e}")
            return {email: [] for email in emails}


# =============================================================================
# MEETING LINK GENERATOR
# =============================================================================

class MeetingLinkGenerator:
    """
    Service for generating video meeting links.
    """

    @staticmethod
    def generate_zoom_meeting(
        topic: str,
        start_time: datetime,
        duration_minutes: int,
        host_email: str = None,
        settings: Dict[str, Any] = None
    ) -> MeetingDetails:
        """
        Generate a Zoom meeting link.

        In production, this would call the Zoom API.
        """
        meeting_id = str(uuid.uuid4().int)[:10]
        password = uuid.uuid4().hex[:6].upper()

        return MeetingDetails(
            provider=MeetingProvider.ZOOM,
            meeting_url=f"https://zoom.us/j/{meeting_id}",
            meeting_id=meeting_id,
            password=password,
            dial_in_numbers=['+1-929-205-6099', '+1-312-626-6799'],
            additional_info={
                'topic': topic,
                'duration': duration_minutes,
                'host_email': host_email,
            }
        )

    @staticmethod
    def generate_teams_meeting(
        subject: str,
        start_time: datetime,
        end_time: datetime,
        organizer_email: str = None
    ) -> MeetingDetails:
        """
        Generate a Microsoft Teams meeting link.

        In production, this would call the Microsoft Graph API.
        """
        meeting_id = uuid.uuid4().hex[:12]

        return MeetingDetails(
            provider=MeetingProvider.TEAMS,
            meeting_url=f"https://teams.microsoft.com/l/meetup-join/{meeting_id}",
            meeting_id=meeting_id,
            additional_info={
                'subject': subject,
                'organizer': organizer_email,
            }
        )

    @staticmethod
    def generate_google_meet(
        title: str,
        calendar_event_id: str = None
    ) -> MeetingDetails:
        """
        Generate a Google Meet link.

        In production, this would be created with the Calendar event.
        """
        meeting_code = f"{uuid.uuid4().hex[:3]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:3]}"

        return MeetingDetails(
            provider=MeetingProvider.GOOGLE_MEET,
            meeting_url=f"https://meet.google.com/{meeting_code}",
            meeting_id=meeting_code,
            additional_info={
                'title': title,
                'calendar_event_id': calendar_event_id,
            }
        )

    @staticmethod
    def generate_jitsi_meeting(
        room_name: str = None
    ) -> MeetingDetails:
        """
        Generate a Jitsi Meet link (no API required).
        """
        room = room_name or f"zumodra-interview-{uuid.uuid4().hex[:8]}"

        return MeetingDetails(
            provider=MeetingProvider.JITSI,
            meeting_url=f"https://meet.jit.si/{room}",
            meeting_id=room,
            additional_info={
                'room_name': room,
                'no_registration_required': True,
            }
        )

    @classmethod
    def generate_meeting(
        cls,
        provider: MeetingProvider,
        topic: str,
        start_time: datetime,
        end_time: datetime,
        host_email: str = None
    ) -> MeetingDetails:
        """
        Generate a meeting link for the specified provider.

        Args:
            provider: Video meeting provider
            topic: Meeting topic/subject
            start_time: Start datetime
            end_time: End datetime
            host_email: Optional host email

        Returns:
            MeetingDetails with link and credentials
        """
        duration = int((end_time - start_time).total_seconds() / 60)

        if provider == MeetingProvider.ZOOM:
            return cls.generate_zoom_meeting(topic, start_time, duration, host_email)
        elif provider == MeetingProvider.TEAMS:
            return cls.generate_teams_meeting(topic, start_time, end_time, host_email)
        elif provider == MeetingProvider.GOOGLE_MEET:
            return cls.generate_google_meet(topic)
        elif provider == MeetingProvider.JITSI:
            return cls.generate_jitsi_meeting()
        else:
            # Default to Jitsi for unsupported providers
            return cls.generate_jitsi_meeting()


# =============================================================================
# INTERVIEW SCHEDULING SERVICE
# =============================================================================

class InterviewSchedulingService:
    """
    Comprehensive service for interview scheduling operations.
    """

    @staticmethod
    def get_interviewer_availability(
        tenant,
        interviewer,
        start_date: date,
        end_date: date,
        duration_minutes: int = 60
    ) -> List[AvailabilitySlot]:
        """
        Get available time slots for an interviewer.

        Args:
            tenant: Tenant context
            interviewer: Interviewer user
            start_date: Start of date range
            end_date: End of date range
            duration_minutes: Required duration

        Returns:
            List of available slots
        """
        available_slots = []

        # Get recurring availability patterns
        patterns = InterviewerAvailability.objects.filter(
            tenant=tenant,
            interviewer=interviewer,
            is_active=True
        )

        # Get exceptions
        exceptions = AvailabilityException.objects.filter(
            tenant=tenant,
            interviewer=interviewer,
            exception_date__range=[start_date, end_date]
        )
        exception_dates = set(e.exception_date for e in exceptions if e.is_all_day)

        # Get existing interview slots
        existing_slots = InterviewSlot.objects.filter(
            tenant=tenant,
            interviewer=interviewer,
            start_time__date__range=[start_date, end_date],
            status=SlotStatus.BOOKED.value
        )

        # Generate slots from patterns
        current_date = start_date
        while current_date <= end_date:
            # Skip exception dates
            if current_date in exception_dates:
                current_date += timedelta(days=1)
                continue

            day_patterns = patterns.filter(day_of_week=current_date.weekday())

            for pattern in day_patterns:
                # Validate timezone before using
                if not validate_timezone(pattern.timezone):
                    logger.warning(
                        f"Invalid timezone '{pattern.timezone}' for pattern {pattern.id}, skipping"
                    )
                    continue
                tz = ZoneInfo(pattern.timezone)
                slot_start = datetime.combine(current_date, pattern.start_time, tzinfo=tz)
                slot_end = datetime.combine(current_date, pattern.end_time, tzinfo=tz)

                # Skip past times
                if slot_end < timezone.now():
                    continue

                # Check for partial exceptions
                partial_exceptions = exceptions.filter(
                    exception_date=current_date,
                    is_all_day=False
                )

                # Generate time slots within the pattern
                current_slot_start = slot_start
                while current_slot_start + timedelta(minutes=duration_minutes) <= slot_end:
                    slot_end_time = current_slot_start + timedelta(minutes=duration_minutes)

                    # Check conflicts
                    has_conflict = False

                    # Check partial exceptions
                    for exc in partial_exceptions:
                        exc_start = datetime.combine(current_date, exc.start_time, tzinfo=tz)
                        exc_end = datetime.combine(current_date, exc.end_time, tzinfo=tz)
                        if current_slot_start < exc_end and slot_end_time > exc_start:
                            has_conflict = True
                            break

                    # Check existing bookings
                    for existing in existing_slots:
                        if current_slot_start < existing.end_time and slot_end_time > existing.start_time:
                            has_conflict = True
                            break

                    if not has_conflict:
                        available_slots.append(AvailabilitySlot(
                            interviewer_id=str(interviewer.id),
                            interviewer_name=interviewer.get_full_name(),
                            slot=TimeSlot(
                                start=current_slot_start,
                                end=slot_end_time,
                                timezone=pattern.timezone
                            ),
                            status=SlotStatus.AVAILABLE
                        ))

                    current_slot_start += timedelta(minutes=30)  # 30-min increments

            current_date += timedelta(days=1)

        return available_slots

    @staticmethod
    def find_panel_availability(
        tenant,
        interviewers: List,
        start_date: date,
        end_date: date,
        duration_minutes: int = 60,
        min_interviewers: int = None
    ) -> List[CommonAvailability]:
        """
        Find common availability across multiple interviewers.

        Args:
            tenant: Tenant context
            interviewers: List of interviewer users
            start_date: Start of date range
            end_date: End of date range
            duration_minutes: Required duration
            min_interviewers: Minimum required interviewers (default: all)

        Returns:
            List of CommonAvailability slots
        """
        if not interviewers:
            return []

        min_required = min_interviewers or len(interviewers)

        # Get availability for each interviewer
        all_availability = {}
        for interviewer in interviewers:
            slots = InterviewSchedulingService.get_interviewer_availability(
                tenant, interviewer, start_date, end_date, duration_minutes
            )
            all_availability[str(interviewer.id)] = slots

        # Find common slots
        common_slots = []

        # Get all unique time slots
        all_slots: Dict[Tuple[datetime, datetime], List[str]] = {}
        for interviewer_id, slots in all_availability.items():
            for avail_slot in slots:
                key = (avail_slot.slot.start, avail_slot.slot.end)
                if key not in all_slots:
                    all_slots[key] = []
                all_slots[key].append(interviewer_id)

        # Filter to slots with minimum interviewers
        for (start, end), available_ids in all_slots.items():
            if len(available_ids) >= min_required:
                common_slots.append(CommonAvailability(
                    slot=TimeSlot(start=start, end=end),
                    available_interviewers=available_ids,
                    total_interviewers=len(interviewers),
                    coverage_percentage=len(available_ids) / len(interviewers) * 100
                ))

        # Sort by coverage percentage (higher first) then by time
        common_slots.sort(key=lambda x: (-x.coverage_percentage, x.slot.start))

        return common_slots

    @staticmethod
    @transaction.atomic
    def schedule_interview(
        tenant,
        application,
        interview_type: str,
        scheduled_start: datetime,
        scheduled_end: datetime,
        interviewers: List,
        title: str = None,
        description: str = '',
        location: str = '',
        meeting_provider: MeetingProvider = None,
        organizer=None,
        candidate_timezone: str = 'America/Toronto',
        send_invites: bool = True,
        create_reminders: bool = True,
        user=None
    ) -> SchedulingResult:
        """
        Schedule an interview with all related operations.

        Args:
            tenant: Tenant context
            application: Application being interviewed
            interview_type: Type of interview
            scheduled_start: Start datetime
            scheduled_end: End datetime
            interviewers: List of interviewer users
            title: Interview title
            description: Description/instructions
            location: Physical location (if in-person)
            meeting_provider: Video meeting provider
            organizer: User organizing the interview
            candidate_timezone: Candidate's timezone
            send_invites: Send calendar invites
            create_reminders: Create reminder notifications
            user: User performing the action (for permission checks)

        Returns:
            SchedulingResult with interview details

        Raises:
            PermissionError: If user lacks permission to schedule interviews
        """
        from ats.models import Interview

        # Permission check: require user with appropriate permissions
        if user is not None:
            if not hasattr(user, 'has_perm') or not (
                user.has_perm('ats.schedule_interview') or
                user.has_perm('ats.manage_interviews') or
                getattr(user, 'is_superuser', False)
            ):
                logger.warning(
                    f"User {user.id} attempted to schedule interview without permission"
                )
                raise PermissionError("User lacks permission to schedule interviews")

            # Verify application belongs to the correct tenant
            if application.tenant != tenant:
                logger.warning(
                    f"Tenant mismatch: user tenant {tenant.id} vs application tenant {application.tenant.id}"
                )
                raise PermissionError("Application does not belong to this tenant")

        # Validate candidate timezone
        if not validate_timezone(candidate_timezone):
            logger.warning(f"Invalid candidate timezone: {candidate_timezone}, using default")
            candidate_timezone = 'America/Toronto'

        conflicts = []
        warnings = []

        # Check for scheduling conflicts
        for interviewer in interviewers:
            conflicting = InterviewSlot.objects.filter(
                tenant=tenant,
                interviewer=interviewer,
                start_time__lt=scheduled_end,
                end_time__gt=scheduled_start,
                status=SlotStatus.BOOKED.value
            ).exists()

            if conflicting:
                conflicts.append(
                    f"{interviewer.get_full_name()} has a conflicting interview"
                )

        if conflicts:
            return SchedulingResult(
                success=False,
                message='Scheduling conflicts detected',
                conflicts=conflicts
            )

        # Generate meeting link if requested
        meeting_details = None
        if meeting_provider:
            meeting_details = MeetingLinkGenerator.generate_meeting(
                provider=meeting_provider,
                topic=title or f"Interview with {application.candidate.full_name}",
                start_time=scheduled_start,
                end_time=scheduled_end,
                host_email=organizer.email if organizer else None
            )

        # Create the interview
        interview = Interview.objects.create(
            application=application,
            interview_type=interview_type,
            status='scheduled',
            title=title or f"{interview_type.replace('_', ' ').title()} Interview",
            description=description,
            scheduled_start=scheduled_start,
            scheduled_end=scheduled_end,
            timezone=candidate_timezone,
            location=location,
            meeting_url=meeting_details.meeting_url if meeting_details else '',
            meeting_id=meeting_details.meeting_id if meeting_details else '',
            meeting_password=meeting_details.password if meeting_details else '',
            organizer=organizer,
        )

        # Add interviewers
        interview.interviewers.set(interviewers)

        # Create interview slots for each interviewer
        for interviewer in interviewers:
            InterviewSlot.objects.create(
                tenant=tenant,
                interviewer=interviewer,
                start_time=scheduled_start,
                end_time=scheduled_end,
                timezone=candidate_timezone,
                status=SlotStatus.BOOKED.value,
                booked_interview=interview,
            )

        # Create reminders if requested
        if create_reminders:
            InterviewSchedulingService._create_default_reminders(
                tenant, interview, application.candidate.email
            )

        # Send calendar invites (in production, integrate with calendar service)
        if send_invites:
            attendee_emails = [application.candidate.email]
            attendee_emails.extend([i.email for i in interviewers])
            # Calendar integration would happen here
            logger.info(f"Calendar invites would be sent to: {attendee_emails}")

        logger.info(
            f"Interview scheduled: {interview.id} for application {application.id}"
        )

        return SchedulingResult(
            success=True,
            interview_id=str(interview.id),
            message='Interview scheduled successfully',
            meeting_details=meeting_details,
            warnings=warnings
        )

    @staticmethod
    def _create_default_reminders(tenant, interview, candidate_email: str):
        """Create default reminder schedule for an interview."""
        # 1 day before
        one_day_before = interview.scheduled_start - timedelta(days=1)
        if one_day_before > timezone.now():
            InterviewReminder.objects.create(
                tenant=tenant,
                interview=interview,
                reminder_type=ReminderType.ONE_DAY.value,
                scheduled_at=one_day_before,
                recipient_type='all',
            )

        # 1 hour before
        one_hour_before = interview.scheduled_start - timedelta(hours=1)
        if one_hour_before > timezone.now():
            InterviewReminder.objects.create(
                tenant=tenant,
                interview=interview,
                reminder_type=ReminderType.ONE_HOUR.value,
                scheduled_at=one_hour_before,
                recipient_type='all',
            )

        # 15 minutes before (candidate only)
        fifteen_min_before = interview.scheduled_start - timedelta(minutes=15)
        if fifteen_min_before > timezone.now():
            InterviewReminder.objects.create(
                tenant=tenant,
                interview=interview,
                reminder_type=ReminderType.FIFTEEN_MIN.value,
                scheduled_at=fifteen_min_before,
                recipient_type='candidate',
                recipient_email=candidate_email,
            )

    @staticmethod
    @transaction.atomic
    def reschedule_interview(
        interview,
        new_start: datetime,
        new_end: datetime,
        reason: str = '',
        notify_participants: bool = True
    ) -> SchedulingResult:
        """
        Reschedule an existing interview.

        Args:
            interview: Interview to reschedule
            new_start: New start datetime
            new_end: New end datetime
            reason: Reason for rescheduling
            notify_participants: Send notifications

        Returns:
            SchedulingResult with update status
        """
        old_start = interview.scheduled_start
        old_end = interview.scheduled_end

        # Update interview times
        interview.scheduled_start = new_start
        interview.scheduled_end = new_end
        interview.status = 'rescheduled'
        interview.save()

        # Update associated slots
        InterviewSlot.objects.filter(
            booked_interview=interview
        ).update(
            start_time=new_start,
            end_time=new_end
        )

        # Delete old reminders and create new ones
        InterviewReminder.objects.filter(
            interview=interview,
            is_sent=False
        ).delete()

        InterviewSchedulingService._create_default_reminders(
            interview.application.tenant,
            interview,
            interview.application.candidate.email
        )

        # Log activity
        from ats.models import ApplicationActivity
        ApplicationActivity.objects.create(
            application=interview.application,
            activity_type='interview_scheduled',
            notes=f"Interview rescheduled from {old_start} to {new_start}. Reason: {reason}",
            metadata={
                'old_start': old_start.isoformat(),
                'old_end': old_end.isoformat(),
                'new_start': new_start.isoformat(),
                'new_end': new_end.isoformat(),
                'reason': reason,
            }
        )

        logger.info(f"Interview {interview.id} rescheduled to {new_start}")

        return SchedulingResult(
            success=True,
            interview_id=str(interview.id),
            message='Interview rescheduled successfully'
        )

    @staticmethod
    @transaction.atomic
    def cancel_interview(
        interview,
        reason: str = '',
        notify_participants: bool = True,
        cancelled_by=None
    ) -> SchedulingResult:
        """
        Cancel an interview.

        Args:
            interview: Interview to cancel
            reason: Cancellation reason
            notify_participants: Send notifications
            cancelled_by: User cancelling

        Returns:
            SchedulingResult with status
        """
        interview.status = 'cancelled'
        interview.save()

        # Release interview slots
        InterviewSlot.objects.filter(
            booked_interview=interview
        ).update(
            status=SlotStatus.CANCELLED.value,
            booked_interview=None
        )

        # Cancel pending reminders
        InterviewReminder.objects.filter(
            interview=interview,
            is_sent=False
        ).delete()

        # Log activity
        from ats.models import ApplicationActivity
        ApplicationActivity.objects.create(
            application=interview.application,
            activity_type='interview_scheduled',
            performed_by=cancelled_by,
            notes=f"Interview cancelled. Reason: {reason}",
            metadata={
                'action': 'cancelled',
                'reason': reason,
            }
        )

        logger.info(f"Interview {interview.id} cancelled")

        return SchedulingResult(
            success=True,
            interview_id=str(interview.id),
            message='Interview cancelled successfully'
        )

    @staticmethod
    def get_upcoming_interviews(
        tenant,
        user=None,
        days_ahead: int = 7
    ) -> List:
        """
        Get upcoming interviews.

        Args:
            tenant: Tenant context
            user: Optional user to filter by (as interviewer)
            days_ahead: Number of days to look ahead

        Returns:
            QuerySet of upcoming interviews
        """
        from ats.models import Interview

        now = timezone.now()
        end_date = now + timedelta(days=days_ahead)

        queryset = Interview.objects.filter(
            application__tenant=tenant,
            scheduled_start__range=[now, end_date],
            status__in=['scheduled', 'confirmed']
        ).select_related(
            'application', 'application__candidate', 'application__job'
        ).prefetch_related('interviewers')

        if user:
            queryset = queryset.filter(interviewers=user)

        return queryset.order_by('scheduled_start')

    @staticmethod
    def send_pending_reminders(tenant) -> int:
        """
        Send all pending reminders that are due.

        Args:
            tenant: Tenant context

        Returns:
            Count of reminders sent
        """
        now = timezone.now()
        pending = InterviewReminder.objects.filter(
            tenant=tenant,
            scheduled_at__lte=now,
            is_sent=False,
            interview__status__in=['scheduled', 'confirmed']
        ).select_related('interview', 'interview__application')

        sent_count = 0
        for reminder in pending:
            try:
                # In production, send actual email/SMS
                logger.info(
                    f"Sending {reminder.reminder_type} reminder for interview "
                    f"{reminder.interview.id} to {reminder.recipient_type}"
                )
                reminder.mark_sent()
                sent_count += 1
            except Exception as e:
                logger.error(f"Failed to send reminder {reminder.id}: {e}")
                reminder.error_message = str(e)
                reminder.save(update_fields=['error_message'])

        return sent_count
