"""
Calendar integration for scheduling.

Supports generating calendar invites and syncing with:
- Google Calendar
- Microsoft Outlook/Office 365
- iCalendar (.ics files)

Author: Zumodra Team
Since: 2026-01-17
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from io import BytesIO

import pytz
from django.conf import settings
from django.utils.translation import gettext as _


class CalendarEventGenerator:
    """
    Generator for calendar events in various formats.

    Supports iCalendar (.ics), Google Calendar, and Outlook formats.
    """

    def __init__(self, event_data: Dict[str, Any]):
        """
        Initialize calendar event generator.

        Args:
            event_data: Dictionary containing event details:
                - title: Event title
                - description: Event description
                - start: Start datetime
                - end: End datetime
                - location: Location (optional)
                - meeting_url: Video meeting URL (optional)
                - organizer_email: Organizer email
                - organizer_name: Organizer name
                - attendees: List of attendee emails
                - timezone: Timezone string
        """
        self.data = event_data

    def generate_icalendar(self) -> str:
        """
        Generate iCalendar (.ics) format event.

        Returns:
            iCalendar format string
        """
        from icalendar import Calendar, Event, vCalAddress, vText

        # Create calendar
        cal = Calendar()
        cal.add('prodid', '-//Zumodra Scheduling//zumodra.com//')
        cal.add('version', '2.0')
        cal.add('method', 'REQUEST')

        # Create event
        event = Event()
        event.add('summary', self.data['title'])
        event.add('description', self.data.get('description', ''))
        event.add('dtstart', self.data['start'])
        event.add('dtend', self.data['end'])
        event.add('dtstamp', datetime.now(pytz.UTC))

        # Add location
        if self.data.get('location'):
            event.add('location', self.data['location'])

        # Add meeting URL to description if present
        if self.data.get('meeting_url'):
            description = self.data.get('description', '')
            description += f"\n\nJoin meeting: {self.data['meeting_url']}"
            event['description'] = vText(description)

        # Add organizer
        if self.data.get('organizer_email'):
            organizer = vCalAddress(f"MAILTO:{self.data['organizer_email']}")
            organizer.params['cn'] = vText(self.data.get('organizer_name', ''))
            organizer.params['role'] = vText('CHAIR')
            event['organizer'] = organizer

        # Add attendees
        for attendee_email in self.data.get('attendees', []):
            attendee = vCalAddress(f"MAILTO:{attendee_email}")
            attendee.params['role'] = vText('REQ-PARTICIPANT')
            attendee.params['rsvp'] = vText('TRUE')
            event.add('attendee', attendee, encode=0)

        # Add timezone
        if self.data.get('timezone'):
            event.add('tzid', self.data['timezone'])

        # Add to calendar
        cal.add_component(event)

        return cal.to_ical().decode('utf-8')

    def generate_google_calendar_url(self) -> str:
        """
        Generate Google Calendar add event URL.

        Returns:
            Google Calendar URL
        """
        from urllib.parse import urlencode

        # Format dates for Google Calendar
        start = self._format_google_date(self.data['start'])
        end = self._format_google_date(self.data['end'])

        # Build parameters
        params = {
            'action': 'TEMPLATE',
            'text': self.data['title'],
            'dates': f"{start}/{end}",
        }

        if self.data.get('description'):
            params['details'] = self.data['description']

        if self.data.get('location'):
            params['location'] = self.data['location']
        elif self.data.get('meeting_url'):
            params['location'] = self.data['meeting_url']

        # Add attendees (comma-separated)
        if self.data.get('attendees'):
            params['add'] = ','.join(self.data['attendees'])

        base_url = 'https://calendar.google.com/calendar/render'
        return f"{base_url}?{urlencode(params)}"

    def generate_outlook_url(self) -> str:
        """
        Generate Outlook/Office 365 add event URL.

        Returns:
            Outlook calendar URL
        """
        from urllib.parse import urlencode

        # Format dates for Outlook (ISO 8601)
        start = self.data['start'].isoformat()
        end = self.data['end'].isoformat()

        # Build parameters
        params = {
            'path': '/calendar/action/compose',
            'rru': 'addevent',
            'subject': self.data['title'],
            'startdt': start,
            'enddt': end,
        }

        if self.data.get('description'):
            params['body'] = self.data['description']

        if self.data.get('location'):
            params['location'] = self.data['location']
        elif self.data.get('meeting_url'):
            # Add meeting URL to body
            body = params.get('body', '')
            body += f"\n\nJoin meeting: {self.data['meeting_url']}"
            params['body'] = body

        base_url = 'https://outlook.live.com/calendar/0/deeplink/compose'
        return f"{base_url}?{urlencode(params)}"

    def generate_ics_file(self) -> BytesIO:
        """
        Generate .ics file as BytesIO object.

        Returns:
            BytesIO object containing .ics file
        """
        ical_content = self.generate_icalendar()
        file_obj = BytesIO(ical_content.encode('utf-8'))
        file_obj.name = 'event.ics'
        return file_obj

    @staticmethod
    def _format_google_date(dt: datetime) -> str:
        """
        Format datetime for Google Calendar.

        Args:
            dt: Datetime to format

        Returns:
            Formatted string (YYYYMMDDTHHmmssZ)
        """
        # Convert to UTC
        if dt.tzinfo is None:
            dt = pytz.UTC.localize(dt)
        else:
            dt = dt.astimezone(pytz.UTC)

        return dt.strftime('%Y%m%dT%H%M%SZ')


class CalendarSync:
    """
    Service for syncing events with external calendars.

    Supports Google Calendar and Microsoft Outlook/Office 365.
    """

    def __init__(self, provider: str, credentials: Dict[str, str]):
        """
        Initialize calendar sync service.

        Args:
            provider: Calendar provider ('google', 'outlook')
            credentials: Provider-specific credentials
        """
        self.provider = provider
        self.credentials = credentials

    def create_event(self, event_data: Dict[str, Any]) -> Optional[str]:
        """
        Create event in external calendar.

        Args:
            event_data: Event data dictionary

        Returns:
            Event ID if successful, None otherwise
        """
        if self.provider == 'google':
            return self._create_google_event(event_data)
        elif self.provider == 'outlook':
            return self._create_outlook_event(event_data)
        return None

    def update_event(
        self,
        event_id: str,
        event_data: Dict[str, Any]
    ) -> bool:
        """
        Update existing event in external calendar.

        Args:
            event_id: External event ID
            event_data: Updated event data

        Returns:
            True if successful
        """
        if self.provider == 'google':
            return self._update_google_event(event_id, event_data)
        elif self.provider == 'outlook':
            return self._update_outlook_event(event_id, event_data)
        return False

    def delete_event(self, event_id: str) -> bool:
        """
        Delete event from external calendar.

        Args:
            event_id: External event ID

        Returns:
            True if successful
        """
        if self.provider == 'google':
            return self._delete_google_event(event_id)
        elif self.provider == 'outlook':
            return self._delete_outlook_event(event_id)
        return False

    def _create_google_event(self, event_data: Dict[str, Any]) -> Optional[str]:
        """Create event in Google Calendar."""
        try:
            from googleapiclient.discovery import build
            from google.oauth2.credentials import Credentials

            # Build credentials
            creds = Credentials(
                token=self.credentials.get('access_token'),
                refresh_token=self.credentials.get('refresh_token'),
                token_uri='https://oauth2.googleapis.com/token',
                client_id=self.credentials.get('client_id'),
                client_secret=self.credentials.get('client_secret')
            )

            # Build service
            service = build('calendar', 'v3', credentials=creds)

            # Create event
            event = {
                'summary': event_data['title'],
                'description': event_data.get('description', ''),
                'start': {
                    'dateTime': event_data['start'].isoformat(),
                    'timeZone': event_data.get('timezone', 'America/Toronto'),
                },
                'end': {
                    'dateTime': event_data['end'].isoformat(),
                    'timeZone': event_data.get('timezone', 'America/Toronto'),
                },
            }

            if event_data.get('location'):
                event['location'] = event_data['location']

            if event_data.get('attendees'):
                event['attendees'] = [
                    {'email': email} for email in event_data['attendees']
                ]

            # Insert event
            created_event = service.events().insert(
                calendarId='primary',
                body=event,
                sendUpdates='all'
            ).execute()

            return created_event.get('id')

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to create Google Calendar event: {e}")
            return None

    def _update_google_event(
        self,
        event_id: str,
        event_data: Dict[str, Any]
    ) -> bool:
        """Update event in Google Calendar."""
        # Implementation similar to _create_google_event
        # Using service.events().update() instead of insert()
        return False  # Placeholder

    def _delete_google_event(self, event_id: str) -> bool:
        """Delete event from Google Calendar."""
        # Implementation using service.events().delete()
        return False  # Placeholder

    def _create_outlook_event(self, event_data: Dict[str, Any]) -> Optional[str]:
        """Create event in Outlook/Office 365."""
        try:
            import requests

            access_token = self.credentials.get('access_token')
            if not access_token:
                return None

            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json',
            }

            # Build event
            event = {
                'subject': event_data['title'],
                'body': {
                    'contentType': 'HTML',
                    'content': event_data.get('description', ''),
                },
                'start': {
                    'dateTime': event_data['start'].isoformat(),
                    'timeZone': event_data.get('timezone', 'America/Toronto'),
                },
                'end': {
                    'dateTime': event_data['end'].isoformat(),
                    'timeZone': event_data.get('timezone', 'America/Toronto'),
                },
            }

            if event_data.get('location'):
                event['location'] = {'displayName': event_data['location']}

            if event_data.get('attendees'):
                event['attendees'] = [
                    {
                        'emailAddress': {'address': email},
                        'type': 'required'
                    }
                    for email in event_data['attendees']
                ]

            # Create event
            response = requests.post(
                'https://graph.microsoft.com/v1.0/me/events',
                headers=headers,
                json=event
            )

            if response.status_code == 201:
                return response.json().get('id')

            return None

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to create Outlook event: {e}")
            return None

    def _update_outlook_event(
        self,
        event_id: str,
        event_data: Dict[str, Any]
    ) -> bool:
        """Update event in Outlook/Office 365."""
        # Implementation using PATCH to /me/events/{id}
        return False  # Placeholder

    def _delete_outlook_event(self, event_id: str) -> bool:
        """Delete event from Outlook/Office 365."""
        # Implementation using DELETE to /me/events/{id}
        return False  # Placeholder


def generate_calendar_links(event_data: Dict[str, Any]) -> Dict[str, str]:
    """
    Generate calendar links for all supported providers.

    Args:
        event_data: Event data dictionary

    Returns:
        Dictionary with 'google', 'outlook', and 'ics' keys
    """
    generator = CalendarEventGenerator(event_data)

    return {
        'google': generator.generate_google_calendar_url(),
        'outlook': generator.generate_outlook_url(),
        'ics': generator.generate_icalendar(),
    }
