"""
Calendar Integration Providers

Implements calendar integrations for:
- Google Calendar
- Microsoft Outlook Calendar
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional
from zoneinfo import ZoneInfo

from .base import (
    CalendarProvider,
    IntegrationError,
    AuthenticationError,
    ConfigurationError,
)

logger = logging.getLogger(__name__)


class GoogleCalendarProvider(CalendarProvider):
    """
    Google Calendar integration provider.
    Uses Google Calendar API v3.
    """

    provider_name = 'google_calendar'
    display_name = 'Google Calendar'

    # API configuration
    api_base_url = 'https://www.googleapis.com/calendar/v3'

    # OAuth configuration
    oauth_authorize_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    oauth_token_url = 'https://oauth2.googleapis.com/token'
    oauth_revoke_url = 'https://oauth2.googleapis.com/revoke'
    oauth_scopes = [
        'https://www.googleapis.com/auth/calendar',
        'https://www.googleapis.com/auth/calendar.events',
    ]

    def get_authorization_url(self, state: str, extra_params: Dict = None) -> str:
        """Generate Google OAuth authorization URL with offline access."""
        params = extra_params or {}
        params.update({
            'access_type': 'offline',
            'prompt': 'consent',  # Force refresh token generation
        })
        return super().get_authorization_url(state, params)

    def test_connection(self) -> Tuple[bool, str]:
        """Test Google Calendar connection by fetching calendar list."""
        try:
            response = self.make_request('GET', 'users/me/calendarList')
            if response.status_code == 200:
                return True, "Successfully connected to Google Calendar"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get information about the connected Google account."""
        # Fetch primary calendar which contains account info
        response = self.make_request('GET', 'calendars/primary')
        if response.status_code != 200:
            raise IntegrationError("Failed to fetch account info")

        data = response.json()
        return {
            'id': data.get('id'),
            'email': data.get('id'),  # Primary calendar ID is the email
            'name': data.get('summary'),
            'timezone': data.get('timeZone'),
        }

    def list_calendars(self) -> List[Dict]:
        """List all calendars accessible to the user."""
        calendars = []
        page_token = None

        while True:
            params = {'maxResults': 250}
            if page_token:
                params['pageToken'] = page_token

            response = self.make_request('GET', 'users/me/calendarList', params=params)
            if response.status_code != 200:
                raise IntegrationError(f"Failed to list calendars: {response.status_code}")

            data = response.json()
            for cal in data.get('items', []):
                calendars.append({
                    'id': cal.get('id'),
                    'name': cal.get('summary'),
                    'description': cal.get('description', ''),
                    'timezone': cal.get('timeZone'),
                    'is_primary': cal.get('primary', False),
                    'access_role': cal.get('accessRole'),
                    'background_color': cal.get('backgroundColor'),
                })

            page_token = data.get('nextPageToken')
            if not page_token:
                break

        return calendars

    def list_events(
        self,
        calendar_id: str,
        start_time: datetime,
        end_time: datetime,
        max_results: int = 100
    ) -> List[Dict]:
        """
        List events within a time range.

        Args:
            calendar_id: Calendar ID (use 'primary' for default)
            start_time: Start of time range
            end_time: End of time range
            max_results: Maximum number of events to return

        Returns:
            List of event dictionaries
        """
        events = []
        page_token = None

        while True:
            params = {
                'timeMin': start_time.isoformat() + 'Z',
                'timeMax': end_time.isoformat() + 'Z',
                'maxResults': min(max_results - len(events), 250),
                'singleEvents': True,
                'orderBy': 'startTime',
            }
            if page_token:
                params['pageToken'] = page_token

            response = self.make_request(
                'GET',
                f'calendars/{calendar_id}/events',
                params=params
            )

            if response.status_code != 200:
                raise IntegrationError(f"Failed to list events: {response.status_code}")

            data = response.json()
            for event in data.get('items', []):
                events.append(self._normalize_event(event))

            page_token = data.get('nextPageToken')
            if not page_token or len(events) >= max_results:
                break

        return events

    def create_event(self, calendar_id: str, event_data: Dict) -> Dict:
        """
        Create a new calendar event.

        Args:
            calendar_id: Calendar ID
            event_data: Event data with keys:
                - title: Event title
                - description: Event description
                - start_time: Start datetime
                - end_time: End datetime
                - timezone: Timezone string
                - location: Event location
                - attendees: List of attendee emails
                - reminders: List of reminder dicts

        Returns:
            Created event data
        """
        google_event = self._prepare_event_data(event_data)

        response = self.make_request(
            'POST',
            f'calendars/{calendar_id}/events',
            data=google_event,
            params={'sendUpdates': 'all'}
        )

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create event: {response.text}")

        return self._normalize_event(response.json())

    def update_event(self, calendar_id: str, event_id: str, event_data: Dict) -> Dict:
        """Update an existing calendar event."""
        google_event = self._prepare_event_data(event_data)

        response = self.make_request(
            'PUT',
            f'calendars/{calendar_id}/events/{event_id}',
            data=google_event,
            params={'sendUpdates': 'all'}
        )

        if response.status_code != 200:
            raise IntegrationError(f"Failed to update event: {response.text}")

        return self._normalize_event(response.json())

    def delete_event(self, calendar_id: str, event_id: str) -> bool:
        """Delete a calendar event."""
        response = self.make_request(
            'DELETE',
            f'calendars/{calendar_id}/events/{event_id}',
            params={'sendUpdates': 'all'}
        )

        return response.status_code in [200, 204]

    def get_free_busy(
        self,
        calendar_ids: List[str],
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, List[Dict]]:
        """
        Get free/busy information for calendars.

        Returns:
            Dict mapping calendar IDs to list of busy periods
        """
        data = {
            'timeMin': start_time.isoformat() + 'Z',
            'timeMax': end_time.isoformat() + 'Z',
            'items': [{'id': cal_id} for cal_id in calendar_ids]
        }

        response = self.make_request('POST', 'freeBusy', data=data)

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get free/busy: {response.text}")

        result = {}
        for cal_id, cal_data in response.json().get('calendars', {}).items():
            result[cal_id] = [
                {
                    'start': period.get('start'),
                    'end': period.get('end'),
                }
                for period in cal_data.get('busy', [])
            ]

        return result

    def _prepare_event_data(self, event_data: Dict) -> Dict:
        """Convert normalized event data to Google Calendar format."""
        google_event = {
            'summary': event_data.get('title', ''),
            'description': event_data.get('description', ''),
        }

        # Handle start/end times
        start_time = event_data.get('start_time')
        end_time = event_data.get('end_time')
        timezone = event_data.get('timezone', 'UTC')

        if event_data.get('all_day'):
            google_event['start'] = {'date': start_time.strftime('%Y-%m-%d')}
            google_event['end'] = {'date': end_time.strftime('%Y-%m-%d')}
        else:
            google_event['start'] = {
                'dateTime': start_time.isoformat(),
                'timeZone': timezone,
            }
            google_event['end'] = {
                'dateTime': end_time.isoformat(),
                'timeZone': timezone,
            }

        # Optional fields
        if event_data.get('location'):
            google_event['location'] = event_data['location']

        if event_data.get('attendees'):
            google_event['attendees'] = [
                {'email': email} for email in event_data['attendees']
            ]

        if event_data.get('conference'):
            google_event['conferenceData'] = {
                'createRequest': {
                    'requestId': f"zumodra-{datetime.now().timestamp()}",
                    'conferenceSolutionKey': {'type': 'hangoutsMeet'}
                }
            }

        return google_event

    def _normalize_event(self, google_event: Dict) -> Dict:
        """Convert Google Calendar event to normalized format."""
        start = google_event.get('start', {})
        end = google_event.get('end', {})

        return {
            'id': google_event.get('id'),
            'title': google_event.get('summary', ''),
            'description': google_event.get('description', ''),
            'start_time': start.get('dateTime') or start.get('date'),
            'end_time': end.get('dateTime') or end.get('date'),
            'timezone': start.get('timeZone'),
            'all_day': 'date' in start,
            'location': google_event.get('location', ''),
            'status': google_event.get('status'),
            'html_link': google_event.get('htmlLink'),
            'organizer': google_event.get('organizer', {}).get('email'),
            'attendees': [
                {
                    'email': att.get('email'),
                    'name': att.get('displayName'),
                    'response_status': att.get('responseStatus'),
                }
                for att in google_event.get('attendees', [])
            ],
            'conference_url': self._extract_conference_url(google_event),
            'created_at': google_event.get('created'),
            'updated_at': google_event.get('updated'),
        }

    def _extract_conference_url(self, google_event: Dict) -> Optional[str]:
        """Extract video conference URL from event."""
        conf_data = google_event.get('conferenceData', {})
        for entry_point in conf_data.get('entryPoints', []):
            if entry_point.get('entryPointType') == 'video':
                return entry_point.get('uri')
        return None


class OutlookCalendarProvider(CalendarProvider):
    """
    Microsoft Outlook Calendar integration provider.
    Uses Microsoft Graph API.
    """

    provider_name = 'outlook_calendar'
    display_name = 'Outlook Calendar'

    # API configuration
    api_base_url = 'https://graph.microsoft.com/v1.0'

    # OAuth configuration
    oauth_authorize_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
    oauth_token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
    oauth_scopes = [
        'offline_access',
        'Calendars.ReadWrite',
        'User.Read',
    ]

    def test_connection(self) -> Tuple[bool, str]:
        """Test Outlook connection by fetching user profile."""
        try:
            response = self.make_request('GET', 'me')
            if response.status_code == 200:
                return True, "Successfully connected to Outlook Calendar"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get information about the connected Microsoft account."""
        response = self.make_request('GET', 'me')
        if response.status_code != 200:
            raise IntegrationError("Failed to fetch account info")

        data = response.json()
        return {
            'id': data.get('id'),
            'email': data.get('mail') or data.get('userPrincipalName'),
            'name': data.get('displayName'),
            'job_title': data.get('jobTitle'),
        }

    def list_calendars(self) -> List[Dict]:
        """List all calendars accessible to the user."""
        calendars = []
        url = 'me/calendars'

        while url:
            response = self.make_request('GET', url)
            if response.status_code != 200:
                raise IntegrationError(f"Failed to list calendars: {response.status_code}")

            data = response.json()
            for cal in data.get('value', []):
                calendars.append({
                    'id': cal.get('id'),
                    'name': cal.get('name'),
                    'owner': cal.get('owner', {}).get('address'),
                    'can_edit': cal.get('canEdit', False),
                    'is_default': cal.get('isDefaultCalendar', False),
                    'color': cal.get('hexColor'),
                })

            url = data.get('@odata.nextLink')
            if url:
                # Extract just the path from the full URL
                url = url.replace(self.api_base_url + '/', '')

        return calendars

    def list_events(
        self,
        calendar_id: str,
        start_time: datetime,
        end_time: datetime,
        max_results: int = 100
    ) -> List[Dict]:
        """List events within a time range."""
        events = []

        # Use calendarView for expanded recurring events
        params = {
            'startDateTime': start_time.isoformat(),
            'endDateTime': end_time.isoformat(),
            '$top': min(max_results, 100),
            '$orderby': 'start/dateTime',
        }

        endpoint = f'me/calendars/{calendar_id}/calendarView' if calendar_id else 'me/calendar/calendarView'
        url = endpoint

        while url and len(events) < max_results:
            response = self.make_request('GET', url, params=params if url == endpoint else None)

            if response.status_code != 200:
                raise IntegrationError(f"Failed to list events: {response.status_code}")

            data = response.json()
            for event in data.get('value', []):
                events.append(self._normalize_event(event))

            url = data.get('@odata.nextLink')
            if url:
                url = url.replace(self.api_base_url + '/', '')

        return events[:max_results]

    def create_event(self, calendar_id: str, event_data: Dict) -> Dict:
        """Create a new calendar event."""
        outlook_event = self._prepare_event_data(event_data)

        endpoint = f'me/calendars/{calendar_id}/events' if calendar_id else 'me/calendar/events'
        response = self.make_request('POST', endpoint, data=outlook_event)

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create event: {response.text}")

        return self._normalize_event(response.json())

    def update_event(self, calendar_id: str, event_id: str, event_data: Dict) -> Dict:
        """Update an existing calendar event."""
        outlook_event = self._prepare_event_data(event_data)

        response = self.make_request(
            'PATCH',
            f'me/events/{event_id}',
            data=outlook_event
        )

        if response.status_code != 200:
            raise IntegrationError(f"Failed to update event: {response.text}")

        return self._normalize_event(response.json())

    def delete_event(self, calendar_id: str, event_id: str) -> bool:
        """Delete a calendar event."""
        response = self.make_request('DELETE', f'me/events/{event_id}')
        return response.status_code in [200, 204]

    def _prepare_event_data(self, event_data: Dict) -> Dict:
        """Convert normalized event data to Outlook format."""
        outlook_event = {
            'subject': event_data.get('title', ''),
            'body': {
                'contentType': 'HTML',
                'content': event_data.get('description', ''),
            },
        }

        # Handle times
        start_time = event_data.get('start_time')
        end_time = event_data.get('end_time')
        timezone = event_data.get('timezone', 'UTC')

        if event_data.get('all_day'):
            outlook_event['isAllDay'] = True
            outlook_event['start'] = {
                'dateTime': start_time.strftime('%Y-%m-%dT00:00:00'),
                'timeZone': timezone,
            }
            outlook_event['end'] = {
                'dateTime': end_time.strftime('%Y-%m-%dT00:00:00'),
                'timeZone': timezone,
            }
        else:
            outlook_event['start'] = {
                'dateTime': start_time.isoformat(),
                'timeZone': timezone,
            }
            outlook_event['end'] = {
                'dateTime': end_time.isoformat(),
                'timeZone': timezone,
            }

        # Optional fields
        if event_data.get('location'):
            outlook_event['location'] = {'displayName': event_data['location']}

        if event_data.get('attendees'):
            outlook_event['attendees'] = [
                {
                    'emailAddress': {'address': email},
                    'type': 'required',
                }
                for email in event_data['attendees']
            ]

        if event_data.get('conference'):
            outlook_event['isOnlineMeeting'] = True
            outlook_event['onlineMeetingProvider'] = 'teamsForBusiness'

        return outlook_event

    def _normalize_event(self, outlook_event: Dict) -> Dict:
        """Convert Outlook event to normalized format."""
        start = outlook_event.get('start', {})
        end = outlook_event.get('end', {})

        return {
            'id': outlook_event.get('id'),
            'title': outlook_event.get('subject', ''),
            'description': outlook_event.get('body', {}).get('content', ''),
            'start_time': start.get('dateTime'),
            'end_time': end.get('dateTime'),
            'timezone': start.get('timeZone'),
            'all_day': outlook_event.get('isAllDay', False),
            'location': outlook_event.get('location', {}).get('displayName', ''),
            'status': outlook_event.get('showAs'),
            'html_link': outlook_event.get('webLink'),
            'organizer': outlook_event.get('organizer', {}).get('emailAddress', {}).get('address'),
            'attendees': [
                {
                    'email': att.get('emailAddress', {}).get('address'),
                    'name': att.get('emailAddress', {}).get('name'),
                    'response_status': att.get('status', {}).get('response'),
                }
                for att in outlook_event.get('attendees', [])
            ],
            'conference_url': outlook_event.get('onlineMeeting', {}).get('joinUrl'),
            'created_at': outlook_event.get('createdDateTime'),
            'updated_at': outlook_event.get('lastModifiedDateTime'),
        }
