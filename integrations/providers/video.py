"""
Video Conferencing Integration Providers

Implements video meeting integrations for:
- Zoom
- Microsoft Teams
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional

from .base import (
    VideoProvider,
    IntegrationError,
    AuthenticationError,
    ConfigurationError,
)

logger = logging.getLogger(__name__)


class ZoomProvider(VideoProvider):
    """
    Zoom video conferencing integration provider.
    Uses Zoom API v2.
    """

    provider_name = 'zoom'
    display_name = 'Zoom'

    # API configuration
    api_base_url = 'https://api.zoom.us/v2'

    # OAuth configuration
    oauth_authorize_url = 'https://zoom.us/oauth/authorize'
    oauth_token_url = 'https://zoom.us/oauth/token'
    oauth_scopes = [
        'meeting:write:admin',
        'meeting:read:admin',
        'user:read:admin',
        'recording:read:admin',
    ]

    def get_authorization_url(self, state: str, extra_params: Dict = None) -> str:
        """Generate Zoom OAuth authorization URL."""
        params = extra_params or {}
        return super().get_authorization_url(state, params)

    def test_connection(self) -> Tuple[bool, str]:
        """Test Zoom API connection."""
        try:
            response = self.make_request('GET', 'users/me')
            if response.status_code == 200:
                data = response.json()
                return True, f"Connected as {data.get('email')}"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get Zoom user/account information."""
        response = self.make_request('GET', 'users/me')

        if response.status_code != 200:
            raise IntegrationError("Failed to fetch account info")

        data = response.json()
        return {
            'id': data.get('id'),
            'email': data.get('email'),
            'first_name': data.get('first_name'),
            'last_name': data.get('last_name'),
            'type': data.get('type'),  # 1=Basic, 2=Licensed, 3=On-prem
            'pmi': data.get('pmi'),  # Personal Meeting ID
            'timezone': data.get('timezone'),
            'account_id': data.get('account_id'),
        }

    def create_meeting(
        self,
        topic: str,
        start_time: datetime,
        duration_minutes: int,
        settings: Dict = None,
        agenda: str = None,
        password: str = None
    ) -> Dict:
        """
        Create a Zoom meeting.

        Args:
            topic: Meeting topic/title
            start_time: Meeting start time
            duration_minutes: Duration in minutes
            settings: Meeting settings dict
            agenda: Meeting agenda/description
            password: Meeting password

        Returns:
            Dict with meeting details including join URL
        """
        meeting_data = {
            'topic': topic,
            'type': 2,  # Scheduled meeting
            'start_time': start_time.strftime('%Y-%m-%dT%H:%M:%S'),
            'duration': duration_minutes,
            'timezone': settings.get('timezone', 'UTC') if settings else 'UTC',
        }

        if agenda:
            meeting_data['agenda'] = agenda
        if password:
            meeting_data['password'] = password

        # Default settings
        default_settings = {
            'host_video': True,
            'participant_video': True,
            'join_before_host': True,
            'mute_upon_entry': True,
            'waiting_room': False,
            'auto_recording': 'none',
        }

        if settings:
            default_settings.update(settings)

        meeting_data['settings'] = default_settings

        response = self.make_request('POST', 'users/me/meetings', data=meeting_data)

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create meeting: {response.text}")

        data = response.json()
        return self._normalize_meeting(data)

    def get_meeting(self, meeting_id: str) -> Dict:
        """Get meeting details."""
        response = self.make_request('GET', f'meetings/{meeting_id}')

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get meeting: {response.status_code}")

        return self._normalize_meeting(response.json())

    def update_meeting(self, meeting_id: str, meeting_data: Dict) -> Dict:
        """Update meeting details."""
        update_data = {}

        if 'topic' in meeting_data:
            update_data['topic'] = meeting_data['topic']
        if 'start_time' in meeting_data:
            start = meeting_data['start_time']
            if isinstance(start, datetime):
                start = start.strftime('%Y-%m-%dT%H:%M:%S')
            update_data['start_time'] = start
        if 'duration' in meeting_data:
            update_data['duration'] = meeting_data['duration']
        if 'agenda' in meeting_data:
            update_data['agenda'] = meeting_data['agenda']
        if 'settings' in meeting_data:
            update_data['settings'] = meeting_data['settings']

        response = self.make_request('PATCH', f'meetings/{meeting_id}', data=update_data)

        if response.status_code not in [200, 204]:
            raise IntegrationError(f"Failed to update meeting: {response.text}")

        # Fetch updated meeting details
        return self.get_meeting(meeting_id)

    def delete_meeting(self, meeting_id: str) -> bool:
        """Cancel/delete a meeting."""
        response = self.make_request('DELETE', f'meetings/{meeting_id}')
        return response.status_code in [200, 204]

    def list_meetings(self, type: str = 'upcoming', page_size: int = 30) -> List[Dict]:
        """
        List meetings for the authenticated user.

        Args:
            type: Meeting type (scheduled, live, upcoming)
            page_size: Number of results per page

        Returns:
            List of meeting dictionaries
        """
        meetings = []
        next_page_token = None

        while True:
            params = {
                'type': type,
                'page_size': page_size,
            }
            if next_page_token:
                params['next_page_token'] = next_page_token

            response = self.make_request('GET', 'users/me/meetings', params=params)

            if response.status_code != 200:
                raise IntegrationError(f"Failed to list meetings: {response.status_code}")

            data = response.json()
            for meeting in data.get('meetings', []):
                meetings.append(self._normalize_meeting(meeting))

            next_page_token = data.get('next_page_token')
            if not next_page_token:
                break

        return meetings

    def get_meeting_recordings(self, meeting_id: str) -> List[Dict]:
        """Get recordings for a meeting."""
        response = self.make_request('GET', f'meetings/{meeting_id}/recordings')

        if response.status_code == 404:
            return []  # No recordings found
        if response.status_code != 200:
            raise IntegrationError(f"Failed to get recordings: {response.status_code}")

        data = response.json()
        recordings = []

        for file in data.get('recording_files', []):
            recordings.append({
                'id': file.get('id'),
                'meeting_id': meeting_id,
                'file_type': file.get('file_type'),
                'file_size': file.get('file_size'),
                'recording_start': file.get('recording_start'),
                'recording_end': file.get('recording_end'),
                'download_url': file.get('download_url'),
                'play_url': file.get('play_url'),
                'status': file.get('status'),
            })

        return recordings

    def get_meeting_participants(self, meeting_id: str) -> List[Dict]:
        """Get participants of a past meeting."""
        response = self.make_request('GET', f'past_meetings/{meeting_id}/participants')

        if response.status_code != 200:
            return []

        data = response.json()
        return [
            {
                'id': p.get('id'),
                'name': p.get('name'),
                'email': p.get('user_email'),
                'join_time': p.get('join_time'),
                'leave_time': p.get('leave_time'),
                'duration': p.get('duration'),
            }
            for p in data.get('participants', [])
        ]

    def _normalize_meeting(self, zoom_meeting: Dict) -> Dict:
        """Convert Zoom meeting to normalized format."""
        return {
            'id': str(zoom_meeting.get('id')),
            'uuid': zoom_meeting.get('uuid'),
            'topic': zoom_meeting.get('topic'),
            'type': zoom_meeting.get('type'),
            'start_time': zoom_meeting.get('start_time'),
            'duration': zoom_meeting.get('duration'),
            'timezone': zoom_meeting.get('timezone'),
            'agenda': zoom_meeting.get('agenda', ''),
            'created_at': zoom_meeting.get('created_at'),
            'join_url': zoom_meeting.get('join_url'),
            'start_url': zoom_meeting.get('start_url'),
            'password': zoom_meeting.get('password'),
            'host_id': zoom_meeting.get('host_id'),
            'host_email': zoom_meeting.get('host_email'),
            'status': zoom_meeting.get('status', 'waiting'),
        }

    def handle_webhook(self, event_type: str, payload: Dict) -> Dict[str, Any]:
        """Handle Zoom webhook events."""
        logger.info(f"Processing Zoom webhook: {event_type}")

        event_data = payload.get('payload', {}).get('object', {})

        if event_type == 'meeting.started':
            return {
                'action': 'meeting_started',
                'meeting_id': event_data.get('id'),
                'host_id': event_data.get('host_id'),
                'start_time': event_data.get('start_time'),
            }

        elif event_type == 'meeting.ended':
            return {
                'action': 'meeting_ended',
                'meeting_id': event_data.get('id'),
                'end_time': event_data.get('end_time'),
                'duration': event_data.get('duration'),
            }

        elif event_type == 'meeting.participant_joined':
            return {
                'action': 'participant_joined',
                'meeting_id': event_data.get('id'),
                'participant': event_data.get('participant', {}),
            }

        elif event_type == 'recording.completed':
            return {
                'action': 'recording_completed',
                'meeting_id': event_data.get('id'),
                'recording_files': event_data.get('recording_files', []),
            }

        return {'action': 'unhandled', 'event_type': event_type}


class MicrosoftTeamsProvider(VideoProvider):
    """
    Microsoft Teams meeting integration provider.
    Uses Microsoft Graph API.
    """

    provider_name = 'teams_meeting'
    display_name = 'Microsoft Teams'

    # API configuration
    api_base_url = 'https://graph.microsoft.com/v1.0'

    # OAuth configuration
    oauth_authorize_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
    oauth_token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
    oauth_scopes = [
        'offline_access',
        'User.Read',
        'OnlineMeetings.ReadWrite',
        'Calendars.ReadWrite',
    ]

    def test_connection(self) -> Tuple[bool, str]:
        """Test Microsoft Graph API connection."""
        try:
            response = self.make_request('GET', 'me')
            if response.status_code == 200:
                data = response.json()
                return True, f"Connected as {data.get('displayName')}"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get Microsoft user account information."""
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

    def create_meeting(
        self,
        topic: str,
        start_time: datetime,
        duration_minutes: int,
        settings: Dict = None,
        participants: List[str] = None
    ) -> Dict:
        """
        Create a Microsoft Teams online meeting.

        Args:
            topic: Meeting subject
            start_time: Meeting start time
            duration_minutes: Duration in minutes
            settings: Meeting options
            participants: List of participant emails

        Returns:
            Dict with meeting details including join URL
        """
        end_time = start_time + timedelta(minutes=duration_minutes)

        meeting_data = {
            'subject': topic,
            'startDateTime': start_time.isoformat(),
            'endDateTime': end_time.isoformat(),
        }

        # Add participants if provided
        if participants:
            meeting_data['participants'] = {
                'attendees': [
                    {
                        'upn': email,
                        'role': 'attendee',
                    }
                    for email in participants
                ]
            }

        # Meeting settings
        if settings:
            lobby_bypass = settings.get('lobby_bypass', 'organization')
            meeting_data['lobbyBypassSettings'] = {
                'scope': lobby_bypass,
                'isDialInBypassEnabled': settings.get('dial_in_bypass', False),
            }

            if settings.get('record_automatically'):
                meeting_data['recordAutomatically'] = True

        response = self.make_request('POST', 'me/onlineMeetings', data=meeting_data)

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create meeting: {response.text}")

        return self._normalize_meeting(response.json())

    def get_meeting(self, meeting_id: str) -> Dict:
        """Get online meeting details."""
        response = self.make_request('GET', f'me/onlineMeetings/{meeting_id}')

        if response.status_code != 200:
            raise IntegrationError(f"Failed to get meeting: {response.status_code}")

        return self._normalize_meeting(response.json())

    def update_meeting(self, meeting_id: str, meeting_data: Dict) -> Dict:
        """Update meeting details."""
        update_data = {}

        if 'topic' in meeting_data:
            update_data['subject'] = meeting_data['topic']
        if 'start_time' in meeting_data:
            update_data['startDateTime'] = meeting_data['start_time'].isoformat()
        if 'end_time' in meeting_data:
            update_data['endDateTime'] = meeting_data['end_time'].isoformat()

        response = self.make_request('PATCH', f'me/onlineMeetings/{meeting_id}', data=update_data)

        if response.status_code != 200:
            raise IntegrationError(f"Failed to update meeting: {response.text}")

        return self._normalize_meeting(response.json())

    def delete_meeting(self, meeting_id: str) -> bool:
        """Delete/cancel an online meeting."""
        response = self.make_request('DELETE', f'me/onlineMeetings/{meeting_id}')
        return response.status_code in [200, 204]

    def get_meeting_recordings(self, meeting_id: str) -> List[Dict]:
        """
        Get recordings for a Teams meeting.
        Note: Requires additional permissions and may need to use different endpoints.
        """
        # Teams recordings are stored in OneDrive/SharePoint
        # This is a simplified implementation
        response = self.make_request(
            'GET',
            f'me/onlineMeetings/{meeting_id}/recordings'
        )

        if response.status_code != 200:
            return []

        data = response.json()
        return [
            {
                'id': rec.get('id'),
                'meeting_id': meeting_id,
                'created_at': rec.get('createdDateTime'),
                'content_url': rec.get('content'),
            }
            for rec in data.get('value', [])
        ]

    def create_calendar_event_with_meeting(
        self,
        subject: str,
        start_time: datetime,
        end_time: datetime,
        attendees: List[str],
        body: str = None
    ) -> Dict:
        """
        Create a calendar event with Teams meeting attached.

        This is often the preferred way to create Teams meetings
        as it integrates with Outlook calendar.
        """
        event_data = {
            'subject': subject,
            'start': {
                'dateTime': start_time.isoformat(),
                'timeZone': 'UTC',
            },
            'end': {
                'dateTime': end_time.isoformat(),
                'timeZone': 'UTC',
            },
            'attendees': [
                {
                    'emailAddress': {'address': email},
                    'type': 'required',
                }
                for email in attendees
            ],
            'isOnlineMeeting': True,
            'onlineMeetingProvider': 'teamsForBusiness',
        }

        if body:
            event_data['body'] = {
                'contentType': 'HTML',
                'content': body,
            }

        response = self.make_request('POST', 'me/calendar/events', data=event_data)

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to create event: {response.text}")

        data = response.json()
        return {
            'event_id': data.get('id'),
            'subject': data.get('subject'),
            'start': data.get('start', {}).get('dateTime'),
            'end': data.get('end', {}).get('dateTime'),
            'join_url': data.get('onlineMeeting', {}).get('joinUrl'),
            'web_link': data.get('webLink'),
        }

    def _normalize_meeting(self, teams_meeting: Dict) -> Dict:
        """Convert Teams meeting to normalized format."""
        return {
            'id': teams_meeting.get('id'),
            'topic': teams_meeting.get('subject'),
            'start_time': teams_meeting.get('startDateTime'),
            'end_time': teams_meeting.get('endDateTime'),
            'join_url': teams_meeting.get('joinWebUrl'),
            'video_teleconference_id': teams_meeting.get('videoTeleconferenceId'),
            'conference_id': teams_meeting.get('conferenceId'),
            'toll_number': teams_meeting.get('audioConferencing', {}).get('tollNumber'),
            'toll_free_number': teams_meeting.get('audioConferencing', {}).get('tollFreeNumber'),
            'created_at': teams_meeting.get('creationDateTime'),
            'chat_id': teams_meeting.get('chatInfo', {}).get('threadId'),
        }

    def handle_webhook(self, event_type: str, payload: Dict) -> Dict[str, Any]:
        """Handle Teams webhook events (via Microsoft Graph subscriptions)."""
        logger.info(f"Processing Teams webhook: {event_type}")

        resource = payload.get('resource', '')
        change_type = payload.get('changeType', '')

        return {
            'action': f'{change_type}_{event_type}',
            'resource': resource,
            'client_state': payload.get('clientState'),
            'subscription_id': payload.get('subscriptionId'),
        }
