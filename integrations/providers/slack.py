"""
Slack Integration Provider

Implements Slack notifications and messaging integration.
"""

import logging
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from .base import (
    MessagingProvider,
    IntegrationError,
    AuthenticationError,
    ConfigurationError,
)

logger = logging.getLogger(__name__)


class SlackProvider(MessagingProvider):
    """
    Slack integration provider.
    Uses Slack Web API and supports both OAuth and webhook integrations.
    """

    provider_name = 'slack'
    display_name = 'Slack'

    # API configuration
    api_base_url = 'https://slack.com/api'

    # OAuth configuration
    oauth_authorize_url = 'https://slack.com/oauth/v2/authorize'
    oauth_token_url = 'https://slack.com/api/oauth.v2.access'
    oauth_scopes = [
        'channels:read',
        'channels:write',
        'chat:write',
        'chat:write.public',
        'users:read',
        'users:read.email',
        'team:read',
        'files:write',
        'reactions:write',
    ]

    def get_authorization_url(self, state: str, extra_params: Dict = None) -> str:
        """Generate Slack OAuth authorization URL."""
        params = extra_params or {}
        params['user_scope'] = ''  # Only request bot scopes
        return super().get_authorization_url(state, params)

    def get_headers(self) -> Dict[str, str]:
        """Get headers for Slack API requests."""
        creds = self.get_credentials()
        return {
            'Authorization': f"Bearer {creds.get('access_token')}",
            'Content-Type': 'application/json; charset=utf-8',
        }

    def test_connection(self) -> Tuple[bool, str]:
        """Test Slack API connection."""
        try:
            response = self.make_request('POST', 'auth.test')
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    return True, f"Connected to {data.get('team')} as {data.get('user')}"
                return False, data.get('error', 'Unknown error')
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get Slack workspace information."""
        response = self.make_request('POST', 'auth.test')

        if response.status_code != 200 or not response.json().get('ok'):
            raise IntegrationError("Failed to fetch account info")

        data = response.json()

        # Get team info for more details
        team_response = self.make_request('POST', 'team.info')
        team_data = team_response.json().get('team', {}) if team_response.json().get('ok') else {}

        return {
            'team_id': data.get('team_id'),
            'team_name': data.get('team'),
            'bot_user_id': data.get('user_id'),
            'bot_name': data.get('user'),
            'team_domain': team_data.get('domain'),
            'team_icon': team_data.get('icon', {}).get('image_132'),
        }

    def send_message(
        self,
        channel: str,
        message: str,
        attachments: List[Dict] = None,
        blocks: List[Dict] = None,
        thread_ts: str = None,
        unfurl_links: bool = True
    ) -> Dict:
        """
        Send a message to a Slack channel.

        Args:
            channel: Channel ID or name (e.g., #general, C0123456789)
            message: Plain text message
            attachments: Rich message attachments
            blocks: Block Kit blocks for rich formatting
            thread_ts: Thread timestamp to reply in thread
            unfurl_links: Whether to unfurl URLs

        Returns:
            Dict with message details including timestamp
        """
        payload = {
            'channel': channel,
            'text': message,
            'unfurl_links': unfurl_links,
            'unfurl_media': True,
        }

        if attachments:
            payload['attachments'] = attachments
        if blocks:
            payload['blocks'] = blocks
        if thread_ts:
            payload['thread_ts'] = thread_ts

        response = self.make_request('POST', 'chat.postMessage', data=payload)

        if response.status_code != 200:
            raise IntegrationError(f"Failed to send message: {response.status_code}")

        data = response.json()
        if not data.get('ok'):
            raise IntegrationError(f"Slack API error: {data.get('error')}")

        return {
            'channel': data.get('channel'),
            'ts': data.get('ts'),
            'message': data.get('message', {}),
        }

    def send_notification(
        self,
        channel: str,
        title: str,
        message: str,
        color: str = '#36a64f',
        fields: List[Dict] = None,
        actions: List[Dict] = None
    ) -> Dict:
        """
        Send a rich notification with attachments.

        Args:
            channel: Channel ID or name
            title: Notification title
            message: Notification message
            color: Attachment bar color (hex)
            fields: List of field dicts with title, value, short
            actions: List of interactive actions

        Returns:
            Dict with message details
        """
        attachment = {
            'color': color,
            'title': title,
            'text': message,
            'ts': int(datetime.now().timestamp()),
            'footer': 'Zumodra',
            'footer_icon': 'https://zumodra.com/favicon.ico',
        }

        if fields:
            attachment['fields'] = [
                {
                    'title': f.get('title'),
                    'value': f.get('value'),
                    'short': f.get('short', True),
                }
                for f in fields
            ]

        if actions:
            attachment['actions'] = actions

        return self.send_message(
            channel=channel,
            message=title,
            attachments=[attachment]
        )

    def send_block_message(
        self,
        channel: str,
        blocks: List[Dict],
        fallback_text: str = 'New notification'
    ) -> Dict:
        """
        Send a Block Kit formatted message.

        Args:
            channel: Channel ID or name
            blocks: Block Kit blocks
            fallback_text: Fallback text for notifications

        Returns:
            Dict with message details
        """
        return self.send_message(
            channel=channel,
            message=fallback_text,
            blocks=blocks
        )

    def update_message(self, channel: str, ts: str, message: str, blocks: List[Dict] = None) -> Dict:
        """Update an existing message."""
        payload = {
            'channel': channel,
            'ts': ts,
            'text': message,
        }

        if blocks:
            payload['blocks'] = blocks

        response = self.make_request('POST', 'chat.update', data=payload)

        if response.status_code != 200 or not response.json().get('ok'):
            raise IntegrationError(f"Failed to update message: {response.json().get('error')}")

        return response.json()

    def delete_message(self, channel: str, ts: str) -> bool:
        """Delete a message."""
        response = self.make_request(
            'POST',
            'chat.delete',
            data={'channel': channel, 'ts': ts}
        )

        return response.json().get('ok', False)

    def list_channels(self, types: str = 'public_channel,private_channel') -> List[Dict]:
        """
        List available Slack channels.

        Args:
            types: Comma-separated channel types

        Returns:
            List of channel dictionaries
        """
        channels = []
        cursor = None

        while True:
            params = {
                'types': types,
                'limit': 200,
                'exclude_archived': True,
            }
            if cursor:
                params['cursor'] = cursor

            response = self.make_request('POST', 'conversations.list', data=params)

            if response.status_code != 200 or not response.json().get('ok'):
                raise IntegrationError(f"Failed to list channels: {response.json().get('error')}")

            data = response.json()
            for channel in data.get('channels', []):
                channels.append({
                    'id': channel.get('id'),
                    'name': channel.get('name'),
                    'is_private': channel.get('is_private', False),
                    'is_member': channel.get('is_member', False),
                    'num_members': channel.get('num_members', 0),
                    'topic': channel.get('topic', {}).get('value', ''),
                    'purpose': channel.get('purpose', {}).get('value', ''),
                })

            cursor = data.get('response_metadata', {}).get('next_cursor')
            if not cursor:
                break

        return channels

    def get_channel(self, channel_id: str) -> Dict:
        """Get channel information."""
        response = self.make_request(
            'POST',
            'conversations.info',
            data={'channel': channel_id}
        )

        if response.status_code != 200 or not response.json().get('ok'):
            raise IntegrationError(f"Failed to get channel: {response.json().get('error')}")

        channel = response.json().get('channel', {})
        return {
            'id': channel.get('id'),
            'name': channel.get('name'),
            'is_private': channel.get('is_private'),
            'topic': channel.get('topic', {}).get('value', ''),
            'purpose': channel.get('purpose', {}).get('value', ''),
            'member_count': channel.get('num_members'),
        }

    def list_users(self) -> List[Dict]:
        """List workspace users."""
        users = []
        cursor = None

        while True:
            params = {'limit': 200}
            if cursor:
                params['cursor'] = cursor

            response = self.make_request('POST', 'users.list', data=params)

            if response.status_code != 200 or not response.json().get('ok'):
                raise IntegrationError(f"Failed to list users: {response.json().get('error')}")

            data = response.json()
            for user in data.get('members', []):
                if not user.get('is_bot') and not user.get('deleted'):
                    users.append({
                        'id': user.get('id'),
                        'name': user.get('name'),
                        'real_name': user.get('real_name'),
                        'email': user.get('profile', {}).get('email'),
                        'is_admin': user.get('is_admin', False),
                        'avatar': user.get('profile', {}).get('image_72'),
                    })

            cursor = data.get('response_metadata', {}).get('next_cursor')
            if not cursor:
                break

        return users

    def upload_file(
        self,
        channels: List[str],
        content: bytes,
        filename: str,
        title: str = None,
        comment: str = None
    ) -> Dict:
        """
        Upload a file to Slack.

        Args:
            channels: List of channel IDs to share to
            content: File content bytes
            filename: Filename
            title: File title
            comment: Initial comment

        Returns:
            Dict with file details
        """
        import io

        files = {'file': (filename, io.BytesIO(content))}
        data = {
            'channels': ','.join(channels),
            'filename': filename,
        }

        if title:
            data['title'] = title
        if comment:
            data['initial_comment'] = comment

        response = self.session.post(
            f'{self.api_base_url}/files.upload',
            headers={'Authorization': self.get_headers()['Authorization']},
            data=data,
            files=files,
            timeout=self.request_timeout
        )

        if response.status_code != 200 or not response.json().get('ok'):
            raise IntegrationError(f"Failed to upload file: {response.json().get('error')}")

        file_data = response.json().get('file', {})
        return {
            'id': file_data.get('id'),
            'name': file_data.get('name'),
            'title': file_data.get('title'),
            'url': file_data.get('permalink'),
            'size': file_data.get('size'),
        }

    def add_reaction(self, channel: str, ts: str, emoji: str) -> bool:
        """Add a reaction to a message."""
        response = self.make_request(
            'POST',
            'reactions.add',
            data={
                'channel': channel,
                'timestamp': ts,
                'name': emoji,
            }
        )

        return response.json().get('ok', False)

    def send_webhook_message(
        self,
        webhook_url: str,
        message: str,
        attachments: List[Dict] = None,
        blocks: List[Dict] = None
    ) -> bool:
        """
        Send a message via incoming webhook (no OAuth required).

        Args:
            webhook_url: Slack incoming webhook URL
            message: Plain text message
            attachments: Rich message attachments
            blocks: Block Kit blocks

        Returns:
            True if successful
        """
        import requests

        payload = {'text': message}
        if attachments:
            payload['attachments'] = attachments
        if blocks:
            payload['blocks'] = blocks

        response = requests.post(
            webhook_url,
            json=payload,
            timeout=30
        )

        return response.status_code == 200

    def handle_webhook(self, event_type: str, payload: Dict) -> Dict[str, Any]:
        """Handle Slack Events API webhook."""
        logger.info(f"Processing Slack event: {event_type}")

        # Handle URL verification challenge
        if event_type == 'url_verification':
            return {
                'action': 'challenge',
                'challenge': payload.get('challenge'),
            }

        # Handle event callbacks
        event = payload.get('event', {})
        return {
            'action': event.get('type'),
            'channel': event.get('channel'),
            'user': event.get('user'),
            'text': event.get('text'),
            'ts': event.get('ts'),
            'thread_ts': event.get('thread_ts'),
        }

    def verify_webhook_signature(self, payload: bytes, signature: str, timestamp: str) -> bool:
        """
        Verify Slack webhook signature.

        Args:
            payload: Raw request body
            signature: X-Slack-Signature header value
            timestamp: X-Slack-Request-Timestamp header value

        Returns:
            True if signature is valid
        """
        import hmac
        import hashlib

        config = self.integration.config if self.integration else {}
        signing_secret = config.get('signing_secret', '')

        if not signing_secret:
            return False

        sig_basestring = f"v0:{timestamp}:{payload.decode()}"
        expected = 'v0=' + hmac.new(
            signing_secret.encode(),
            sig_basestring.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected, signature)


# Notification templates for common use cases
class SlackNotificationTemplates:
    """Pre-built notification templates for common HR/recruiting events."""

    @staticmethod
    def new_application(applicant_name: str, job_title: str, apply_url: str) -> List[Dict]:
        """Template for new job application notification."""
        return [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f'*New Application Received!* :tada:\n\n*Applicant:* {applicant_name}\n*Position:* {job_title}'
                }
            },
            {
                'type': 'actions',
                'elements': [
                    {
                        'type': 'button',
                        'text': {'type': 'plain_text', 'text': 'View Application'},
                        'url': apply_url,
                        'style': 'primary',
                    }
                ]
            }
        ]

    @staticmethod
    def interview_scheduled(candidate_name: str, job_title: str, interview_time: str, interviewer: str) -> List[Dict]:
        """Template for interview scheduled notification."""
        return [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f'*Interview Scheduled* :calendar:\n\n*Candidate:* {candidate_name}\n*Position:* {job_title}\n*Time:* {interview_time}\n*Interviewer:* {interviewer}'
                }
            }
        ]

    @staticmethod
    def offer_accepted(candidate_name: str, job_title: str, start_date: str) -> List[Dict]:
        """Template for offer accepted notification."""
        return [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f'*Offer Accepted!* :rocket:\n\n*New Hire:* {candidate_name}\n*Position:* {job_title}\n*Start Date:* {start_date}'
                }
            }
        ]

    @staticmethod
    def background_check_complete(candidate_name: str, status: str) -> List[Dict]:
        """Template for background check completion notification."""
        emoji = ':white_check_mark:' if status == 'clear' else ':warning:'
        return [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f'*Background Check Complete* {emoji}\n\n*Candidate:* {candidate_name}\n*Status:* {status.title()}'
                }
            }
        ]
