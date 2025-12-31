"""
Email Integration Providers

Implements email integrations for:
- Gmail (Google Workspace)
- Outlook Email (Microsoft 365)
- SMTP (Generic)
"""

import logging
import smtplib
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import Dict, Any, List, Tuple, Optional

from django.conf import settings

from .base import (
    EmailProvider,
    IntegrationError,
    AuthenticationError,
    ConfigurationError,
)

logger = logging.getLogger(__name__)


class GmailProvider(EmailProvider):
    """
    Gmail integration provider.
    Uses Gmail API for sending and reading emails.
    """

    provider_name = 'gmail'
    display_name = 'Gmail'

    # API configuration
    api_base_url = 'https://gmail.googleapis.com/gmail/v1'

    # OAuth configuration
    oauth_authorize_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    oauth_token_url = 'https://oauth2.googleapis.com/token'
    oauth_revoke_url = 'https://oauth2.googleapis.com/revoke'
    oauth_scopes = [
        'https://www.googleapis.com/auth/gmail.send',
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.modify',
    ]

    def get_authorization_url(self, state: str, extra_params: Dict = None) -> str:
        """Generate Gmail OAuth authorization URL."""
        params = extra_params or {}
        params.update({
            'access_type': 'offline',
            'prompt': 'consent',
        })
        return super().get_authorization_url(state, params)

    def test_connection(self) -> Tuple[bool, str]:
        """Test Gmail connection by fetching profile."""
        try:
            response = self.make_request('GET', 'users/me/profile')
            if response.status_code == 200:
                return True, "Successfully connected to Gmail"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get Gmail account information."""
        response = self.make_request('GET', 'users/me/profile')
        if response.status_code != 200:
            raise IntegrationError("Failed to fetch account info")

        data = response.json()
        return {
            'email': data.get('emailAddress'),
            'messages_total': data.get('messagesTotal'),
            'threads_total': data.get('threadsTotal'),
        }

    def send_email(
        self,
        to: List[str],
        subject: str,
        body: str,
        html_body: str = None,
        cc: List[str] = None,
        bcc: List[str] = None,
        attachments: List[Dict] = None,
        reply_to: str = None
    ) -> Dict:
        """
        Send an email via Gmail API.

        Args:
            to: List of recipient email addresses
            subject: Email subject
            body: Plain text body
            html_body: HTML body (optional)
            cc: CC recipients
            bcc: BCC recipients
            attachments: List of dicts with 'filename', 'content', 'content_type'
            reply_to: Reply-to address

        Returns:
            Dict with message id and thread id
        """
        # Get sender email
        account_info = self.get_account_info()
        sender_email = account_info.get('email')

        # Build message
        if html_body or attachments:
            message = MIMEMultipart('alternative')
            message.attach(MIMEText(body, 'plain'))
            if html_body:
                message.attach(MIMEText(html_body, 'html'))
        else:
            message = MIMEText(body, 'plain')

        message['From'] = sender_email
        message['To'] = ', '.join(to)
        message['Subject'] = subject

        if cc:
            message['Cc'] = ', '.join(cc)
        if bcc:
            message['Bcc'] = ', '.join(bcc)
        if reply_to:
            message['Reply-To'] = reply_to

        # Add attachments
        if attachments:
            for attachment in attachments:
                part = MIMEApplication(
                    attachment['content'],
                    Name=attachment['filename']
                )
                part['Content-Disposition'] = f'attachment; filename="{attachment["filename"]}"'
                message.attach(part)

        # Encode message
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')

        # Send via API
        response = self.make_request(
            'POST',
            'users/me/messages/send',
            data={'raw': raw_message}
        )

        if response.status_code not in [200, 201]:
            raise IntegrationError(f"Failed to send email: {response.text}")

        data = response.json()
        return {
            'message_id': data.get('id'),
            'thread_id': data.get('threadId'),
            'label_ids': data.get('labelIds', []),
        }

    def list_messages(
        self,
        folder: str = 'INBOX',
        limit: int = 50,
        page_token: str = None,
        query: str = None
    ) -> Dict:
        """
        List email messages.

        Args:
            folder: Label/folder name (INBOX, SENT, etc.)
            limit: Maximum messages to return
            page_token: Pagination token
            query: Gmail search query

        Returns:
            Dict with messages list and next page token
        """
        params = {
            'maxResults': min(limit, 100),
            'labelIds': folder,
        }
        if page_token:
            params['pageToken'] = page_token
        if query:
            params['q'] = query

        response = self.make_request('GET', 'users/me/messages', params=params)

        if response.status_code != 200:
            raise IntegrationError(f"Failed to list messages: {response.status_code}")

        data = response.json()
        messages = []

        # Fetch message details for each message
        for msg in data.get('messages', []):
            msg_detail = self.get_message(msg['id'])
            if msg_detail:
                messages.append(msg_detail)

        return {
            'messages': messages,
            'next_page_token': data.get('nextPageToken'),
            'result_size_estimate': data.get('resultSizeEstimate'),
        }

    def get_message(self, message_id: str) -> Optional[Dict]:
        """Get full message details."""
        response = self.make_request(
            'GET',
            f'users/me/messages/{message_id}',
            params={'format': 'full'}
        )

        if response.status_code != 200:
            return None

        data = response.json()
        return self._normalize_message(data)

    def _normalize_message(self, gmail_message: Dict) -> Dict:
        """Convert Gmail message to normalized format."""
        headers = {h['name'].lower(): h['value'] for h in gmail_message.get('payload', {}).get('headers', [])}

        return {
            'id': gmail_message.get('id'),
            'thread_id': gmail_message.get('threadId'),
            'subject': headers.get('subject', ''),
            'from': headers.get('from', ''),
            'to': headers.get('to', ''),
            'cc': headers.get('cc', ''),
            'date': headers.get('date', ''),
            'snippet': gmail_message.get('snippet', ''),
            'labels': gmail_message.get('labelIds', []),
            'is_read': 'UNREAD' not in gmail_message.get('labelIds', []),
        }


class OutlookEmailProvider(EmailProvider):
    """
    Microsoft Outlook Email integration provider.
    Uses Microsoft Graph API.
    """

    provider_name = 'outlook_email'
    display_name = 'Outlook Email'

    # API configuration
    api_base_url = 'https://graph.microsoft.com/v1.0'

    # OAuth configuration
    oauth_authorize_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
    oauth_token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
    oauth_scopes = [
        'offline_access',
        'Mail.Send',
        'Mail.Read',
        'Mail.ReadWrite',
        'User.Read',
    ]

    def test_connection(self) -> Tuple[bool, str]:
        """Test Outlook connection."""
        try:
            response = self.make_request('GET', 'me')
            if response.status_code == 200:
                return True, "Successfully connected to Outlook"
            return False, f"Connection failed: {response.status_code}"
        except AuthenticationError as e:
            return False, f"Authentication failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get Outlook account information."""
        response = self.make_request('GET', 'me')
        if response.status_code != 200:
            raise IntegrationError("Failed to fetch account info")

        data = response.json()
        return {
            'id': data.get('id'),
            'email': data.get('mail') or data.get('userPrincipalName'),
            'name': data.get('displayName'),
        }

    def send_email(
        self,
        to: List[str],
        subject: str,
        body: str,
        html_body: str = None,
        cc: List[str] = None,
        bcc: List[str] = None,
        attachments: List[Dict] = None,
        reply_to: str = None
    ) -> Dict:
        """Send an email via Microsoft Graph API."""
        message = {
            'subject': subject,
            'body': {
                'contentType': 'HTML' if html_body else 'Text',
                'content': html_body or body,
            },
            'toRecipients': [
                {'emailAddress': {'address': email}} for email in to
            ],
        }

        if cc:
            message['ccRecipients'] = [
                {'emailAddress': {'address': email}} for email in cc
            ]
        if bcc:
            message['bccRecipients'] = [
                {'emailAddress': {'address': email}} for email in bcc
            ]
        if reply_to:
            message['replyTo'] = [{'emailAddress': {'address': reply_to}}]

        # Handle attachments
        if attachments:
            message['attachments'] = []
            for att in attachments:
                message['attachments'].append({
                    '@odata.type': '#microsoft.graph.fileAttachment',
                    'name': att['filename'],
                    'contentBytes': base64.b64encode(att['content']).decode('utf-8'),
                    'contentType': att.get('content_type', 'application/octet-stream'),
                })

        response = self.make_request(
            'POST',
            'me/sendMail',
            data={'message': message, 'saveToSentItems': True}
        )

        if response.status_code not in [200, 202]:
            raise IntegrationError(f"Failed to send email: {response.text}")

        return {
            'status': 'sent',
            'message': 'Email sent successfully',
        }

    def list_messages(
        self,
        folder: str = 'inbox',
        limit: int = 50,
        page_token: str = None,
        query: str = None
    ) -> Dict:
        """List email messages from Outlook."""
        endpoint = f'me/mailFolders/{folder}/messages'
        params = {
            '$top': min(limit, 100),
            '$orderby': 'receivedDateTime desc',
        }

        if page_token:
            # page_token is the skip token URL
            endpoint = page_token.replace(self.api_base_url + '/', '')
            params = None
        if query:
            params['$filter'] = query

        response = self.make_request('GET', endpoint, params=params)

        if response.status_code != 200:
            raise IntegrationError(f"Failed to list messages: {response.status_code}")

        data = response.json()
        messages = [self._normalize_message(msg) for msg in data.get('value', [])]

        return {
            'messages': messages,
            'next_page_token': data.get('@odata.nextLink'),
        }

    def _normalize_message(self, outlook_message: Dict) -> Dict:
        """Convert Outlook message to normalized format."""
        return {
            'id': outlook_message.get('id'),
            'subject': outlook_message.get('subject', ''),
            'from': outlook_message.get('from', {}).get('emailAddress', {}).get('address', ''),
            'to': ', '.join([
                r.get('emailAddress', {}).get('address', '')
                for r in outlook_message.get('toRecipients', [])
            ]),
            'date': outlook_message.get('receivedDateTime'),
            'snippet': outlook_message.get('bodyPreview', ''),
            'is_read': outlook_message.get('isRead', False),
            'has_attachments': outlook_message.get('hasAttachments', False),
            'importance': outlook_message.get('importance'),
        }


class SMTPProvider(EmailProvider):
    """
    Generic SMTP email provider.
    Supports any SMTP server configuration.
    """

    provider_name = 'smtp'
    display_name = 'SMTP'

    # No OAuth for SMTP
    oauth_authorize_url = ''
    oauth_token_url = ''

    def get_credentials(self) -> Dict[str, Any]:
        """Get SMTP credentials from integration config."""
        if not self.integration:
            raise ConfigurationError("No integration instance provided")

        creds = self.integration.credentials
        config = self.integration.config

        return {
            'host': config.get('smtp_host', settings.EMAIL_HOST),
            'port': config.get('smtp_port', settings.EMAIL_PORT),
            'username': creds.username or settings.EMAIL_HOST_USER,
            'password': creds.password or settings.EMAIL_HOST_PASSWORD,
            'use_tls': config.get('use_tls', settings.EMAIL_USE_TLS),
            'use_ssl': config.get('use_ssl', settings.EMAIL_USE_SSL),
            'from_email': config.get('from_email', settings.DEFAULT_FROM_EMAIL),
        }

    def test_connection(self) -> Tuple[bool, str]:
        """Test SMTP connection."""
        try:
            creds = self.get_credentials()

            if creds['use_ssl']:
                server = smtplib.SMTP_SSL(creds['host'], creds['port'], timeout=10)
            else:
                server = smtplib.SMTP(creds['host'], creds['port'], timeout=10)
                if creds['use_tls']:
                    server.starttls()

            server.login(creds['username'], creds['password'])
            server.quit()
            return True, "Successfully connected to SMTP server"

        except smtplib.SMTPAuthenticationError:
            return False, "SMTP authentication failed"
        except smtplib.SMTPConnectError:
            return False, "Failed to connect to SMTP server"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def get_account_info(self) -> Dict[str, Any]:
        """Get SMTP configuration info."""
        creds = self.get_credentials()
        return {
            'host': creds['host'],
            'port': creds['port'],
            'from_email': creds['from_email'],
            'use_tls': creds['use_tls'],
        }

    def send_email(
        self,
        to: List[str],
        subject: str,
        body: str,
        html_body: str = None,
        cc: List[str] = None,
        bcc: List[str] = None,
        attachments: List[Dict] = None,
        reply_to: str = None
    ) -> Dict:
        """Send email via SMTP."""
        creds = self.get_credentials()

        # Build message
        if html_body or attachments:
            message = MIMEMultipart('mixed')
            alt_part = MIMEMultipart('alternative')
            alt_part.attach(MIMEText(body, 'plain'))
            if html_body:
                alt_part.attach(MIMEText(html_body, 'html'))
            message.attach(alt_part)
        else:
            message = MIMEText(body, 'plain')

        message['From'] = creds['from_email']
        message['To'] = ', '.join(to)
        message['Subject'] = subject

        if cc:
            message['Cc'] = ', '.join(cc)
        if reply_to:
            message['Reply-To'] = reply_to

        # Add attachments
        if attachments:
            for att in attachments:
                part = MIMEApplication(att['content'], Name=att['filename'])
                part['Content-Disposition'] = f'attachment; filename="{att["filename"]}"'
                message.attach(part)

        # Collect all recipients
        all_recipients = list(to)
        if cc:
            all_recipients.extend(cc)
        if bcc:
            all_recipients.extend(bcc)

        try:
            if creds['use_ssl']:
                server = smtplib.SMTP_SSL(creds['host'], creds['port'], timeout=30)
            else:
                server = smtplib.SMTP(creds['host'], creds['port'], timeout=30)
                if creds['use_tls']:
                    server.starttls()

            server.login(creds['username'], creds['password'])
            server.sendmail(creds['from_email'], all_recipients, message.as_string())
            server.quit()

            return {
                'status': 'sent',
                'message': 'Email sent successfully',
                'recipients': all_recipients,
            }

        except Exception as e:
            raise IntegrationError(f"Failed to send email: {str(e)}")

    def list_messages(
        self,
        folder: str = 'inbox',
        limit: int = 50,
        page_token: str = None
    ) -> Dict:
        """SMTP doesn't support reading messages."""
        return {
            'messages': [],
            'error': 'SMTP provider does not support reading messages',
        }
