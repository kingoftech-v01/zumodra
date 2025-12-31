"""
Base Integration Provider

Abstract base class and mixins for all integration providers.
Implements common functionality for OAuth, webhooks, and sync operations.
"""

import logging
import requests
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


class IntegrationError(Exception):
    """Base exception for integration errors."""
    pass


class AuthenticationError(IntegrationError):
    """Raised when authentication fails."""
    pass


class RateLimitError(IntegrationError):
    """Raised when rate limit is exceeded."""
    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after


class ConfigurationError(IntegrationError):
    """Raised when integration is misconfigured."""
    pass


class SyncError(IntegrationError):
    """Raised when sync operation fails."""
    pass


class OAuthMixin:
    """
    Mixin providing OAuth 2.0 functionality.
    Handles authorization URL generation, token exchange, and refresh.
    """

    # OAuth configuration - override in subclasses
    oauth_authorize_url: str = ''
    oauth_token_url: str = ''
    oauth_revoke_url: str = ''
    oauth_scopes: List[str] = []
    oauth_response_type: str = 'code'

    def get_oauth_config(self) -> Dict[str, str]:
        """
        Get OAuth client configuration from settings.
        Override to customize configuration source.
        """
        provider_key = self.provider_name.upper()
        return {
            'client_id': getattr(settings, f'{provider_key}_CLIENT_ID', ''),
            'client_secret': getattr(settings, f'{provider_key}_CLIENT_SECRET', ''),
            'redirect_uri': getattr(settings, f'{provider_key}_REDIRECT_URI', ''),
        }

    def get_authorization_url(self, state: str, extra_params: Dict = None) -> str:
        """
        Generate OAuth authorization URL.

        Args:
            state: CSRF state parameter
            extra_params: Additional URL parameters

        Returns:
            Authorization URL string
        """
        config = self.get_oauth_config()
        params = {
            'client_id': config['client_id'],
            'redirect_uri': config['redirect_uri'],
            'response_type': self.oauth_response_type,
            'scope': ' '.join(self.oauth_scopes),
            'state': state,
        }
        if extra_params:
            params.update(extra_params)

        return f"{self.oauth_authorize_url}?{urlencode(params)}"

    def exchange_code_for_tokens(self, code: str) -> Dict[str, Any]:
        """
        Exchange authorization code for access and refresh tokens.

        Args:
            code: Authorization code from OAuth callback

        Returns:
            Dictionary containing access_token, refresh_token, expires_in, etc.
        """
        config = self.get_oauth_config()
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': config['client_id'],
            'client_secret': config['client_secret'],
            'redirect_uri': config['redirect_uri'],
        }

        response = requests.post(
            self.oauth_token_url,
            data=data,
            headers={'Accept': 'application/json'},
            timeout=30
        )

        if response.status_code != 200:
            logger.error(f"Token exchange failed: {response.text}")
            raise AuthenticationError(f"Failed to exchange code: {response.status_code}")

        return response.json()

    def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh expired access token using refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            Dictionary containing new access_token, expires_in, etc.
        """
        config = self.get_oauth_config()
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': config['client_id'],
            'client_secret': config['client_secret'],
        }

        response = requests.post(
            self.oauth_token_url,
            data=data,
            headers={'Accept': 'application/json'},
            timeout=30
        )

        if response.status_code != 200:
            logger.error(f"Token refresh failed: {response.text}")
            raise AuthenticationError(f"Failed to refresh token: {response.status_code}")

        return response.json()

    def revoke_token(self, token: str) -> bool:
        """
        Revoke OAuth token.

        Args:
            token: Access or refresh token to revoke

        Returns:
            True if revocation succeeded
        """
        if not self.oauth_revoke_url:
            return True

        config = self.get_oauth_config()
        data = {
            'token': token,
            'client_id': config['client_id'],
            'client_secret': config['client_secret'],
        }

        try:
            response = requests.post(
                self.oauth_revoke_url,
                data=data,
                timeout=30
            )
            return response.status_code in [200, 204]
        except Exception as e:
            logger.warning(f"Token revocation failed: {e}")
            return False


class WebhookMixin:
    """
    Mixin providing webhook handling functionality.
    """

    def verify_webhook_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        """
        Verify webhook signature. Override in subclasses for provider-specific logic.

        Args:
            payload: Raw request body
            signature: Signature from headers
            secret: Webhook secret

        Returns:
            True if signature is valid
        """
        import hmac
        import hashlib

        expected = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected, signature)

    def parse_webhook_payload(self, payload: Dict) -> Dict[str, Any]:
        """
        Parse webhook payload into standardized format.
        Override in subclasses for provider-specific parsing.

        Args:
            payload: Raw webhook payload

        Returns:
            Parsed and normalized payload
        """
        return payload

    def get_webhook_event_type(self, payload: Dict) -> str:
        """
        Extract event type from webhook payload.
        Override in subclasses for provider-specific extraction.

        Args:
            payload: Webhook payload

        Returns:
            Event type string
        """
        return payload.get('event_type', payload.get('type', 'unknown'))


class BaseIntegrationProvider(ABC, OAuthMixin, WebhookMixin):
    """
    Abstract base class for all integration providers.

    Subclasses must implement:
    - provider_name: Unique provider identifier
    - display_name: Human-readable provider name
    - test_connection(): Verify credentials are valid
    - get_account_info(): Fetch account/user information
    """

    # Provider identification - override in subclasses
    provider_name: str = ''
    display_name: str = ''
    provider_type: str = ''  # calendar, email, job_board, etc.

    # API configuration
    api_base_url: str = ''
    api_version: str = ''

    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds

    # Default timeout for API requests
    request_timeout: int = 30

    def __init__(self, integration=None):
        """
        Initialize provider with optional integration instance.

        Args:
            integration: Integration model instance
        """
        self.integration = integration
        self._session = None

    @property
    def session(self) -> requests.Session:
        """Get or create requests session with default configuration."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({
                'User-Agent': f'Zumodra/{settings.VERSION if hasattr(settings, "VERSION") else "1.0"}',
                'Accept': 'application/json',
            })
        return self._session

    def get_credentials(self) -> Dict[str, Any]:
        """
        Get credentials from integration instance.

        Returns:
            Dictionary with access_token, api_key, etc.
        """
        if not self.integration or not hasattr(self.integration, 'credentials'):
            raise ConfigurationError("No integration credentials available")

        creds = self.integration.credentials
        return {
            'access_token': creds.access_token,
            'refresh_token': creds.refresh_token,
            'api_key': creds.api_key,
            'api_secret': creds.api_secret,
        }

    def get_headers(self) -> Dict[str, str]:
        """
        Get HTTP headers for API requests.
        Override to customize headers.

        Returns:
            Dictionary of HTTP headers
        """
        creds = self.get_credentials()
        headers = {}

        if creds.get('access_token'):
            headers['Authorization'] = f"Bearer {creds['access_token']}"
        elif creds.get('api_key'):
            headers['Authorization'] = f"Bearer {creds['api_key']}"

        return headers

    def make_request(
        self,
        method: str,
        endpoint: str,
        data: Dict = None,
        params: Dict = None,
        headers: Dict = None,
        retry_on_401: bool = True
    ) -> requests.Response:
        """
        Make authenticated API request with error handling.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (without base URL)
            data: Request body data
            params: URL query parameters
            headers: Additional headers
            retry_on_401: Whether to retry after refreshing token on 401

        Returns:
            Response object
        """
        url = f"{self.api_base_url}/{endpoint.lstrip('/')}"

        request_headers = self.get_headers()
        if headers:
            request_headers.update(headers)

        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                headers=request_headers,
                timeout=self.request_timeout
            )

            # Handle rate limiting
            if response.status_code == 429:
                retry_after = response.headers.get('Retry-After', 60)
                raise RateLimitError(
                    "Rate limit exceeded",
                    retry_after=int(retry_after)
                )

            # Handle authentication errors
            if response.status_code == 401:
                if retry_on_401 and self._try_refresh_token():
                    return self.make_request(
                        method, endpoint, data, params, headers,
                        retry_on_401=False
                    )
                raise AuthenticationError("Authentication failed")

            return response

        except requests.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise IntegrationError(f"Request failed: {e}")

    def _try_refresh_token(self) -> bool:
        """
        Attempt to refresh access token.

        Returns:
            True if refresh succeeded
        """
        if not self.integration or not hasattr(self.integration, 'credentials'):
            return False

        creds = self.integration.credentials
        if not creds.can_refresh:
            return False

        try:
            tokens = self.refresh_access_token(creds.refresh_token)
            creds.update_tokens(
                access_token=tokens.get('access_token'),
                refresh_token=tokens.get('refresh_token'),
                expires_in=tokens.get('expires_in'),
                scope=tokens.get('scope')
            )
            logger.info(f"Successfully refreshed token for {self.provider_name}")
            return True
        except AuthenticationError:
            logger.error(f"Token refresh failed for {self.provider_name}")
            self.integration.status = 'expired'
            self.integration.save()
            return False

    @abstractmethod
    def test_connection(self) -> Tuple[bool, str]:
        """
        Test if the integration is properly configured and connected.

        Returns:
            Tuple of (success: bool, message: str)
        """
        pass

    @abstractmethod
    def get_account_info(self) -> Dict[str, Any]:
        """
        Get information about the connected account.

        Returns:
            Dictionary with account details (id, name, email, etc.)
        """
        pass

    def connect(self, credentials: Dict[str, Any]) -> bool:
        """
        Establish connection using provided credentials.
        Override for custom connection logic.

        Args:
            credentials: Dictionary with tokens/keys

        Returns:
            True if connection successful
        """
        if not self.integration:
            raise ConfigurationError("No integration instance provided")

        # Store credentials
        from integrations.models import IntegrationCredential
        cred, _ = IntegrationCredential.objects.get_or_create(
            integration=self.integration
        )

        # Update based on credential type
        if 'access_token' in credentials:
            cred.auth_type = 'oauth2'
            cred.access_token = credentials.get('access_token', '')
            cred.refresh_token = credentials.get('refresh_token', '')
            if 'expires_in' in credentials:
                cred.expires_at = timezone.now() + timedelta(seconds=credentials['expires_in'])
            cred.scope = credentials.get('scope', '')
        elif 'api_key' in credentials:
            cred.auth_type = 'api_key'
            cred.api_key = credentials.get('api_key', '')
            cred.api_secret = credentials.get('api_secret', '')

        cred.save()

        # Test the connection
        success, message = self.test_connection()
        if success:
            self.integration.activate()
            return True
        else:
            self.integration.mark_error(message)
            return False

    def disconnect(self) -> bool:
        """
        Disconnect integration and revoke tokens.

        Returns:
            True if disconnection successful
        """
        if not self.integration:
            return False

        # Revoke tokens if OAuth
        if hasattr(self.integration, 'credentials'):
            creds = self.integration.credentials
            if creds.access_token:
                self.revoke_token(creds.access_token)
            if creds.refresh_token:
                self.revoke_token(creds.refresh_token)
            creds.delete()

        self.integration.deactivate(reason="Disconnected by user")
        return True

    def sync(
        self,
        resource_type: str = None,
        full_sync: bool = False,
        cursor: str = None
    ) -> Dict[str, Any]:
        """
        Perform data synchronization.
        Override in subclasses to implement sync logic.

        Args:
            resource_type: Type of resource to sync (optional)
            full_sync: Whether to do full sync vs incremental
            cursor: Sync cursor for incremental sync

        Returns:
            Dictionary with sync results
        """
        return {
            'status': 'not_implemented',
            'message': f'Sync not implemented for {self.provider_name}'
        }

    def handle_webhook(self, event_type: str, payload: Dict) -> Dict[str, Any]:
        """
        Handle incoming webhook event.
        Override in subclasses to implement webhook handling.

        Args:
            event_type: Type of webhook event
            payload: Webhook payload data

        Returns:
            Dictionary with handling result
        """
        return {
            'status': 'not_implemented',
            'message': f'Webhook handling not implemented for {self.provider_name}'
        }


class CalendarProvider(BaseIntegrationProvider):
    """Base class for calendar integration providers."""
    provider_type = 'calendar'

    @abstractmethod
    def list_calendars(self) -> List[Dict]:
        """List available calendars."""
        pass

    @abstractmethod
    def list_events(
        self,
        calendar_id: str,
        start_time: datetime,
        end_time: datetime
    ) -> List[Dict]:
        """List events in date range."""
        pass

    @abstractmethod
    def create_event(self, calendar_id: str, event_data: Dict) -> Dict:
        """Create a new calendar event."""
        pass

    @abstractmethod
    def update_event(self, calendar_id: str, event_id: str, event_data: Dict) -> Dict:
        """Update an existing event."""
        pass

    @abstractmethod
    def delete_event(self, calendar_id: str, event_id: str) -> bool:
        """Delete an event."""
        pass


class EmailProvider(BaseIntegrationProvider):
    """Base class for email integration providers."""
    provider_type = 'email'

    @abstractmethod
    def send_email(
        self,
        to: List[str],
        subject: str,
        body: str,
        html_body: str = None,
        attachments: List = None
    ) -> Dict:
        """Send an email."""
        pass

    @abstractmethod
    def list_messages(
        self,
        folder: str = 'inbox',
        limit: int = 50,
        page_token: str = None
    ) -> Dict:
        """List email messages."""
        pass


class JobBoardProvider(BaseIntegrationProvider):
    """Base class for job board integration providers."""
    provider_type = 'job_board'

    @abstractmethod
    def post_job(self, job_data: Dict) -> Dict:
        """Post a job listing."""
        pass

    @abstractmethod
    def update_job(self, job_id: str, job_data: Dict) -> Dict:
        """Update a job listing."""
        pass

    @abstractmethod
    def close_job(self, job_id: str) -> bool:
        """Close/unpublish a job listing."""
        pass

    @abstractmethod
    def get_applications(self, job_id: str) -> List[Dict]:
        """Get applications for a job."""
        pass


class BackgroundCheckProvider(BaseIntegrationProvider):
    """Base class for background check integration providers."""
    provider_type = 'background_check'

    @abstractmethod
    def create_candidate(self, candidate_data: Dict) -> Dict:
        """Create a candidate for background check."""
        pass

    @abstractmethod
    def create_invitation(self, candidate_id: str, package: str) -> Dict:
        """Create/send background check invitation."""
        pass

    @abstractmethod
    def get_report(self, report_id: str) -> Dict:
        """Get background check report."""
        pass

    @abstractmethod
    def get_report_status(self, report_id: str) -> Dict:
        """Get status of background check."""
        pass


class ESignProvider(BaseIntegrationProvider):
    """Base class for e-signature integration providers."""
    provider_type = 'esign'

    @abstractmethod
    def create_envelope(self, document_data: Dict, signers: List[Dict]) -> Dict:
        """Create a document envelope for signing."""
        pass

    @abstractmethod
    def get_envelope_status(self, envelope_id: str) -> Dict:
        """Get envelope/document status."""
        pass

    @abstractmethod
    def download_document(self, envelope_id: str, document_id: str) -> bytes:
        """Download signed document."""
        pass

    @abstractmethod
    def void_envelope(self, envelope_id: str, reason: str) -> bool:
        """Void/cancel an envelope."""
        pass


class HRISProvider(BaseIntegrationProvider):
    """Base class for HRIS integration providers."""
    provider_type = 'hris'

    @abstractmethod
    def list_employees(self, status: str = 'active') -> List[Dict]:
        """List employees."""
        pass

    @abstractmethod
    def get_employee(self, employee_id: str) -> Dict:
        """Get employee details."""
        pass

    @abstractmethod
    def create_employee(self, employee_data: Dict) -> Dict:
        """Create new employee record."""
        pass

    @abstractmethod
    def update_employee(self, employee_id: str, employee_data: Dict) -> Dict:
        """Update employee record."""
        pass


class MessagingProvider(BaseIntegrationProvider):
    """Base class for messaging integration providers."""
    provider_type = 'messaging'

    @abstractmethod
    def send_message(
        self,
        channel: str,
        message: str,
        attachments: List = None
    ) -> Dict:
        """Send a message to channel."""
        pass

    @abstractmethod
    def list_channels(self) -> List[Dict]:
        """List available channels."""
        pass


class VideoProvider(BaseIntegrationProvider):
    """Base class for video conferencing providers."""
    provider_type = 'video'

    @abstractmethod
    def create_meeting(
        self,
        topic: str,
        start_time: datetime,
        duration_minutes: int,
        settings: Dict = None
    ) -> Dict:
        """Create a video meeting."""
        pass

    @abstractmethod
    def get_meeting(self, meeting_id: str) -> Dict:
        """Get meeting details."""
        pass

    @abstractmethod
    def update_meeting(self, meeting_id: str, meeting_data: Dict) -> Dict:
        """Update meeting details."""
        pass

    @abstractmethod
    def delete_meeting(self, meeting_id: str) -> bool:
        """Cancel/delete a meeting."""
        pass

    @abstractmethod
    def get_meeting_recordings(self, meeting_id: str) -> List[Dict]:
        """Get meeting recordings."""
        pass
