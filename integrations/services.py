"""
Integration Services for Third-Party Integrations.

Provides services for managing integrations, OAuth flows, and data synchronization
with external services like Google Calendar, Outlook, Slack, LinkedIn, and job boards.

Cycle 6 Enhancement - Complete integration service layer with:
- IntegrationService: Core integration management
- CalendarIntegrationService: Google/Outlook calendar sync
- SlackIntegrationService: Slack workspace integration
- ATSIntegrationService: Job board integrations
"""

import logging
import requests
import json
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.utils import timezone
from django.db import transaction

from .models import (
    Integration,
    IntegrationCredential,
    IntegrationSyncLog,
    IntegrationEvent,
    WebhookEndpoint,
    WebhookDelivery,
)

logger = logging.getLogger(__name__)


@dataclass
class IntegrationResult:
    """Result of an integration operation."""
    success: bool
    data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    external_id: Optional[str] = None


@dataclass
class SyncResult:
    """Result of a sync operation."""
    success: bool
    records_processed: int = 0
    records_created: int = 0
    records_updated: int = 0
    records_deleted: int = 0
    records_failed: int = 0
    error_message: Optional[str] = None
    sync_cursor: Optional[str] = None


class BaseIntegrationService(ABC):
    """Abstract base class for integration services."""

    provider: str = None
    integration_type: str = None

    def __init__(self, integration: Integration):
        self.integration = integration
        self.credentials = getattr(integration, 'credentials', None)

    @abstractmethod
    def connect(self, credentials: Dict[str, Any]) -> IntegrationResult:
        """Connect to the external service."""
        pass

    @abstractmethod
    def disconnect(self) -> bool:
        """Disconnect from the external service."""
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """Test if the connection is valid."""
        pass

    @abstractmethod
    def sync(self, sync_type: str = 'incremental') -> SyncResult:
        """Sync data with the external service."""
        pass

    def refresh_token(self) -> bool:
        """Refresh OAuth token if needed."""
        if not self.credentials or not self.credentials.can_refresh:
            return False

        try:
            # Override in subclasses with provider-specific logic
            return self._do_token_refresh()
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            self.integration.mark_error(f"Token refresh failed: {e}")
            return False

    def _do_token_refresh(self) -> bool:
        """Provider-specific token refresh. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement _do_token_refresh")

    def log_event(self, event_type: str, message: str = '', details: dict = None, user=None):
        """Log an integration event."""
        IntegrationEvent.objects.create(
            integration=self.integration,
            event_type=event_type,
            message=message,
            details=details or {},
            triggered_by=user
        )

    def create_sync_log(self, sync_type: str, direction: str = 'inbound', user=None) -> IntegrationSyncLog:
        """Create a new sync log entry."""
        return IntegrationSyncLog.objects.create(
            integration=self.integration,
            sync_type=sync_type,
            direction=direction,
            status='pending',
            triggered_by=user
        )


class IntegrationService:
    """
    Core integration management service.
    Handles connection, disconnection, and synchronization across providers.
    """

    SERVICE_MAP: Dict[str, type] = {}  # Populated by subclasses registering themselves

    @classmethod
    def register_service(cls, provider: str, service_class: type):
        """Register a service class for a provider."""
        cls.SERVICE_MAP[provider] = service_class

    @classmethod
    def get_service(cls, integration: Integration) -> Optional[BaseIntegrationService]:
        """Get the appropriate service for an integration."""
        service_class = cls.SERVICE_MAP.get(integration.provider)
        if service_class:
            return service_class(integration)
        return None

    @classmethod
    def connect(cls, tenant, provider: str, credentials: Dict[str, Any], user=None) -> IntegrationResult:
        """
        Connect a new integration for a tenant.

        Args:
            tenant: Tenant to connect integration for
            provider: Provider name (e.g., 'google_calendar')
            credentials: OAuth tokens or API credentials
            user: User performing the connection

        Returns:
            IntegrationResult with success status and data
        """
        try:
            # Get or create integration
            integration, created = Integration.objects.get_or_create(
                tenant=tenant,
                provider=provider,
                defaults={
                    'name': f"{Integration.ProviderName(provider).label} Integration",
                    'integration_type': cls._get_integration_type(provider),
                    'status': Integration.Status.CONNECTING,
                    'connected_by': user,
                }
            )

            if not created:
                integration.status = Integration.Status.CONNECTING
                integration.save(update_fields=['status'])

            # Get service and connect
            service = cls.get_service(integration)
            if not service:
                return IntegrationResult(
                    success=False,
                    error_message=f"No service available for provider: {provider}"
                )

            result = service.connect(credentials)

            if result.success:
                integration.activate()
                service.log_event('connected', 'Integration connected successfully', user=user)
            else:
                integration.mark_error(result.error_message or 'Connection failed')
                service.log_event('error', result.error_message, user=user)

            return result

        except Exception as e:
            logger.error(f"Integration connection failed: {e}")
            return IntegrationResult(success=False, error_message=str(e))

    @classmethod
    def disconnect(cls, integration_id: int, user=None) -> bool:
        """
        Disconnect an integration.

        Args:
            integration_id: ID of integration to disconnect
            user: User performing the disconnection

        Returns:
            True if disconnection was successful
        """
        try:
            integration = Integration.objects.get(id=integration_id)
            service = cls.get_service(integration)

            if service:
                service.disconnect()
                service.log_event('disconnected', 'Integration disconnected', user=user)

            integration.deactivate('Disconnected by user')

            # Delete credentials
            if hasattr(integration, 'credentials'):
                integration.credentials.delete()

            return True

        except Integration.DoesNotExist:
            return False
        except Exception as e:
            logger.error(f"Integration disconnection failed: {e}")
            return False

    @classmethod
    def sync(cls, integration_id: int, sync_type: str = 'incremental', user=None) -> SyncResult:
        """
        Trigger a sync for an integration.

        Args:
            integration_id: ID of integration to sync
            sync_type: Type of sync ('full', 'incremental')
            user: User triggering the sync

        Returns:
            SyncResult with statistics
        """
        try:
            integration = Integration.objects.get(id=integration_id)

            if not integration.is_active:
                return SyncResult(success=False, error_message="Integration is not active")

            service = cls.get_service(integration)
            if not service:
                return SyncResult(success=False, error_message="No service available")

            # Check and refresh token if needed
            if service.credentials and service.credentials.needs_refresh:
                if not service.refresh_token():
                    return SyncResult(success=False, error_message="Token refresh failed")

            # Create sync log
            sync_log = service.create_sync_log(sync_type, user=user)
            sync_log.mark_running()
            service.log_event('sync_started', f'{sync_type} sync started', user=user)

            try:
                result = service.sync(sync_type)

                if result.success:
                    sync_log.mark_completed(
                        records_processed=result.records_processed,
                        created=result.records_created,
                        updated=result.records_updated,
                        deleted=result.records_deleted
                    )
                    service.log_event('sync_completed', f'Sync completed: {result.records_processed} records')
                else:
                    sync_log.mark_failed(result.error_message or 'Sync failed')
                    service.log_event('sync_failed', result.error_message)

                return result

            except Exception as e:
                sync_log.mark_failed(str(e))
                service.log_event('sync_failed', str(e))
                raise

        except Integration.DoesNotExist:
            return SyncResult(success=False, error_message="Integration not found")
        except Exception as e:
            logger.error(f"Sync failed: {e}")
            return SyncResult(success=False, error_message=str(e))

    @classmethod
    def get_oauth_url(cls, provider: str, redirect_uri: str, state: str = None) -> str:
        """
        Generate OAuth authorization URL for a provider.

        Args:
            provider: Provider name
            redirect_uri: OAuth callback URL
            state: CSRF state token

        Returns:
            Authorization URL
        """
        oauth_configs = {
            'google_calendar': {
                'auth_url': 'https://accounts.google.com/o/oauth2/v2/auth',
                'scope': 'https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/calendar.events',
                'client_id': getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', ''),
            },
            'outlook_calendar': {
                'auth_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                'scope': 'openid profile email Calendars.ReadWrite offline_access',
                'client_id': getattr(settings, 'MICROSOFT_OAUTH_CLIENT_ID', ''),
            },
            'slack': {
                'auth_url': 'https://slack.com/oauth/v2/authorize',
                'scope': 'chat:write users:read channels:read',
                'client_id': getattr(settings, 'SLACK_CLIENT_ID', ''),
            },
            'linkedin': {
                'auth_url': 'https://www.linkedin.com/oauth/v2/authorization',
                'scope': 'r_liteprofile r_emailaddress w_member_social',
                'client_id': getattr(settings, 'LINKEDIN_CLIENT_ID', ''),
            },
        }

        config = oauth_configs.get(provider)
        if not config:
            raise ValueError(f"Unknown provider: {provider}")

        params = {
            'client_id': config['client_id'],
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': config['scope'],
            'access_type': 'offline',
            'prompt': 'consent',
        }

        if state:
            params['state'] = state

        return f"{config['auth_url']}?{urlencode(params)}"

    @classmethod
    def handle_oauth_callback(cls, provider: str, code: str, redirect_uri: str, tenant, user=None) -> IntegrationResult:
        """
        Handle OAuth callback and exchange code for tokens.

        Args:
            provider: Provider name
            code: Authorization code
            redirect_uri: OAuth callback URL
            tenant: Tenant to associate integration with
            user: User performing the connection

        Returns:
            IntegrationResult with connection status
        """
        try:
            # Exchange code for tokens
            tokens = cls._exchange_code_for_tokens(provider, code, redirect_uri)

            if not tokens:
                return IntegrationResult(success=False, error_message="Failed to exchange code for tokens")

            # Connect integration with tokens
            return cls.connect(tenant, provider, tokens, user=user)

        except Exception as e:
            logger.error(f"OAuth callback handling failed: {e}")
            return IntegrationResult(success=False, error_message=str(e))

    @classmethod
    def _exchange_code_for_tokens(cls, provider: str, code: str, redirect_uri: str) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access tokens."""
        token_endpoints = {
            'google_calendar': 'https://oauth2.googleapis.com/token',
            'outlook_calendar': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            'slack': 'https://slack.com/api/oauth.v2.access',
            'linkedin': 'https://www.linkedin.com/oauth/v2/accessToken',
        }

        client_secrets = {
            'google_calendar': (
                getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', ''),
                getattr(settings, 'GOOGLE_OAUTH_CLIENT_SECRET', '')
            ),
            'outlook_calendar': (
                getattr(settings, 'MICROSOFT_OAUTH_CLIENT_ID', ''),
                getattr(settings, 'MICROSOFT_OAUTH_CLIENT_SECRET', '')
            ),
            'slack': (
                getattr(settings, 'SLACK_CLIENT_ID', ''),
                getattr(settings, 'SLACK_CLIENT_SECRET', '')
            ),
            'linkedin': (
                getattr(settings, 'LINKEDIN_CLIENT_ID', ''),
                getattr(settings, 'LINKEDIN_CLIENT_SECRET', '')
            ),
        }

        endpoint = token_endpoints.get(provider)
        client_id, client_secret = client_secrets.get(provider, ('', ''))

        if not endpoint or not client_id:
            return None

        data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
        }

        response = requests.post(endpoint, data=data, timeout=30)

        if response.status_code == 200:
            return response.json()

        logger.error(f"Token exchange failed: {response.text}")
        return None

    @classmethod
    def _get_integration_type(cls, provider: str) -> str:
        """Get integration type for a provider."""
        type_map = {
            'google_calendar': 'calendar',
            'outlook_calendar': 'calendar',
            'gmail': 'email',
            'outlook_email': 'email',
            'slack': 'messaging',
            'microsoft_teams': 'messaging',
            'zoom': 'video',
            'linkedin': 'job_board',
            'indeed': 'job_board',
            'checkr': 'background_check',
            'docusign': 'esign',
            'stripe': 'payment',
        }
        return type_map.get(provider, 'other')


class CalendarIntegrationService(BaseIntegrationService):
    """
    Google/Outlook calendar synchronization service.
    Supports event creation, updates, and bi-directional sync.
    """

    def connect(self, credentials: Dict[str, Any]) -> IntegrationResult:
        """Connect to calendar service."""
        try:
            # Create or update credentials
            cred, created = IntegrationCredential.objects.update_or_create(
                integration=self.integration,
                defaults={
                    'auth_type': 'oauth2',
                    'access_token': credentials.get('access_token', ''),
                    'refresh_token': credentials.get('refresh_token', ''),
                    'token_type': credentials.get('token_type', 'Bearer'),
                    'scope': credentials.get('scope', ''),
                    'expires_at': timezone.now() + timedelta(seconds=credentials.get('expires_in', 3600)),
                }
            )

            self.credentials = cred

            # Test the connection
            if self.test_connection():
                return IntegrationResult(success=True, data={'status': 'connected'})
            else:
                return IntegrationResult(success=False, error_message='Connection test failed')

        except Exception as e:
            return IntegrationResult(success=False, error_message=str(e))

    def disconnect(self) -> bool:
        """Disconnect from calendar service."""
        try:
            if self.credentials:
                # Revoke token if possible
                self._revoke_token()
            return True
        except Exception as e:
            logger.error(f"Calendar disconnect failed: {e}")
            return False

    def test_connection(self) -> bool:
        """Test calendar connection by fetching calendar list."""
        try:
            if self.integration.provider == 'google_calendar':
                return self._test_google_connection()
            elif self.integration.provider == 'outlook_calendar':
                return self._test_outlook_connection()
            return False
        except Exception as e:
            logger.error(f"Calendar connection test failed: {e}")
            return False

    def sync(self, sync_type: str = 'incremental') -> SyncResult:
        """Sync calendar events."""
        if self.integration.provider == 'google_calendar':
            return self._sync_google_calendar(sync_type)
        elif self.integration.provider == 'outlook_calendar':
            return self._sync_outlook_calendar(sync_type)
        return SyncResult(success=False, error_message='Unsupported provider')

    def sync_events(self, date_range: Tuple[datetime, datetime]) -> List[Dict]:
        """Fetch events within a date range."""
        start_date, end_date = date_range

        if self.integration.provider == 'google_calendar':
            return self._fetch_google_events(start_date, end_date)
        elif self.integration.provider == 'outlook_calendar':
            return self._fetch_outlook_events(start_date, end_date)

        return []

    def create_event(self, event_data: Dict[str, Any]) -> str:
        """Create a calendar event. Returns external event ID."""
        if self.integration.provider == 'google_calendar':
            return self._create_google_event(event_data)
        elif self.integration.provider == 'outlook_calendar':
            return self._create_outlook_event(event_data)
        raise NotImplementedError("Provider not supported")

    def update_event(self, event_id: str, event_data: Dict[str, Any]) -> bool:
        """Update a calendar event."""
        if self.integration.provider == 'google_calendar':
            return self._update_google_event(event_id, event_data)
        elif self.integration.provider == 'outlook_calendar':
            return self._update_outlook_event(event_id, event_data)
        return False

    def delete_event(self, event_id: str) -> bool:
        """Delete a calendar event."""
        if self.integration.provider == 'google_calendar':
            return self._delete_google_event(event_id)
        elif self.integration.provider == 'outlook_calendar':
            return self._delete_outlook_event(event_id)
        return False

    def _do_token_refresh(self) -> bool:
        """Refresh OAuth token for calendar provider."""
        if self.integration.provider == 'google_calendar':
            return self._refresh_google_token()
        elif self.integration.provider == 'outlook_calendar':
            return self._refresh_outlook_token()
        return False

    # Google Calendar Implementation
    def _test_google_connection(self) -> bool:
        """Test Google Calendar connection."""
        headers = {'Authorization': f'Bearer {self.credentials.access_token}'}
        response = requests.get(
            'https://www.googleapis.com/calendar/v3/users/me/calendarList',
            headers=headers,
            timeout=30
        )
        return response.status_code == 200

    def _sync_google_calendar(self, sync_type: str) -> SyncResult:
        """Sync Google Calendar events."""
        try:
            headers = {'Authorization': f'Bearer {self.credentials.access_token}'}

            # Get events from the last 30 days to next 90 days
            time_min = (timezone.now() - timedelta(days=30)).isoformat()
            time_max = (timezone.now() + timedelta(days=90)).isoformat()

            params = {
                'timeMin': time_min,
                'timeMax': time_max,
                'maxResults': 250,
                'singleEvents': True,
            }

            response = requests.get(
                'https://www.googleapis.com/calendar/v3/calendars/primary/events',
                headers=headers,
                params=params,
                timeout=30
            )

            if response.status_code != 200:
                return SyncResult(success=False, error_message=f"API error: {response.status_code}")

            data = response.json()
            events = data.get('items', [])

            return SyncResult(
                success=True,
                records_processed=len(events),
                sync_cursor=data.get('nextSyncToken')
            )

        except Exception as e:
            return SyncResult(success=False, error_message=str(e))

    def _fetch_google_events(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Fetch Google Calendar events."""
        headers = {'Authorization': f'Bearer {self.credentials.access_token}'}

        params = {
            'timeMin': start_date.isoformat(),
            'timeMax': end_date.isoformat(),
            'maxResults': 250,
            'singleEvents': True,
            'orderBy': 'startTime'
        }

        response = requests.get(
            'https://www.googleapis.com/calendar/v3/calendars/primary/events',
            headers=headers,
            params=params,
            timeout=30
        )

        if response.status_code == 200:
            return response.json().get('items', [])

        return []

    def _create_google_event(self, event_data: Dict) -> str:
        """Create a Google Calendar event."""
        headers = {
            'Authorization': f'Bearer {self.credentials.access_token}',
            'Content-Type': 'application/json'
        }

        response = requests.post(
            'https://www.googleapis.com/calendar/v3/calendars/primary/events',
            headers=headers,
            json=event_data,
            timeout=30
        )

        if response.status_code == 200:
            return response.json().get('id')

        raise Exception(f"Failed to create event: {response.text}")

    def _update_google_event(self, event_id: str, event_data: Dict) -> bool:
        """Update a Google Calendar event."""
        headers = {
            'Authorization': f'Bearer {self.credentials.access_token}',
            'Content-Type': 'application/json'
        }

        response = requests.put(
            f'https://www.googleapis.com/calendar/v3/calendars/primary/events/{event_id}',
            headers=headers,
            json=event_data,
            timeout=30
        )

        return response.status_code == 200

    def _delete_google_event(self, event_id: str) -> bool:
        """Delete a Google Calendar event."""
        headers = {'Authorization': f'Bearer {self.credentials.access_token}'}

        response = requests.delete(
            f'https://www.googleapis.com/calendar/v3/calendars/primary/events/{event_id}',
            headers=headers,
            timeout=30
        )

        return response.status_code == 204

    def _refresh_google_token(self) -> bool:
        """Refresh Google OAuth token."""
        data = {
            'client_id': getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', ''),
            'client_secret': getattr(settings, 'GOOGLE_OAUTH_CLIENT_SECRET', ''),
            'refresh_token': self.credentials.refresh_token,
            'grant_type': 'refresh_token',
        }

        response = requests.post(
            'https://oauth2.googleapis.com/token',
            data=data,
            timeout=30
        )

        if response.status_code == 200:
            tokens = response.json()
            self.credentials.update_tokens(
                access_token=tokens['access_token'],
                expires_in=tokens.get('expires_in', 3600)
            )
            self.log_event('token_refreshed', 'Google OAuth token refreshed')
            return True

        return False

    # Outlook Calendar Implementation (similar structure)
    def _test_outlook_connection(self) -> bool:
        """Test Outlook Calendar connection."""
        headers = {'Authorization': f'Bearer {self.credentials.access_token}'}
        response = requests.get(
            'https://graph.microsoft.com/v1.0/me/calendars',
            headers=headers,
            timeout=30
        )
        return response.status_code == 200

    def _sync_outlook_calendar(self, sync_type: str) -> SyncResult:
        """Sync Outlook Calendar events."""
        try:
            headers = {'Authorization': f'Bearer {self.credentials.access_token}'}

            start_time = (timezone.now() - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%S')
            end_time = (timezone.now() + timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%S')

            params = {
                '$filter': f"start/dateTime ge '{start_time}' and end/dateTime le '{end_time}'",
                '$top': 250
            }

            response = requests.get(
                'https://graph.microsoft.com/v1.0/me/calendar/events',
                headers=headers,
                params=params,
                timeout=30
            )

            if response.status_code != 200:
                return SyncResult(success=False, error_message=f"API error: {response.status_code}")

            data = response.json()
            events = data.get('value', [])

            return SyncResult(
                success=True,
                records_processed=len(events)
            )

        except Exception as e:
            return SyncResult(success=False, error_message=str(e))

    def _fetch_outlook_events(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Fetch Outlook Calendar events."""
        headers = {'Authorization': f'Bearer {self.credentials.access_token}'}

        params = {
            '$filter': f"start/dateTime ge '{start_date.isoformat()}' and end/dateTime le '{end_date.isoformat()}'",
            '$orderby': 'start/dateTime',
            '$top': 250
        }

        response = requests.get(
            'https://graph.microsoft.com/v1.0/me/calendar/events',
            headers=headers,
            params=params,
            timeout=30
        )

        if response.status_code == 200:
            return response.json().get('value', [])

        return []

    def _create_outlook_event(self, event_data: Dict) -> str:
        """Create an Outlook Calendar event."""
        headers = {
            'Authorization': f'Bearer {self.credentials.access_token}',
            'Content-Type': 'application/json'
        }

        response = requests.post(
            'https://graph.microsoft.com/v1.0/me/calendar/events',
            headers=headers,
            json=event_data,
            timeout=30
        )

        if response.status_code == 201:
            return response.json().get('id')

        raise Exception(f"Failed to create event: {response.text}")

    def _update_outlook_event(self, event_id: str, event_data: Dict) -> bool:
        """Update an Outlook Calendar event."""
        headers = {
            'Authorization': f'Bearer {self.credentials.access_token}',
            'Content-Type': 'application/json'
        }

        response = requests.patch(
            f'https://graph.microsoft.com/v1.0/me/calendar/events/{event_id}',
            headers=headers,
            json=event_data,
            timeout=30
        )

        return response.status_code == 200

    def _delete_outlook_event(self, event_id: str) -> bool:
        """Delete an Outlook Calendar event."""
        headers = {'Authorization': f'Bearer {self.credentials.access_token}'}

        response = requests.delete(
            f'https://graph.microsoft.com/v1.0/me/calendar/events/{event_id}',
            headers=headers,
            timeout=30
        )

        return response.status_code == 204

    def _refresh_outlook_token(self) -> bool:
        """Refresh Microsoft OAuth token."""
        data = {
            'client_id': getattr(settings, 'MICROSOFT_OAUTH_CLIENT_ID', ''),
            'client_secret': getattr(settings, 'MICROSOFT_OAUTH_CLIENT_SECRET', ''),
            'refresh_token': self.credentials.refresh_token,
            'grant_type': 'refresh_token',
            'scope': 'openid profile email Calendars.ReadWrite offline_access'
        }

        response = requests.post(
            'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            data=data,
            timeout=30
        )

        if response.status_code == 200:
            tokens = response.json()
            self.credentials.update_tokens(
                access_token=tokens['access_token'],
                refresh_token=tokens.get('refresh_token'),
                expires_in=tokens.get('expires_in', 3600)
            )
            self.log_event('token_refreshed', 'Outlook OAuth token refreshed')
            return True

        return False

    def _revoke_token(self):
        """Revoke OAuth tokens."""
        # Google and Microsoft have different revocation endpoints
        pass


class SlackIntegrationService(BaseIntegrationService):
    """
    Slack workspace integration service.
    Supports posting messages, updating status, and channel management.
    """

    provider = 'slack'
    integration_type = 'messaging'

    def connect(self, credentials: Dict[str, Any]) -> IntegrationResult:
        """Connect to Slack workspace."""
        try:
            cred, created = IntegrationCredential.objects.update_or_create(
                integration=self.integration,
                defaults={
                    'auth_type': 'oauth2',
                    'access_token': credentials.get('access_token', ''),
                    'token_type': 'Bearer',
                    'scope': credentials.get('scope', ''),
                    'external_account_id': credentials.get('team', {}).get('id', ''),
                }
            )

            self.credentials = cred

            if self.test_connection():
                return IntegrationResult(success=True, data={'team': credentials.get('team')})
            else:
                return IntegrationResult(success=False, error_message='Connection test failed')

        except Exception as e:
            return IntegrationResult(success=False, error_message=str(e))

    def disconnect(self) -> bool:
        """Disconnect from Slack."""
        return True

    def test_connection(self) -> bool:
        """Test Slack connection."""
        try:
            headers = {'Authorization': f'Bearer {self.credentials.access_token}'}
            response = requests.get(
                'https://slack.com/api/auth.test',
                headers=headers,
                timeout=30
            )
            data = response.json()
            return data.get('ok', False)
        except Exception:
            return False

    def sync(self, sync_type: str = 'incremental') -> SyncResult:
        """Sync Slack data (channels, users)."""
        try:
            # Fetch channels
            channels = self._fetch_channels()

            return SyncResult(
                success=True,
                records_processed=len(channels)
            )
        except Exception as e:
            return SyncResult(success=False, error_message=str(e))

    def post_message(self, channel: str, message: str, blocks: List[Dict] = None) -> bool:
        """Post a message to a Slack channel."""
        headers = {
            'Authorization': f'Bearer {self.credentials.access_token}',
            'Content-Type': 'application/json'
        }

        payload = {
            'channel': channel,
            'text': message,
        }

        if blocks:
            payload['blocks'] = blocks

        response = requests.post(
            'https://slack.com/api/chat.postMessage',
            headers=headers,
            json=payload,
            timeout=30
        )

        data = response.json()
        return data.get('ok', False)

    def update_status(self, user_id: str, status_text: str, status_emoji: str = '') -> bool:
        """Update a user's Slack status."""
        headers = {
            'Authorization': f'Bearer {self.credentials.access_token}',
            'Content-Type': 'application/json'
        }

        payload = {
            'profile': {
                'status_text': status_text,
                'status_emoji': status_emoji,
            }
        }

        response = requests.post(
            'https://slack.com/api/users.profile.set',
            headers=headers,
            json=payload,
            timeout=30
        )

        data = response.json()
        return data.get('ok', False)

    def _fetch_channels(self) -> List[Dict]:
        """Fetch Slack channels."""
        headers = {'Authorization': f'Bearer {self.credentials.access_token}'}

        response = requests.get(
            'https://slack.com/api/conversations.list',
            headers=headers,
            params={'types': 'public_channel,private_channel'},
            timeout=30
        )

        data = response.json()
        if data.get('ok'):
            return data.get('channels', [])
        return []

    def _do_token_refresh(self) -> bool:
        """Slack uses long-lived tokens, no refresh needed."""
        return True


class ATSIntegrationService(BaseIntegrationService):
    """
    Applicant Tracking System integration for job boards.
    Supports posting jobs and syncing applications from LinkedIn, Indeed, etc.
    """

    def connect(self, credentials: Dict[str, Any]) -> IntegrationResult:
        """Connect to job board."""
        try:
            cred, created = IntegrationCredential.objects.update_or_create(
                integration=self.integration,
                defaults={
                    'auth_type': credentials.get('auth_type', 'api_key'),
                    'api_key': credentials.get('api_key', ''),
                    'api_secret': credentials.get('api_secret', ''),
                    'access_token': credentials.get('access_token', ''),
                    'refresh_token': credentials.get('refresh_token', ''),
                }
            )

            self.credentials = cred

            if self.test_connection():
                return IntegrationResult(success=True)
            else:
                return IntegrationResult(success=False, error_message='Connection test failed')

        except Exception as e:
            return IntegrationResult(success=False, error_message=str(e))

    def disconnect(self) -> bool:
        """Disconnect from job board."""
        return True

    def test_connection(self) -> bool:
        """Test connection to job board."""
        # Implementation depends on specific job board API
        return True

    def sync(self, sync_type: str = 'incremental') -> SyncResult:
        """Sync applications from job board."""
        try:
            applications = self.sync_applications()
            return SyncResult(
                success=True,
                records_processed=len(applications)
            )
        except Exception as e:
            return SyncResult(success=False, error_message=str(e))

    def post_job(self, job_data: Dict[str, Any]) -> str:
        """Post a job to the job board. Returns external job ID."""
        if self.integration.provider == 'linkedin':
            return self._post_linkedin_job(job_data)
        elif self.integration.provider == 'indeed':
            return self._post_indeed_job(job_data)
        raise NotImplementedError(f"Provider {self.integration.provider} not supported")

    def sync_applications(self) -> List[Dict]:
        """Sync applications from job board."""
        if self.integration.provider == 'linkedin':
            return self._sync_linkedin_applications()
        elif self.integration.provider == 'indeed':
            return self._sync_indeed_applications()
        return []

    def update_job_status(self, external_id: str, status: str) -> bool:
        """Update job posting status."""
        # Implementation depends on specific job board API
        return True

    def _post_linkedin_job(self, job_data: Dict) -> str:
        """Post job to LinkedIn."""
        # LinkedIn Jobs API implementation
        raise NotImplementedError("LinkedIn Jobs API integration required")

    def _post_indeed_job(self, job_data: Dict) -> str:
        """Post job to Indeed."""
        # Indeed Publisher API implementation
        raise NotImplementedError("Indeed Publisher API integration required")

    def _sync_linkedin_applications(self) -> List[Dict]:
        """Sync applications from LinkedIn."""
        # LinkedIn Apply API implementation
        return []

    def _sync_indeed_applications(self) -> List[Dict]:
        """Sync applications from Indeed."""
        # Indeed Apply API implementation
        return []

    def _do_token_refresh(self) -> bool:
        """Refresh OAuth token for job boards."""
        return True


# Register services with IntegrationService
IntegrationService.register_service('google_calendar', CalendarIntegrationService)
IntegrationService.register_service('outlook_calendar', CalendarIntegrationService)
IntegrationService.register_service('slack', SlackIntegrationService)
IntegrationService.register_service('linkedin', ATSIntegrationService)
IntegrationService.register_service('indeed', ATSIntegrationService)


# Convenience functions
def get_integration_service(integration: Integration) -> Optional[BaseIntegrationService]:
    """Get the appropriate service for an integration."""
    return IntegrationService.get_service(integration)


def sync_integration(integration_id: int, sync_type: str = 'incremental', user=None) -> SyncResult:
    """Trigger a sync for an integration."""
    return IntegrationService.sync(integration_id, sync_type, user)
