"""
Integrations API Views and ViewSets

Tenant-aware REST API views for managing integrations, OAuth flows,
webhooks, and sync operations.
"""

import hashlib
import hmac
import json
import logging
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from api.base import (
    TenantAwareViewSet,
    TenantAwareReadOnlyViewSet,
    TenantAwareAPIView,
    APIResponse,
    StandardPagination,
)
from .models import (
    Integration,
    IntegrationCredential,
    IntegrationSyncLog,
    WebhookEndpoint,
    WebhookDelivery,
    IntegrationEvent,
)
from .serializers import (
    IntegrationSerializer,
    IntegrationListSerializer,
    IntegrationCreateSerializer,
    IntegrationUpdateSerializer,
    IntegrationSyncLogSerializer,
    IntegrationSyncLogDetailSerializer,
    WebhookEndpointSerializer,
    WebhookEndpointListSerializer,
    WebhookEndpointCreateSerializer,
    WebhookDeliverySerializer,
    WebhookDeliveryDetailSerializer,
    IntegrationEventSerializer,
    IntegrationConnectSerializer,
    OAuthCallbackSerializer,
    SyncTriggerSerializer,
    AvailableIntegrationSerializer,
    IntegrationStatusSerializer,
    IntegrationStatsSerializer,
    WebhookStatsSerializer,
    IncomingWebhookSerializer,
    WebhookVerificationSerializer,
    IntegrationCredentialWriteSerializer,
)
from .webhooks import WebhookValidator


logger = logging.getLogger(__name__)


# =============================================================================
# PROVIDER INFO
# =============================================================================

def get_provider_class(provider_name: str):
    """Get provider class for a given provider name."""
    from .providers.calendar import GoogleCalendarProvider, OutlookCalendarProvider
    from .providers.email import GmailProvider, OutlookEmailProvider, SMTPProvider
    from .providers.job_boards import IndeedProvider, LinkedInProvider, GlassdoorProvider
    from .providers.background_check import CheckrProvider, SterlingProvider
    from .providers.esign import DocuSignProvider, HelloSignProvider
    from .providers.hris import BambooHRProvider, WorkdayProvider
    from .providers.slack import SlackProvider
    from .providers.video import ZoomProvider, MicrosoftTeamsProvider

    providers = {
        'google_calendar': GoogleCalendarProvider,
        'outlook_calendar': OutlookCalendarProvider,
        'gmail': GmailProvider,
        'outlook_email': OutlookEmailProvider,
        'smtp': SMTPProvider,
        'indeed': IndeedProvider,
        'linkedin': LinkedInProvider,
        'glassdoor': GlassdoorProvider,
        'checkr': CheckrProvider,
        'sterling': SterlingProvider,
        'docusign': DocuSignProvider,
        'hellosign': HelloSignProvider,
        'bamboohr': BambooHRProvider,
        'workday': WorkdayProvider,
        'slack': SlackProvider,
        'zoom': ZoomProvider,
        'teams_meeting': MicrosoftTeamsProvider,
    }

    return providers.get(provider_name)


def get_provider_info():
    """Get information about available providers."""
    return {
        'google_calendar': {
            'display_name': 'Google Calendar',
            'type': 'calendar',
            'type_display': 'Calendar',
            'description': 'Sync interview schedules with Google Calendar',
            'is_oauth': True,
            'features': ['calendar_sync', 'event_creation', 'availability'],
            'icon_url': '/static/integrations/google.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/google-calendar',
        },
        'outlook_calendar': {
            'display_name': 'Outlook Calendar',
            'type': 'calendar',
            'type_display': 'Calendar',
            'description': 'Sync interview schedules with Outlook Calendar',
            'is_oauth': True,
            'features': ['calendar_sync', 'event_creation', 'availability'],
            'icon_url': '/static/integrations/microsoft.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/outlook-calendar',
        },
        'gmail': {
            'display_name': 'Gmail',
            'type': 'email',
            'type_display': 'Email',
            'description': 'Send emails via Gmail',
            'is_oauth': True,
            'features': ['send_email', 'read_email', 'email_tracking'],
            'icon_url': '/static/integrations/gmail.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/gmail',
        },
        'outlook_email': {
            'display_name': 'Outlook Email',
            'type': 'email',
            'type_display': 'Email',
            'description': 'Send emails via Outlook',
            'is_oauth': True,
            'features': ['send_email', 'read_email'],
            'icon_url': '/static/integrations/outlook.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/outlook-email',
        },
        'slack': {
            'display_name': 'Slack',
            'type': 'communication',
            'type_display': 'Communication',
            'description': 'Send notifications to Slack channels',
            'is_oauth': True,
            'features': ['notifications', 'channel_messages', 'direct_messages'],
            'icon_url': '/static/integrations/slack.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/slack',
        },
        'zoom': {
            'display_name': 'Zoom',
            'type': 'video',
            'type_display': 'Video',
            'description': 'Create video interview meetings',
            'is_oauth': True,
            'features': ['create_meeting', 'recordings', 'scheduling'],
            'icon_url': '/static/integrations/zoom.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/zoom',
        },
        'teams_meeting': {
            'display_name': 'Microsoft Teams',
            'type': 'video',
            'type_display': 'Video',
            'description': 'Create Teams video meetings',
            'is_oauth': True,
            'features': ['create_meeting', 'scheduling'],
            'icon_url': '/static/integrations/teams.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/teams',
        },
        'checkr': {
            'display_name': 'Checkr',
            'type': 'background_check',
            'type_display': 'Background Check',
            'description': 'Run background checks on candidates',
            'is_oauth': False,
            'features': ['background_check', 'criminal_records', 'verification'],
            'icon_url': '/static/integrations/checkr.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/checkr',
        },
        'sterling': {
            'display_name': 'Sterling',
            'type': 'background_check',
            'type_display': 'Background Check',
            'description': 'Run background checks',
            'is_oauth': False,
            'features': ['background_check', 'verification'],
            'icon_url': '/static/integrations/sterling.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/sterling',
        },
        'docusign': {
            'display_name': 'DocuSign',
            'type': 'esign',
            'type_display': 'E-Signature',
            'description': 'Send offer letters for e-signature',
            'is_oauth': True,
            'features': ['esign', 'document_tracking', 'templates'],
            'icon_url': '/static/integrations/docusign.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/docusign',
        },
        'hellosign': {
            'display_name': 'HelloSign',
            'type': 'esign',
            'type_display': 'E-Signature',
            'description': 'Send documents for e-signature',
            'is_oauth': True,
            'features': ['esign', 'document_tracking'],
            'icon_url': '/static/integrations/hellosign.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/hellosign',
        },
        'bamboohr': {
            'display_name': 'BambooHR',
            'type': 'hris',
            'type_display': 'HRIS',
            'description': 'Sync employee data with BambooHR',
            'is_oauth': False,
            'features': ['employee_sync', 'onboarding', 'time_off'],
            'icon_url': '/static/integrations/bamboohr.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/bamboohr',
        },
        'workday': {
            'display_name': 'Workday',
            'type': 'hris',
            'type_display': 'HRIS',
            'description': 'Sync employee data with Workday',
            'is_oauth': True,
            'features': ['employee_sync', 'positions'],
            'icon_url': '/static/integrations/workday.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/workday',
        },
        'indeed': {
            'display_name': 'Indeed',
            'type': 'job_board',
            'type_display': 'Job Board',
            'description': 'Post jobs to Indeed',
            'is_oauth': False,
            'features': ['job_posting', 'applications'],
            'icon_url': '/static/integrations/indeed.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/indeed',
        },
        'linkedin': {
            'display_name': 'LinkedIn Jobs',
            'type': 'job_board',
            'type_display': 'Job Board',
            'description': 'Post jobs to LinkedIn',
            'is_oauth': True,
            'features': ['job_posting', 'applications'],
            'icon_url': '/static/integrations/linkedin.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/linkedin',
        },
        'stripe': {
            'display_name': 'Stripe',
            'type': 'payment',
            'type_display': 'Payment',
            'description': 'Process payments and manage subscriptions',
            'is_oauth': True,
            'features': ['payments', 'subscriptions', 'invoicing'],
            'icon_url': '/static/integrations/stripe.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/stripe',
        },
        'quickbooks': {
            'display_name': 'QuickBooks',
            'type': 'accounting',
            'type_display': 'Accounting',
            'description': 'Sync invoices and financial data',
            'is_oauth': True,
            'features': ['invoice_sync', 'expense_tracking', 'reporting'],
            'icon_url': '/static/integrations/quickbooks.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/quickbooks',
        },
        'twilio': {
            'display_name': 'Twilio',
            'type': 'sms',
            'type_display': 'SMS',
            'description': 'Send SMS notifications via Twilio',
            'is_oauth': False,
            'features': ['sms', 'voice', 'whatsapp'],
            'icon_url': '/static/integrations/twilio.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/twilio',
        },
        'sendgrid': {
            'display_name': 'SendGrid',
            'type': 'email',
            'type_display': 'Email',
            'description': 'Send transactional emails via SendGrid',
            'is_oauth': False,
            'features': ['email_delivery', 'templates', 'analytics'],
            'icon_url': '/static/integrations/sendgrid.svg',
            'documentation_url': 'https://docs.zumodra.com/integrations/sendgrid',
        },
    }


# =============================================================================
# PAGINATION
# =============================================================================

class IntegrationPagination(StandardPagination):
    """Pagination for integration-related endpoints."""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


# =============================================================================
# INTEGRATION VIEWSET
# =============================================================================

class IntegrationViewSet(TenantAwareViewSet):
    """
    ViewSet for managing integrations.

    Provides CRUD operations plus:
    - List available providers
    - Connect/disconnect integrations
    - Trigger sync operations
    - View sync history

    Endpoints:
    - GET /integrations/ - List all integrations
    - POST /integrations/ - Create new integration
    - GET /integrations/{uuid}/ - Get integration details
    - PUT /integrations/{uuid}/ - Update integration
    - DELETE /integrations/{uuid}/ - Delete integration
    - GET /integrations/available_providers/ - List available providers
    - POST /integrations/{uuid}/connect/ - Connect integration
    - POST /integrations/{uuid}/disconnect/ - Disconnect integration
    - POST /integrations/{uuid}/sync/ - Trigger sync
    - GET /integrations/{uuid}/sync_history/ - Get sync history
    - GET /integrations/{uuid}/status/ - Get status
    - GET /integrations/stats/ - Get statistics
    """

    serializer_class = IntegrationSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = IntegrationPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['provider', 'integration_type', 'status', 'is_enabled']
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'provider', 'status', 'created_at', 'last_sync_at']
    ordering = ['-created_at']
    lookup_field = 'uuid'
    tenant_field = 'tenant'

    def get_queryset(self):
        """Get integrations with related data."""
        queryset = Integration.objects.select_related(
            'credentials', 'connected_by'
        ).prefetch_related('webhook_endpoints', 'sync_logs')
        return queryset

    def get_serializer_class(self):
        if self.action == 'list':
            return IntegrationListSerializer
        if self.action == 'create':
            return IntegrationCreateSerializer
        if self.action in ['update', 'partial_update']:
            return IntegrationUpdateSerializer
        return IntegrationSerializer

    def perform_create(self, serializer):
        """Create integration with tenant and user."""
        serializer.save(
            connected_by=self.request.user,
            connected_at=timezone.now()
        )

    @action(detail=False, methods=['get'])
    def available_providers(self, request):
        """
        List available integration providers.

        Returns all supported providers with:
        - Provider details and features
        - Whether already connected for this tenant
        """
        tenant = getattr(request, 'tenant', None)
        connected_providers = set()

        if tenant:
            connected_providers = set(
                Integration.objects.filter(tenant=tenant)
                .values_list('provider', flat=True)
            )
        else:
            # Try to get from user's tenant membership
            tenant_membership = getattr(request.user, 'tenant_memberships', None)
            if tenant_membership:
                membership = tenant_membership.first()
                if membership:
                    connected_providers = set(
                        Integration.objects.filter(tenant=membership.tenant)
                        .values_list('provider', flat=True)
                    )

        providers = []
        provider_info = get_provider_info()

        for provider, info in provider_info.items():
            providers.append({
                'provider': provider,
                'display_name': info.get('display_name', provider),
                'integration_type': info.get('type', 'custom'),
                'type_display': info.get('type_display', 'Custom'),
                'description': info.get('description', ''),
                'is_oauth': info.get('is_oauth', False),
                'is_connected': provider in connected_providers,
                'features': info.get('features', []),
                'icon_url': info.get('icon_url'),
                'documentation_url': info.get('documentation_url'),
            })

        serializer = AvailableIntegrationSerializer(providers, many=True)
        return APIResponse.success(data=serializer.data)

    @action(detail=True, methods=['post'])
    def connect(self, request, uuid=None):
        """
        Connect/authorize an integration.

        For OAuth providers: Returns authorization URL
        For API key providers: Validates and stores credentials
        """
        integration = self.get_object()

        provider_info = get_provider_info().get(integration.provider, {})
        provider_class = get_provider_class(integration.provider)

        if not provider_class:
            return APIResponse.error(
                message=_("Provider %(provider)s not supported") % {'provider': integration.provider},
                error_code="PROVIDER_NOT_SUPPORTED"
            )

        provider = provider_class(integration)

        if provider_info.get('is_oauth') and hasattr(provider, 'oauth_authorize_url'):
            # Generate state token for CSRF protection
            state = secrets.token_urlsafe(32)

            # Store state in session
            request.session[f'oauth_state_{integration.uuid}'] = state
            redirect_url = request.data.get(
                'redirect_url',
                request.build_absolute_uri('/integrations/')
            )
            request.session[f'oauth_redirect_{integration.uuid}'] = redirect_url

            auth_url = provider.get_authorization_url(state)

            return APIResponse.success(
                data={
                    'authorization_url': auth_url,
                    'state': state,
                    'provider': integration.provider,
                },
                message=_("Redirect user to authorization URL")
            )
        else:
            # API key based connection
            serializer = IntegrationConnectSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            credentials = serializer.validated_data.get('credentials', {})

            if provider.connect(credentials):
                # Update integration status
                integration.status = 'connected'
                integration.connected_at = timezone.now()
                integration.connected_by = request.user
                integration.save()

                # Log event
                IntegrationEvent.objects.create(
                    integration=integration,
                    event_type='connected',
                    message=_("Integration connected successfully"),
                    triggered_by=request.user,
                )

                return APIResponse.success(
                    message=_("Integration connected successfully")
                )
            else:
                return APIResponse.error(
                    message=_("Failed to connect integration"),
                    error_code="CONNECTION_FAILED"
                )

    @action(detail=True, methods=['post'])
    def disconnect(self, request, uuid=None):
        """
        Disconnect an integration.

        Revokes credentials and marks as disconnected.
        """
        integration = self.get_object()

        provider_class = get_provider_class(integration.provider)
        if provider_class:
            try:
                provider = provider_class(integration)
                provider.disconnect()
            except Exception as e:
                logger.warning(f"Failed to disconnect provider: {e}")
        else:
            integration.deactivate("Disconnected by user")

        # Update status
        integration.status = 'disconnected'
        integration.disconnected_at = timezone.now()
        integration.save()

        # Delete credentials
        if hasattr(integration, 'credentials'):
            integration.credentials.delete()

        # Log event
        IntegrationEvent.objects.create(
            integration=integration,
            event_type='disconnected',
            message=_("Integration disconnected by user"),
            triggered_by=request.user
        )

        return APIResponse.success(
            message=_("Integration disconnected successfully")
        )

    @action(detail=True, methods=['post'])
    def sync(self, request, uuid=None):
        """
        Trigger a sync operation for the integration.

        Supports:
        - Full or incremental sync
        - Specific resource type sync
        """
        integration = self.get_object()

        if not integration.is_active:
            return APIResponse.error(
                message=_("Integration is not active"),
                error_code="INTEGRATION_INACTIVE"
            )

        serializer = SyncTriggerSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create sync log
        sync_log = IntegrationSyncLog.objects.create(
            integration=integration,
            sync_type=serializer.validated_data.get('sync_type', 'manual'),
            direction='inbound',
            status='pending',
            resource_type=serializer.validated_data.get('resource_type', ''),
            triggered_by=request.user
        )

        # Trigger async sync task
        from .tasks import run_integration_sync
        run_integration_sync.delay(sync_log.uuid.hex)

        return APIResponse.success(
            data={
                'sync_id': str(sync_log.uuid),
                'status': 'pending',
            },
            message=_("Sync operation started")
        )

    @action(detail=True, methods=['get'])
    def sync_history(self, request, uuid=None):
        """Get sync history for an integration."""
        integration = self.get_object()

        sync_logs = IntegrationSyncLog.objects.filter(
            integration=integration
        ).select_related('triggered_by').order_by('-started_at')

        # Pagination
        page = self.paginate_queryset(sync_logs)
        if page is not None:
            serializer = IntegrationSyncLogSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = IntegrationSyncLogSerializer(sync_logs, many=True)
        return APIResponse.success(data=serializer.data)

    @action(detail=True, methods=['get'])
    def status(self, request, uuid=None):
        """Get detailed status for an integration."""
        integration = self.get_object()

        # Check credentials
        credentials_valid = False
        credentials_expiring_soon = False
        days_until_expiry = None

        if hasattr(integration, 'credentials'):
            creds = integration.credentials
            credentials_valid = not creds.is_expired
            credentials_expiring_soon = creds.needs_refresh

            if creds.expires_at:
                days_until_expiry = (creds.expires_at - timezone.now()).days

        status_data = {
            'provider': integration.provider,
            'provider_display': integration.get_provider_display(),
            'status': integration.status,
            'status_display': integration.get_status_display(),
            'is_active': integration.is_active,
            'last_sync_at': integration.last_sync_at,
            'next_sync_at': integration.next_sync_at,
            'error_count': integration.sync_error_count,
            'credentials_valid': credentials_valid,
            'credentials_expiring_soon': credentials_expiring_soon,
            'days_until_expiry': days_until_expiry,
        }

        serializer = IntegrationStatusSerializer(status_data)
        return APIResponse.success(data=serializer.data)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get integration statistics for tenant."""
        queryset = self.filter_queryset(self.get_queryset())

        today = timezone.now().date()
        today_start = timezone.make_aware(
            timezone.datetime.combine(today, timezone.datetime.min.time())
        )

        # Sync logs for today
        sync_logs_today = IntegrationSyncLog.objects.filter(
            integration__in=queryset,
            started_at__gte=today_start
        )

        # Webhook deliveries for today
        webhooks_today = WebhookDelivery.objects.filter(
            endpoint__integration__in=queryset,
            received_at__gte=today_start
        )

        stats = {
            'total_integrations': queryset.count(),
            'active_integrations': queryset.filter(status='connected').count(),
            'inactive_integrations': queryset.filter(status='disconnected').count(),
            'error_integrations': queryset.filter(status='error').count(),
            'by_type': dict(
                queryset.values('integration_type')
                .annotate(count=Count('id'))
                .values_list('integration_type', 'count')
            ),
            'by_status': dict(
                queryset.values('status')
                .annotate(count=Count('id'))
                .values_list('status', 'count')
            ),
            'total_syncs_today': sync_logs_today.count(),
            'successful_syncs_today': sync_logs_today.filter(status='success').count(),
            'failed_syncs_today': sync_logs_today.filter(status='failed').count(),
            'total_webhooks_today': webhooks_today.count(),
        }

        serializer = IntegrationStatsSerializer(stats)
        return APIResponse.success(data=serializer.data)

    @action(detail=True, methods=['get'])
    def events(self, request, uuid=None):
        """Get events for an integration."""
        integration = self.get_object()

        events = IntegrationEvent.objects.filter(
            integration=integration
        ).select_related('triggered_by').order_by('-created_at')

        page = self.paginate_queryset(events)
        if page is not None:
            serializer = IntegrationEventSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = IntegrationEventSerializer(events, many=True)
        return APIResponse.success(data=serializer.data)

    @action(detail=True, methods=['post'])
    def test(self, request, uuid=None):
        """Test connectivity for an integration."""
        integration = self.get_object()

        provider_class = get_provider_class(integration.provider)
        if not provider_class:
            return APIResponse.error(
                message=_("Provider %(provider)s not supported") % {'provider': integration.provider},
                error_code="PROVIDER_NOT_SUPPORTED"
            )

        provider = provider_class(integration)
        success, message = provider.test_connection()

        if success:
            return APIResponse.success(
                message=message or _("Connection test successful")
            )
        else:
            return APIResponse.error(
                message=message or _("Connection test failed"),
                error_code="CONNECTION_TEST_FAILED"
            )

    @action(detail=True, methods=['post'])
    def refresh_token(self, request, uuid=None):
        """Manually refresh OAuth token for an integration."""
        integration = self.get_object()

        if not hasattr(integration, 'credentials'):
            return APIResponse.error(
                message=_("No credentials found for this integration"),
                error_code="NO_CREDENTIALS"
            )

        provider_class = get_provider_class(integration.provider)
        if not provider_class:
            return APIResponse.error(
                message=_("Provider %(provider)s not supported") % {'provider': integration.provider},
                error_code="PROVIDER_NOT_SUPPORTED"
            )

        provider = provider_class(integration)

        try:
            if provider.refresh_access_token():
                return APIResponse.success(
                    message=_("Token refreshed successfully")
                )
            else:
                return APIResponse.error(
                    message=_("Failed to refresh token"),
                    error_code="TOKEN_REFRESH_FAILED"
                )
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return APIResponse.error(
                message=str(e),
                error_code="TOKEN_REFRESH_ERROR"
            )


# =============================================================================
# OAUTH CALLBACK VIEW
# =============================================================================

class OAuthCallbackView(APIView):
    """
    Handle OAuth callbacks from providers.

    Receives authorization code from OAuth provider and exchanges
    it for access tokens.

    Endpoints:
    - GET /integrations/oauth/callback/<provider>/ - OAuth callback
    - GET /integrations/oauth/callback/ - Generic OAuth callback
    """

    permission_classes = [AllowAny]  # Callback comes from external service

    def get(self, request, provider=None):
        """Handle OAuth callback GET request."""
        serializer = OAuthCallbackSerializer(data=request.query_params)

        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            logger.error(f"OAuth callback validation failed: {e}")
            return self._error_response("Invalid callback parameters")

        code = serializer.validated_data['code']
        state = serializer.validated_data['state']

        # Find integration by state
        integration = None
        redirect_url = None

        for key in list(request.session.keys()):
            if key.startswith('oauth_state_') and request.session[key] == state:
                integration_uuid = key.replace('oauth_state_', '')
                try:
                    integration = Integration.objects.get(uuid=integration_uuid)
                    redirect_url = request.session.get(f'oauth_redirect_{integration_uuid}', '/')

                    # Clean up session
                    del request.session[key]
                    if f'oauth_redirect_{integration_uuid}' in request.session:
                        del request.session[f'oauth_redirect_{integration_uuid}']
                except Integration.DoesNotExist:
                    pass
                break

        if not integration:
            logger.error(f"OAuth callback: Invalid state parameter")
            return self._error_response("Invalid or expired OAuth state")

        # Exchange code for tokens
        provider_class = get_provider_class(integration.provider)
        if not provider_class:
            return self._error_response(f"Provider {integration.provider} not supported")

        provider_instance = provider_class(integration)

        try:
            tokens = provider_instance.exchange_code_for_tokens(code)

            # Store credentials
            credentials, _ = IntegrationCredential.objects.get_or_create(
                integration=integration
            )
            credentials.update_tokens(
                access_token=tokens.get('access_token'),
                refresh_token=tokens.get('refresh_token'),
                expires_in=tokens.get('expires_in'),
                scope=tokens.get('scope', ''),
            )

            # Get account info if available
            try:
                account_info = provider_instance.get_account_info()
                credentials.external_user_id = account_info.get('id', '')
                credentials.external_account_id = account_info.get('account_id', '')
                credentials.save()
            except Exception as e:
                logger.warning(f"Failed to get account info: {e}")

            # Activate integration
            integration.activate()

            # Log event
            IntegrationEvent.objects.create(
                integration=integration,
                event_type='connected',
                message=f'Successfully connected to {integration.get_provider_display()}',
                triggered_by=request.user if request.user.is_authenticated else None,
            )

            # Redirect back to app
            if redirect_url:
                separator = '&' if '?' in redirect_url else '?'
                return redirect(f"{redirect_url}{separator}integration={integration.uuid}&status=connected")

            return Response({
                'status': 'connected',
                'integration_id': str(integration.uuid),
            })

        except Exception as e:
            logger.error(f"OAuth callback failed: {e}")

            IntegrationEvent.objects.create(
                integration=integration,
                event_type='error',
                message=f'OAuth connection failed: {str(e)}',
                triggered_by=request.user if request.user.is_authenticated else None,
            )

            if redirect_url:
                separator = '&' if '?' in redirect_url else '?'
                return redirect(f"{redirect_url}{separator}integration={integration.uuid}&status=error&message={str(e)}")

            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    def _error_response(self, message):
        """Return error response or redirect."""
        error_url = getattr(settings, 'INTEGRATION_OAUTH_ERROR_URL', None)
        if error_url:
            return redirect(f"{error_url}?error={message}")
        return HttpResponseBadRequest(message)


# =============================================================================
# WEBHOOK VIEWSETS
# =============================================================================

class WebhookEndpointViewSet(TenantAwareViewSet):
    """
    ViewSet for managing webhook endpoints.

    Endpoints:
    - GET /webhooks/ - List webhook endpoints
    - POST /webhooks/ - Create webhook endpoint
    - GET /webhooks/{uuid}/ - Get endpoint details
    - PUT /webhooks/{uuid}/ - Update endpoint
    - DELETE /webhooks/{uuid}/ - Delete endpoint
    - POST /webhooks/{uuid}/regenerate_secret/ - Regenerate secret
    - GET /webhooks/{uuid}/deliveries/ - Get delivery history
    - GET /webhooks/stats/ - Get webhook statistics
    """

    serializer_class = WebhookEndpointSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = IntegrationPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['status', 'is_enabled', 'integration__uuid']
    search_fields = ['name', 'endpoint_path']
    ordering_fields = ['name', 'created_at', 'last_received_at']
    ordering = ['-created_at']
    lookup_field = 'uuid'
    tenant_field = 'integration__tenant'

    def get_queryset(self):
        return WebhookEndpoint.objects.select_related('integration')

    def get_serializer_class(self):
        if self.action == 'list':
            return WebhookEndpointListSerializer
        if self.action == 'create':
            return WebhookEndpointCreateSerializer
        return WebhookEndpointSerializer

    def perform_create(self, serializer):
        """Create webhook endpoint with auto-generated path and secret."""
        integration_uuid = serializer.validated_data.pop('integration')

        # Get tenant for filtering
        tenant = getattr(self.request, 'tenant', None)
        if not tenant:
            tenant_membership = getattr(self.request.user, 'tenant_memberships', None)
            if tenant_membership:
                membership = tenant_membership.first()
                tenant = membership.tenant if membership else None

        integration = get_object_or_404(
            Integration, uuid=integration_uuid
        )

        # Generate unique endpoint path
        endpoint_path = f"{integration.provider}/{secrets.token_urlsafe(16)}"
        secret_key = secrets.token_urlsafe(32)

        serializer.save(
            integration=integration,
            endpoint_path=endpoint_path,
            secret_key=secret_key
        )

    @action(detail=True, methods=['post'])
    def regenerate_secret(self, request, uuid=None):
        """Regenerate the webhook secret key."""
        endpoint = self.get_object()
        endpoint.secret_key = secrets.token_urlsafe(32)
        endpoint.save()

        return APIResponse.success(
            data={'secret_key': endpoint.secret_key},
            message=_("Webhook secret regenerated successfully")
        )

    @action(detail=True, methods=['get'])
    def deliveries(self, request, uuid=None):
        """Get delivery history for a webhook endpoint."""
        endpoint = self.get_object()

        deliveries = WebhookDelivery.objects.filter(
            endpoint=endpoint
        ).order_by('-received_at')

        page = self.paginate_queryset(deliveries)
        if page is not None:
            serializer = WebhookDeliverySerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WebhookDeliverySerializer(deliveries, many=True)
        return APIResponse.success(data=serializer.data)

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get webhook statistics."""
        queryset = self.filter_queryset(self.get_queryset())

        total_received = sum(e.total_received for e in queryset)
        total_processed = sum(e.total_processed for e in queryset)
        total_failed = sum(e.total_failed for e in queryset)

        stats = {
            'total_endpoints': queryset.count(),
            'active_endpoints': queryset.filter(is_enabled=True, status='active').count(),
            'total_received': total_received,
            'total_processed': total_processed,
            'total_failed': total_failed,
            'success_rate': (total_processed / total_received * 100) if total_received > 0 else 100.0,
            'by_status': dict(
                queryset.values('status')
                .annotate(count=Count('id'))
                .values_list('status', 'count')
            ),
        }

        serializer = WebhookStatsSerializer(stats)
        return APIResponse.success(data=serializer.data)


class WebhookDeliveryViewSet(TenantAwareReadOnlyViewSet):
    """
    Read-only ViewSet for webhook deliveries.

    Endpoints:
    - GET /webhook-deliveries/ - List all deliveries
    - GET /webhook-deliveries/{uuid}/ - Get delivery details
    - POST /webhook-deliveries/{uuid}/retry/ - Retry failed delivery
    """

    serializer_class = WebhookDeliverySerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = IntegrationPagination
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['status', 'event_type', 'endpoint__uuid']
    ordering_fields = ['received_at', 'processed_at']
    ordering = ['-received_at']
    lookup_field = 'uuid'
    tenant_field = 'endpoint__integration__tenant'

    def get_queryset(self):
        return WebhookDelivery.objects.select_related('endpoint', 'endpoint__integration')

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return WebhookDeliveryDetailSerializer
        return WebhookDeliverySerializer

    @action(detail=True, methods=['post'])
    def retry(self, request, uuid=None):
        """Retry a failed webhook delivery."""
        delivery = self.get_object()

        if not delivery.can_retry:
            return APIResponse.error(
                message=_("This delivery cannot be retried (max retries reached or already processed)"),
                error_code="CANNOT_RETRY"
            )

        # Queue for retry
        from .tasks import retry_webhook_delivery
        retry_webhook_delivery.delay(delivery.uuid.hex)

        delivery.retry_count += 1
        delivery.status = 'pending'
        delivery.save()

        return APIResponse.success(
            message=_("Webhook delivery queued for retry")
        )


# =============================================================================
# WEBHOOK RECEIVER VIEW
# =============================================================================

class WebhookReceiverView(APIView):
    """
    Receive incoming webhooks from external services.

    Endpoints:
    - POST /integrations/webhooks/<endpoint_path>/ - Receive webhook
    - GET /integrations/webhooks/<endpoint_path>/ - Handle verification challenges
    """

    permission_classes = [AllowAny]  # Webhooks come from external services

    def get(self, request, endpoint_path):
        """
        Handle webhook verification challenges.

        Some providers (Stripe, Facebook, etc.) send GET requests to verify
        the endpoint before sending webhooks.
        """
        endpoint = self._get_endpoint(endpoint_path)
        if not endpoint:
            return HttpResponse(status=404)

        # Check for verification challenge
        serializer = WebhookVerificationSerializer(data=request.GET)
        if serializer.is_valid():
            challenge = serializer.validated_data.get('challenge')
            if challenge:
                return HttpResponse(challenge, content_type='text/plain')

        return HttpResponse(status=200)

    def post(self, request, endpoint_path):
        """
        Receive and process incoming webhook.

        1. Find the endpoint
        2. Validate signature if configured
        3. Log delivery
        4. Queue for async processing
        """
        endpoint = self._get_endpoint(endpoint_path)

        if not endpoint:
            logger.warning(f"Webhook received for unknown endpoint: {endpoint_path}")
            return HttpResponse(status=404)

        if not endpoint.is_enabled:
            logger.info(f"Webhook received for disabled endpoint: {endpoint_path}")
            return HttpResponse(status=410)  # Gone

        # Get request data
        try:
            payload = request.body.decode('utf-8')
            payload_json = json.loads(payload) if payload else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = request.body
            payload_json = {}

        # Extract event info
        event_type = (
            payload_json.get('type') or
            payload_json.get('event') or
            request.headers.get('X-Event-Type', 'unknown')
        )
        event_id = (
            payload_json.get('id') or
            request.headers.get('X-Event-ID', '')
        )

        # Create delivery record
        delivery = WebhookDelivery.objects.create(
            endpoint=endpoint,
            event_type=event_type,
            event_id=event_id,
            status='pending',
            headers=dict(request.headers),
            payload=payload_json,
            source_ip=self._get_client_ip(request),
            received_at=timezone.now()
        )

        # Validate signature
        signature_valid = True
        if endpoint.secret_key:
            validator = WebhookValidator(endpoint)
            signature_valid = validator.validate_signature(
                payload=request.body,
                headers=request.headers
            )
            delivery.signature_valid = signature_valid

        if not signature_valid:
            delivery.status = 'failed'
            delivery.status_message = 'Invalid signature'
            delivery.save()

            # Update endpoint stats
            endpoint.total_received += 1
            endpoint.total_failed += 1
            endpoint.last_received_at = timezone.now()
            endpoint.save()

            logger.warning(f"Invalid webhook signature for endpoint: {endpoint_path}")
            return HttpResponse(status=401)

        # Update endpoint stats
        endpoint.total_received += 1
        endpoint.last_received_at = timezone.now()
        endpoint.save()

        # Queue for async processing
        from .tasks import process_webhook_delivery
        process_webhook_delivery.delay(delivery.id)

        delivery.save()

        return HttpResponse(status=202)  # Accepted

    def _get_endpoint(self, endpoint_path):
        """Get webhook endpoint by path."""
        try:
            return WebhookEndpoint.objects.select_related(
                'integration'
            ).get(endpoint_path=endpoint_path)
        except WebhookEndpoint.DoesNotExist:
            return None

    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')


# =============================================================================
# SYNC LOG VIEWSET
# =============================================================================

class IntegrationSyncLogViewSet(TenantAwareReadOnlyViewSet):
    """
    Read-only ViewSet for sync logs.

    Endpoints:
    - GET /sync-logs/ - List all sync logs
    - GET /sync-logs/{uuid}/ - Get sync log details
    - POST /sync-logs/{uuid}/retry/ - Retry a failed sync
    """

    serializer_class = IntegrationSyncLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = IntegrationPagination
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['status', 'sync_type', 'direction', 'integration__uuid']
    ordering_fields = ['started_at', 'completed_at']
    ordering = ['-started_at']
    lookup_field = 'uuid'
    tenant_field = 'integration__tenant'

    def get_queryset(self):
        return IntegrationSyncLog.objects.select_related(
            'integration', 'triggered_by'
        )

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return IntegrationSyncLogDetailSerializer
        return IntegrationSyncLogSerializer

    @action(detail=True, methods=['post'])
    def retry(self, request, uuid=None):
        """Retry a failed sync."""
        sync_log = self.get_object()

        if not sync_log.can_retry:
            return APIResponse.error(
                message=_("Sync cannot be retried"),
                error_code="CANNOT_RETRY"
            )

        # Create new sync log for retry
        new_sync = IntegrationSyncLog.objects.create(
            integration=sync_log.integration,
            sync_type=sync_log.sync_type,
            resource_type=sync_log.resource_type,
            triggered_by=request.user,
        )

        # Trigger sync task
        from .tasks import run_integration_sync
        run_integration_sync.delay(new_sync.uuid.hex)

        return APIResponse.success(
            data={'sync_id': str(new_sync.uuid)},
            message=_("Sync retry started")
        )


# =============================================================================
# INTEGRATION EVENT VIEWSET
# =============================================================================

class IntegrationEventViewSet(TenantAwareReadOnlyViewSet):
    """
    Read-only ViewSet for integration events.

    Endpoints:
    - GET /integration-events/ - List all events
    - GET /integration-events/{uuid}/ - Get event details
    """

    serializer_class = IntegrationEventSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = IntegrationPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['event_type', 'integration__uuid']
    search_fields = ['message']
    ordering_fields = ['created_at']
    ordering = ['-created_at']
    lookup_field = 'uuid'
    tenant_field = 'integration__tenant'

    def get_queryset(self):
        return IntegrationEvent.objects.select_related(
            'integration', 'triggered_by'
        )
