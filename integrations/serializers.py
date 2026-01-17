"""
Integrations API Serializers

Tenant-aware serializers for the integrations REST API.
Uses base serializer classes from api.serializers_base for consistent tenant handling.
"""

from rest_framework import serializers
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.conf import settings

from api.serializers_base import (
    TenantAwareSerializer,
    TenantWritableSerializer,
    AuditableSerializer,
    SlimSerializer,
)
from .models import (
    Integration,
    IntegrationCredential,
    IntegrationSyncLog,
    WebhookEndpoint,
    WebhookDelivery,
    IntegrationEvent,
)


# =============================================================================
# CREDENTIAL SERIALIZERS
# =============================================================================

class IntegrationCredentialSerializer(serializers.ModelSerializer):
    """
    Serializer for integration credentials.
    Sensitive fields are hidden/write-only for security.
    """
    is_expired = serializers.BooleanField(read_only=True)
    needs_refresh = serializers.BooleanField(read_only=True)
    has_access_token = serializers.SerializerMethodField()
    has_refresh_token = serializers.SerializerMethodField()
    has_api_key = serializers.SerializerMethodField()

    class Meta:
        model = IntegrationCredential
        fields = [
            'uuid',
            'auth_type',
            'scope',
            'expires_at',
            'external_user_id',
            'external_account_id',
            'is_expired',
            'needs_refresh',
            'has_access_token',
            'has_refresh_token',
            'has_api_key',
            'last_refreshed_at',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'is_expired',
            'needs_refresh',
            'last_refreshed_at',
            'created_at',
            'updated_at',
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_has_access_token(self, obj):
        """Check if access token exists without exposing it."""
        return bool(obj.access_token)

    @extend_schema_field(OpenApiTypes.STR)
    def get_has_refresh_token(self, obj):
        """Check if refresh token exists without exposing it."""
        return bool(obj.refresh_token)

    @extend_schema_field(OpenApiTypes.STR)
    def get_has_api_key(self, obj):
        """Check if API key exists without exposing it."""
        return bool(obj.api_key)


class IntegrationCredentialWriteSerializer(serializers.Serializer):
    """Serializer for updating credentials (tokens, API keys)."""
    access_token = serializers.CharField(required=False, allow_blank=True, write_only=True)
    refresh_token = serializers.CharField(required=False, allow_blank=True, write_only=True)
    api_key = serializers.CharField(required=False, allow_blank=True, write_only=True)
    api_secret = serializers.CharField(required=False, allow_blank=True, write_only=True)
    expires_in = serializers.IntegerField(required=False, min_value=0)
    scope = serializers.CharField(required=False, allow_blank=True)


# =============================================================================
# INTEGRATION SERIALIZERS
# =============================================================================

class IntegrationListSerializer(TenantAwareSerializer):
    """
    Lightweight serializer for listing integrations.
    Used in list views and dropdowns.
    """
    provider_display = serializers.CharField(source='get_provider_display', read_only=True)
    type_display = serializers.CharField(source='get_integration_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    has_credentials = serializers.SerializerMethodField()

    class Meta:
        model = Integration
        fields = [
            'uuid',
            'name',
            'provider',
            'provider_display',
            'integration_type',
            'type_display',
            'status',
            'status_display',
            'is_enabled',
            'is_active',
            'has_credentials',
            'last_sync_at',
            'created_at',
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_has_credentials(self, obj):
        return hasattr(obj, 'credentials')


class IntegrationSerializer(TenantAwareSerializer):
    """
    Full serializer for integration details.
    Credentials are hidden for security.
    """
    provider_display = serializers.CharField(source='get_provider_display', read_only=True)
    type_display = serializers.CharField(source='get_integration_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    credentials = IntegrationCredentialSerializer(read_only=True)
    connected_by_email = serializers.EmailField(source='connected_by.email', read_only=True)
    webhook_count = serializers.SerializerMethodField()
    recent_sync_count = serializers.SerializerMethodField()

    class Meta:
        model = Integration
        fields = [
            'uuid',
            'name',
            'description',
            'provider',
            'provider_display',
            'integration_type',
            'type_display',
            'status',
            'status_display',
            'status_message',
            'config',
            'is_enabled',
            'is_active',
            'needs_reconnection',
            'auto_sync',
            'sync_interval_minutes',
            'last_sync_at',
            'next_sync_at',
            'sync_error_count',
            'connected_by_email',
            'connected_at',
            'disconnected_at',
            'credentials',
            'webhook_count',
            'recent_sync_count',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'provider_display',
            'type_display',
            'status_display',
            'is_active',
            'needs_reconnection',
            'last_sync_at',
            'next_sync_at',
            'sync_error_count',
            'connected_by_email',
            'connected_at',
            'disconnected_at',
            'credentials',
            'webhook_count',
            'recent_sync_count',
            'created_at',
            'updated_at',
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_webhook_count(self, obj):
        return obj.webhook_endpoints.count()

    @extend_schema_field(OpenApiTypes.STR)
    def get_recent_sync_count(self, obj):
        return obj.sync_logs.count()


class IntegrationCreateSerializer(TenantWritableSerializer):
    """Serializer for creating a new integration."""

    class Meta:
        model = Integration
        fields = [
            'name',
            'description',
            'provider',
            'integration_type',
            'config',
            'is_enabled',
            'auto_sync',
            'sync_interval_minutes',
        ]

    def validate_provider(self, value):
        """Validate that provider is supported."""
        valid_providers = [choice[0] for choice in Integration.ProviderName.choices]
        if value not in valid_providers:
            raise serializers.ValidationError(
                _("Invalid provider: %(provider)s") % {'provider': value}
            )
        return value

    def validate(self, attrs):
        """Validate integration doesn't already exist for tenant."""
        tenant = self.tenant
        if not tenant:
            # Try to get from request context
            request = self.context.get('request')
            if request and hasattr(request.user, 'tenant_memberships'):
                membership = request.user.tenant_memberships.first()
                tenant = membership.tenant if membership else None

        if tenant:
            provider = attrs.get('provider')
            if Integration.objects.filter(tenant=tenant, provider=provider).exists():
                raise serializers.ValidationError({
                    'provider': _('Integration for %(provider)s already exists for this tenant.') % {
                        'provider': provider
                    }
                })

        return attrs


class IntegrationUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating integration settings."""

    class Meta:
        model = Integration
        fields = [
            'name',
            'description',
            'config',
            'is_enabled',
            'auto_sync',
            'sync_interval_minutes',
        ]


# =============================================================================
# SYNC LOG SERIALIZERS
# =============================================================================

class IntegrationSyncLogSerializer(serializers.ModelSerializer):
    """Serializer for sync log entries."""
    type_display = serializers.CharField(source='get_sync_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    direction_display = serializers.CharField(source='get_direction_display', read_only=True)
    triggered_by_email = serializers.EmailField(source='triggered_by.email', read_only=True)
    integration_name = serializers.CharField(source='integration.name', read_only=True)
    integration_provider = serializers.CharField(source='integration.provider', read_only=True)

    class Meta:
        model = IntegrationSyncLog
        fields = [
            'uuid',
            'integration_name',
            'integration_provider',
            'sync_type',
            'type_display',
            'direction',
            'direction_display',
            'status',
            'status_display',
            'resource_type',
            'records_processed',
            'records_created',
            'records_updated',
            'records_deleted',
            'records_failed',
            'error_message',
            'error_details',
            'retry_count',
            'max_retries',
            'can_retry',
            'duration_seconds',
            'success_rate',
            'triggered_by_email',
            'started_at',
            'completed_at',
        ]
        read_only_fields = fields


class IntegrationSyncLogDetailSerializer(IntegrationSyncLogSerializer):
    """Detailed sync log serializer with sync cursor."""

    class Meta(IntegrationSyncLogSerializer.Meta):
        fields = IntegrationSyncLogSerializer.Meta.fields + ['sync_cursor']


# =============================================================================
# WEBHOOK SERIALIZERS
# =============================================================================

class WebhookEndpointListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for listing webhook endpoints."""
    integration_name = serializers.CharField(source='integration.name', read_only=True)
    integration_uuid = serializers.UUIDField(source='integration.uuid', read_only=True)
    full_url = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = WebhookEndpoint
        fields = [
            'uuid',
            'name',
            'integration_name',
            'integration_uuid',
            'endpoint_path',
            'full_url',
            'status',
            'status_display',
            'is_enabled',
            'total_received',
            'total_processed',
            'total_failed',
            'last_received_at',
            'created_at',
        ]
        read_only_fields = fields

    @extend_schema_field(OpenApiTypes.STR)
    def get_full_url(self, obj):
        return obj.get_full_url()


class WebhookEndpointSerializer(serializers.ModelSerializer):
    """
    Full serializer for webhook endpoint configuration.
    Includes secret key for setup purposes.
    """
    integration_name = serializers.CharField(source='integration.name', read_only=True)
    integration_provider = serializers.CharField(source='integration.provider', read_only=True)
    full_url = serializers.SerializerMethodField()
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    success_rate = serializers.SerializerMethodField()

    class Meta:
        model = WebhookEndpoint
        fields = [
            'uuid',
            'name',
            'integration_name',
            'integration_provider',
            'endpoint_path',
            'full_url',
            'secret_key',
            'signature_header',
            'signature_algorithm',
            'subscribed_events',
            'status',
            'status_display',
            'is_enabled',
            'total_received',
            'total_processed',
            'total_failed',
            'success_rate',
            'last_received_at',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'uuid',
            'integration_name',
            'integration_provider',
            'endpoint_path',
            'full_url',
            'secret_key',
            'total_received',
            'total_processed',
            'total_failed',
            'success_rate',
            'last_received_at',
            'created_at',
            'updated_at',
        ]

    @extend_schema_field(OpenApiTypes.STR)
    def get_full_url(self, obj):
        return obj.get_full_url()

    @extend_schema_field(OpenApiTypes.STR)
    def get_success_rate(self, obj):
        """Calculate success rate percentage."""
        if obj.total_received == 0:
            return 100.0
        return round((obj.total_processed / obj.total_received) * 100, 2)


class WebhookEndpointCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating webhook endpoints."""
    integration = serializers.UUIDField(
        write_only=True,
        help_text=_("UUID of the integration to create webhook for")
    )

    class Meta:
        model = WebhookEndpoint
        fields = [
            'integration',
            'name',
            'subscribed_events',
            'signature_header',
            'signature_algorithm',
        ]


class WebhookDeliverySerializer(serializers.ModelSerializer):
    """Serializer for webhook delivery records."""
    endpoint_name = serializers.CharField(source='endpoint.name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = WebhookDelivery
        fields = [
            'uuid',
            'endpoint_name',
            'event_type',
            'event_id',
            'status',
            'status_display',
            'status_message',
            'signature_valid',
            'response_status_code',
            'response_time_ms',
            'retry_count',
            'max_retries',
            'can_retry',
            'processing_time_ms',
            'source_ip',
            'received_at',
            'processed_at',
        ]
        read_only_fields = fields


class WebhookDeliveryDetailSerializer(WebhookDeliverySerializer):
    """Detailed serializer including payload and response."""

    class Meta(WebhookDeliverySerializer.Meta):
        fields = WebhookDeliverySerializer.Meta.fields + [
            'headers',
            'payload',
            'response_body',
            'processing_result',
            'next_retry_at',
        ]


# =============================================================================
# INTEGRATION EVENT SERIALIZERS
# =============================================================================

class IntegrationEventSerializer(serializers.ModelSerializer):
    """Serializer for integration events."""
    event_type_display = serializers.CharField(source='get_event_type_display', read_only=True)
    triggered_by_email = serializers.EmailField(source='triggered_by.email', read_only=True)
    integration_name = serializers.CharField(source='integration.name', read_only=True)

    class Meta:
        model = IntegrationEvent
        fields = [
            'uuid',
            'integration_name',
            'event_type',
            'event_type_display',
            'message',
            'details',
            'triggered_by_email',
            'created_at',
        ]
        read_only_fields = fields


# =============================================================================
# OAUTH & CONNECTION SERIALIZERS
# =============================================================================

class OAuthCallbackSerializer(serializers.Serializer):
    """Serializer for OAuth callback data."""
    code = serializers.CharField(
        required=True,
        help_text=_("Authorization code from OAuth provider")
    )
    state = serializers.CharField(
        required=True,
        help_text=_("State token for CSRF protection")
    )
    error = serializers.CharField(required=False, allow_blank=True)
    error_description = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        if attrs.get('error'):
            raise serializers.ValidationError({
                'error': attrs.get('error_description', attrs.get('error'))
            })
        return attrs


class IntegrationConnectSerializer(serializers.Serializer):
    """
    Serializer for initiating integration connection.
    Supports both OAuth and API key based connections.
    """
    provider = serializers.ChoiceField(
        choices=Integration.ProviderName.choices,
        help_text=_("Provider to connect")
    )
    redirect_url = serializers.URLField(
        required=False,
        help_text=_("URL to redirect after OAuth completion")
    )

    # For API key based connections
    credentials = serializers.DictField(
        required=False,
        help_text=_("API credentials (for non-OAuth providers)")
    )

    # Additional config
    config = serializers.DictField(
        required=False,
        default=dict,
        help_text=_("Additional provider-specific configuration")
    )


class SyncTriggerSerializer(serializers.Serializer):
    """Serializer for triggering a sync operation."""
    sync_type = serializers.ChoiceField(
        choices=IntegrationSyncLog.SyncType.choices,
        default='manual',
        help_text=_("Type of sync to perform")
    )
    resource_type = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text=_("Specific resource type to sync (e.g., 'contacts', 'events')")
    )
    full_sync = serializers.BooleanField(
        default=False,
        help_text=_("Perform full sync instead of incremental")
    )


# =============================================================================
# AVAILABLE INTEGRATIONS SERIALIZER
# =============================================================================

class AvailableIntegrationSerializer(serializers.Serializer):
    """Serializer for available integration providers."""
    provider = serializers.CharField()
    display_name = serializers.CharField()
    integration_type = serializers.CharField()
    type_display = serializers.CharField()
    description = serializers.CharField()
    is_oauth = serializers.BooleanField()
    is_connected = serializers.BooleanField()
    features = serializers.ListField(child=serializers.CharField())
    icon_url = serializers.URLField(required=False, allow_null=True)
    documentation_url = serializers.URLField(required=False, allow_null=True)


# =============================================================================
# STATUS & STATISTICS SERIALIZERS
# =============================================================================

class IntegrationStatusSerializer(serializers.Serializer):
    """Serializer for integration status response."""
    provider = serializers.CharField()
    provider_display = serializers.CharField()
    status = serializers.CharField()
    status_display = serializers.CharField()
    is_active = serializers.BooleanField()
    last_sync_at = serializers.DateTimeField(allow_null=True)
    next_sync_at = serializers.DateTimeField(allow_null=True)
    error_count = serializers.IntegerField()
    credentials_valid = serializers.BooleanField()
    credentials_expiring_soon = serializers.BooleanField()
    days_until_expiry = serializers.IntegerField(allow_null=True)


class IntegrationStatsSerializer(serializers.Serializer):
    """Serializer for integration statistics."""
    total_integrations = serializers.IntegerField()
    active_integrations = serializers.IntegerField()
    inactive_integrations = serializers.IntegerField()
    error_integrations = serializers.IntegerField()
    by_type = serializers.DictField()
    by_status = serializers.DictField()
    total_syncs_today = serializers.IntegerField()
    successful_syncs_today = serializers.IntegerField()
    failed_syncs_today = serializers.IntegerField()
    total_webhooks_today = serializers.IntegerField()


class WebhookStatsSerializer(serializers.Serializer):
    """Serializer for webhook statistics."""
    total_endpoints = serializers.IntegerField()
    active_endpoints = serializers.IntegerField()
    total_received = serializers.IntegerField()
    total_processed = serializers.IntegerField()
    total_failed = serializers.IntegerField()
    success_rate = serializers.FloatField()
    by_status = serializers.DictField()


# =============================================================================
# WEBHOOK INCOMING SERIALIZERS
# =============================================================================

class IncomingWebhookSerializer(serializers.Serializer):
    """
    Serializer for incoming webhook payloads.
    Used for logging and validation.
    """
    event_type = serializers.CharField(required=False)
    event_id = serializers.CharField(required=False, allow_blank=True)
    payload = serializers.DictField()
    timestamp = serializers.DateTimeField(required=False)


class WebhookVerificationSerializer(serializers.Serializer):
    """Serializer for webhook verification challenges."""
    challenge = serializers.CharField(required=False)
    verify_token = serializers.CharField(required=False)
    mode = serializers.CharField(required=False)
