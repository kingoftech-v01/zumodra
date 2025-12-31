"""
Integrations Admin Configuration

Django admin interface for managing integrations.
"""

from django.contrib import admin
from django.utils.html import format_html

from .models import (
    Integration,
    IntegrationCredential,
    IntegrationSyncLog,
    WebhookEndpoint,
    WebhookDelivery,
    IntegrationEvent,
)


class IntegrationCredentialInline(admin.StackedInline):
    """Inline for integration credentials."""
    model = IntegrationCredential
    extra = 0
    readonly_fields = [
        'uuid', 'is_expired', 'needs_refresh', 'last_refreshed_at',
        'created_at', 'updated_at',
    ]
    fieldsets = (
        ('Authentication', {
            'fields': ('auth_type', 'token_type', 'scope'),
        }),
        ('External IDs', {
            'fields': ('external_user_id', 'external_account_id'),
        }),
        ('Token Status', {
            'fields': ('expires_at', 'refresh_expires_at', 'is_expired', 'needs_refresh', 'last_refreshed_at'),
        }),
        ('Metadata', {
            'fields': ('uuid', 'created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )


class WebhookEndpointInline(admin.TabularInline):
    """Inline for webhook endpoints."""
    model = WebhookEndpoint
    extra = 0
    readonly_fields = ['uuid', 'endpoint_path', 'total_received', 'total_processed', 'total_failed', 'last_received_at']
    fields = ['name', 'endpoint_path', 'status', 'is_enabled', 'total_received', 'total_processed']


@admin.register(Integration)
class IntegrationAdmin(admin.ModelAdmin):
    """Admin for Integration model."""
    list_display = [
        'name', 'tenant', 'provider', 'integration_type', 'status_badge',
        'is_enabled', 'auto_sync', 'last_sync_at', 'created_at',
    ]
    list_filter = [
        'status', 'integration_type', 'provider', 'is_enabled', 'auto_sync',
    ]
    search_fields = ['name', 'tenant__name', 'provider']
    readonly_fields = [
        'uuid', 'status_message', 'sync_error_count', 'last_sync_at',
        'next_sync_at', 'connected_at', 'disconnected_at', 'created_at', 'updated_at',
    ]
    inlines = [IntegrationCredentialInline, WebhookEndpointInline]

    fieldsets = (
        (None, {
            'fields': ('tenant', 'name', 'description', 'provider', 'integration_type'),
        }),
        ('Status', {
            'fields': ('status', 'status_message', 'is_enabled'),
        }),
        ('Sync Settings', {
            'fields': ('auto_sync', 'sync_interval_minutes', 'sync_error_count'),
        }),
        ('Sync History', {
            'fields': ('last_sync_at', 'next_sync_at'),
        }),
        ('Configuration', {
            'fields': ('config',),
            'classes': ('collapse',),
        }),
        ('Connection Info', {
            'fields': ('connected_by', 'connected_at', 'disconnected_at'),
        }),
        ('Metadata', {
            'fields': ('uuid', 'created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )

    def status_badge(self, obj):
        colors = {
            'active': 'green',
            'inactive': 'gray',
            'pending': 'orange',
            'connecting': 'blue',
            'error': 'red',
            'expired': 'darkred',
            'suspended': 'purple',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(IntegrationSyncLog)
class IntegrationSyncLogAdmin(admin.ModelAdmin):
    """Admin for IntegrationSyncLog model."""
    list_display = [
        'integration', 'sync_type', 'direction', 'status_badge',
        'records_processed', 'records_failed', 'duration_display',
        'started_at',
    ]
    list_filter = ['status', 'sync_type', 'direction', 'integration__provider']
    search_fields = ['integration__name', 'resource_type']
    readonly_fields = [
        'uuid', 'integration', 'started_at', 'completed_at',
        'records_processed', 'records_created', 'records_updated',
        'records_deleted', 'records_failed', 'retry_count',
        'sync_cursor',
    ]
    date_hierarchy = 'started_at'

    fieldsets = (
        (None, {
            'fields': ('integration', 'sync_type', 'direction', 'status', 'resource_type'),
        }),
        ('Statistics', {
            'fields': (
                'records_processed', 'records_created', 'records_updated',
                'records_deleted', 'records_failed',
            ),
        }),
        ('Error Info', {
            'fields': ('error_message', 'error_details', 'retry_count', 'max_retries', 'next_retry_at'),
        }),
        ('Timing', {
            'fields': ('started_at', 'completed_at'),
        }),
        ('Metadata', {
            'fields': ('uuid', 'sync_cursor', 'triggered_by'),
            'classes': ('collapse',),
        }),
    )

    def status_badge(self, obj):
        colors = {
            'pending': 'orange',
            'running': 'blue',
            'completed': 'green',
            'partial': 'goldenrod',
            'failed': 'red',
            'cancelled': 'gray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'

    def duration_display(self, obj):
        duration = obj.duration_seconds
        if duration is None:
            return '-'
        if duration < 60:
            return f'{duration:.1f}s'
        return f'{duration / 60:.1f}m'
    duration_display.short_description = 'Duration'


@admin.register(WebhookEndpoint)
class WebhookEndpointAdmin(admin.ModelAdmin):
    """Admin for WebhookEndpoint model."""
    list_display = [
        'name', 'integration', 'status', 'is_enabled',
        'total_received', 'total_processed', 'total_failed',
        'last_received_at',
    ]
    list_filter = ['status', 'is_enabled', 'integration__provider']
    search_fields = ['name', 'integration__name', 'endpoint_path']
    readonly_fields = [
        'uuid', 'endpoint_path', 'secret_key',
        'total_received', 'total_processed', 'total_failed',
        'last_received_at', 'created_at', 'updated_at',
    ]

    fieldsets = (
        (None, {
            'fields': ('integration', 'name', 'status', 'is_enabled'),
        }),
        ('Endpoint', {
            'fields': ('endpoint_path', 'secret_key'),
        }),
        ('Security', {
            'fields': ('signature_header', 'signature_algorithm'),
        }),
        ('Event Filtering', {
            'fields': ('subscribed_events',),
        }),
        ('Statistics', {
            'fields': ('total_received', 'total_processed', 'total_failed', 'last_received_at'),
        }),
        ('Metadata', {
            'fields': ('uuid', 'created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )


@admin.register(WebhookDelivery)
class WebhookDeliveryAdmin(admin.ModelAdmin):
    """Admin for WebhookDelivery model."""
    list_display = [
        'event_type', 'endpoint', 'status_badge', 'signature_valid',
        'retry_count', 'received_at',
    ]
    list_filter = ['status', 'signature_valid', 'endpoint__integration__provider']
    search_fields = ['event_type', 'event_id', 'endpoint__name']
    readonly_fields = [
        'uuid', 'endpoint', 'event_type', 'event_id',
        'headers', 'payload', 'signature_received', 'signature_valid',
        'response_status_code', 'response_body', 'response_time_ms',
        'processing_result', 'source_ip', 'user_agent',
        'received_at', 'processed_at',
    ]
    date_hierarchy = 'received_at'

    fieldsets = (
        (None, {
            'fields': ('endpoint', 'event_type', 'event_id', 'status', 'status_message'),
        }),
        ('Signature', {
            'fields': ('signature_received', 'signature_valid'),
        }),
        ('Payload', {
            'fields': ('headers', 'payload'),
            'classes': ('collapse',),
        }),
        ('Response', {
            'fields': ('response_status_code', 'response_body', 'response_time_ms'),
            'classes': ('collapse',),
        }),
        ('Retry', {
            'fields': ('retry_count', 'max_retries', 'next_retry_at'),
        }),
        ('Processing', {
            'fields': ('processing_result', 'processed_at'),
        }),
        ('Request Info', {
            'fields': ('source_ip', 'user_agent'),
            'classes': ('collapse',),
        }),
        ('Metadata', {
            'fields': ('uuid', 'received_at'),
            'classes': ('collapse',),
        }),
    )

    def status_badge(self, obj):
        colors = {
            'pending': 'orange',
            'processing': 'blue',
            'delivered': 'green',
            'failed': 'red',
            'retrying': 'goldenrod',
            'expired': 'gray',
        }
        color = colors.get(obj.status, 'gray')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(IntegrationEvent)
class IntegrationEventAdmin(admin.ModelAdmin):
    """Admin for IntegrationEvent model."""
    list_display = ['integration', 'event_type', 'message_preview', 'triggered_by', 'created_at']
    list_filter = ['event_type', 'integration__provider']
    search_fields = ['integration__name', 'message']
    readonly_fields = ['uuid', 'integration', 'event_type', 'message', 'details', 'triggered_by', 'created_at']
    date_hierarchy = 'created_at'

    def message_preview(self, obj):
        if len(obj.message) > 50:
            return obj.message[:50] + '...'
        return obj.message
    message_preview.short_description = 'Message'
