"""
Finance Webhooks Admin - Webhook Event Management
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import (
    WebhookEvent,
    WebhookRetry,
    WebhookSignature,
    WebhookEventType,
)


class WebhookRetryInline(admin.TabularInline):
    model = WebhookRetry
    extra = 0
    readonly_fields = [
        'retry_number',
        'retry_at',
        'succeeded',
        'error_message',
        'next_retry_at',
    ]
    can_delete = False
    max_num = 0  # Read-only

    fields = [
        'retry_number',
        'retry_at',
        'succeeded',
        'error_message',
        'next_retry_at',
    ]

    def has_add_permission(self, request, obj=None):
        return False


class WebhookSignatureInline(admin.TabularInline):
    model = WebhookSignature
    extra = 0
    readonly_fields = [
        'verified',
        'algorithm',
        'timestamp',
        'ip_address',
    ]
    can_delete = False
    max_num = 0  # Read-only

    fields = [
        'verified',
        'algorithm',
        'timestamp',
        'ip_address',
    ]

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(WebhookEvent)
class WebhookEventAdmin(admin.ModelAdmin):
    list_display = [
        'webhook_id',
        'source_display',
        'event_type',
        'status_display',
        'signature_status',
        'retry_count',
        'received_at',
        'processed_at',
    ]
    list_filter = [
        'source',
        'status',
        'signature_verified',
        'received_at',
    ]
    search_fields = [
        'webhook_id',
        'event_id',
        'event_type',
        'error_message',
    ]
    readonly_fields = [
        'webhook_id',
        'received_at',
        'updated_at',
        'payload_display',
        'related_object_link',
    ]
    date_hierarchy = 'received_at'
    inlines = [WebhookSignatureInline, WebhookRetryInline]

    fieldsets = (
        (
            'Webhook Details',
            {
                'fields': (
                    'webhook_id',
                    'source',
                    'event_type',
                    'event_id',
                    'status',
                )
            },
        ),
        (
            'Processing',
            {
                'fields': (
                    'processed_at',
                    'error_message',
                    'retry_count',
                )
            },
        ),
        (
            'Signature',
            {
                'fields': (
                    'signature_verified',
                    'signature',
                ),
                'classes': ('collapse',),
            },
        ),
        (
            'Payload',
            {
                'fields': ('payload_display',),
                'classes': ('collapse',),
            },
        ),
        (
            'Related Object',
            {
                'fields': (
                    'content_type',
                    'object_id',
                    'related_object_link',
                ),
                'classes': ('collapse',),
            },
        ),
        ('Metadata', {'fields': ('metadata',), 'classes': ('collapse',)}),
        (
            'Timestamps',
            {
                'fields': ('received_at', 'updated_at'),
                'classes': ('collapse',),
            },
        ),
    )

    def has_add_permission(self, request):
        """Webhooks are received from external sources, not created manually"""
        return False

    def source_display(self, obj):
        colors = {
            'stripe': 'blue',
            'avalara': 'green',
            'quickbooks': 'purple',
            'xero': 'orange',
        }
        color = colors.get(obj.source, 'black')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_source_display(),
        )

    source_display.short_description = 'Source'

    def status_display(self, obj):
        colors = {
            'pending': 'orange',
            'processing': 'blue',
            'succeeded': 'green',
            'failed': 'red',
            'ignored': 'gray',
        }
        color = colors.get(obj.status, 'black')

        icon = ''
        if obj.status == 'succeeded':
            icon = '✓ '
        elif obj.status == 'failed':
            icon = '✗ '
        elif obj.status == 'processing':
            icon = '⟳ '

        return format_html(
            '<span style="color: {}; font-weight: bold;">{}{}</span>',
            color,
            icon,
            obj.get_status_display(),
        )

    status_display.short_description = 'Status'

    def signature_status(self, obj):
        if obj.signature_verified:
            return format_html(
                '<span style="color: green; font-weight: bold;">✓ Verified</span>'
            )
        return format_html(
            '<span style="color: red; font-weight: bold;">✗ Unverified</span>'
        )

    signature_status.short_description = 'Signature'

    def payload_display(self, obj):
        """Display formatted JSON payload"""
        import json

        try:
            formatted = json.dumps(obj.payload, indent=2)
            return format_html(
                '<pre style="background-color: #f5f5f5; padding: 10px; '
                'border-radius: 4px; max-height: 400px; overflow: auto;">{}</pre>',
                formatted
            )
        except Exception:
            return str(obj.payload)

    payload_display.short_description = 'Payload'

    def related_object_link(self, obj):
        """Link to related object if exists"""
        if obj.content_type and obj.object_id:
            try:
                related_obj = obj.related_object
                model_name = obj.content_type.model
                app_label = obj.content_type.app_label

                url = reverse(
                    f'admin:{app_label}_{model_name}_change',
                    args=[obj.object_id]
                )

                return format_html(
                    '<a href="{}" target="_blank">{} #{}</a>',
                    url,
                    obj.content_type.model_class().__name__,
                    obj.object_id
                )
            except Exception as e:
                return format_html(
                    '<span style="color: red;">Error: {}</span>',
                    str(e)
                )
        return '-'

    related_object_link.short_description = 'Related Object'


@admin.register(WebhookRetry)
class WebhookRetryAdmin(admin.ModelAdmin):
    list_display = [
        'webhook_event_link',
        'retry_number',
        'retry_at',
        'succeeded_display',
        'next_retry_at',
    ]
    list_filter = ['succeeded', 'retry_at']
    search_fields = [
        'webhook_event__webhook_id',
        'webhook_event__event_type',
        'error_message',
    ]
    readonly_fields = [
        'webhook_event',
        'retry_number',
        'retry_at',
        'succeeded',
        'error_message',
        'next_retry_at',
    ]
    date_hierarchy = 'retry_at'

    fieldsets = (
        (
            'Retry Details',
            {
                'fields': (
                    'webhook_event',
                    'retry_number',
                    'retry_at',
                    'succeeded',
                )
            },
        ),
        (
            'Error Details',
            {'fields': ('error_message',)},
        ),
        (
            'Next Retry',
            {'fields': ('next_retry_at',)},
        ),
    )

    def has_add_permission(self, request):
        """Retries are created automatically"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Keep audit trail"""
        return False

    def webhook_event_link(self, obj):
        url = reverse(
            'admin:finance_webhooks_webhookevent_change',
            args=[obj.webhook_event.pk]
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.webhook_event.webhook_id
        )

    webhook_event_link.short_description = 'Webhook Event'

    def succeeded_display(self, obj):
        if obj.succeeded:
            return format_html(
                '<span style="color: green; font-weight: bold;">✓ Succeeded</span>'
            )
        return format_html(
            '<span style="color: red; font-weight: bold;">✗ Failed</span>'
        )

    succeeded_display.short_description = 'Result'


@admin.register(WebhookSignature)
class WebhookSignatureAdmin(admin.ModelAdmin):
    list_display = [
        'webhook_event_link',
        'verified_display',
        'algorithm',
        'timestamp',
        'ip_address',
    ]
    list_filter = ['verified', 'algorithm', 'timestamp']
    search_fields = [
        'webhook_event__webhook_id',
        'ip_address',
        'user_agent',
    ]
    readonly_fields = [
        'webhook_event',
        'verified',
        'signature',
        'expected_signature',
        'algorithm',
        'timestamp',
        'ip_address',
        'user_agent',
    ]
    date_hierarchy = 'timestamp'

    fieldsets = (
        (
            'Verification Details',
            {
                'fields': (
                    'webhook_event',
                    'verified',
                    'algorithm',
                    'timestamp',
                )
            },
        ),
        (
            'Signatures',
            {
                'fields': (
                    'signature',
                    'expected_signature',
                ),
                'classes': ('collapse',),
            },
        ),
        (
            'Request Details',
            {
                'fields': (
                    'ip_address',
                    'user_agent',
                ),
                'classes': ('collapse',),
            },
        ),
    )

    def has_add_permission(self, request):
        """Signature logs are created automatically"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Keep security audit trail"""
        return False

    def webhook_event_link(self, obj):
        url = reverse(
            'admin:finance_webhooks_webhookevent_change',
            args=[obj.webhook_event.pk]
        )
        return format_html(
            '<a href="{}">{}</a>',
            url,
            obj.webhook_event.webhook_id
        )

    webhook_event_link.short_description = 'Webhook Event'

    def verified_display(self, obj):
        if obj.verified:
            return format_html(
                '<span style="color: green; font-weight: bold;">✓ Valid</span>'
            )
        return format_html(
            '<span style="color: red; font-weight: bold;">✗ Invalid</span>'
        )

    verified_display.short_description = 'Status'


@admin.register(WebhookEventType)
class WebhookEventTypeAdmin(admin.ModelAdmin):
    list_display = [
        'source',
        'event_type',
        'handler_path',
        'is_enabled',
        'auto_retry',
        'max_retries',
    ]
    list_filter = ['source', 'is_enabled', 'auto_retry']
    search_fields = ['event_type', 'handler_path', 'description']
    readonly_fields = ['created_at', 'updated_at']

    fieldsets = (
        (
            'Event Type',
            {
                'fields': (
                    'source',
                    'event_type',
                    'description',
                )
            },
        ),
        (
            'Handler',
            {'fields': ('handler_path',)},
        ),
        (
            'Settings',
            {
                'fields': (
                    'is_enabled',
                    'auto_retry',
                    'max_retries',
                )
            },
        ),
        (
            'Timestamps',
            {
                'fields': ('created_at', 'updated_at'),
                'classes': ('collapse',),
            },
        ),
    )

    def get_readonly_fields(self, request, obj=None):
        """Make source and event_type read-only when editing"""
        if obj:  # Editing existing object
            return self.readonly_fields + ['source', 'event_type']
        return self.readonly_fields
