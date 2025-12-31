"""
Django Admin configuration for notifications app.
"""

from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from django.db.models import Count
from import_export.admin import ImportExportModelAdmin

from .models import (
    Notification,
    NotificationChannel,
    NotificationTemplate,
    NotificationPreference,
    ScheduledNotification,
    NotificationDeliveryLog,
)


class NotificationDeliveryLogInline(admin.TabularInline):
    """Inline for viewing delivery logs on notification detail."""
    model = NotificationDeliveryLog
    extra = 0
    readonly_fields = [
        'attempt_number', 'status', 'response_code',
        'error_type', 'error_message', 'external_id',
        'started_at', 'completed_at', 'duration_ms'
    ]
    can_delete = False

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(NotificationChannel)
class NotificationChannelAdmin(admin.ModelAdmin):
    """Admin for NotificationChannel model."""
    list_display = [
        'name', 'channel_type', 'is_active',
        'rate_limit_per_hour', 'template_count', 'created_at'
    ]
    list_filter = ['channel_type', 'is_active']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at', 'updated_at']

    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'channel_type', 'is_active', 'description')
        }),
        ('Configuration', {
            'fields': ('config', 'rate_limit_per_hour')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def template_count(self, obj):
        return obj.templates.count()
    template_count.short_description = 'Templates'


@admin.register(NotificationTemplate)
class NotificationTemplateAdmin(ImportExportModelAdmin):
    """Admin for NotificationTemplate model."""
    list_display = [
        'name', 'template_type', 'channel', 'language',
        'is_active', 'notification_count', 'created_at'
    ]
    list_filter = ['template_type', 'channel', 'language', 'is_active']
    search_fields = ['name', 'subject', 'body', 'description']
    readonly_fields = ['created_at', 'updated_at', 'created_by']
    autocomplete_fields = ['channel']
    raw_id_fields = ['created_by']

    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'template_type', 'channel', 'language', 'is_active', 'description')
        }),
        ('Content', {
            'fields': ('subject', 'body', 'html_body')
        }),
        ('Configuration', {
            'fields': ('default_context',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def notification_count(self, obj):
        return obj.notifications.count()
    notification_count.short_description = 'Sent'

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(NotificationPreference)
class NotificationPreferenceAdmin(admin.ModelAdmin):
    """Admin for NotificationPreference model."""
    list_display = [
        'user', 'notifications_enabled', 'email_digest_frequency',
        'quiet_hours_enabled', 'global_unsubscribe', 'updated_at'
    ]
    list_filter = [
        'notifications_enabled', 'email_digest_frequency',
        'quiet_hours_enabled', 'global_unsubscribe'
    ]
    search_fields = ['user__email', 'user__username', 'phone_number']
    readonly_fields = ['unsubscribe_token', 'created_at', 'updated_at']
    raw_id_fields = ['user']

    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Global Settings', {
            'fields': (
                'notifications_enabled', 'global_unsubscribe',
                'email_digest_frequency'
            )
        }),
        ('Quiet Hours', {
            'fields': (
                'quiet_hours_enabled', 'quiet_hours_start',
                'quiet_hours_end', 'timezone'
            )
        }),
        ('Channel Preferences', {
            'fields': ('channel_preferences', 'type_preferences'),
            'classes': ('collapse',)
        }),
        ('Contact Information', {
            'fields': ('phone_number', 'slack_user_id', 'fcm_token', 'apns_token'),
            'classes': ('collapse',)
        }),
        ('Unsubscribe', {
            'fields': ('unsubscribe_token', 'unsubscribed_types'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(Notification)
class NotificationAdmin(ImportExportModelAdmin):
    """Admin for Notification model."""
    list_display = [
        'title_truncated', 'recipient', 'notification_type',
        'channel_type', 'status_badge', 'priority_badge',
        'is_read', 'created_at'
    ]
    list_filter = [
        'notification_type', 'channel__channel_type', 'status',
        'priority', 'is_read', 'is_dismissed', 'created_at'
    ]
    search_fields = [
        'title', 'message', 'recipient__email',
        'recipient__username', 'uuid'
    ]
    readonly_fields = [
        'uuid', 'created_at', 'updated_at', 'sent_at',
        'delivered_at', 'read_at', 'dismissed_at'
    ]
    autocomplete_fields = ['channel', 'template']
    raw_id_fields = ['recipient', 'sender']
    date_hierarchy = 'created_at'
    inlines = [NotificationDeliveryLogInline]

    fieldsets = (
        ('Identification', {
            'fields': ('uuid', 'batch_id')
        }),
        ('Recipients', {
            'fields': ('recipient', 'sender')
        }),
        ('Channel & Type', {
            'fields': ('channel', 'notification_type', 'template', 'priority')
        }),
        ('Content', {
            'fields': ('title', 'message', 'html_message', 'action_url', 'action_text')
        }),
        ('Context', {
            'fields': ('context_data',),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': (
                'status', 'is_read', 'read_at',
                'is_dismissed', 'dismissed_at'
            )
        }),
        ('Delivery', {
            'fields': (
                'sent_at', 'delivered_at', 'error_message',
                'retry_count', 'max_retries', 'external_id'
            ),
            'classes': ('collapse',)
        }),
        ('Expiration', {
            'fields': ('expires_at',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = [
        'mark_as_read', 'mark_as_unread', 'dismiss_notifications',
        'retry_failed_notifications'
    ]

    def title_truncated(self, obj):
        return obj.title[:50] + '...' if len(obj.title) > 50 else obj.title
    title_truncated.short_description = 'Title'

    def channel_type(self, obj):
        return obj.channel.channel_type if obj.channel else '-'
    channel_type.short_description = 'Channel'

    def status_badge(self, obj):
        colors = {
            'pending': '#ffc107',
            'queued': '#17a2b8',
            'sending': '#17a2b8',
            'sent': '#28a745',
            'delivered': '#28a745',
            'read': '#6c757d',
            'failed': '#dc3545',
            'cancelled': '#6c757d',
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background: {}; color: white; padding: 2px 8px; '
            'border-radius: 4px; font-size: 11px;">{}</span>',
            color, obj.status.upper()
        )
    status_badge.short_description = 'Status'

    def priority_badge(self, obj):
        colors = {
            'low': '#6c757d',
            'normal': '#17a2b8',
            'high': '#ffc107',
            'urgent': '#dc3545',
        }
        color = colors.get(obj.priority, '#6c757d')
        return format_html(
            '<span style="background: {}; color: white; padding: 2px 8px; '
            'border-radius: 4px; font-size: 11px;">{}</span>',
            color, obj.priority.upper()
        )
    priority_badge.short_description = 'Priority'

    @admin.action(description='Mark selected notifications as read')
    def mark_as_read(self, request, queryset):
        count = queryset.update(
            is_read=True,
            read_at=timezone.now(),
            status='read'
        )
        self.message_user(request, f'{count} notifications marked as read.')

    @admin.action(description='Mark selected notifications as unread')
    def mark_as_unread(self, request, queryset):
        count = queryset.update(
            is_read=False,
            read_at=None,
            status='delivered'
        )
        self.message_user(request, f'{count} notifications marked as unread.')

    @admin.action(description='Dismiss selected notifications')
    def dismiss_notifications(self, request, queryset):
        count = queryset.update(
            is_dismissed=True,
            dismissed_at=timezone.now()
        )
        self.message_user(request, f'{count} notifications dismissed.')

    @admin.action(description='Retry failed notifications')
    def retry_failed_notifications(self, request, queryset):
        from .tasks import send_notification_task

        failed = queryset.filter(status='failed', retry_count__lt=3)
        count = 0
        for notification in failed:
            send_notification_task.delay(
                recipient_id=notification.recipient_id,
                notification_type=notification.notification_type,
                title=notification.title,
                message=notification.message,
                channels=[notification.channel.channel_type],
                priority=notification.priority,
                context_data=notification.context_data,
            )
            count += 1

        self.message_user(request, f'{count} notifications queued for retry.')


@admin.register(ScheduledNotification)
class ScheduledNotificationAdmin(admin.ModelAdmin):
    """Admin for ScheduledNotification model."""
    list_display = [
        'name_or_template', 'recipient_or_broadcast', 'template',
        'scheduled_at', 'recurrence', 'is_active', 'is_processed',
        'next_run_at'
    ]
    list_filter = ['is_active', 'is_processed', 'recurrence', 'scheduled_at']
    search_fields = ['name', 'description', 'template__name', 'recipient__email']
    readonly_fields = ['uuid', 'last_run_at', 'next_run_at', 'created_at', 'updated_at']
    autocomplete_fields = ['template']
    raw_id_fields = ['recipient', 'created_by']
    date_hierarchy = 'scheduled_at'

    fieldsets = (
        ('Identification', {
            'fields': ('uuid', 'name', 'description')
        }),
        ('Recipients', {
            'fields': ('recipient', 'recipient_filter')
        }),
        ('Template', {
            'fields': ('template', 'context_data')
        }),
        ('Scheduling', {
            'fields': (
                'scheduled_at', 'recurrence', 'recurrence_end_date',
                'last_run_at', 'next_run_at'
            )
        }),
        ('Status', {
            'fields': ('is_active', 'is_processed')
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = ['activate', 'deactivate', 'process_now']

    def name_or_template(self, obj):
        return obj.name or obj.template.name
    name_or_template.short_description = 'Name'

    def recipient_or_broadcast(self, obj):
        if obj.recipient:
            return obj.recipient.email
        elif obj.recipient_filter:
            return 'Broadcast (filtered)'
        return 'Broadcast (all)'
    recipient_or_broadcast.short_description = 'Recipient'

    @admin.action(description='Activate selected scheduled notifications')
    def activate(self, request, queryset):
        count = queryset.update(is_active=True)
        self.message_user(request, f'{count} scheduled notifications activated.')

    @admin.action(description='Deactivate selected scheduled notifications')
    def deactivate(self, request, queryset):
        count = queryset.update(is_active=False)
        self.message_user(request, f'{count} scheduled notifications deactivated.')

    @admin.action(description='Process selected scheduled notifications now')
    def process_now(self, request, queryset):
        from .tasks import process_scheduled_notifications
        process_scheduled_notifications.delay()
        self.message_user(request, 'Scheduled notifications are being processed.')


@admin.register(NotificationDeliveryLog)
class NotificationDeliveryLogAdmin(admin.ModelAdmin):
    """Admin for NotificationDeliveryLog model."""
    list_display = [
        'notification_id', 'attempt_number', 'status',
        'response_code', 'duration_ms', 'started_at'
    ]
    list_filter = ['status', 'started_at']
    search_fields = ['notification__uuid', 'error_message', 'external_id']
    readonly_fields = [
        'notification', 'attempt_number', 'status',
        'request_payload', 'response_payload', 'response_code',
        'error_type', 'error_message', 'error_traceback',
        'started_at', 'completed_at', 'duration_ms', 'external_id'
    ]
    date_hierarchy = 'started_at'

    def notification_id(self, obj):
        return str(obj.notification.uuid)[:8]
    notification_id.short_description = 'Notification'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
