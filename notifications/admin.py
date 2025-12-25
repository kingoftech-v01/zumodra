from django.contrib import admin
from .models import Notification, NotificationPreference


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['title', 'recipient', 'notification_type', 'is_read', 'created_at']
    list_filter = ['notification_type', 'is_read', 'created_at']
    search_fields = ['title', 'message', 'recipient__email']
    readonly_fields = ['created_at', 'read_at']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Recipients', {
            'fields': ('recipient', 'sender')
        }),
        ('Content', {
            'fields': ('notification_type', 'title', 'message', 'action_url')
        }),
        ('Status', {
            'fields': ('is_read', 'read_at', 'expires_at')
        }),
        ('Timestamps', {
            'fields': ('created_at',)
        }),
    )


@admin.register(NotificationPreference)
class NotificationPreferenceAdmin(admin.ModelAdmin):
    list_display = ['user', 'email_on_proposal', 'email_on_contract', 'daily_digest', 'weekly_digest']
    search_fields = ['user__email']
