"""
Notification Serializers for REST API.

Provides tenant-aware serializers for notification models to support API endpoints.
Uses base serializer classes from api.serializers_base for consistent tenant handling.
"""

from datetime import timedelta
from typing import List

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.utils.timesince import timesince

from api.serializers_base import (
    TenantAwareSerializer,
    TenantWritableSerializer,
    AuditableSerializer,
    SlimSerializer,
    UUIDListSerializer,
)
from .models import (
    Notification,
    NotificationChannel,
    NotificationTemplate,
    NotificationPreference,
    ScheduledNotification,
    NotificationDeliveryLog,
)

User = get_user_model()


# =============================================================================
# USER SERIALIZERS
# =============================================================================

class UserMinimalSerializer(serializers.ModelSerializer):
    """Minimal user serializer for notification sender/recipient."""
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'uuid', 'username', 'email', 'first_name', 'last_name', 'full_name']
        read_only_fields = fields

    def get_full_name(self, obj):
        return obj.get_full_name() or obj.username


# =============================================================================
# NOTIFICATION TYPE SERIALIZERS
# =============================================================================

class NotificationTypeSerializer(serializers.Serializer):
    """Notification type configuration for available notification types."""
    value = serializers.CharField()
    label = serializers.CharField()
    category = serializers.CharField(required=False)
    description = serializers.CharField(required=False)
    default_channels = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=list
    )
    is_system = serializers.BooleanField(default=False)


class NotificationChannelSerializer(serializers.ModelSerializer):
    """Serializer for NotificationChannel model."""
    channel_type_display = serializers.CharField(
        source='get_channel_type_display',
        read_only=True
    )

    class Meta:
        model = NotificationChannel
        fields = [
            'id', 'name', 'channel_type', 'channel_type_display',
            'is_active', 'description', 'config',
            'rate_limit_per_hour', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


# =============================================================================
# NOTIFICATION PREFERENCE SERIALIZERS
# =============================================================================

class NotificationPreferenceSerializer(TenantAwareSerializer):
    """
    Serializer for NotificationPreference model.
    Handles user notification preferences across channels and types.
    """
    user_email = serializers.EmailField(source='user.email', read_only=True)
    available_channels = serializers.SerializerMethodField()

    class Meta:
        model = NotificationPreference
        fields = [
            'id', 'user_email', 'notifications_enabled',
            'quiet_hours_enabled', 'quiet_hours_start', 'quiet_hours_end',
            'timezone', 'channel_preferences', 'type_preferences',
            'phone_number', 'slack_user_id',
            'email_digest_frequency', 'unsubscribe_token',
            'global_unsubscribe', 'unsubscribed_types',
            'available_channels', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user_email', 'unsubscribe_token',
            'available_channels', 'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'fcm_token': {'write_only': True},
            'apns_token': {'write_only': True},
        }

    def get_available_channels(self, obj):
        """Get list of available notification channels."""
        return [
            {'value': choice[0], 'label': str(choice[1])}
            for choice in NotificationChannel.CHANNEL_TYPES
        ]


class NotificationPreferenceUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating notification preferences."""

    class Meta:
        model = NotificationPreference
        fields = [
            'notifications_enabled', 'quiet_hours_enabled',
            'quiet_hours_start', 'quiet_hours_end', 'timezone',
            'channel_preferences', 'type_preferences', 'phone_number',
            'email_digest_frequency', 'global_unsubscribe', 'unsubscribed_types'
        ]


# =============================================================================
# NOTIFICATION TEMPLATE SERIALIZERS
# =============================================================================

class NotificationTemplateListSerializer(serializers.ModelSerializer):
    """List serializer for NotificationTemplate model."""
    channel_name = serializers.CharField(source='channel.name', read_only=True)
    channel_type = serializers.CharField(source='channel.channel_type', read_only=True)
    template_type_display = serializers.CharField(
        source='get_template_type_display',
        read_only=True
    )

    class Meta:
        model = NotificationTemplate
        fields = [
            'id', 'name', 'template_type', 'template_type_display',
            'channel', 'channel_name', 'channel_type', 'language',
            'is_active', 'description', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


class NotificationTemplateDetailSerializer(AuditableSerializer):
    """Detail serializer for NotificationTemplate model with full content."""
    channel = NotificationChannelSerializer(read_only=True)
    channel_id = serializers.PrimaryKeyRelatedField(
        queryset=NotificationChannel.objects.all(),
        source='channel',
        write_only=True
    )
    created_by = UserMinimalSerializer(read_only=True)
    template_type_display = serializers.CharField(
        source='get_template_type_display',
        read_only=True
    )

    class Meta:
        model = NotificationTemplate
        fields = [
            'id', 'name', 'template_type', 'template_type_display',
            'channel', 'channel_id', 'subject', 'body', 'html_body',
            'language', 'is_active', 'description', 'default_context',
            'created_by', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at', 'created_by']


# =============================================================================
# NOTIFICATION DELIVERY LOG SERIALIZERS
# =============================================================================

class NotificationDeliveryLogSerializer(serializers.ModelSerializer):
    """Serializer for NotificationDeliveryLog model."""

    class Meta:
        model = NotificationDeliveryLog
        fields = [
            'id', 'attempt_number', 'status', 'response_code',
            'error_type', 'error_message', 'external_id',
            'started_at', 'completed_at', 'duration_ms'
        ]
        read_only_fields = fields


# =============================================================================
# NOTIFICATION SERIALIZERS
# =============================================================================

class NotificationListSerializer(TenantAwareSerializer):
    """
    Lightweight notification list serializer.
    Optimized for listing notifications with minimal data.
    """
    sender = UserMinimalSerializer(read_only=True)
    channel_type = serializers.CharField(source='channel.channel_type', read_only=True)
    channel_name = serializers.CharField(source='channel.name', read_only=True)
    time_ago = serializers.SerializerMethodField()
    notification_type_display = serializers.CharField(
        source='get_notification_type_display',
        read_only=True
    )

    class Meta:
        model = Notification
        fields = [
            'id', 'uuid', 'notification_type', 'notification_type_display',
            'title', 'message', 'action_url', 'action_text',
            'status', 'priority', 'is_read', 'read_at',
            'is_dismissed', 'dismissed_at', 'sender',
            'channel_type', 'channel_name', 'time_ago',
            'created_at', 'expires_at'
        ]
        read_only_fields = fields

    def get_time_ago(self, obj):
        """Get human-readable time since notification was created."""
        if obj.created_at:
            return timesince(obj.created_at, timezone.now())
        return None


class NotificationSerializer(TenantAwareSerializer):
    """
    Full notification display serializer.
    Used for single notification retrieval with all details.
    """
    sender = UserMinimalSerializer(read_only=True)
    recipient = UserMinimalSerializer(read_only=True)
    channel = NotificationChannelSerializer(read_only=True)
    template = NotificationTemplateListSerializer(read_only=True)
    delivery_logs = NotificationDeliveryLogSerializer(many=True, read_only=True)
    time_ago = serializers.SerializerMethodField()
    is_expired = serializers.BooleanField(read_only=True)
    notification_type_display = serializers.CharField(
        source='get_notification_type_display',
        read_only=True
    )
    status_display = serializers.CharField(
        source='get_status_display',
        read_only=True
    )
    priority_display = serializers.CharField(
        source='get_priority_display',
        read_only=True
    )

    class Meta:
        model = Notification
        fields = [
            'id', 'uuid', 'recipient', 'sender', 'channel', 'template',
            'notification_type', 'notification_type_display',
            'title', 'message', 'html_message',
            'action_url', 'action_text', 'context_data',
            'status', 'status_display', 'priority', 'priority_display',
            'is_read', 'read_at', 'is_dismissed', 'dismissed_at',
            'sent_at', 'delivered_at', 'error_message',
            'retry_count', 'max_retries', 'external_id',
            'expires_at', 'is_expired', 'batch_id', 'time_ago',
            'created_at', 'updated_at', 'delivery_logs'
        ]
        read_only_fields = fields

    def get_time_ago(self, obj):
        """Get human-readable time since notification was created."""
        if obj.created_at:
            return timesince(obj.created_at, timezone.now())
        return None


class NotificationDetailSerializer(NotificationSerializer):
    """Alias for backward compatibility."""
    pass


# =============================================================================
# NOTIFICATION CREATE/ACTION SERIALIZERS
# =============================================================================

class NotificationCreateSerializer(serializers.Serializer):
    """Serializer for creating new notifications via API."""
    recipient_id = serializers.IntegerField(
        help_text=_("ID of the user to receive the notification")
    )
    notification_type = serializers.CharField(
        max_length=50,
        help_text=_("Type of notification (e.g., 'new_message', 'payment_received')")
    )
    title = serializers.CharField(
        max_length=255,
        help_text=_("Notification title")
    )
    message = serializers.CharField(
        help_text=_("Notification message body")
    )
    channels = serializers.ListField(
        child=serializers.CharField(max_length=20),
        required=False,
        default=['in_app', 'email'],
        help_text=_("Channels to send notification through")
    )
    action_url = serializers.URLField(
        required=False,
        allow_blank=True,
        help_text=_("URL for the notification action button")
    )
    action_text = serializers.CharField(
        max_length=100,
        required=False,
        default='View',
        help_text=_("Text for the action button")
    )
    priority = serializers.ChoiceField(
        choices=['low', 'normal', 'high', 'urgent'],
        default='normal',
        help_text=_("Notification priority level")
    )
    context_data = serializers.JSONField(
        required=False,
        default=dict,
        help_text=_("Additional context data for template rendering")
    )
    template_name = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True,
        help_text=_("Name of notification template to use")
    )
    content_type = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text=_("Content type for related object")
    )
    object_id = serializers.IntegerField(
        required=False,
        allow_null=True,
        help_text=_("ID of related object")
    )

    def validate_recipient_id(self, value):
        try:
            User.objects.get(pk=value)
        except User.DoesNotExist:
            raise serializers.ValidationError(_("Recipient user does not exist"))
        return value

    def validate_channels(self, value):
        valid_channels = ['email', 'sms', 'push', 'in_app', 'slack', 'webhook']
        for channel in value:
            if channel not in valid_channels:
                raise serializers.ValidationError(
                    _("Invalid channel: %(channel)s. Valid channels are: %(valid)s") % {
                        'channel': channel,
                        'valid': ', '.join(valid_channels)
                    }
                )
        return value


class BulkNotificationSerializer(serializers.Serializer):
    """
    Serializer for sending bulk notifications to multiple recipients.
    Supports sending the same notification to many users at once.
    """
    recipient_ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1,
        max_length=1000,
        help_text=_("List of recipient user UUIDs")
    )
    notification_type = serializers.CharField(
        max_length=50,
        help_text=_("Type of notification")
    )
    title = serializers.CharField(
        max_length=255,
        help_text=_("Notification title")
    )
    message = serializers.CharField(
        help_text=_("Notification message body")
    )
    channels = serializers.ListField(
        child=serializers.CharField(max_length=20),
        required=False,
        default=['in_app'],
        help_text=_("Channels to send through")
    )
    action_url = serializers.URLField(
        required=False,
        allow_blank=True
    )
    priority = serializers.ChoiceField(
        choices=['low', 'normal', 'high', 'urgent'],
        default='normal'
    )
    context = serializers.DictField(
        required=False,
        default=dict,
        help_text=_("Context data for template rendering")
    )

    def validate_recipient_ids(self, value):
        """Validate all recipient UUIDs exist."""
        existing_uuids = set(
            User.objects.filter(uuid__in=value).values_list('uuid', flat=True)
        )
        missing_uuids = set(value) - existing_uuids
        if missing_uuids:
            raise serializers.ValidationError(
                _("Users not found: %(uuids)s") % {'uuids': list(missing_uuids)[:5]}
            )
        return value


class NotificationActionSerializer(serializers.Serializer):
    """Serializer for notification actions (mark read, dismiss, etc.)."""
    notification_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False,
        help_text=_("List of notification IDs to act on")
    )
    action = serializers.ChoiceField(
        choices=['mark_read', 'mark_unread', 'dismiss', 'mark_all_read', 'dismiss_all'],
        help_text=_("Action to perform")
    )


# =============================================================================
# SCHEDULED NOTIFICATION SERIALIZERS
# =============================================================================

class ScheduledNotificationSerializer(AuditableSerializer):
    """Serializer for ScheduledNotification model."""
    template = NotificationTemplateListSerializer(read_only=True)
    template_id = serializers.PrimaryKeyRelatedField(
        queryset=NotificationTemplate.objects.all(),
        source='template',
        write_only=True
    )
    recipient = UserMinimalSerializer(read_only=True)
    recipient_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        source='recipient',
        write_only=True,
        required=False,
        allow_null=True
    )
    created_by = UserMinimalSerializer(read_only=True)
    recurrence_display = serializers.CharField(
        source='get_recurrence_display',
        read_only=True
    )

    class Meta:
        model = ScheduledNotification
        fields = [
            'id', 'uuid', 'recipient', 'recipient_id', 'recipient_filter',
            'template', 'template_id', 'context_data', 'scheduled_at',
            'recurrence', 'recurrence_display', 'recurrence_end_date',
            'last_run_at', 'next_run_at', 'is_active', 'is_processed',
            'name', 'description', 'created_by', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'uuid', 'last_run_at', 'next_run_at', 'is_processed',
            'created_by', 'created_at', 'updated_at'
        ]


# =============================================================================
# STATISTICS SERIALIZERS
# =============================================================================

class NotificationStatsSerializer(serializers.Serializer):
    """Serializer for notification statistics."""
    total_notifications = serializers.IntegerField()
    unread_count = serializers.IntegerField()
    read_count = serializers.IntegerField()
    dismissed_count = serializers.IntegerField()
    by_type = serializers.DictField()
    by_channel = serializers.DictField()
    by_status = serializers.DictField()
    by_priority = serializers.DictField()
    recent_notifications = NotificationListSerializer(many=True)


class UnreadCountSerializer(serializers.Serializer):
    """Serializer for unread notification count response."""
    unread_count = serializers.IntegerField()
    last_notification_at = serializers.DateTimeField(allow_null=True)


# =============================================================================
# UNSUBSCRIBE & DEVICE REGISTRATION SERIALIZERS
# =============================================================================

class UnsubscribeSerializer(serializers.Serializer):
    """Serializer for unsubscribe action."""
    token = serializers.UUIDField(
        help_text=_("Unsubscribe token from notification preferences")
    )
    notification_type = serializers.CharField(
        max_length=50,
        required=False,
        help_text=_("Specific notification type to unsubscribe from")
    )
    global_unsubscribe = serializers.BooleanField(
        default=False,
        help_text=_("Unsubscribe from all notifications")
    )


class RegisterDeviceSerializer(serializers.Serializer):
    """Serializer for registering push notification device tokens."""
    token = serializers.CharField(
        max_length=500,
        help_text=_("Device token for push notifications")
    )
    device_type = serializers.ChoiceField(
        choices=['fcm', 'apns'],
        help_text=_("Type of device (Firebase Cloud Messaging or Apple Push Notification)")
    )
    device_id = serializers.CharField(
        max_length=255,
        required=False,
        help_text=_("Unique device identifier")
    )

    def save(self, user):
        """Save the device token to user's notification preferences."""
        prefs, _ = NotificationPreference.objects.get_or_create(user=user)

        if self.validated_data['device_type'] == 'fcm':
            prefs.fcm_token = self.validated_data['token']
        else:
            prefs.apns_token = self.validated_data['token']

        prefs.save()
        return prefs


# =============================================================================
# WEBSOCKET NOTIFICATION SERIALIZERS
# =============================================================================

class WebSocketNotificationSerializer(serializers.Serializer):
    """
    Serializer for WebSocket notification payloads.
    Used for real-time notification delivery.
    """
    id = serializers.IntegerField()
    uuid = serializers.UUIDField()
    notification_type = serializers.CharField()
    title = serializers.CharField()
    message = serializers.CharField()
    action_url = serializers.URLField(allow_blank=True)
    action_text = serializers.CharField()
    priority = serializers.CharField()
    is_read = serializers.BooleanField()
    created_at = serializers.DateTimeField()
    sender = UserMinimalSerializer(allow_null=True)
    time_ago = serializers.CharField()


class NotificationCountUpdateSerializer(serializers.Serializer):
    """Serializer for real-time unread count updates via WebSocket."""
    type = serializers.CharField(default='unread_count_update')
    count = serializers.IntegerField()
    timestamp = serializers.DateTimeField()
