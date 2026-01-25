"""
Finance Webhooks API Serializers
"""

from rest_framework import serializers
from django.contrib.contenttypes.models import ContentType
from ..models import (
    WebhookEvent,
    WebhookRetry,
    WebhookSignature,
    WebhookEventType,
)


# ============= WebhookEvent Serializers =============

class WebhookEventListSerializer(serializers.ModelSerializer):
    """Lightweight webhook event list"""
    source_display = serializers.CharField(source='get_source_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    retry_count = serializers.IntegerField(read_only=True)
    processing_time = serializers.SerializerMethodField()

    class Meta:
        model = WebhookEvent
        fields = [
            'webhook_id', 'source', 'source_display', 'event_type',
            'event_id', 'status', 'status_display', 'signature_verified',
            'retry_count', 'processing_time', 'received_at', 'processed_at',
        ]
        read_only_fields = fields

    def get_processing_time(self, obj):
        """Calculate processing time in seconds"""
        if obj.processed_at and obj.received_at:
            delta = obj.processed_at - obj.received_at
            return delta.total_seconds()
        return None


class WebhookEventDetailSerializer(serializers.ModelSerializer):
    """Full webhook event details with payload"""
    source_display = serializers.CharField(source='get_source_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    processing_time = serializers.SerializerMethodField()
    related_object_type = serializers.SerializerMethodField()
    retries_count = serializers.IntegerField(source='retries.count', read_only=True)

    class Meta:
        model = WebhookEvent
        fields = [
            'webhook_id', 'source', 'source_display', 'event_type', 'event_id',
            'status', 'status_display', 'payload', 'signature_verified',
            'signature', 'retry_count', 'retries_count', 'error_message',
            'processing_time', 'related_object_type', 'object_id',
            'metadata', 'received_at', 'processed_at', 'updated_at',
        ]
        read_only_fields = fields

    def get_processing_time(self, obj):
        if obj.processed_at and obj.received_at:
            delta = obj.processed_at - obj.received_at
            return delta.total_seconds()
        return None

    def get_related_object_type(self, obj):
        """Get content type of related object"""
        if obj.content_type:
            return f"{obj.content_type.app_label}.{obj.content_type.model}"
        return None


# ============= WebhookRetry Serializers =============

class WebhookRetryListSerializer(serializers.ModelSerializer):
    """Lightweight webhook retry list"""
    webhook_id = serializers.CharField(source='webhook_event.webhook_id', read_only=True)
    webhook_source = serializers.CharField(source='webhook_event.source', read_only=True)
    webhook_event_type = serializers.CharField(source='webhook_event.event_type', read_only=True)

    class Meta:
        model = WebhookRetry
        fields = [
            'id', 'webhook_id', 'webhook_source', 'webhook_event_type',
            'retry_number', 'retry_at', 'succeeded', 'error_message',
            'next_retry_at',
        ]
        read_only_fields = fields


class WebhookRetryDetailSerializer(serializers.ModelSerializer):
    """Full webhook retry details"""
    webhook_event = WebhookEventListSerializer(read_only=True)

    class Meta:
        model = WebhookRetry
        fields = [
            'id', 'webhook_event', 'retry_number', 'retry_at',
            'succeeded', 'error_message', 'next_retry_at',
        ]
        read_only_fields = fields


# ============= WebhookSignature Serializers =============

class WebhookSignatureListSerializer(serializers.ModelSerializer):
    """Lightweight webhook signature list"""
    webhook_id = serializers.CharField(source='webhook_event.webhook_id', read_only=True)
    webhook_source = serializers.CharField(source='webhook_event.source', read_only=True)

    class Meta:
        model = WebhookSignature
        fields = [
            'id', 'webhook_id', 'webhook_source', 'verified',
            'algorithm', 'ip_address', 'timestamp',
        ]
        read_only_fields = fields


class WebhookSignatureDetailSerializer(serializers.ModelSerializer):
    """Full webhook signature details"""
    webhook_event = WebhookEventListSerializer(read_only=True)

    class Meta:
        model = WebhookSignature
        fields = [
            'id', 'webhook_event', 'verified', 'signature',
            'expected_signature', 'algorithm', 'timestamp',
            'ip_address', 'user_agent',
        ]
        read_only_fields = fields


# ============= WebhookEventType Serializers =============

class WebhookEventTypeListSerializer(serializers.ModelSerializer):
    """Lightweight webhook event type list"""
    source_display = serializers.CharField(source='get_source_display', read_only=True)
    recent_events_count = serializers.SerializerMethodField()

    class Meta:
        model = WebhookEventType
        fields = [
            'id', 'source', 'source_display', 'event_type',
            'is_enabled', 'auto_retry', 'max_retries',
            'recent_events_count', 'created_at',
        ]
        read_only_fields = ['id', 'created_at']

    def get_recent_events_count(self, obj):
        """Count events of this type in last 24 hours"""
        from django.utils import timezone
        from datetime import timedelta

        twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
        return WebhookEvent.objects.filter(
            source=obj.source,
            event_type=obj.event_type,
            received_at__gte=twenty_four_hours_ago
        ).count()


class WebhookEventTypeDetailSerializer(serializers.ModelSerializer):
    """Full webhook event type details"""
    source_display = serializers.CharField(source='get_source_display', read_only=True)
    total_events = serializers.SerializerMethodField()
    succeeded_events = serializers.SerializerMethodField()
    failed_events = serializers.SerializerMethodField()

    class Meta:
        model = WebhookEventType
        fields = [
            'id', 'source', 'source_display', 'event_type',
            'handler_path', 'is_enabled', 'auto_retry', 'max_retries',
            'description', 'total_events', 'succeeded_events',
            'failed_events', 'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_total_events(self, obj):
        """Total events of this type (all time)"""
        return WebhookEvent.objects.filter(
            source=obj.source,
            event_type=obj.event_type
        ).count()

    def get_succeeded_events(self, obj):
        """Succeeded events of this type (all time)"""
        return WebhookEvent.objects.filter(
            source=obj.source,
            event_type=obj.event_type,
            status='succeeded'
        ).count()

    def get_failed_events(self, obj):
        """Failed events of this type (all time)"""
        return WebhookEvent.objects.filter(
            source=obj.source,
            event_type=obj.event_type,
            status='failed'
        ).count()


class WebhookEventTypeCreateSerializer(serializers.ModelSerializer):
    """Create/update webhook event type"""
    class Meta:
        model = WebhookEventType
        fields = [
            'source', 'event_type', 'handler_path', 'is_enabled',
            'auto_retry', 'max_retries', 'description',
        ]

    def validate_handler_path(self, value):
        """Validate handler path is a valid Python import path"""
        if not value:
            raise serializers.ValidationError("Handler path is required")

        # Basic format validation (module.function)
        parts = value.split('.')
        if len(parts) < 2:
            raise serializers.ValidationError(
                "Handler path must be in format: module.path.to.function"
            )

        return value

    def validate_max_retries(self, value):
        """Validate max retries is reasonable"""
        if value < 0:
            raise serializers.ValidationError("Max retries cannot be negative")
        if value > 10:
            raise serializers.ValidationError("Max retries cannot exceed 10")
        return value
